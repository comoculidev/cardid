"""
Hikvision ISAPI kart dinləyicisi - ÇOXLU CİHAZ versiyası.

Hər cihaz üçün ayrıca thread-lər işləyir:
  * alertStream (canlı hadisələr)
  * AcsEvent polling (cihazın öz event loqu)
Kart yalnız OXUNDUĞU cihazda, cards.csv-də varsa həmin cihazın qapısını açır.
"""
import csv
import json
import logging
import os
import re
import sys
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

import requests
import urllib3
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from dotenv import load_dotenv

# Windows console (cp1251/cp1252) can crash on Azerbaijani characters in log lines.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")


def env_int_set(name, default=""):
    return {int(x) for x in os.getenv(name, default).split(",") if x.strip()}


SCHEME = os.getenv("DEVICE_SCHEME", "http").strip().lower()
PORT = os.getenv("DEVICE_PORT", "").strip()
USER = os.getenv("DEVICE_USER", "admin").strip()
PASSWORD = os.getenv("DEVICE_PASSWORD", "")
EVENT_PATH = os.getenv("EVENT_PATH", "/ISAPI/Event/notification/alertStream").strip()
DOOR_PATH = os.getenv("DOOR_PATH", "/ISAPI/AccessControl/RemoteControl/door/1").strip()
COOLDOWN = float(os.getenv("COOLDOWN_SECONDS", "5"))
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() in ("1", "true", "yes")
CARDS_FILE = BASE / os.getenv("CARDS_FILE", "cards.csv")
MAX_EVENT_AGE = float(os.getenv("MAX_EVENT_AGE_SECONDS", "120"))
CARD_MAJOR_TYPES = env_int_set("CARD_MAJOR_TYPES", "5")
OPEN_SUB_TYPES = env_int_set("OPEN_SUB_TYPES", "")
POLL_ENABLED = os.getenv("POLL_ACS_EVENTS", "true").lower() in ("1", "true", "yes")
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL_SECONDS", "1.5"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
CARDS_RELOAD_SECONDS = 5.0
LOGS = BASE / "logs"
LOGS.mkdir(exist_ok=True)


def device_ips():
    """DEVICE_IPS (tam IP-lər) varsa o; yoxsa DEVICE_SUBNET + DEVICE_LAST_OCTETS."""
    full = [x.strip() for x in os.getenv("DEVICE_IPS", "").split(",") if x.strip()]
    if full:
        return list(dict.fromkeys(full))
    subnet = os.getenv("DEVICE_SUBNET", "10.0.70").strip().strip(".")
    octets = [x.strip() for x in os.getenv("DEVICE_LAST_OCTETS", "").split(",") if x.strip()]
    if not octets and os.getenv("DEVICE_IP", "").strip():  # köhnə .env uyğunluğu
        return [os.getenv("DEVICE_IP").strip()]
    return list(dict.fromkeys(f"{subnet}.{o}" for o in octets))


if not VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.StreamHandler(),
        RotatingFileHandler(LOGS / "card_access.log", maxBytes=5_000_000, backupCount=5, encoding="utf-8"),
    ],
)
_log = logging.getLogger("cards")

ROOT_START_RE = re.compile(rb"<(?:[A-Za-z_][\w.-]*:)?EventNotificationAlert\b", re.I)
CARD_KEYS = ("cardNo", "cardNO", "card_no", "nfcCode", "nfc_code", "cardNumber", "cardNumberString")
EVENT_KEYS = ("eventType", "event_type")
EMPLOYEE_KEYS = ("employeeNoString", "employeeNo")
MAJOR_KEYS = ("majorEventType",)
SUB_KEYS = ("subEventType",)
SERIAL_KEYS = ("serialNo",)
CURRENT_KEYS = ("currentEvent",)
STATE_KEYS = ("eventState", "event_state", "state")


# --------------------------------------------------------------------------- helpers
def norm(value):
    return re.sub(r"[^0-9A-Za-z]", "", str(value or "")).upper()


def card_key(value):
    """Comparison key: normalized, leading zeros ignored (Excel often strips them)."""
    n = norm(value)
    return n.lstrip("0") or ("0" if n else "")


def to_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def to_bool(value):
    if value is None or str(value).strip() == "":
        return None
    return str(value).strip().lower() in ("true", "1", "yes")


def event_age_seconds(date_text):
    """Age of the event according to its own timestamp; None if it cannot be parsed."""
    if not date_text:
        return None
    try:
        dt = datetime.fromisoformat(str(date_text).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.astimezone()  # assume local time
    return (datetime.now(timezone.utc) - dt).total_seconds()


# --------------------------------------------------------------------------- cards
class Cards:
    """cards.csv - ddəyişəndə proqramı dayandırmadan avtomatik yenidən oxuyur."""

    def __init__(self, path):
        self.path = path
        self.data = {}
        self.mtime = None
        self.checked = 0.0
        self.lock = threading.Lock()
        self._load(initial=True)

    def _load(self, initial=False):
        allowed = {}
        if not self.path.exists():
            if initial:
                _log.warning("Kart faylı tapılmadı: %s. Proqram yenə də bütün oxunuşları loglayacaq.", self.path)
            self.data, self.mtime = allowed, None
            return
        try:
            mtime = self.path.stat().st_mtime
            with self.path.open("r", encoding="utf-8-sig", newline="") as file:
                reader = csv.DictReader(file)
                if not reader.fieldnames:
                    _log.warning("cards.csv başlıq sətri yoxdur. Gözlənilən sütunlar: card_no,name")
                    return
                for row in reader:
                    clean = {str(k or "").strip().lower(): v for k, v in row.items() if k}
                    raw = (clean.get("card_no") or clean.get("nfc_code") or clean.get("card")
                           or clean.get("cardno") or clean.get("nfc") or "")
                    name = (clean.get("name") or clean.get("full_name") or clean.get("ad_soyad")
                            or clean.get("employee_name") or "")
                    name = (name or "").strip() or "(ad yoxdur)"
                    for part in str(raw or "").replace(",", ";").split(";"):  # bir xanada bir neçə kart
                        card = card_key(part)
                        if card:
                            if card in allowed and allowed[card] != name:
                                _log.warning("Təkrar kart nömrəsi cards.csv-də: %s (%s / %s)", part.strip(), allowed[card], name)
                            allowed[card] = name
                    emp = card_key(clean.get("employee_no") or clean.get("employeeno") or "")
                    if emp:
                        allowed.setdefault("EMP:" + emp, name)
            self.data, self.mtime = allowed, mtime
            if not initial:
                _log.info("cards.csv yenidən oxundu | kart sayı: %d", sum(1 for k in allowed if not k.startswith("EMP:")))
        except Exception:
            _log.exception("cards.csv oxuna bilmədi; əvvəlki siyahı saxlanıldı")

    def get(self):
        now = time.monotonic()
        if now - self.checked >= CARDS_RELOAD_SECONDS:
            with self.lock:
                if now - self.checked >= CARDS_RELOAD_SECONDS:
                    self.checked = now
                    try:
                        m = self.path.stat().st_mtime if self.path.exists() else None
                    except OSError:
                        m = self.mtime
                    if m != self.mtime:
                        self._load()
        return self.data


# --------------------------------------------------------------------------- parsing
def lname(tag):
    return tag.rsplit("}", 1)[-1].split(":")[-1] if isinstance(tag, str) else ""


def xml_value(root, keys):
    wanted = {key.lower() for key in keys}
    for element in root.iter():
        if lname(element.tag).lower() in wanted and element.text and element.text.strip():
            return element.text.strip()
    return ""


def find_json_value(obj, keys):
    """Search nested JSON dictionaries/lists without depending on firmware nesting."""
    wanted = {key.lower() for key in keys}
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in wanted and value is not None and not isinstance(value, (dict, list)):
                text = str(value).strip()
                if text:
                    return text
        for value in obj.values():
            found = find_json_value(value, keys)
            if found:
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = find_json_value(value, keys)
            if found:
                return found
    return ""


def parse_event(payload):
    """Return normalized event info, or None for an unparseable payload."""
    data = payload.strip().lstrip("﻿\x00 \r\n\t")
    if not data:
        return None

    if data.startswith("{") or data.startswith("["):
        try:
            obj = json.loads(data)
            return {
                "format": "JSON",
                "type": find_json_value(obj, EVENT_KEYS),
                "state": find_json_value(obj, STATE_KEYS),
                "card_raw": find_json_value(obj, CARD_KEYS),
                "date": find_json_value(obj, ("dateTime", "time")),
                "description": find_json_value(obj, ("eventDescription", "description")),
                "employee": find_json_value(obj, EMPLOYEE_KEYS),
                "major": to_int(find_json_value(obj, MAJOR_KEYS)),
                "sub": to_int(find_json_value(obj, SUB_KEYS)),
                "serial": to_int(find_json_value(obj, SERIAL_KEYS)),
                "current": to_bool(find_json_value(obj, CURRENT_KEYS)),
                "raw": data,
            }
        except json.JSONDecodeError:
            pass

    starts = list(re.finditer(r"<(?:[A-Za-z_][\w.-]*:)?EventNotificationAlert\b", data, re.I))
    if not starts:
        starts = list(re.finditer(r"<(?:[A-Za-z_][\w.-]*:)?AccessControllerEvent\b", data, re.I))
    if not starts:
        xml_text = data
    else:
        xml_text = data[starts[0].start():]
        root_name_match = re.match(r"<(?:[A-Za-z_][\w.-]*:)?([A-Za-z_][\w.-]*)\b", xml_text)
        if root_name_match:
            root_name = root_name_match.group(1)
            close = re.search(r"</(?:[A-Za-z_][\w.-]*:)?" + re.escape(root_name) + r"\s*>", xml_text, re.I)
            if close:
                xml_text = xml_text[:close.end()]

    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, ValueError):
        return None

    return {
        "format": "XML",
        "type": xml_value(root, EVENT_KEYS),
        "state": xml_value(root, STATE_KEYS),
        "card_raw": xml_value(root, CARD_KEYS),
        "date": xml_value(root, ("dateTime", "time")),
        "description": xml_value(root, ("eventDescription", "description")),
        "employee": xml_value(root, EMPLOYEE_KEYS),
        "major": to_int(xml_value(root, MAJOR_KEYS)),
        "sub": to_int(xml_value(root, SUB_KEYS)),
        "serial": to_int(xml_value(root, SERIAL_KEYS)),
        "current": to_bool(xml_value(root, CURRENT_KEYS)),
        "raw": xml_text,
    }


def extract_payloads(buffer):
    """Extract complete event XML/JSON payloads from a multipart stream."""
    payloads = []
    while buffer:
        xml_match = ROOT_START_RE.search(buffer)
        json_match = re.search(rb"(?:^|[\r\n])\s*(\{)", buffer)
        candidates = []
        if xml_match:
            candidates.append((xml_match.start(), "xml"))
        if json_match:
            candidates.append((json_match.start(1), "json"))
        if not candidates:
            if len(buffer) > 65536:
                buffer = buffer[-4096:]
            break

        start, kind = min(candidates, key=lambda item: item[0])
        if kind == "xml":
            tag_match = re.match(rb"<(?:(?:[A-Za-z_][\w.-]*):)?([A-Za-z_][\w.-]*)\b", buffer[start:])
            if not tag_match:
                buffer = buffer[start + 1:]
                continue
            root_name = tag_match.group(1)
            closing = b"</" + root_name + b">"
            end = buffer.find(closing, start)
            if end < 0:
                close_match = re.search(rb"</(?:[A-Za-z_][\w.-]*:)?" + re.escape(root_name) + rb"\s*>", buffer[start:], re.I)
                if not close_match:
                    if start:
                        buffer = buffer[start:]
                    break
                end = start + close_match.end()
            else:
                end += len(closing)
            payloads.append(buffer[start:end].decode("utf-8", "replace"))
            buffer = buffer[end:]
        else:
            depth = 0
            in_string = False
            escaped = False
            end = None
            for idx in range(start, len(buffer)):
                byte = buffer[idx]
                if in_string:
                    if escaped:
                        escaped = False
                    elif byte == 0x5C:
                        escaped = True
                    elif byte == 0x22:
                        in_string = False
                else:
                    if byte == 0x22:
                        in_string = True
                    elif byte == 0x7B:
                        depth += 1
                    elif byte == 0x7D:
                        depth -= 1
                        if depth == 0:
                            end = idx + 1
                            break
            if end is None:
                if start:
                    buffer = buffer[start:]
                if len(buffer) > 1_048_576:
                    buffer = b""
                break
            payloads.append(buffer[start:end].decode("utf-8", "replace"))
            buffer = buffer[end:]
    return payloads, buffer


# --------------------------------------------------------------------------- device
class Device:
    """Bir cihaz: öz serialNo vəziyyəti, öz cooldown-u, öz bağlantısı."""

    def __init__(self, ip, cards):
        self.ip = ip
        self.tag = "[%s]" % ip
        self.cards = cards
        self.last_seen = {}
        self.lock = threading.Lock()
        self.state_file = LOGS / ("state_%s.json" % ip.replace(":", "_"))
        self.last_serial = self._load_state()
        self.use_basic = False

    # --- logging with device tag
    def log(self, level, msg, *args, **kw):
        _log.log(level, self.tag + " " + msg, *args, **kw)

    # --- state
    def _load_state(self):
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8")).get("last_serial")
        except Exception:
            return None

    def _save_state(self):
        try:
            self.state_file.write_text(json.dumps({"last_serial": self.last_serial}), encoding="utf-8")
        except OSError:
            self.log(logging.DEBUG, "state faylı yazıla bilmədi", exc_info=True)

    # --- http
    def base_url(self):
        return f"{SCHEME}://{self.ip}{':' + PORT if PORT else ''}"

    def request(self, method, path, **kw):
        """Digest auth; cihaz yalnız Basic qəbul edirsə avtomatik Basic-ə keçir."""
        kw.setdefault("verify", VERIFY_TLS)
        url = self.base_url() + path
        auth = HTTPBasicAuth(USER, PASSWORD) if self.use_basic else HTTPDigestAuth(USER, PASSWORD)
        r = requests.request(method, url, auth=auth, **kw)
        if r.status_code == 401 and not self.use_basic:
            www = r.headers.get("WWW-Authenticate", "").lower()
            if "basic" in www and "digest" not in www:
                r.close()
                self.use_basic = True
                self.log(logging.INFO, "Cihaz Basic auth tələb edir; Basic-ə keçildi")
                r = requests.request(method, url, auth=HTTPBasicAuth(USER, PASSWORD), **kw)
        return r

    # --- door
    def open_door(self, card, name):
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<RemoteControlDoor version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema">'
            '<cmd>open</cmd></RemoteControlDoor>'
        )
        try:
            response = self.request("PUT", DOOR_PATH, data=body.encode("utf-8"),
                                    headers={"Content-Type": "application/xml"}, timeout=15)
            if response.ok:
                self.log(logging.INFO, "QAPI AÇILDI | ad=%s | NFC=%s | HTTP=%s", name, card, response.status_code)
            else:
                self.log(logging.ERROR, "QAPI AÇILMADI | NFC=%s | HTTP=%s | cavab=%s",
                         card, response.status_code, response.text[:300].replace("\n", " "))
        except requests.RequestException:
            self.log(logging.ERROR, "Qapı açma əmri uğursuz oldu | NFC=%s", card, exc_info=True)

    # --- event handling
    def handle_payload(self, payload):
        event = parse_event(payload)
        if not event:
            sample = re.sub(r"\s+", " ", payload)[:500]
            if sample:
                self.log(logging.WARNING, "Hadisə alındı, amma XML/JSON kimi oxunmadı | payload=%s", sample)
            return
        self.process_event(event)

    def process_event(self, event):
        allowed = self.cards.get()
        event_type = event["type"].strip()
        st = event["state"].strip().lower()
        major, sub, serial = event["major"], event["sub"], event["serial"]
        raw_card = event["card_raw"].strip()
        card = card_key(raw_card)
        employee = card_key(event["employee"])
        has_card = bool(card) and card != "0"
        is_access_event = event_type.lower() in (
            "accesscontrollerevent", "accesscontroller", "access_control_event"
        )

        # 1) Replay protection (serialNo hər cihaz üçün ayrıca izlənir).
        with self.lock:
            if serial is not None and self.last_serial is not None and serial <= self.last_serial:
                self.log(logging.DEBUG, "Təkrar/köhnə hadisə atıldı | serialNo=%s", serial)
                return
            if serial is not None:
                self.last_serial = serial
                self._save_state()

        stale_reason = None
        if event["current"] is False:
            stale_reason = "currentEvent=false (cihaz arxivi)"
        else:
            age = event_age_seconds(event["date"])
            if MAX_EVENT_AGE and age is not None and age > MAX_EVENT_AGE:
                stale_reason = "hadisə %d san köhnədir (tarix=%s)" % (age, event["date"])
        if stale_reason:
            self.log(logging.DEBUG, "Tarixi hadisə keçildi, qapı açılmır | %s | major=%s sub=%s serialNo=%s",
                     stale_reason, major, sub, serial)
            return

        if not is_access_event:
            self.log(logging.DEBUG, "Kartla əlaqəli olmayan hadisə: tip=%s", event_type or "naməlum")
            return

        if major is not None and major not in CARD_MAJOR_TYPES:
            host = re.search(r'"remoteHostAddr":\s*"([^"]*)"', event["raw"])
            self.log(logging.INFO, "Sistem/əməliyyat hadisəsi (kart deyil) | major=%s sub=%s | host=%s | serialNo=%s",
                     major, sub, host.group(1) if host else "-", serial)
            return

        if not has_card and not employee:
            # major/sub kart tipli olsa da kart yoxdursa (məs. qapı düyməsi) sadəcə log
            self.log(logging.WARNING, "KART HADİSƏSİ GƏLDİ, AMMA KART/İŞÇİ KODU TAPILMADI | major=%s sub=%s | payload=%s",
                     major, sub, re.sub(r"\s+", " ", event["raw"])[:700])
            return

        shown = raw_card or event["employee"]
        self.log(logging.INFO, "KART OXUDULDU | NFC=%s | major=%s sub=%s | state=%s | tarix=%s",
                 shown, major, sub, st or "naməlum", event["date"] or "-")

        if st and st not in ("active", "true", "1"):
            self.log(logging.INFO, "Kart hadisəsi aktiv deyil; qapı açılmadı | NFC=%s | state=%s", shown, st)
            return

        if OPEN_SUB_TYPES and sub not in OPEN_SUB_TYPES:
            self.log(logging.INFO, "subEventType=%s icazəli siyahıda deyil; qapı açılmadı | NFC=%s", sub, shown)
            return

        if has_card and card in allowed:
            key = card
        elif employee and ("EMP:" + employee) in allowed:
            key = "EMP:" + employee
        else:
            key = None
        if key is None:
            self.log(logging.WARNING, "İCAZƏSİZ / TANINMAYAN KART | NFC=%s | işçi=%s", raw_card or "-", event["employee"] or "-")
            return

        now = time.monotonic()
        with self.lock:
            prev = self.last_seen.get(key)
            if prev is not None and now - prev < COOLDOWN:
                self.log(logging.INFO, "Təkrar event cooldown səbəbi ilə qapı əmrinə çevrilmədi | NFC=%s", shown)
                return
            self.last_seen[key] = now
        name = allowed[key]
        self.log(logging.INFO, "İCAZƏ VERİLDİ | ad=%s | NFC=%s", name, shown)
        threading.Thread(target=self.open_door, args=(shown, name), daemon=True).start()

    # --- AcsEvent polling
    def _acs_search(self, since, until, position=0, max_results=30):
        body = {"AcsEventCond": {
            "searchID": "cardpoll", "searchResultPosition": position, "maxResults": max_results,
            "major": 0, "minor": 0, "startTime": since, "endTime": until,
        }}
        r = self.request("POST", "/ISAPI/AccessControl/AcsEvent?format=json", json=body, timeout=15)
        if r.status_code != 200:
            raise RuntimeError("AcsEvent HTTP %s | %s" % (r.status_code, r.text[:300].replace("\n", " ")))
        return r.json().get("AcsEvent") or {}

    def _acs_fetch(self, seconds_back):
        now = datetime.now().astimezone()
        since = (now - timedelta(seconds=seconds_back)).isoformat(timespec="seconds")
        until = (now + timedelta(hours=1)).isoformat(timespec="seconds")
        items, pos = [], 0
        while pos < 500:
            res = self._acs_search(since, until, pos)
            batch = res.get("InfoList") or []
            items.extend(batch)
            pos += len(batch)
            if not batch or res.get("responseStatusStrg") != "MORE":
                break
        return sorted(items, key=lambda i: to_int(i.get("serialNo")) or 0)

    @staticmethod
    def acs_item_to_event(item):
        return {
            "format": "ACS", "type": "AccessControllerEvent", "state": "active",
            "card_raw": str(item.get("cardNo") or ""),
            "employee": str(item.get("employeeNoString") or item.get("employeeNo") or ""),
            "date": item.get("time") or "", "description": item.get("name") or "",
            "major": to_int(item.get("major")), "sub": to_int(item.get("minor")),
            "serial": to_int(item.get("serialNo")), "current": True,
            "raw": json.dumps(item, ensure_ascii=False),
        }

    def poll_loop(self):
        baseline_done = False
        fails = 0
        while True:
            try:
                if not baseline_done:
                    items = self._acs_fetch(86400)
                    top = max([to_int(i.get("serialNo")) or 0 for i in items] or [0])
                    with self.lock:
                        if top and (self.last_serial is None or top > self.last_serial):
                            self.last_serial = top
                            self._save_state()
                    baseline_done = True
                    self.log(logging.INFO, "AcsEvent polling aktivdir | baza serialNo=%s (bundan köhnələr emal olunmur)", top)
                else:
                    for item in self._acs_fetch(120):
                        ev = self.acs_item_to_event(item)
                        with self.lock:
                            seen = self.last_serial
                        if ev["serial"] is not None and seen is not None and ev["serial"] <= seen:
                            continue
                        self.log(logging.INFO, "CİHAZ LOGU | serialNo=%s major=%s minor=%s kart=%s işçi=%s vaxt=%s",
                                 ev["serial"], ev["major"], ev["sub"], ev["card_raw"] or "-",
                                 ev["employee"] or "-", ev["date"])
                        self.process_event(ev)
                if fails:
                    self.log(logging.INFO, "AcsEvent polling bərpa olundu")
                fails = 0
            except Exception as exc:
                fails += 1
                if fails == 1 or fails % 20 == 0:  # log spam olmasın
                    self.log(logging.WARNING, "AcsEvent polling xətası (%d): %s", fails, exc)
                time.sleep(min(5 * fails, 30))
                continue
            time.sleep(POLL_INTERVAL)

    # --- alertStream
    def stream_loop(self):
        path = EVENT_PATH
        delay = 4
        while True:
            try:
                with self.request(
                    "GET", path, stream=True, timeout=(10, 90),
                    headers={"Accept": "multipart/mixed, application/xml, application/json", "Connection": "keep-alive"},
                ) as response:
                    if response.status_code != 200:
                        body = response.text[:500].replace("\n", " ")
                        self.log(logging.ERROR, "Event stream HTTP %s | %s", response.status_code, body)
                        time.sleep(delay)
                        delay = min(delay * 2, 30)
                        continue

                    delay = 4
                    self.log(logging.INFO, "Event stream qoşuldu: HTTP %s | Content-Type=%s",
                             response.status_code, response.headers.get("Content-Type", "naməlum"))
                    buffer = b""
                    for chunk in response.iter_content(chunk_size=1024):
                        if not chunk:
                            continue
                        buffer += chunk
                        payloads, buffer = extract_payloads(buffer)
                        for payload in payloads:
                            try:
                                self.handle_payload(payload)
                            except Exception:
                                self.log(logging.ERROR, "Hadisə emalı xətası", exc_info=True)
            except requests.exceptions.ReadTimeout:
                self.log(logging.WARNING, "Event stream oxuma timeout-u; yenidən qoşulmağa cəhd edilir.")
                time.sleep(2)
            except requests.RequestException as exc:
                self.log(logging.ERROR, "Cihazla əlaqə xətası: %s. %d saniyəyə yenidən qoşulacaq.", exc, delay)
                time.sleep(delay)
                delay = min(delay * 2, 30)
            except Exception:
                self.log(logging.ERROR, "Gözlənilməyən xəta. %d saniyəyə yenidən cəhd ediləcək.", delay, exc_info=True)
                time.sleep(delay)
                delay = min(delay * 2, 30)


def main():
    if not PASSWORD or PASSWORD == "BURAYA_CIHAZ_SIFRESI":
        raise SystemExit("XƏTA: .env faylında DEVICE_PASSWORD sətrinə real cihaz şifrəsini yazın.")
    ips = device_ips()
    if not ips:
        raise SystemExit("XƏTA: .env faylında DEVICE_LAST_OCTETS (və ya DEVICE_IPS) göstərilməyib.")

    cards = Cards(CARDS_FILE)
    _log.info("Hikvision ISAPI kart dinləyicisi başladılır | cihaz sayı: %d", len(ips))
    _log.info("Cihazlar: %s | event endpoint: %s", ", ".join(ips), EVENT_PATH)
    _log.info("İcazəli kart sayı: %d | MAX_EVENT_AGE=%ss | kart major tipləri=%s",
              sum(1 for k in cards.data if not k.startswith("EMP:")), MAX_EVENT_AGE, sorted(CARD_MAJOR_TYPES))

    for ip in ips:
        dev = Device(ip, cards)
        dev.log(logging.INFO, "Son emal olunan serialNo: %s", dev.last_serial)
        threading.Thread(target=dev.stream_loop, name="stream-" + ip, daemon=True).start()
        if POLL_ENABLED:
            threading.Thread(target=dev.poll_loop, name="poll-" + ip, daemon=True).start()

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        _log.info("Proqram istifadəçi tərəfindən dayandırıldı.")


if __name__ == "__main__":
    main()
