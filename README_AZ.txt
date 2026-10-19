HIKVISION NFC/KART GİRİŞ SİSTEMİ — DÜZƏLDİLMİŞ VERSİYA
=====================================================

Bu proqram Hikvision ISAPI alertStream endpoint-indən hadisələri dinləyir.
XML və JSON payload-ları oxuyur, cardNo sahəsini həm EventNotificationAlert,
həm də onun daxilindəki AccessControllerEvent obyektindən tapır.

QURAŞDIRMA (Windows CMD)
1. ZIP-i qovluğa çıxarın.
2. Həmin qovluqda CMD açın.
3. py -m venv .venv
4. .venv\Scripts\activate.bat
5. python -m pip install --upgrade pip
6. pip install -r requirements.txt
7. copy .env.example .env
8. .env faylını açın:
   - DEVICE_SUBNET + DEVICE_LAST_OCTETS: cihazların IP-ləri (10.0.70.55, .57, .56, .54, .58, .53, .50, .60, .59, .65)
   - DEVICE_USER / DEVICE_PASSWORD bütün cihazlar üçün eynidir
   - DEVICE_USER / DEVICE_PASSWORD: ISAPI icazəsi olan istifadəçi
   - EVENT_PATH: cihaz dəstəkləyirsə /ISAPI/Event/notification/alertStream
9. python main.py

cards.csv formatı:
card_no,name
1234567890,Əli Məmmədov
0012345678,Aysel Əliyeva

Kart kodlarının əvvəldəki sıfırlarını qorumaq üçün Excel-də sütunu Text edin.
cards.csv boş olsa belə proqram başlayır və tanınmayan kart oxunuşlarını loglayır.

LOG
logs/card_access.log

ƏSAS LOG SƏTİRLƏRİ
- Event stream qoşuldu: HTTP 200: bağlantı uğurludur, amma təkbaşına kart hadisəsi gəldiyini sübut etmir.
- KART OXUDULDU: payload içindən kart kodu tapıldı.
- ACCESS HADİSƏSİ GƏLDİ, AMMA KART KODU TAPILMADI: hadisə var, lakin payload-da tanınan kart sahəsi tapılmayıb; payload nümunəsi loglanır.
- TANINMAYAN KART: kart kodu gəlib, cards.csv-də yoxdur.
- HTTP 401/403: cihaz istifadəçi/şifrəsi və ISAPI icazələrini yoxlayın.
- Event stream qoşulur, lakin kart oxudanda heç bir event/payload gəlmirsə: bu artıq yalnız Python parsing problemi deyil. Cihaz modeli/firmware, access-control event konfiqurasiyası və ISAPI hesab icazələri yoxlanmalıdır.

QAPI TƏHLÜKƏSİZLİYİ
Qapı yalnız cards.csv-də olan və aktiv access-controller event kimi tanınan kart üçün açılmağa cəhd edir.
Proqram kart hadisəsini loglasa da, tanınmayan kart qapını açmır.
Bu proqramı yalnız özünüzün idarə etdiyiniz cihazda işlədin. Cihazı internetə açmayın.

v3 DÜZƏLİŞLƏRİ (loga əsasən)
- Loqdakı hadisələr (dateTime=2026-09-12, currentEvent=false) cihazın saxladığı KÖHNƏ arxivdir; stream qoşulanda cihaz onları təkrar göndərir.
  Əvvəl bunlar xəbərdarlıq kimi loglanırdı və kart olsaydı qapını açardı. İndi currentEvent=false, köhnə tarix və artıq görülmüş serialNo atılır
  (son serialNo logs/state.json faylında saxlanılır).
- majorEventType=3 / subEventType=112, 113, 1078 kart oxunuşu deyil, cihazın əməliyyat logudur (remote login/logout, konfiqurasiya;
  remoteHostAddr=10.0.70.22 bu proqramın özünün qoşulmasıdır). Artıq xəbərdarlıq yox, yalnız qısa məlumat sətri verilir.
- Qapı yalnız kart hadisəsi tipində (CARD_MAJOR_TYPES, default 5) açılır. İstəsəniz OPEN_SUB_TYPES=1 ilə yalnız "etibarlı kart" hadisəsini qəbul edin.
- "type" açarı axtarışdan çıxarıldı (cardType ilə qarışırdı). employeeNoString dəstəyi əlavə edildi (cards.csv-də employee_no sütunu).
- cards.csv-də Excel-in sildiyi baş sıfırlar artıq uyğunluğa mane olmur.
- Cooldown ilk hadisədə səhvən bloklaya bilərdi - düzəldildi. Log faylı rotasiya olunur (5 MB x 5). Windows konsolunda Azərbaycan hərfləri üçün UTF-8.
- Cihaz fərqli IP-dədir (log: 10.0.70.56, nümunə: .52) - .env-də DEVICE_IP-ni yoxlayın.
- Kart oxudanda "KART OXUDULDU" görünmürsə: cihazda kart əslində major=5 hadisəsi göndərmir; web interfeysdə Event/Access Control hadisələrini və
  ISAPI hesabının "Remote: Notify Surveillance Center" icazəsini yoxlayın. Diaqnostika üçün logging səviyyəsini DEBUG edin.

ÇOXLU CİHAZ
- Hər cihaz üçün ayrıca stream + polling thread-i işləyir, loglarda [IP] prefiksi var.
- Kart hansı cihazda oxunubsa, yalnız həmin cihazın qapısı açılır.
- serialNo və cooldown hər cihaz üçün ayrıca saxlanılır (logs/state_<IP>.json).
- cards.csv dəyişəndə proqramı dayandırmadan 5 saniyə içində avtomatik yenilənir.
- cards.csv sütunları: card_no,name,employee_no
