# OT-Medeus — Ajan Çalışma Kılavuzu

Her oturumun başında okunur. Claude, Codex, Gemini, hangi ajan çalışırsa çalışsın geçerlidir.
Güncel durum, açık bulgular ve sıradaki işler için: **DURUM.md**.

## Proje
OT / ICS / BMS varlık keşif ve envanter motoru (Osmedeus tarzı modüler iş akışı).
İleride Osmedeus tabanlı tarama SaaS'ının (FastAPI + PostgreSQL) OT keşif modülü olacak.
Python 3.8+. Çekirdek yalnızca standart kütüphane; `scapy` ve `nmap` opsiyonel.
Modül yapısı: README.md → "Yapı" (tek kaynak; burada tekrarlanmaz).

Proje sahibi yazılımcı değil, kodu ajan yazar. Değişiklikleri sade Türkçe özetle,
teknik terimi ilk geçtiği yerde bir cümleyle açıkla.

## Komutlar
- Testler: `python3 -m unittest discover -s tests -v`
- Derleme kontrolü: `python3 -m py_compile ot_medeus/*.py ot_medeus/scanners/*.py`
- Yardım: `python3 -m ot_medeus -h`

## Çalışma kuralları
1. **Önce teşhis, sonra düzeltme.** Sahip açıkça "düzelt" demeden kodu değiştirme.
   Sorun bildirildiğinde: sorunları listele → kanıtla (test ya da çıktı) → hangisinin
   düzeltileceğini sor.
2. **Her düzeltme bir testle gelir.** Önce kırmızı test, sonra düzeltme, sonra tüm testler.
   Hiçbir test kırılmadan iş bitmiş sayılmaz. Testi yeşile çevirmek için testi gevşetme;
   test yanlışsa önce sahibe söyle.
3. **Kod değişirse not da değişir.** Modül ekleyip/çıkarınca README "Yapı" bölümünü aynı
   değişiklikte güncelle (B1 testi kontrol eder). Açıklamalar mümkün olduğunca kodun
   içindeki docstring'lerde dursun.
4. **Oturum sonunda DURUM.md'yi güncelle:** biten, açık, sıradaki, sahibin kararları.

## OT güvenlik kuralları (yasak → doğrusu)
- Cihaza yazan, kontrol eden, durum değiştiren paket gönderme
  → Yalnızca kimlik/okuma sorguları (Modbus 0x2B/0x0E, EtherNet/IP ListIdentity,
  BACnet ReadProperty ya da tekil Who-Is).
- Yayın (broadcast) paketi gönderme (BACnet DNET=0xFFFF, global Who-Is vb.)
  → Hedef IP'ye tekil (unicast), yerel ağ sorgusu.
- Limiter'ı atlayan ağ çağrısı yazma
  → Her bağlantı `probes.tcp_connect` / `limiter.acquire()` üzerinden geçer.
- `passive` profil ve `--passive-only` hedefe paket gönderemez
  → Pasif modda yalnızca dinleme ve üçüncü taraf OSINT.
- Kullanıcının vermediği IP'yi aktif tarama
  → crt.sh / Censys / FOFA'dan gelen IP'leri sahip kapsam kararını verene kadar
  yalnızca "aday" olarak listele (DURUM.md → Karar 1).
- Varsayılan profili hızlandırma → varsayılan `safe` kalır; hız yeni profil olarak eklenir.

## Kod kuralları
- Hataları sessizce yutma (`except Exception: pass`, boş liste dönme)
  → Workflow `notes` üzerinden kullanıcıya görünür uyarı üret.
- Bir host'taki hata tüm taramayı düşürmesin → host bazında yakala, not düş, devam et.
- Kısa/yaygın kelimeyi imza olarak ekleme ("NJ", "Digi", "Priva")
  → Kelime sınırıyla eşle ve `tests/` altındaki sıradan-sayfa örneğine yeni bir vaka ekle.
- Uydurma veri yok (CVE, OUI, nmap script adı, API uç noktası)
  → Yalnızca doğrulanmış kaynak; doğrulama tarihini yorum olarak yaz.
- Yeni zorunlu bağımlılık ekleme → opsiyonel extra olarak öner, sahibe sor.

## Bilinen tuzaklar
- nmap, `--script` içinde tek bir bilinmeyen ad olsa bile taramayı başlatmadan çıkar.
- CIRCL'in `/api/cvefor` uç noktası herkese açık sunucuda kapatılmış görünüyor.
- 1024 altı portlar (502, 102) test için root ister; testlerde 44818 gibi portları kullan.
