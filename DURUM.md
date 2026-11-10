# DURUM — Devir Notu

**Son güncelleme:** 10.11.2026 · **Kod sürümü:** 0.4.1 + K1–K3 düzeltmeleri
**Repo:** https://github.com/dog4n/ot-medeus (özel, Claude'a bağlı) · **Mac kopyası:** ~/Documents/ot-medeus (git klonu değil; değişiklikler elle senkronlanıyor)

## Nerede kaldık
- Teşhis: 14 bulgu (aşağıda). `tests/test_teshis.py`: 19 test → **11 yeşil, 8 kırmızı**.
  Kırmızı = bulgu hâlâ açık (B1, Y1–Y4).
- **Kapatılanlar (10.11.2026):** K1, K2, K3 ve yan etki olarak O2.
  - K1: `passive` profil artık hedefe paket göndermiyor; `internal-active`/`full` ile kullanılınca araç hata veriyor. Dış taramada BACnet/SSL sorguları `enable_probes`'a uyuyor.
  - K2: Aktif tarama yalnızca `-t` hedeflerine. crt.sh/Censys/FOFA IP'leri raporda "adaylar" tablosunda olası sahip tahminiyle (Cloudflare aralıkları, CNAME sonekleri, Shodan etiketi) listeleniyor; `--scan-discovered` ile açıkça taranabiliyor. Domain eşleşmesi düzeltildi (`notkurum.com.tr` artık alınmıyor).
  - K3: BACnet sorgusu global yayın Who-Is yerine hedefe tekil ReadProperty (nmap bacnet-info ile aynı bayt dizilimi); yalnızca hedef IP'den gelen yanıt kabul ediliyor.
  - O2: `run_workflow` çağıranın hedef listesini değiştirmiyor; OSINT IP'leri iç ağ taramasına karışmıyor.

## Açık bulgular (öncelik sırasıyla)
| ID | Bulgu | Kanıt | Test |
|----|-------|-------|------|
| **Y1** | Web portunda HTTP olmayan tek bir servis (`BadStatusLine`) tüm taramayı çökertiyor, hiçbir sonuç kaydedilmiyor. | uçtan uca tarama çöktü | Y1 |
| **Y2** | nmap motoru hiç sonuç vermiyor: `modicon-info` resmi nmap'te yok → nmap çıkar, kod hatayı yutar. | nmap repo + `nse_main.lua` | Y2 |
| **Y3** | Yanlış pozitif imzalar: Priva→privacy, Ovation→innovation, Digi→DigiCert, SEL-→carousel-, NJ, Milestone. Alt alan kelimeleri de: ot→hotmail, su→support, gen→agent, ups→groups. | örnek sayfa/alt alanlar | Y3 |
| **Y4** | Sınıflandırma: 2404 (IEC-104) RTU yerine HMI çıkıyor; yanıt vermeyen Modbus portu "yüksek" güven alıyor; nmap'in bulduğu üretici "Bilinmiyor" ile eziliyor. | doğrudan çağrı | Y4 |
| **Y5** | CVE zenginleştirme büyük olasılıkla boş dönüyor: CIRCL `/api/cvefor` herkese açık sunucuda kapatılmış görünüyor (ares/pycvesearch belgeleri). Canlı doğrulanmadı. | belge | — |
| **O1** | Canlı olmayan hostlar elenmiyor: çoğu boş bir /24, safe profilde tahminen ~45 dk. ARP sonucu varsa sadece yanıt verenler taranmalı. | hesap | — |
| **O3** | Diff, aynı workspace'teki farklı akışları (iç/dış/pasif) karşılaştırıp sahte "yeni/kaybolan cihaz" alarmı üretiyor. | kod okuma | — |
| **O4** | Hatalar sessizce yutuluyor (crt.sh, ARP'ta root yoksa, nmap, CVE): kullanıcı "0 bulgu" görür, nedenini bilmez. | kod okuma | — |
| **B1** | README eski: v0.3'ü anlatıyor; classify, cve, osint, oui_loader, nmap_ics "Yapı"da yok. | — | B1 |
| **B2** | Küçükler: tekrarlı imzalar (Desigo, Teltonika); OUI filtresi geniş ("abb", "delta", "apc"); API anahtarları komut satırında (shell geçmişine düşer); HTML raporda kapanan portlar yok; "taranan hedef" CIDR sayısını sayıyor; adaylar SQLite'a kaydedilmiyor (yalnızca JSON/MD/HTML raporda). | kod okuma | — |

## Sahibin verdiği kararlar
1. ✅ **Kapsam (K2), 10.11.2026:** Keşfedilen IP'ler varsayılan olarak yalnızca listelenir; aktif tarama `--scan-discovered` ile.
2. ✅ **Sürüm kontrolü, 10.11.2026:** Özel repo açıldı ve Claude'a bağlandı.

## Sahibin vermesi gereken kararlar
1. **CVE kaynağı (Y5):** NVD API 2.0, CIRCL Vulnerability-Lookup'un yeni API'si ya da çevrimdışı veri.
2. **Diff kapsamı (O3):** workspace bazında mı, workspace + akış + hedef bazında mı?

## Sıradaki işler
1. Y1–Y4 düzelt; Y5 için karar 1 bekleniyor.
2. O1, O3, O4; sonra B1–B2.
3. Tüm testler yeşil olunca: Osmedeus SaaS'a modül olarak bağlama.
