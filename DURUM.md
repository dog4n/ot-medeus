# DURUM — Devir Notu

**Son güncelleme:** 10.11.2026 · **Kod sürümü:** 0.4.1 (Downloads/ot-medeus.zip, 3 Kasım)

## Nerede kaldık
- Proje 10.11.2026'da yeniden ele alındı. **Kod henüz değiştirilmedi.**
- Teşhis yapıldı: 14 bulgu. 12'si `tests/test_teshis.py` ile kanıtlandı
  (13 test: 12 kırmızı, 1 yeşil). Kırmızı = bulgu hâlâ açık.
- AGENTS.md (tüm ajanlar için kurallar) ve CLAUDE.md eklendi.

## Bulgular (öncelik sırasıyla)
| ID | Bulgu | Kanıt | Test |
|----|-------|-------|------|
| **K1** | `passive` profil pasif değil: external/internal-active akışında yine aktif tarıyor, üstelik hız limiti kapalı (NullLimiter). Dış taramada `enable_probes` de kontrol edilmiyor. | 127.0.0.1:44818'e bağlantı açtı | K1 |
| **K2** | Kapsam dışı tarama riski: crt.sh alt alanları ve Censys/FOFA IP'leri doğrudan aktif taranıyor (CDN/paylaşımlı IP olabilir). `endswith(domain)` "notkurum.com.tr"yi de kabul ediyor. | mock'lu crt.sh yanıtı | K2 |
| **K3** | BACnet Who-Is global yayın (DNET=0xFFFF): BACnet router/BBMD'ye ulaşırsa tüm BACnet ağlarına yayılabilir. | gönderilen bayt incelendi | K3 |
| **Y1** | Web portunda HTTP olmayan tek bir servis (`BadStatusLine`) tüm taramayı çökertiyor, hiçbir sonuç kaydedilmiyor. | uçtan uca tarama çöktü | Y1 |
| **Y2** | nmap motoru hiç sonuç vermiyor: `modicon-info` resmi nmap'te yok → nmap çıkar, kod hatayı yutar. | nmap repo + `nse_main.lua` | Y2 |
| **Y3** | Yanlış pozitif imzalar: Priva→privacy, Ovation→innovation, Digi→DigiCert, SEL-→carousel-, NJ, Milestone. Alt alan kelimeleri de: ot→hotmail, su→support, gen→agent, ups→groups. Neredeyse her web sitesi "OT adayı" çıkar. | örnek sayfa/alt alanlar | Y3 |
| **Y4** | Sınıflandırma: 2404 (IEC-104) RTU yerine HMI çıkıyor; yanıt vermeyen Modbus portu "yüksek" güven alıyor; nmap'in bulduğu üretici "Bilinmiyor" ile eziliyor. | doğrudan çağrı | Y4 |
| **Y5** | CVE zenginleştirme büyük olasılıkla boş dönüyor: CIRCL `/api/cvefor` herkese açık sunucuda kapatılmış görünüyor (ares/pycvesearch belgeleri). Buradan erişilemedi, canlı doğrulanmadı. | belge | — |
| **O1** | Canlı olmayan hostlar elenmiyor: çoğu boş bir /24, safe profilde tahminen ~45 dk (254 host × 21 port × 2 sn / 4 thread). ARP sonucu varsa sadece yanıt verenler taranmalı. | hesap | — |
| **O2** | `run_workflow` çağıranın hedef listesini değiştiriyor; `full` akışında OSINT IP'leri iç ağ gibi (ARP dahil) de taranıyor. | mock'lu çağrı | O2 |
| **O3** | Diff, aynı workspace'teki farklı akışları (iç/dış/pasif) karşılaştırıp sahte "yeni/kaybolan cihaz" alarmı üretiyor. | kod okuma | — |
| **O4** | Hatalar sessizce yutuluyor (crt.sh, ARP'ta root yoksa, nmap, CVE): kullanıcı "0 bulgu" görür, nedenini bilmez. | kod okuma | — |
| **B1** | README eski: v0.3'ü anlatıyor; classify, cve, osint, oui_loader, nmap_ics "Yapı"da yok. | — | B1 |
| **B2** | Küçükler: tekrarlı imzalar (Desigo, Teltonika); OUI filtresi geniş ("abb", "delta", "apc"); API anahtarları komut satırında (shell geçmişine düşer); HTML raporda kapanan portlar yok; "taranan hedef" CIDR sayısını sayıyor. | kod okuma | — |

## Sahibin vermesi gereken kararlar
1. **Kapsam (K2):** OSINT'ten bulunan IP'ler aktif taransın mı? Öneri: varsayılan sadece listele; `--scan-discovered` gibi açık bir bayrakla tara.
2. **CVE kaynağı (Y5):** NVD API 2.0, CIRCL Vulnerability-Lookup'un yeni API'si ya da çevrimdışı veri.
3. **Diff kapsamı (O3):** workspace bazında mı, workspace + akış + hedef bazında mı?
4. **Sürüm kontrolü:** Proje git'e (özel GitHub reposu) alınsın mı? Düzeltmelere başlamadan önerilir.

## Sıradaki işler
1. K1–K3 (güvenlik) düzelt → ilgili testler yeşile dönsün.
2. Y1–Y4 düzelt; Y5 için karar 2 bekleniyor.
3. O1–O4, sonra B1–B2.
4. Tüm testler yeşil olunca: Osmedeus SaaS'a modül olarak bağlama.
