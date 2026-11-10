# OT-Medeus

Kurumsal **OT / ICS / BMS keşif ve envanter** motoru. Osmedeus tarzı modüler
iş akışı mimarisi; tek seferlik script değil, `ot_medeus` paketi olarak
kullanılabilir ve bir SaaS'a modül olarak gömülebilir.

> ⚠️ **Yalnızca yetkili kullanım.** Bu araç varlık envanteri ve yetkili
> sızma testi içindir. Taradığınız tüm hedefler (iç ağ dahil) için yazılı
> izniniz olmalıdır. Tüm sorgular salt-okunurdur; cihaza yazma, kontrol
> veya durum değiştirme işlemi yapılmaz.

## Gemini sürümüne göre farklar
- **Dış ağ taramasına rate-limit geldi.** Artık iç ve dış scanner'lar aynı
  paylaşımlı token-bucket limiter'ı kullanır; "safe" profilde global probe
  hızı sınırlıdır (OT cihazlarına nazik).
- **Tarama profilleri** (`safe` / `normal` / `thorough` / `passive`) tek
  yerde toplandı.
- **Kalıcılık + diff.** Her tarama SQLite'a kaydedilir ve bir öncekiyle
  karşılaştırılır: yeni cihaz / yeni OT portu / kaybolan cihaz → alarm sinyali.
- **Sağlamlaştırma.** MAC OUI eşlemesi biçimden bağımsız; geniş `except`
  yerine daraltılmış hata yönetimi; soketler güvenli kapatılıyor.
- **Temiz paket yapısı.** Scanner'lar kütüphane olarak çağrılabilir
  (`from ot_medeus.workflow import run_workflow`).

## v0.3 — kapsam genişletme (en büyük eksik)
Hedef: "akla ilk gelen, geniş kapsamlı OT tarayıcı" olmak.
- **nmap ICS NSE motoru** (`scanners/nmap_ics.py`): `--engine nmap|both` ile
  olgun ICS script'leri (s7-info, modbus-discover, enip-info, bacnet-info,
  fox-info, omron-info, pcworx-info, modicon-info, iec-identify). Protokol
  derinliğini elle yazmadan katlar. nmap yoksa otomatik atlanır.
- **Gerçek IEEE OUI kapsamı** (`oui_loader.py`): resmi OUI kaydını ICS
  üreticilerine göre filtreleyip yükler — uydurma MAC yok. `--oui-file oui.csv`.
- **Genişletilmiş imzalar**: Emerson/Yokogawa/Mitsubishi/Beckhoff/Hirschmann/
  fiziksel güvenlik vb. (94 imza).
- İki motorun bulguları IP bazında birleştirilir (servisler dedup edilir).

## Yapı
```
ot_medeus/
  signatures.py    OUI / port / imza DB + MAC normalize
  config.py        tarama profilleri (rate/timeout/threads)
  ratelimit.py     paylaşımlı token-bucket
  probes.py        salt-okunur Modbus/EtherNet-IP/BACnet/SSL/HTTP sorguları
  models.py        Host / Service / ScanResult veri modelleri
  scanners/
    internal.py    ARP + güvenli aktif + pasif dinleme
    external.py    crt.sh + Shodan InternetDB + rate-limit'li aktif tarama
  storage.py       SQLite workspace + taramalar arası diff
  report.py        JSON / Markdown / HTML rapor
  workflow.py      orkestrasyon
  cli.py           komut satırı
```

## Kurulum
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # scapy sadece iç ağ ARP/pasif için
```

## Kullanım
```bash
# Dış ağ (perimeter) — yetkili hedefler
python -m ot_medeus -w kurum_dis -f external -d kurum.com.tr -t 203.0.113.0/24

# İç ağ güvenli aktif tarama (ARP/pasif için root gerekir)
sudo python -m ot_medeus -w kurum_ic -f internal-active -t 10.10.20.0/24 --profile safe

# Pasif dinleme (hiç paket göndermez)
sudo python -m ot_medeus -w kurum_pasif -f internal-passive -i eth0 --duration 120

# nmap ICS motoruyla geniş kapsam (both = native + nmap birleşik)
sudo python -m ot_medeus -w kurum_ic -f internal-active -t 10.10.20.0/24 \
    --engine both --nmap-udp --oui-file oui.csv --profile safe
```

Çıktılar `workspaces/<workspace>/` altında `scan_<id>.json|md|html` olarak
üretilir; tüm geçmiş `ot_medeus.db` içinde tutulur ve her yeni tarama
öncekiyle otomatik diff'lenir.

## Kütüphane olarak
```python
from ot_medeus.workflow import run_workflow
from ot_medeus.storage import Store

res = run_workflow("kurum", "external", domain="kurum.com.tr", profile_name="safe")
with Store("kurum.db") as s:
    sid = s.save_scan(res)
    print(s.diff("kurum", sid))
```
