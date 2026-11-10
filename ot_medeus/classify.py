"""Varlık sınıflandırma — cihaz tipi ve Purdue seviyesi tahmini.

Açık portlar, protokoller ve banner/sertifika imzalarından heuristik çıkarım.
Sonuç bir TAHMİN'dir; güven derecesi (yüksek/orta/düşük) kanıtın gücüne göre:
  - protokol kimlik sorgusu eşleşti -> yüksek
  - sadece imza/banner eşleşti      -> orta
  - sadece MAC OUI üretici          -> düşük
"""

from __future__ import annotations

from .models import Host
from .signatures import is_known_vendor

# Purdue referansı (OT ağ seviye modeli):
#  L0 saha cihazları, L1 kontrol (PLC/RTU), L2 denetim (HMI/SCADA),
#  L3 operasyon, L3.5 DMZ. BMS ve fiziksel güvenlik ayrı etiketlenir.

_HMI_SIGS = ["wincc", "experion", "deltav", "ovation", "centum", "scada",
             "factorytalk", "ignition", "intouch", "vijeo"]
_CAM_SIGS = ["hikvision", "dahua", "axis", "vivotek", "milestone", "genetec",
             "lenel", "nedap", "paxton", "hid global"]
_UPS_SIGS = ["apc", "powerchute", "power xpert", "eaton", "network management card"]
_BMS_SIGS = ["tridium", "niagara", "desigo", "metasys", "carel", "pcoweb",
             "delta controls", "enteliweb", "sauter", "distech", "reliable controls",
             "johnson controls", "trend control", "priva"]


def _any(hay: str, needles: list[str]) -> bool:
    return any(n in hay for n in needles)


def classify(host: Host) -> Host:
    ports = {s.port for s in host.services}
    probed = any(s.detail for s in host.services)   # kimlik sorgusu yanıt verdi mi
    hay = " ".join(
        [host.vendor or ""]
        + [f"{s.service} {s.detail}" for s in host.services]
        + [f"{w.title} {w.server_header} {' '.join(w.matched_signatures)} {' '.join(w.ssl_matches)}"
           for w in host.web_panels]
    ).lower()

    dtype = ""
    level = ""

    # öncelik: en ayırt edici sinyalden en zayıfa
    if _any(hay, _HMI_SIGS):
        dtype, level = "HMI / SCADA", "L2 (Denetim)"
    elif ports & {102, 502, 44818, 1962, 5007, 9600} or _any(hay, ["simatic", "modicon", "allen-bradley", "s7"]):
        dtype, level = "PLC / Saha Kontrolcüsü", "L1 (Kontrol)"
    elif ports & {20000, 2404}:
        dtype, level = "RTU / SCADA Telemetri", "L1-L2"
    elif ports & {1911, 4911, 47808} or _any(hay, _BMS_SIGS):
        dtype, level = "BMS / İklimlendirme Kontrolcüsü", "Bina Otomasyon (L1-L2)"
    elif 4840 in ports:
        dtype, level = "OPC UA Sunucu / Gateway", "L2-L3"
    elif _any(hay, _CAM_SIGS):
        dtype, level = "IP Kamera / Fiziksel Güvenlik", "Fiziksel Güvenlik"
    elif _any(hay, _UPS_SIGS):
        dtype, level = "UPS / Güç Yönetimi", "L1 (Güç)"
    elif host.web_panels:
        dtype, level = "OT/BMS Yönetim Paneli", "L2 (Denetim)"
    elif is_known_vendor(host.vendor or ""):
        dtype, level = "Tanımlanamayan OT cihazı (üretici bilinen)", "Belirsiz"

    if dtype:
        host.device_type = dtype
        host.purdue_level = level
        if probed:
            host.classification_confidence = "yüksek"
        elif host.web_panels or any(s.service for s in host.services):
            host.classification_confidence = "orta"
        else:
            host.classification_confidence = "düşük"
    return host
