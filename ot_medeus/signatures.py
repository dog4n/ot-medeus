"""OT / ICS / BMS imza veritabanı: MAC OUI, portlar, üretici imzaları.

Gemini sürümüne göre düzeltmeler:
- MAC OUI eşlemesi artık ayraç biçiminden bağımsız (normalize_mac).
- OUI anahtarları tek biçimde (büyük harf, ':' ile) tutulur ve arama
  normalize edilmiş prefix ile yapılır.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# MAC OUI -> üretici. Anahtarlar "XX:XX:XX" (büyük harf) biçimindedir.
# ---------------------------------------------------------------------------
OT_OUI_DB: dict[str, str] = {
    "00:0E:8C": "Siemens AG",
    "00:1B:1B": "Siemens AG",
    "00:1F:F8": "Siemens AG",
    "28:63:36": "Siemens AG",
    "00:80:F4": "Schneider Electric (Telemecanique)",
    "00:00:54": "Schneider Electric",
    "00:00:BC": "Rockwell Automation (Allen-Bradley)",
    "00:1D:9C": "Rockwell Automation",
    "F4:54:33": "Rockwell Automation",
    "00:06:29": "ABB Industrial",
    "00:21:99": "ABB Industrial",
    "00:30:DE": "WAGO Kontakttechnik",
    "00:A0:45": "Phoenix Contact",
    "00:0D:8D": "Moxa Technologies",
    "00:90:E8": "Moxa Technologies",
    "00:40:C7": "Honeywell",
    "00:10:8B": "Honeywell",
    "00:C0:B7": "American Power Conversion (APC UPS)",
    "28:29:86": "APC by Schneider Electric",
    "00:20:85": "Eaton Corporation (UPS/Power)",
    "00:40:8C": "Axis Communications (IP Camera/Physical Sec)",
    "00:0C:E7": "Advantech",
    "00:D0:C9": "Advantech",
}

# ---------------------------------------------------------------------------
# OT/ICS/BMS TCP portları -> protokol/servis
# ---------------------------------------------------------------------------
OT_TCP_PORTS: dict[int, str] = {
    102: "Siemens S7comm / IEC 61850 (ISO-TSAP)",
    502: "Modbus TCP",
    1089: "Foundation Fieldbus HSE",
    1911: "Niagara Fox (Tridium BMS / HVAC)",
    1962: "PCWorx (Phoenix Contact)",
    2404: "IEC 60870-5-104 (Enerji/SCADA)",
    4840: "OPC UA Discovery",
    4911: "Niagara Fox SSL (Tridium BMS)",
    5007: "Mitsubishi MELSEC-Q",
    9600: "OMRON FINS",
    20000: "DNP3 (Distributed Network Protocol)",
    44818: "EtherNet/IP (Rockwell / Allen-Bradley)",
}

OT_UDP_PORTS: dict[int, str] = {
    47808: "BACnet/IP (Bina Otomasyon / HVAC / BMS)",
}

WEB_PORTS: list[int] = [80, 443, 8080, 8443, 8000, 8888, 10443, 4911]

# ---------------------------------------------------------------------------
# Banner / sertifika / HTML içinde aranan üretici imzaları
# ---------------------------------------------------------------------------
OT_SIGNATURES: list[str] = [
    "Siemens", "SIMATIC", "LOGO!", "Ruggedcom", "Scalance", "Desigo",
    "Schneider", "EcoStruxure", "PowerChute", "APC ", "Network Management Card",
    "Tridium", "Niagara", "Vykon", "Honeywell", "Trend Control",
    "Johnson Controls", "Metasys", "Carel", "pCOWeb", "Boss ",
    "Moxa", "OnCell", "NPort", "Teltonika", "RutOS", "Advantech",
    "WAGO", "Phoenix Contact", "Weidmuller", "Rockwell", "Allen-Bradley",
    "ABB ", "Eaton", "Power Xpert", "NetEco", "FusionSolar", "Priva",
    "Delta Controls", "enteliWEB", "BACnet", "Modbus", "SCADA",
    "Hikvision", "Dahua", "Axis Communications", "Milestone",
    # --- genişletilmiş gerçek üretici/ürün imzaları ---
    "Emerson", "DeltaV", "Ovation", "Yokogawa", "Centum", "Experion",
    "WinCC", "TIA Portal", "Mitsubishi", "MELSEC", "OMRON", "CJ2", "NJ",
    "Unitronics", "Beckhoff", "TwinCAT", "Hirschmann", "Belden", "Red Lion",
    "SICK", "Turck", "Pepperl+Fuchs", "Endress+Hauser", "CODESYS", "B&R",
    "Bachmann", "Lantronix", "Digi", "Sierra Wireless", "Teltonika",
    "Danfoss", "Lenze", "KUKA", "FANUC", "Schweitzer", "SEL-",
    "Desigo", "Sauter", "Reliable Controls", "Distech", "Siemens S7",
    "Vivotek", "Genetec", "Lenel", "HID Global", "Nedap", "Paxton",
]

OT_SUBDOMAIN_KEYWORDS: list[str] = [
    "bms", "scada", "plc", "iot", "ot", "ups", "hvac", "iklim", "klima",
    "chiller", "enerji", "energy", "power", "jenerator", "gen", "solar",
    "ges", "kamera", "cam", "cctv", "dvr", "nvr", "kapi", "gate", "access",
    "yangin", "fire", "sensor", "mon", "tesis", "fabrika", "plant", "su",
]

_UNKNOWN = "Standart / Tanımsız OUI"
_NONE = "Bilinmiyor"


def normalize_mac(mac: str | None) -> str | None:
    """Herhangi bir biçimdeki MAC'i 12 hex büyük harfe indirger.

    '00:1b:1b:aa:bb:cc', '001B.1BAA.BBCC', '00-1B-1B-AA-BB-CC' hepsi
    '001B1BAABBCC' olur. Geçersizse None döner.
    """
    if not mac:
        return None
    hex_only = "".join(c for c in mac if c in "0123456789abcdefABCDEF")
    if len(hex_only) < 6:
        return None
    return hex_only[:12].upper()


def lookup_mac_vendor(mac: str | None) -> str:
    """MAC'ten OT üreticisi tahmini. Biçimden bağımsızdır."""
    norm = normalize_mac(mac)
    if not norm:
        return _NONE
    prefix = ":".join(norm[i:i + 2] for i in (0, 2, 4))
    return OT_OUI_DB.get(prefix, _UNKNOWN)


def is_known_vendor(vendor: str) -> bool:
    return vendor not in (_UNKNOWN, _NONE)
