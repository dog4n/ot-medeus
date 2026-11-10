"""IEEE OUI kayıt yükleyici — gerçek, geniş üretici haritası (uydurma MAC yok).

Gömülü OT_OUI_DB elle derlendiği için dardır (~24 kayıt). Gerçek kapsam,
resmi IEEE OUI kaydının ICS üreticilerine göre filtrelenmesiyle gelir.
Dosyayı bir kez indir (çevrimdışı kullanılır):

    https://standards-oui.ieee.org/oui/oui.csv        (IEEE CSV)
    veya nmap'in 'nmap-mac-prefixes' dosyası
    veya klasik oui.txt

Kullanım:
    from ot_medeus.oui_loader import load_oui, merge_into_signatures
    extra = load_oui("oui.csv")          # {'00:1B:1B': 'Siemens AG', ...}
    merge_into_signatures(extra)         # gömülü DB'yi genişletir
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

# ICS / OT / BMS / fiziksel güvenlik üreticileri (ad içinde aranır, küçük harf)
DEFAULT_ICS_VENDORS = [
    "siemens", "schneider", "telemecanique", "modicon", "rockwell",
    "allen-bradley", "abb", "honeywell", "emerson", "yokogawa", "mitsubishi",
    "omron", "wago", "phoenix contact", "moxa", "advantech", "hirschmann",
    "beckhoff", "b&r", "bachmann", "ge fanuc", "ge intelligent", "eaton",
    "american power conversion", "apc", "delta", "hikvision", "dahua", "axis",
    "johnson controls", "tridium", "carel", "belden", "red lion", "weidmuller",
    "pepperl", "sick ag", "turck", "endress", "krohne", "unitronics",
    "lantronix", "digi international", "sierra wireless", "teltonika",
    "lenze", "danfoss", "wiesemann", "kuka", "fanuc", "nari", "sel ",
    "schweitzer", "general electric", "vivotek", "genetec", "hid global",
]

_PREFIX_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]?){2}[0-9A-Fa-f]{2}")


def _norm_prefix(raw: str) -> str | None:
    hex_only = "".join(c for c in raw if c in "0123456789abcdefABCDEF")
    if len(hex_only) < 6:
        return None
    h = hex_only[:6].upper()
    return f"{h[0:2]}:{h[2:4]}:{h[4:6]}"


def _wanted(org: str, vendors: list[str]) -> bool:
    low = org.lower()
    return any(v in low for v in vendors)


def load_oui(path: str | Path, vendors: list[str] | None = None) -> dict[str, str]:
    """IEEE CSV / nmap-mac-prefixes / oui.txt biçimlerini otomatik algılar."""
    vendors = vendors or DEFAULT_ICS_VENDORS
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    first = next((l for l in text.splitlines() if l.strip()), "")

    result: dict[str, str] = {}

    # IEEE CSV: başlıkta 'Registry' ve virgül
    if "," in first and "registry" in first.lower():
        for row in csv.DictReader(text.splitlines()):
            org = (row.get("Organization Name") or "").strip()
            assign = (row.get("Assignment") or "").strip()
            if org and _wanted(org, vendors):
                pfx = _norm_prefix(assign)
                if pfx:
                    result[pfx] = org
        return result

    # oui.txt: '00-1B-1B   (hex)\t\tSiemens AG'
    if "(hex)" in text:
        for line in text.splitlines():
            if "(hex)" not in line:
                continue
            left, _, org = line.partition("(hex)")
            org = org.strip()
            if org and _wanted(org, vendors):
                pfx = _norm_prefix(left)
                if pfx:
                    result[pfx] = org
        return result

    # nmap-mac-prefixes: 'AABBCC Vendor Name'
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or not _PREFIX_RE.match(line):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        pfx, org = _norm_prefix(parts[0]), parts[1].strip()
        if pfx and org and _wanted(org, vendors):
            result[pfx] = org
    return result


def merge_into_signatures(extra: dict[str, str]) -> int:
    """Yüklenen OUI'leri gömülü OT_OUI_DB'ye ekler. Eklenen yeni kayıt sayısı."""
    from . import signatures
    before = len(signatures.OT_OUI_DB)
    signatures.OT_OUI_DB.update(extra)
    return len(signatures.OT_OUI_DB) - before
