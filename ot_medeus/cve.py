"""CVE / ICS-CERT zenginleştirme — yalnızca gerçek kaynaklardan.

Uydurma CVE YOK. Kaynaklar:
  1. Shodan InternetDB 'vulns' alanı (zaten toplanıyor, gerçek).
  2. CPE -> CVE: CIRCL cve-search API (https://cve.circl.lu), çevrimiçiyse.
  3. CISA ICS advisory arama linki (üretici bazlı) — içerik üretmez, yönlendirir.

Ağa erişilemiyorsa (ör. kapalı ortam) sessizce yalnızca Shodan vulns'ları
kullanılır; modül asla CVE icat etmez.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

from .models import Host

CIRCL_API = "https://cve.circl.lu/api/cvefor/{cpe}"
CISA_SEARCH = ("https://www.cisa.gov/news-events/cybersecurity-advisories"
               "?f%5B0%5D=advisory_type%3A95&search_api_fulltext={vendor}")


def gather_cpes(host: Host) -> list[str]:
    cpes = set(host.cpes)
    cpes.update(host.shodan.get("cpes", []) or [])
    for s in host.services:
        for tok in (s.detail or "").split():
            if tok.startswith("cpe:"):
                cpes.add(tok.strip().strip(",;"))
    return sorted(c for c in cpes if c.startswith("cpe:"))


def lookup_circl(cpe: str, timeout: float = 6.0, limit: int = 10) -> list[dict]:
    """CIRCL cve-search'ten bir CPE için CVE listesi. Hata/çevrimdışıysa []."""
    url = CIRCL_API.format(cpe=urllib.parse.quote(cpe, safe=""))
    req = urllib.request.Request(url, headers={"User-Agent": "OT-Medeus/0.4"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return []
    out = []
    items = data if isinstance(data, list) else data.get("results", [])
    for item in items[:limit]:
        out.append({
            "id": item.get("id", ""),
            "summary": (item.get("summary", "") or "")[:200],
            "cvss": item.get("cvss"),
        })
    return [c for c in out if c["id"]]


def enrich(host: Host, online: bool = True) -> Host:
    vulns = set(host.vulns) | set(host.shodan.get("vulns", []) or [])
    details: list[dict] = list(host.cve_details)

    if online:
        for cpe in gather_cpes(host):
            for c in lookup_circl(cpe):
                if c["id"] not in vulns:
                    vulns.add(c["id"])
                    details.append(c)

    host.vulns = sorted(vulns)
    host.cve_details = details[:50]
    if host.vendor and is_vendor_name(host.vendor):
        vq = urllib.parse.quote(host.vendor.split("(")[0].strip())
        host.advisory_urls = [CISA_SEARCH.format(vendor=vq)]
    return host


def is_vendor_name(v: str) -> bool:
    return bool(v) and v not in ("Bilinmiyor", "Standart / Tanımsız OUI")


def enrich_all(hosts: list[Host], online: bool = True) -> list[Host]:
    for h in hosts:
        enrich(h, online=online)
    return hosts
