"""Ek pasif OSINT sağlayıcıları — Censys ve FOFA.

Her ikisi de API anahtarı ister. Anahtar verilmezse sağlayıcı sessizce
atlanır (boş liste döner). Bu katman dış ağ hedef listesini genişletmek için
kullanılır; hedefe dokunmaz, üçüncü taraf veri tabanlarını sorgular.

Anahtarlar ortam değişkeni ya da doğrudan argümanla verilebilir:
  CENSYS_API_ID / CENSYS_API_SECRET
  FOFA_EMAIL / FOFA_KEY
"""

from __future__ import annotations

import base64
import json
import os
import urllib.parse
import urllib.request

CENSYS_URL = "https://search.censys.io/api/v2/hosts/search"
FOFA_URL = "https://fofa.info/api/v1/search/all"


def censys_search(query: str, api_id: str | None = None, api_secret: str | None = None,
                  per_page: int = 100, timeout: float = 15.0) -> list[str]:
    api_id = api_id or os.getenv("CENSYS_API_ID")
    api_secret = api_secret or os.getenv("CENSYS_API_SECRET")
    if not (api_id and api_secret):
        return []
    url = f"{CENSYS_URL}?q={urllib.parse.quote(query)}&per_page={per_page}"
    token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    req = urllib.request.Request(url, headers={
        "Authorization": f"Basic {token}",
        "User-Agent": "OT-Medeus/0.4",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return []
    hits = data.get("result", {}).get("hits", [])
    return sorted({h.get("ip") for h in hits if h.get("ip")})


def fofa_search(query: str, email: str | None = None, key: str | None = None,
                size: int = 100, timeout: float = 15.0) -> list[str]:
    email = email or os.getenv("FOFA_EMAIL")
    key = key or os.getenv("FOFA_KEY")
    if not (email and key):
        return []
    qb64 = base64.b64encode(query.encode()).decode()
    url = (f"{FOFA_URL}?email={urllib.parse.quote(email)}&key={urllib.parse.quote(key)}"
           f"&qbase64={urllib.parse.quote(qb64)}&size={size}&fields=ip,port")
    req = urllib.request.Request(url, headers={"User-Agent": "OT-Medeus/0.4"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return []
    if data.get("error"):
        return []
    ips = {row[0] for row in data.get("results", []) if row}
    return sorted(ips)


def ot_query_censys(domain: str) -> str:
    # dışa açık OT portları olan ve domaine ait sertifika/hostname taşıyan hostlar
    return (f'services.port: {{102,502,1911,2404,20000,44818,47808}} and '
            f'(dns.names: *.{domain} or services.tls.certificates.leaf_data.names: *.{domain})')


def ot_query_fofa(domain: str) -> str:
    return f'domain="{domain}" && (port="502" || port="102" || port="47808" || port="44818")'


def discover(domain: str, *, censys_id=None, censys_secret=None,
             fofa_email=None, fofa_key=None) -> dict[str, list[str]]:
    """Verilen domain için OT odaklı OSINT; sağlayıcı -> IP listesi."""
    out: dict[str, list[str]] = {}
    c = censys_search(ot_query_censys(domain), censys_id, censys_secret)
    if c:
        out["censys"] = c
    f = fofa_search(ot_query_fofa(domain), fofa_email, fofa_key)
    if f:
        out["fofa"] = f
    return out
