"""Dış ağ (perimeter) OT/BMS keşfi — pasif keşif + kapsamlı, rate-limit'li aktif tarama.

İki ayrı katman var ve aralarındaki çizgi bilinçli:

1. Pasif keşif (hedefe dokunmaz): crt.sh sertifika kayıtları, DNS çözümleme,
   Shodan InternetDB. Buradan gelen IP'ler **aday**dır — kullanıcı bu IP'leri
   taramak için izin vermemiş olabilir (CDN, Microsoft 365, SaaS sağlayıcıları...).
   `build_candidates` bunları kapsam ve olası sahip bilgisiyle listeler.

2. Aktif tarama: yalnızca `run_external`'a verilen hedefler (kullanıcının -t ile
   verdikleri; açıkça istenirse adaylar da). Tüm scanner'lar aynı paylaşımlı
   limiter'ı kullanır; "safe" profil dış tarama için de geçerlidir.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import socket
import urllib.request

from ..config import ScanProfile
from ..models import Host, Service, WebPanel
from ..probes import (
    inspect_ssl_certificate,
    probe_bacnet_udp,
    probe_http_service,
    tcp_port_open,
)
from ..ratelimit import Limiter
from ..signatures import OT_SUBDOMAIN_KEYWORDS, OT_TCP_PORTS, WEB_PORTS


# --- Olası sahip (CDN / SaaS) ipuçları ---------------------------------------
# Cloudflare'in yayımladığı IPv4 aralıkları.
# Kaynak: https://www.cloudflare.com/ips-v4 (10.11.2026'da doğrulandı).
_CLOUDFLARE_V4 = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)]

# Yaygın sağlayıcıların CNAME (kanonik ad) sonekleri. Örnekleyicidir, eksik olabilir;
# eşleşme yoksa sahip "bilinmiyor" kalır — bu, kuruma ait olduğu anlamına gelmez.
_PROVIDER_CNAME_SUFFIXES: list[tuple[str, str]] = [
    ("cloudflare.net", "Cloudflare"),
    ("cloudfront.net", "Amazon CloudFront"),
    ("akamaiedge.net", "Akamai"), ("edgekey.net", "Akamai"),
    ("edgesuite.net", "Akamai"), ("akamai.net", "Akamai"),
    ("fastly.net", "Fastly"), ("fastlylb.net", "Fastly"),
    ("azureedge.net", "Microsoft Azure CDN"), ("azurefd.net", "Microsoft Azure Front Door"),
    ("azurewebsites.net", "Microsoft Azure App Service"),
    ("trafficmanager.net", "Microsoft Azure Traffic Manager"),
    ("outlook.com", "Microsoft 365"),
    ("amazonaws.com", "Amazon Web Services"),
    ("googlehosted.com", "Google"), ("appspot.com", "Google App Engine"),
    ("github.io", "GitHub Pages"),
    ("zendesk.com", "Zendesk"),
    ("herokudns.com", "Heroku"),
    ("incapdns.net", "Imperva"),
    ("myshopify.com", "Shopify"),
]


def owner_hint(ip: str, canonical: str, shodan: dict | None) -> str:
    """IP'nin kuruma değil bir CDN/SaaS sağlayıcısına ait olabileceğine dair ipucu.

    Bir TAHMİNDİR. Boş dize = sağlayıcı tanınmadı (kurumun kendi IP'si de olabilir,
    tanınmayan bir sağlayıcı da).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        addr = None
    if addr is not None and addr.version == 4 and any(addr in n for n in _CLOUDFLARE_V4):
        return "Cloudflare"
    c = (canonical or "").lower().rstrip(".")
    for suffix, name in _PROVIDER_CNAME_SUFFIXES:
        if c == suffix or c.endswith("." + suffix):
            return name
    tags = [str(t).lower() for t in (shodan or {}).get("tags", []) or []]
    if "cdn" in tags:
        return "CDN (Shodan etiketi)"
    if "cloud" in tags:
        return "Bulut sağlayıcı (Shodan etiketi)"
    return ""


# --- Pasif keşif -------------------------------------------------------------
def _resolve(name: str) -> tuple[str | None, str]:
    """(IPv4, kanonik ad). Kanonik ad CNAME zincirinin sonudur (sağlayıcı ipucu için)."""
    try:
        canonical, _aliases, ips = socket.gethostbyname_ex(name)
    except (OSError, UnicodeError):
        return None, ""
    return (ips[0] if ips else None), (canonical or "").lower()


def _belongs_to(name: str, domain: str) -> bool:
    """name, domain'in kendisi ya da alt alanı mı? ('notkurum.com.tr' kurum.com.tr değildir.)"""
    d = domain.lower().strip(".")
    return name == d or name.endswith("." + d)


def fetch_crt_sh_subdomains(domain: str, timeout: float = 15.0) -> dict[str, dict]:
    """crt.sh'tan domainin alt alanlarını bulur ve çözümler. Hedefe paket göndermez."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Ubuntu; Linux x86_64)"})
    subs: set[str] = set()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                clean = name.strip().lower().lstrip("*.")
                if clean and "@" not in clean and " " not in clean and _belongs_to(clean, domain):
                    subs.add(clean)
    except Exception:
        return {}

    resolved: dict[str, dict] = {}
    for sub in sorted(subs):
        ip, canonical = _resolve(sub)
        if not ip:
            continue
        resolved[sub] = {
            "ip": ip,
            "canonical": canonical,
            "ot_keyword_match": any(k in sub for k in OT_SUBDOMAIN_KEYWORDS),
        }
    return resolved


def query_shodan_internetdb(ip: str, timeout: float = 4.0) -> dict:
    """API anahtarsız, pasif Shodan InternetDB sorgusu."""
    url = f"https://internetdb.shodan.io/{ip}"
    req = urllib.request.Request(url, headers={"User-Agent": "OT-Medeus/0.4"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except Exception:
        pass
    return {}


def _target_networks(raw: list[str]) -> list:
    """Kullanıcının verdiği hedefleri (IP/CIDR/hostname) ağ listesine çevirir (kapsam kontrolü)."""
    nets = []
    for item in raw:
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            ip, _ = _resolve(item)
            if ip:
                nets.append(ipaddress.ip_network(ip))
    return nets


def build_candidates(discovered: dict[str, set[str]], subdomains: dict[str, dict],
                     user_targets: list[str]) -> list[dict]:
    """Keşifte bulunan IP'leri 'aday' kaydına çevirir. Yalnızca pasif sorgu yapar.

    discovered: ip -> kaynaklar (ör. {"crt.sh:www.kurum.com.tr", "censys"})
    Her aday: ip, sources, canonical, owner_hint, in_scope, scanned, shodan_ports,
    shodan_tags, ot_keyword_match. `scanned` alanını workflow doldurur.
    """
    nets = _target_networks(user_targets)
    canon_by_ip: dict[str, str] = {}
    kw_by_ip: dict[str, bool] = {}
    for info in subdomains.values():
        canon_by_ip.setdefault(info["ip"], info.get("canonical", ""))
        kw_by_ip[info["ip"]] = kw_by_ip.get(info["ip"], False) or info.get("ot_keyword_match", False)

    ips = []
    for ip in sorted(discovered):
        try:
            ips.append((ip, ipaddress.ip_address(ip)))
        except ValueError:
            continue

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        shodan_by_ip = dict(zip([i for i, _ in ips], ex.map(query_shodan_internetdb, [i for i, _ in ips])))

    out: list[dict] = []
    for ip, addr in ips:
        shodan = shodan_by_ip.get(ip) or {}
        canonical = canon_by_ip.get(ip, "")
        out.append({
            "ip": ip,
            "sources": sorted(discovered[ip]),
            "canonical": canonical,
            "owner_hint": owner_hint(ip, canonical, shodan),
            "in_scope": any(addr.version == n.version and addr in n for n in nets),
            "scanned": False,
            "shodan_ports": shodan.get("ports", []) or [],
            "shodan_tags": shodan.get("tags", []) or [],
            "ot_keyword_match": kw_by_ip.get(ip, False),
        })
    return out


# --- Hedef başına aktif (rate-limit'li) kontrol ------------------------------
def scan_ip(ip: str, profile: ScanProfile, limiter: Limiter, passive_only: bool) -> Host:
    host = Host(ip=ip, source="osint")

    shodan = query_shodan_internetdb(ip)
    if shodan:
        host.shodan = {
            "ports": shodan.get("ports", []),
            "hostnames": shodan.get("hostnames", []),
            "tags": shodan.get("tags", []),
            "cpes": shodan.get("cpes", []),
            "vulns": shodan.get("vulns", []),
        }
        if set(shodan.get("ports", [])) & set(OT_TCP_PORTS) or "ics" in shodan.get("tags", []):
            host.is_ot_candidate = True

    if passive_only:
        return host

    host.source = "active"
    for port, desc in OT_TCP_PORTS.items():
        if not tcp_port_open(ip, port, profile.timeout, limiter):
            continue
        detail = ""
        if port == 4911 and profile.enable_probes:
            sigs = inspect_ssl_certificate(ip, port, profile.timeout, limiter)
            detail = f"SSL imzaları: {sigs}" if sigs else ""
        host.services.append(Service(port=port, protocol="TCP", service=desc, detail=detail))
        host.is_ot_candidate = True

    if profile.enable_probes and probe_bacnet_udp(ip, profile.timeout, limiter):
        host.services.append(Service(port=47808, protocol="UDP",
                                     service="BACnet/IP (dışa açık BMS/HVAC)"))
        host.is_ot_candidate = True

    for wport in WEB_PORTS:
        if not tcp_port_open(ip, wport, profile.timeout, limiter):
            continue
        winfo = probe_http_service(ip, wport, profile.timeout, limiter)
        if winfo and (winfo["matched_signatures"] or winfo["ssl_matches"]):
            host.web_panels.append(WebPanel(
                port=winfo["port"], scheme=winfo["scheme"], title=winfo["title"],
                server_header=winfo["server_header"],
                matched_signatures=winfo["matched_signatures"],
                ssl_matches=winfo["ssl_matches"],
            ))
            host.is_ot_candidate = True

    return host


def _expand_targets(raw: list[str]) -> list[str]:
    ips: set[str] = set()
    for item in raw:
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
            iterable = net.hosts() if net.num_addresses > 1 else [net.network_address]
            for ip in iterable:
                ips.add(str(ip))
        except ValueError:
            try:
                ips.add(socket.gethostbyname(item))
            except socket.gaierror:
                continue
    return sorted(ips)


def run_external(targets: list[str], profile: ScanProfile, limiter: Limiter,
                 passive_only: bool = False,
                 errors: list[str] | None = None) -> tuple[list[Host], int]:
    """Yalnızca verilen hedefleri tarar. Keşif (crt.sh/OSINT) burada YAPILMAZ.

    passive_only=True iken hedefe paket gitmez; sadece Shodan InternetDB sorulur.
    Bir IP'de beklenmeyen hata olursa o IP atlanır, hata `errors`'a yazılır (Y1).
    Dönüş: (bulunan hostlar, taranan IP sayısı).
    """
    ip_list = _expand_targets(list(targets))
    found: list[Host] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, profile.threads)) as ex:
        futures = {ex.submit(scan_ip, ip, profile, limiter, passive_only): ip for ip in ip_list}
        for fut in concurrent.futures.as_completed(futures):
            try:
                host = fut.result()
            except Exception as e:  # noqa: BLE001 — tek IP tüm taramayı düşürmesin
                if errors is not None:
                    errors.append(f"{futures[fut]} taranırken hata, IP atlandı: "
                                  f"{type(e).__name__}: {e}")
                continue
            if host.is_ot_candidate or host.shodan.get("ports"):
                found.append(host)
    return found, len(ip_list)
