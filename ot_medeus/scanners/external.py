"""Dış ağ (perimeter) OT/BMS keşfi — OSINT + rate-limit'li aktif tarama.

ÖNEMLİ DÜZELTME (Gemini sürümüne göre):
Gemini'de scan_external_ip hiçbir hız sınırı olmadan tüm OT portlarını ve
web portlarını tarıyordu. Dışarı açık bir OT cihazı da hassas olabilir;
burada iç modülle AYNI paylaşımlı limiter kullanılır ve "safe" profil
dış tarama için de geçerlidir.

OSINT katmanı (crt.sh, Shodan InternetDB) tamamen pasiftir: hedefe
dokunmaz, üçüncü taraf kaynakları sorgular.
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


# --- Pasif OSINT -----------------------------------------------------------
def fetch_crt_sh_subdomains(domain: str, timeout: float = 15.0) -> dict[str, dict]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Ubuntu; Linux x86_64)"})
    subs: set[str] = set()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                clean = name.strip().lower().lstrip("*.")
                if clean.endswith(domain.lower()):
                    subs.add(clean)
    except Exception:
        return {}

    resolved: dict[str, dict] = {}
    for sub in sorted(subs):
        try:
            ip = socket.gethostbyname(sub)
        except socket.gaierror:
            continue
        resolved[sub] = {
            "ip": ip,
            "ot_keyword_match": any(k in sub for k in OT_SUBDOMAIN_KEYWORDS),
        }
    return resolved


def query_shodan_internetdb(ip: str, timeout: float = 4.0) -> dict:
    """API anahtarsız, pasif Shodan InternetDB sorgusu."""
    url = f"https://internetdb.shodan.io/{ip}"
    req = urllib.request.Request(url, headers={"User-Agent": "OT-Medeus/0.2"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except Exception:
        pass
    return {}


# --- Hedef başına aktif (rate-limit'li) kontrol ----------------------------
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
        if port == 4911:
            sigs = inspect_ssl_certificate(ip, port, profile.timeout, limiter)
            detail = f"SSL imzaları: {sigs}" if sigs else ""
        host.services.append(Service(port=port, protocol="TCP", service=desc, detail=detail))
        host.is_ot_candidate = True

    if probe_bacnet_udp(ip, profile.timeout, limiter):
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
                 domain: str | None = None, passive_only: bool = False
                 ) -> tuple[list[Host], dict, int]:
    raw = list(targets)
    subdomains: dict[str, dict] = {}
    if domain:
        subdomains = fetch_crt_sh_subdomains(domain)
        raw.extend(info["ip"] for info in subdomains.values())

    ip_list = _expand_targets(raw)
    found: list[Host] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=profile.threads) as ex:
        futures = {ex.submit(scan_ip, ip, profile, limiter, passive_only): ip for ip in ip_list}
        for fut in concurrent.futures.as_completed(futures):
            host = fut.result()
            if host.is_ot_candidate or host.shodan.get("ports"):
                found.append(host)
    return found, subdomains, len(ip_list)
