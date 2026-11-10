"""Orkestrasyon motoru — iş akışlarını çalıştırıp sonucu tek ScanResult'ta toplar.

İş akışları:
  external          : OSINT (crt.sh + Shodan) + rate-limit'li dış aktif tarama
  internal-active   : ARP + güvenli aktif OT port/kimlik taraması
  internal-passive  : sıfır-paket pasif dinleme (scapy)
  full              : external + internal-active

Tarama motoru (engine):
  native : saf-Python probe'lar (bağımlılıksız, her yerde çalışır)
  nmap   : nmap ICS NSE script'leri (çok daha geniş protokol kapsamı)
  both   : ikisini çalıştırıp bulguları IP bazında birleştirir
"""

from __future__ import annotations

from datetime import datetime, timezone

from .config import ScanProfile, get_profile
from .models import Host, ScanResult, Service
from .ratelimit import NullLimiter, RateLimiter
from .scanners import external as ext
from .scanners import internal as intl
from .scanners import nmap_ics
from . import classify as classify_mod
from . import cve as cve_mod
from . import osint as osint_mod


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _merge_hosts(primary: list[Host], extra: list[Host]) -> list[Host]:
    """İki motorun bulgularını IP bazında birleştirir (servisleri dedup eder)."""
    by_ip: dict[str, Host] = {h.ip: h for h in primary}
    for h in extra:
        if h.ip not in by_ip:
            by_ip[h.ip] = h
            continue
        base = by_ip[h.ip]
        base.mac = base.mac or h.mac
        base.vendor = base.vendor or h.vendor
        seen = {s.key() for s in base.services}
        for s in h.services:
            if s.key() not in seen:
                base.services.append(s)
                seen.add(s.key())
        base.web_panels.extend(h.web_panels)
        base.is_ot_candidate = base.is_ot_candidate or h.is_ot_candidate
        if base.source != "nmap" and h.source == "nmap":
            base.source = f"{base.source}+nmap"
    return list(by_ip.values())


def _run_nmap(targets: list[str], profile: ScanProfile, udp: bool,
              notes: list[str]) -> list[Host]:
    if not nmap_ics.nmap_available():
        notes.append("nmap bulunamadı; nmap motoru atlandı (native motor çalıştı).")
        return []
    hosts: list[Host] = []
    for t in targets:
        hosts.extend(nmap_ics.run_nmap_ics(t, profile, udp=udp))
    return hosts


def run_workflow(
    workspace: str,
    workflow: str,
    *,
    targets: list[str] | None = None,
    domain: str | None = None,
    interface: str | None = None,
    duration: int = 60,
    profile_name: str | None = None,
    passive_only: bool = False,
    engine: str = "native",
    nmap_udp: bool = False,
    enrich: bool = True,
    cve_online: bool = True,
    osint_creds: dict | None = None,
) -> ScanResult:
    profile: ScanProfile = get_profile(profile_name)
    limiter = NullLimiter() if profile.rate <= 0 else RateLimiter(profile.rate)
    targets = targets or []
    use_nmap = engine in ("nmap", "both")
    use_native = engine in ("native", "both")
    notes: list[str] = []

    result = ScanResult(
        workspace=workspace, workflow=workflow, profile=profile.name,
        parameters={
            "targets": targets, "domain": domain, "interface": interface,
            "duration": duration, "passive_only": passive_only,
            "engine": engine, "nmap_udp": nmap_udp,
        },
    )

    if workflow in ("external", "full"):
        if domain and osint_creds:
            discovered = osint_mod.discover(domain, **osint_creds)
            if discovered:
                result.parameters["osint"] = discovered
                for ips in discovered.values():
                    targets.extend(ips)
        if use_native:
            hosts, subs, total = ext.run_external(
                targets, profile, limiter, domain=domain, passive_only=passive_only
            )
            result.hosts = _merge_hosts(result.hosts, hosts)
            result.subdomains = subs
            result.total_scanned += total
        if use_nmap and not passive_only:
            nmap_targets = list(targets)
            nmap_targets += [i["ip"] for i in result.subdomains.values()]
            result.hosts = _merge_hosts(result.hosts, _run_nmap(nmap_targets, profile, nmap_udp, notes))

    if workflow in ("internal-active", "full"):
        for cidr in targets:
            if use_native:
                result.hosts = _merge_hosts(result.hosts, intl.run_active(cidr, profile, limiter))
            if use_nmap:
                result.hosts = _merge_hosts(result.hosts, _run_nmap([cidr], profile, nmap_udp, notes))
            result.total_scanned += 1

    if workflow == "internal-passive":
        if not interface:
            raise ValueError("internal-passive iş akışı için 'interface' gerekli.")
        result.hosts = _merge_hosts(result.hosts, intl.run_passive(interface, duration))
        result.total_scanned += len(result.hosts)

    # --- son-işleme: sınıflandırma + CVE zenginleştirme ---
    if enrich:
        for h in result.hosts:
            if h.is_ot_candidate:
                classify_mod.classify(h)
        cve_mod.enrich_all([h for h in result.hosts if h.is_ot_candidate],
                           online=cve_online)

    if notes:
        result.parameters["notes"] = notes
    result.finished_at = _now()
    return result
