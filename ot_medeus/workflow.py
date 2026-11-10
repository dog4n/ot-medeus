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
    scan_discovered: bool = False,
) -> ScanResult:
    """İş akışını çalıştırır.

    Kapsam kuralı: aktif tarama yalnızca `targets` içindeki IP/CIDR'lara yapılır.
    crt.sh / Censys / FOFA ile bulunan IP'ler `result.candidates` olarak listelenir;
    `scan_discovered=True` verilmedikçe onlara paket gönderilmez.

    Pasif kuralı: 'passive' profil hedefe hiç paket göndermez. Bu yüzden aktif iç ağ
    taraması yapan 'internal-active' ve 'full' akışlarıyla birlikte kullanılamaz.
    """
    profile: ScanProfile = get_profile(profile_name)
    targets = list(targets or [])          # çağıranın listesini değiştirme
    passive_profile = profile.name == "passive"
    if passive_profile and workflow in ("internal-active", "full"):
        raise ValueError(
            "'passive' profil hedefe paket gönderemez; 'internal-active' ve 'full' akışları "
            "aktif tarama yapar. Pasif iç ağ keşfi için 'internal-passive' kullanın."
        )
    if profile.rate <= 0 and not passive_profile:
        raise ValueError("Hız limiti olmayan bir profil aktif taramada kullanılamaz.")
    external_passive = passive_only or passive_profile
    limiter = NullLimiter() if profile.rate <= 0 else RateLimiter(profile.rate)
    use_nmap = engine in ("nmap", "both")
    use_native = engine in ("native", "both")
    notes: list[str] = []

    result = ScanResult(
        workspace=workspace, workflow=workflow, profile=profile.name,
        parameters={
            "targets": list(targets), "domain": domain, "interface": interface,
            "duration": duration, "passive_only": external_passive,
            "engine": engine, "nmap_udp": nmap_udp, "scan_discovered": scan_discovered,
        },
    )

    if workflow in ("external", "full"):
        # 1) Pasif keşif: hedefe dokunmaz, sadece aday üretir.
        discovered: dict[str, set[str]] = {}
        if domain:
            result.subdomains = ext.fetch_crt_sh_subdomains(domain)
            for name, info in result.subdomains.items():
                discovered.setdefault(info["ip"], set()).add(f"crt.sh:{name}")
        if domain and osint_creds:
            osint_hits = osint_mod.discover(domain, **osint_creds)
            if osint_hits:
                result.parameters["osint"] = osint_hits
                for provider, ips in osint_hits.items():
                    for ip in ips:
                        discovered.setdefault(ip, set()).add(provider)
        result.candidates = ext.build_candidates(discovered, result.subdomains, targets)

        # 2) Kapsam: yalnızca kullanıcının hedefleri; adaylar sadece açıkça istenirse.
        extra: list[str] = []
        if scan_discovered and not external_passive:
            extra = [c["ip"] for c in result.candidates if not c["in_scope"]]
        for c in result.candidates:
            c["scanned"] = (not external_passive) and (c["in_scope"] or scan_discovered)
        skipped = [c for c in result.candidates if not c["scanned"]]
        if skipped and not external_passive:
            notes.append(f"{len(skipped)} keşfedilen IP kapsam dışı olduğu için taranmadı "
                         "(aday olarak listelendi). Taramak için: --scan-discovered")
        scan_list = targets + extra

        # 3) Aktif tarama (pasif modda yalnızca Shodan InternetDB sorulur).
        if use_native and scan_list:
            hosts, total = ext.run_external(scan_list, profile, limiter,
                                            passive_only=external_passive, errors=notes)
            result.hosts = _merge_hosts(result.hosts, hosts)
            result.total_scanned += total
        if use_nmap and scan_list:
            if external_passive:
                notes.append("Pasif modda nmap motoru çalıştırılmadı.")
            else:
                result.hosts = _merge_hosts(result.hosts,
                                            _run_nmap(scan_list, profile, nmap_udp, notes))

    if workflow in ("internal-active", "full"):
        for cidr in targets:
            if use_native:
                result.hosts = _merge_hosts(result.hosts,
                                            intl.run_active(cidr, profile, limiter, errors=notes))
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
