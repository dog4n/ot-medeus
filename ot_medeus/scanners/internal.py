"""İç ağ OT/BMS keşfi — güvenli aktif tarama + pasif dinleme.

Aktif tarama: ARP ile MAC/üretici tespiti + rate-limit'li TCP port kontrolü +
salt-okunur OT kimlik sorguları. Pasif dinleme: hiç paket göndermeden
(scapy sniff) OT protokol trafiğini ve OUI'leri yakalar.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..config import ScanProfile
from ..models import Host, Service, WebPanel
from ..probes import (
    inspect_ssl_certificate,
    probe_bacnet_udp,
    probe_ethernet_ip_identity,
    probe_http_service,
    probe_modbus_device_id,
    tcp_port_open,
)
from ..ratelimit import Limiter
from ..signatures import (
    OT_TCP_PORTS,
    OT_UDP_PORTS,
    WEB_PORTS,
    is_known_vendor,
    lookup_mac_vendor,
)

try:
    from scapy.all import ARP, Ether, IP, TCP, UDP, sniff, srp  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:  # scapy yoksa pasif/ARP devre dışı, aktif tarama çalışır
    SCAPY_AVAILABLE = False


def arp_discover(subnet: str, timeout: float) -> dict[str, str]:
    """Subnet'te IP -> MAC haritası (scapy gerekir, root yetkisi ister)."""
    if not SCAPY_AVAILABLE:
        return {}
    mac_map: dict[str, str] = {}
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                     timeout=timeout, verbose=False)
        for _, rcv in ans:
            mac_map[rcv.psrc] = rcv.hwsrc
    except Exception:
        pass
    return mac_map


def scan_host(ip: str, mac: str | None, profile: ScanProfile, limiter: Limiter) -> Host:
    host = Host(ip=ip, mac=mac, vendor=lookup_mac_vendor(mac), source="active")

    for port, name in OT_TCP_PORTS.items():
        if not tcp_port_open(ip, port, profile.timeout, limiter):
            continue
        detail = ""
        if profile.enable_probes:
            if port == 502:
                detail = probe_modbus_device_id(ip, profile.timeout, limiter)
            elif port == 44818:
                detail = probe_ethernet_ip_identity(ip, profile.timeout, limiter)
            elif port == 4911:
                sigs = inspect_ssl_certificate(ip, port, profile.timeout, limiter)
                detail = f"SSL imzaları: {sigs}" if sigs else ""
        host.services.append(Service(port=port, protocol="TCP", service=name, detail=detail))

    if profile.enable_probes and probe_bacnet_udp(ip, profile.timeout, limiter):
        host.services.append(Service(
            port=47808, protocol="UDP",
            service=OT_UDP_PORTS[47808],
            detail="BACnet/IP yanıt verdi (BMS/İklimlendirme)",
        ))

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

    host.is_ot_candidate = bool(host.services or host.web_panels) or is_known_vendor(host.vendor or "")
    return host


def _expand_hosts(target_cidr: str) -> list[str]:
    net = ipaddress.ip_network(target_cidr, strict=False)
    if net.num_addresses > 1:
        return [str(ip) for ip in net.hosts()]
    return [str(net.network_address)]


def run_active(target_cidr: str, profile: ScanProfile, limiter: Limiter,
               errors: list[str] | None = None) -> list[Host]:
    """Subnet'i tarar. Bir cihazda beklenmeyen hata olursa o cihaz atlanır, tarama sürer;
    hata `errors` listesine (workflow notları) yazılır (Y1)."""
    hosts = _expand_hosts(target_cidr)
    mac_map = arp_discover(target_cidr, profile.timeout)
    found: list[Host] = []
    with ThreadPoolExecutor(max_workers=profile.threads) as ex:
        futures = {
            ex.submit(scan_host, ip, mac_map.get(ip), profile, limiter): ip
            for ip in hosts
        }
        for fut in as_completed(futures):
            try:
                host = fut.result()
            except Exception as e:  # noqa: BLE001 — tek cihaz tüm taramayı düşürmesin
                if errors is not None:
                    errors.append(f"{futures[fut]} taranırken hata, cihaz atlandı: "
                                  f"{type(e).__name__}: {e}")
                continue
            if host.is_ot_candidate:
                found.append(host)
    return found


def run_passive(interface: str, duration: int) -> list[Host]:
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Pasif dinleme için scapy gerekli (pip install scapy).")

    discovered: dict[str, Host] = {}
    protos: dict[str, set[str]] = {}
    all_tcp = set(OT_TCP_PORTS)
    all_udp = set(OT_UDP_PORTS)

    def handler(pkt):
        src_ip = src_mac = proto = None
        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src
        if pkt.haslayer(ARP):
            src_ip, src_mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        elif pkt.haslayer(IP):
            src_ip = pkt[IP].src
            if pkt.haslayer(TCP):
                sp, dp = pkt[TCP].sport, pkt[TCP].dport
                if sp in all_tcp:
                    proto = f"TCP/{sp} ({OT_TCP_PORTS[sp]})"
                elif dp in all_tcp:
                    proto = f"->TCP/{dp} ({OT_TCP_PORTS[dp]})"
            elif pkt.haslayer(UDP):
                sp, dp = pkt[UDP].sport, pkt[UDP].dport
                p = sp if sp in all_udp else (dp if dp in all_udp else None)
                if p is not None:
                    proto = f"UDP/{p} ({OT_UDP_PORTS[p]})"

        if not src_ip or src_ip == "0.0.0.0":
            return
        vendor = lookup_mac_vendor(src_mac)
        if not (is_known_vendor(vendor) or proto):
            return
        if src_ip not in discovered:
            discovered[src_ip] = Host(ip=src_ip, mac=src_mac, vendor=vendor,
                                      source="passive", is_ot_candidate=True)
            protos[src_ip] = set()
        if proto:
            protos[src_ip].add(proto)

    sniff(iface=interface, prn=handler, timeout=duration, store=False)

    for ip, host in discovered.items():
        for p in sorted(protos[ip]):
            # pasifte port numarasını metinden ayıklamıyoruz; detay olarak tutuyoruz
            host.services.append(Service(port=0, protocol="OBSERVED", service=p))
    return list(discovered.values())
