"""nmap ICS NSE sarmalayıcı — kapsamı en çok büyüten modül.

Gemini sürümünde her protokol elle yazılıyordu (sadece Modbus/EtherNet-IP/
BACnet derinlemesine). nmap'in olgun ICS NSE script'leri onlarca protokolü
zaten doğru ve bakımlı biçimde parmak izler. Bu modül nmap'i sarar, XML
çıktısını kendi Host/Service modelimize çevirir.

- Tüm script'ler salt-okunur kimlik/keşif script'leridir (*-info, *-discover).
- nmap kurulu değilse modül nazikçe devre dışı kalır (native motor çalışır).
- Profil, nmap zamanlamasına (--max-rate, -T, --scan-delay) eşlenir; "safe"
  profil OT için düşük hızlıdır.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET

from ..config import ScanProfile
from ..models import Host, Service
from ..signatures import OT_TCP_PORTS, OT_UDP_PORTS, is_known_vendor

# nmap ile birlikte gelen / ics-topluluk script'leri. Olmayan script'i nmap
# yok sayar, bu yüzden hepsini güvenle verebiliriz.
ICS_SCRIPTS = [
    "modbus-discover",   # Modbus 502
    "s7-info",           # Siemens S7 102
    "enip-info",         # EtherNet/IP 44818
    "bacnet-info",       # BACnet 47808/udp
    "modicon-info",      # Schneider Modicon
    "omron-info",        # OMRON FINS 9600
    "pcworx-info",       # Phoenix Contact 1962
    "fox-info",          # Tridium Niagara Fox 1911
    "iec-identify",      # IEC 60870-5-104 2404
]

_TCP_PORTS = ",".join(str(p) for p in OT_TCP_PORTS)
_UDP_PORTS = ",".join(str(p) for p in OT_UDP_PORTS)


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _timing_args(profile: ScanProfile, udp: bool) -> list[str]:
    # profil.rate -> nmap --max-rate (saniyedeki paket); OT'ye nazik
    args = ["--max-rate", str(max(1, int(profile.rate or 1)))]
    if profile.name == "safe":
        args += ["-T2", "--scan-delay", "100ms"]
    elif profile.name == "normal":
        args += ["-T3"]
    else:
        args += ["-T4"]
    return args


def build_command(target: str, profile: ScanProfile, udp: bool,
                  extra_scripts: list[str] | None = None) -> list[str]:
    scripts = ",".join(ICS_SCRIPTS + (extra_scripts or []))
    cmd = ["nmap", "-oX", "-", "-Pn", "-sT"]
    ports = f"T:{_TCP_PORTS}"
    if udp:
        cmd.append("-sU")            # UDP/BACnet root gerektirir
        ports += f",U:{_UDP_PORTS}"
    cmd += ["-p", ports, "--script", scripts]
    cmd += _timing_args(profile, udp)
    cmd.append(target)
    return cmd


def parse_nmap_xml(xml_text: str) -> list[Host]:
    """nmap -oX çıktısını Host listesine çevirir (sadece açık portlar)."""
    hosts: list[Host] = []
    if not xml_text.strip():
        return hosts
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts

    for h in root.findall("host"):
        if (st := h.find("status")) is not None and st.get("state") != "up":
            continue
        ip = mac = vendor = None
        for addr in h.findall("address"):
            kind = addr.get("addrtype")
            if kind in ("ipv4", "ipv6"):
                ip = addr.get("addr")
            elif kind == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor") or vendor
        if not ip:
            continue

        host = Host(ip=ip, mac=mac, vendor=vendor, source="nmap")
        for port in h.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port.get("portid"))
            proto = (port.get("protocol") or "tcp").upper()
            svc_el = port.find("service")
            name = OT_TCP_PORTS.get(portid) or OT_UDP_PORTS.get(portid) or ""
            if svc_el is not None:
                prod = " ".join(x for x in (svc_el.get("product"),
                                            svc_el.get("version")) if x)
                name = prod or svc_el.get("name") or name
            scripts = {s.get("id"): (s.get("output") or "").strip()
                       for s in port.findall("script")}
            detail = " | ".join(f"{k}: {v}" for k, v in scripts.items() if v)
            host.services.append(Service(port=portid, protocol=proto,
                                         service=name, detail=detail[:400]))

        host.is_ot_candidate = bool(host.services) or is_known_vendor(vendor or "")
        if host.is_ot_candidate:
            hosts.append(host)
    return hosts


def run_nmap_ics(target: str, profile: ScanProfile, udp: bool = False,
                 extra_scripts: list[str] | None = None,
                 timeout: int = 1800) -> list[Host]:
    """nmap ICS taramasını çalıştırıp Host listesi döndürür.

    udp=True BACnet için gereklidir ama root ister. nmap yoksa RuntimeError.
    """
    if not nmap_available():
        raise RuntimeError("nmap kurulu değil (apt install nmap). Native motoru kullanın.")
    cmd = build_command(target, profile, udp, extra_scripts)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return []
    return parse_nmap_xml(proc.stdout)
