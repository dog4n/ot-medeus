"""Salt-okunur OT/ICS/BMS kimlik ve keşif sorguları.

Bu modüldeki tüm sorgular yalnızca cihazın kimliğini/varlığını doğrulamak
içindir (Modbus Read Device ID 0x2B/0x0E, EtherNet/IP ListIdentity 0x63,
BACnet tekil ReadProperty). Hiçbiri yazma, kontrol veya durum değiştirme işlemi
yapmaz; hiçbiri yayın (broadcast) paketi değildir.

Her ağ dokunuşundan önce paylaşımlı limiter.acquire() çağrılır; böylece
OT cihazlarına giden probe hızı global olarak sınırlanır.
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
import struct

from .ratelimit import Limiter
from .signatures import OT_SIGNATURES


def _ascii(data: bytes, start: int = 0) -> str:
    """Ham byte'lardan yazdırılabilir ASCII çıkarır, boşlukları sadeleştirir."""
    printable = "".join(chr(b) if 32 <= b <= 126 else " " for b in data[start:])
    return " ".join(printable.split())


def tcp_connect(ip: str, port: int, timeout: float, limiter: Limiter) -> socket.socket | None:
    """Rate-limit uygulanmış TCP bağlantısı. Başarısızsa None."""
    limiter.acquire()
    try:
        return socket.create_connection((ip, port), timeout=timeout)
    except (OSError, socket.timeout):
        return None


def tcp_port_open(ip: str, port: int, timeout: float, limiter: Limiter) -> bool:
    s = tcp_connect(ip, port, timeout, limiter)
    if s is None:
        return False
    s.close()
    return True


# ---------------------------------------------------------------------------
# Modbus: Read Device Identification (Function 0x2B / MEI 0x0E)
# ---------------------------------------------------------------------------
def probe_modbus_device_id(ip: str, timeout: float, limiter: Limiter) -> str:
    # MBAP header + PDU: ReadDeviceId, basic conformity, object 0
    payload = b"\x00\x01\x00\x00\x00\x05\x01\x2b\x0e\x01\x00"
    s = tcp_connect(ip, 502, timeout, limiter)
    if s is None:
        return "Modbus TCP Portu Açık"
    try:
        s.sendall(payload)
        resp = s.recv(256)
    except (OSError, socket.timeout):
        return "Modbus TCP Portu Açık"
    finally:
        s.close()
    if len(resp) > 9 and resp[7] == 0x2B:
        text = _ascii(resp, 14)
        return f"Modbus Cihaz Yanıtı: {text}" if text else "Modbus Aktif (MEI Destekleniyor)"
    if len(resp) >= 9 and resp[7] == 0xAB:
        return "Modbus Aktif (Exception döndü — cihaz doğrulandı)"
    return "Modbus TCP Portu Açık"


# ---------------------------------------------------------------------------
# EtherNet/IP: ListIdentity (command 0x63)
# ---------------------------------------------------------------------------
def probe_ethernet_ip_identity(ip: str, timeout: float, limiter: Limiter) -> str:
    payload = struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"\x00" * 8, 0)
    s = tcp_connect(ip, 44818, timeout, limiter)
    if s is None:
        return "EtherNet/IP Portu Açık"
    try:
        s.sendall(payload)
        resp = s.recv(512)
    except (OSError, socket.timeout):
        return "EtherNet/IP Portu Açık"
    finally:
        s.close()
    if len(resp) > 24:
        return f"EtherNet/IP Kimliği: {_ascii(resp, 24)[:60]}"
    return "EtherNet/IP Portu Açık"


# ---------------------------------------------------------------------------
# BACnet/IP: tekil ReadProperty (UDP 47808)
# ---------------------------------------------------------------------------
# Yalnızca hedef IP'ye giden (Original-Unicast-NPDU) okuma sorgusu: Device nesnesinin
# (joker örnek 4194303) object-identifier özelliğini okur. NPDU hedef ağ (DNET)
# taşımaz, bu yüzden BACnet router/BBMD'ler paketi başka ağlara yaymaz.
# Önceki sürüm global yayın Who-Is (DNET=0xFFFF) gönderiyordu — K3.
# Bayt dizilimi nmap bacnet-info.nse send_query() ile aynıdır
# (github.com/nmap/nmap scripts/bacnet-info.nse, 10.11.2026'da doğrulandı).
BACNET_READ_OBJECT_ID = bytes([
    0x81, 0x0A, 0x00, 0x11,        # BVLC: BACnet/IP, Original-Unicast-NPDU, uzunluk 17
    0x01, 0x04,                    # NPDU: sürüm 1, yanıt bekleniyor (DNET yok)
    0x00, 0x05, 0x01, 0x0C,        # APDU: Confirmed-Request, max APDU 1476, invoke 1, ReadProperty
    0x0C, 0x02, 0x3F, 0xFF, 0xFF,  # nesne: Device, örnek 4194303 (joker)
    0x19, 0x4B,                    # özellik: object-identifier (75)
])


def probe_bacnet_udp(ip: str, timeout: float, limiter: Limiter) -> bool:
    """Hedef BACnet/IP cihazı mı? Yalnızca o IP'den gelen BVLC yanıtını kabul eder."""
    limiter.acquire()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(BACNET_READ_OBJECT_ID, (ip, 47808))
        data, addr = sock.recvfrom(512)
        return bool(data and data[0] == 0x81 and addr[0] == ip)
    except (OSError, socket.timeout):
        return False
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Self-signed / cihaz SSL sertifikasından üretici imzası yakalama
# ---------------------------------------------------------------------------
def inspect_ssl_certificate(ip: str, port: int, timeout: float, limiter: Limiter) -> list[str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    limiter.acquire()
    matches: set[str] = set()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except (OSError, socket.timeout, ssl.SSLError):
        return []
    if not der:
        return []
    text = _ascii(der).lower()
    for sig in OT_SIGNATURES:
        if sig.strip().lower() in text:
            matches.add(sig.strip())
    return sorted(matches)


# ---------------------------------------------------------------------------
# HTTP(S) servis parmak izi — BMS/OT web yönetim panelleri
# ---------------------------------------------------------------------------
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_SSL_WEB_PORTS = {443, 8443, 10443, 4911}


def probe_http_service(ip: str, port: int, timeout: float, limiter: Limiter) -> dict | None:
    import urllib.error
    import urllib.request

    use_ssl = port in _SSL_WEB_PORTS
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{ip}:{port}/"
    info = {
        "port": port, "scheme": scheme, "server_header": "",
        "title": "", "matched_signatures": [], "ssl_matches": [],
    }
    if use_ssl:
        info["ssl_matches"] = inspect_ssl_certificate(ip, port, timeout, limiter)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (Ubuntu; Linux x86_64)"}
    )
    limiter.acquire()
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                   context=ctx if use_ssl else None) as resp:
            headers = {k.lower(): v for k, v in resp.info().items()}
            srv = headers.get("server", "")
            auth = headers.get("www-authenticate", "")
            body = resp.read(16384).decode("utf-8", errors="ignore")
            info["server_header"] = f"{srv} {auth}".strip()
            m = _TITLE_RE.search(body)
            if m:
                info["title"] = " ".join(m.group(1).split())[:100]
            combined = f"{info['server_header']} {info['title']} {body[:4000]}".lower()
            info["matched_signatures"] = sorted(
                {s.strip() for s in OT_SIGNATURES if s.strip().lower() in combined}
            )
    except urllib.error.HTTPError as e:
        srv = e.headers.get("Server", "") if e.headers else ""
        auth = e.headers.get("WWW-Authenticate", "") if e.headers else ""
        info["server_header"] = f"HTTP {e.code} | Server: {srv} | Auth: {auth}".strip()
        hay = info["server_header"].lower()
        info["matched_signatures"] = sorted(
            {s.strip() for s in OT_SIGNATURES if s.strip().lower() in hay}
        )
    except (OSError, socket.timeout, ssl.SSLError, ValueError, http.client.HTTPException):
        # HTTPException: portta HTTP olmayan bir servis var (BadStatusLine, IncompleteRead,
        # LineTooLong...). Web paneli değil; taramayı düşürmeden geç (Y1).
        return None

    if any((info["server_header"], info["title"], info["matched_signatures"], info["ssl_matches"])):
        return info
    return None
