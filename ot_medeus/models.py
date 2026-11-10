"""Scanner'lar ve storage arasında paylaşılan veri modelleri.

Dataclass'lar düz dict'e (to_dict) ve geri (from_dict) çevrilebilir; böylece
hem JSON export hem SQLite/Postgres kalıcılığı aynı şemayı kullanır.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Service:
    port: int
    protocol: str          # "TCP" | "UDP"
    service: str           # insan-okur protokol adı
    detail: str = ""       # probe'tan dönen ek kimlik

    def key(self) -> str:
        return f"{self.protocol}/{self.port}"


@dataclass
class WebPanel:
    port: int
    scheme: str
    title: str = ""
    server_header: str = ""
    matched_signatures: list[str] = field(default_factory=list)
    ssl_matches: list[str] = field(default_factory=list)


@dataclass
class Host:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    source: str = ""                  # discovery kaynağı: arp/active/passive/osint/nmap
    is_ot_candidate: bool = False
    services: list[Service] = field(default_factory=list)
    web_panels: list[WebPanel] = field(default_factory=list)
    shodan: dict = field(default_factory=dict)
    # --- zenginleştirme (classify.py + cve.py doldurur) ---
    device_type: str = ""             # PLC / RTU / HMI / BMS / Kamera / UPS ...
    purdue_level: str = ""            # Purdue seviyesi tahmini
    classification_confidence: str = ""   # yüksek / orta / düşük
    cpes: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)          # CVE kimlikleri
    cve_details: list[dict] = field(default_factory=list)   # {id, summary, cvss}
    advisory_urls: list[str] = field(default_factory=list)
    first_seen: str = field(default_factory=_utcnow)
    last_seen: str = field(default_factory=_utcnow)

    def service_keys(self) -> set[str]:
        keys = {s.key() for s in self.services}
        keys |= {f"WEB/{w.port}" for w in self.web_panels}
        return keys

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    workspace: str
    workflow: str
    profile: str
    started_at: str = field(default_factory=_utcnow)
    finished_at: str | None = None
    parameters: dict = field(default_factory=dict)
    hosts: list[Host] = field(default_factory=list)
    subdomains: dict = field(default_factory=dict)
    # Keşifte (crt.sh / Censys / FOFA) bulunan IP'ler. Kullanıcı açıkça istemedikçe
    # aktif taranmazlar; bkz. scanners/external.build_candidates.
    candidates: list[dict] = field(default_factory=list)
    total_scanned: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def ot_hosts(self) -> list[Host]:
        return [h for h in self.hosts if h.is_ot_candidate]
