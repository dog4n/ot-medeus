"""Tarama profilleri — OT güvenliği için merkezi ayar.

Gemini sürümünde timeout/delay/threads parametreleri fonksiyon imzalarına
dağılmıştı. Burada tek yerde, adlandırılmış profiller olarak toplanır.
Varsayılan "safe": OT/ICS ortamlarında düşük hızlı, düşük eşzamanlılık.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    name: str
    rate: float          # global probe/saniye (0 = limitsiz; sadece pasifte)
    timeout: float       # soket timeout (sn)
    threads: int         # eşzamanlı host sayısı
    port_delay: float    # aynı host içinde portlar arası ek gecikme (sn)
    enable_probes: bool  # OT kimlik sorgularını (Modbus ID vb.) gönder


PROFILES: dict[str, ScanProfile] = {
    # OT/ICS için güvenli varsayılan: yavaş ve nazik.
    "safe": ScanProfile("safe", rate=5, timeout=2.0, threads=4,
                        port_delay=0.15, enable_probes=True),
    # Karışık kurumsal ağ, biraz daha hızlı.
    "normal": ScanProfile("normal", rate=20, timeout=1.5, threads=10,
                         port_delay=0.05, enable_probes=True),
    # Yalnızca OT olmayan, dayanıklı ağlar için.
    "thorough": ScanProfile("thorough", rate=50, timeout=1.0, threads=20,
                          port_delay=0.0, enable_probes=True),
    # Hiç aktif paket göndermeyen mod (pasif dinleme / sadece OSINT).
    "passive": ScanProfile("passive", rate=0, timeout=2.0, threads=1,
                         port_delay=0.0, enable_probes=False),
}

DEFAULT_PROFILE = "safe"


def get_profile(name: str | None) -> ScanProfile:
    return PROFILES.get(name or DEFAULT_PROFILE, PROFILES[DEFAULT_PROFILE])
