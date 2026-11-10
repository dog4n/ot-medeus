"""Paylaşımlı, thread-safe token-bucket rate limiter.

Gemini sürümünde iç ağ taramasında `time.sleep(delay)` ile kaba bir
gecikme vardı ama dış ağ taraması (scan_external_ip) hiç sınırlandırılmıyordu.
OT/ICS cihazları ağ yığınında hassastır; bu limiter tüm scanner'lar
tarafından ortak kullanılır, böylece "saniyede kaç probe" global olarak
kontrol altında kalır.
"""

from __future__ import annotations

import threading
import time
from typing import Protocol


class Limiter(Protocol):
    """RateLimiter ve NullLimiter'ın uyduğu arayüz (tip ipucu için)."""

    def acquire(self, tokens: float = 1.0) -> None: ...


class RateLimiter:
    """Token-bucket. `rate` = saniyedeki token (probe), `burst` = kova boyu.

    rate <= 0 ise limitleme kapalıdır (pasif modda anlamlı).
    """

    def __init__(self, rate: float, burst: float | None = None):
        self.rate = float(rate)
        self.capacity = float(burst if burst is not None else max(1.0, rate))
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> None:
        """Yeterli token oluşana kadar bloklar. Uyku kilit dışında yapılır."""
        if self.rate <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                wait = deficit / self.rate
            time.sleep(wait)


class NullLimiter:
    """Hiç sınırlama yapmayan limiter (pasif iş akışları için)."""

    def acquire(self, tokens: float = 1.0) -> None:  # noqa: D401
        return
