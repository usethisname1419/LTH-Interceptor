from __future__ import annotations

import random
import threading
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class ProxyRotator:
    proxies: list[str]
    mode: str = "round_robin"
    mark_dead_on_fail: bool = True
    _idx: int = 0
    _dead: set[str] = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def alive(self) -> list[str]:
        return [p for p in self.proxies if p not in self._dead]

    def next(self) -> str | None:
        with self._lock:
            pool = self.alive()
            if not pool:
                return None
            if self.mode == "random":
                return random.choice(pool)
            proxy = pool[self._idx % len(pool)]
            self._idx += 1
            return proxy

    def mark_dead(self, proxy: str | None) -> None:
        if not proxy or not self.mark_dead_on_fail:
            return
        with self._lock:
            self._dead.add(proxy)

    def mark_ok(self, proxy: str | None) -> None:
        if not proxy:
            return
        with self._lock:
            self._dead.discard(proxy)

    def status(self) -> dict:
        return {
            "total": len(self.proxies),
            "alive": len(self.alive()),
            "dead": sorted(self._dead),
            "mode": self.mode,
        }


def normalize_socks5(proxy: str) -> str:
    proxy = proxy.strip()
    if not proxy:
        raise ValueError("empty proxy")
    if "://" not in proxy:
        proxy = "socks5://" + proxy
    parsed = urlparse(proxy)
    if parsed.scheme not in {"socks5", "socks5h"}:
        raise ValueError(f"Only socks5/socks5h supported, got: {parsed.scheme}")
    return proxy


def to_curl_proxy(proxy: str) -> str:
    # curl prefers socks5h for remote DNS
    p = normalize_socks5(proxy)
    return p.replace("socks5://", "socks5h://", 1) if p.startswith("socks5://") else p


def to_httpx_proxy(proxy: str) -> str:
    return normalize_socks5(proxy).replace("socks5://", "socks5h://", 1)


def to_nuclei_proxy(proxy: str) -> str:
    """Nuclei only accepts http(s)/socks5 — not socks5h."""
    p = normalize_socks5(proxy)
    return p.replace("socks5h://", "socks5://", 1)


def to_ffuf_proxy(proxy: str) -> str:
    """ffuf -x expects socks5:// or http:// — socks5h often makes it print help."""
    p = normalize_socks5(proxy)
    return p.replace("socks5h://", "socks5://", 1)
