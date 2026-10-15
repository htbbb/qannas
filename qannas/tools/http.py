"""The HTTP tool — every request is scope-checked and rate-limited.

No component in Qannas sends traffic except through this class, so the
ScopeGuard here is a true chokepoint. If a request's host is not authorized,
it raises before any socket is opened.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import httpx

from ..scope import ScopeGuard


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float


class HttpTool:
    def __init__(self, guard: ScopeGuard, timeout: int = 15, rate_limit_per_sec: float = 4.0) -> None:
        self.guard = guard
        self.timeout = timeout
        self._min_interval = 1.0 / rate_limit_per_sec if rate_limit_per_sec > 0 else 0.0
        self._last = 0.0
        self._lock = threading.Lock()
        self._client = httpx.Client(
            timeout=timeout, follow_redirects=False,
            headers={"User-Agent": "Qannas/0.1 (authorized-security-testing)"},
        )

    def _throttle(self) -> None:
        with self._lock:
            wait = self._min_interval - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()

    def request(self, method: str, url: str, **kw) -> Response:
        self.guard.check(url)          # <-- authorization gate
        self._throttle()
        t0 = time.perf_counter()
        r = self._client.request(method, url, **kw)
        return Response(
            url=str(r.url), status=r.status_code,
            headers={k.lower(): v for k, v in r.headers.items()},
            text=r.text, elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    def get(self, url: str, **kw) -> Response:
        return self.request("GET", url, **kw)

    def close(self) -> None:
        self._client.close()
