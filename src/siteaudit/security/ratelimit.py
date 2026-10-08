"""In-process sliding-window rate limiter for request bursts.

Durable limits (login attempts, monthly audit quota) live in the database. This limiter only smooths
bursts per client IP on a single web process; behind several processes, put an equivalent limit in the
reverse proxy (see DEPLOYMENT.md).
"""

from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float, max_keys: int = 50_000) -> None:
        self.limit = limit
        self.window = window_seconds
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= self.max_keys:
                    self._evict(now)
                hits = self._hits[key] = deque()
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def _evict(self, now: float) -> None:
        stale = [k for k, v in self._hits.items() if not v or now - v[-1] > self.window]
        for k in stale:
            del self._hits[k]
        if len(self._hits) >= self.max_keys:
            self._hits.clear()

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
