"""Per-principal rate limiting for the governance plane.

Identity and authorization answer *who* and *what*; a governance plane also needs
to bound *how much*. This module implements a token-bucket limiter keyed by
principal name so a single compromised or runaway key cannot saturate the gateway.

The bucket refills at ``rpm`` tokens per minute up to a burst capacity of ``rpm``.
A limit of 0 (or unset) means unlimited, which keeps zero-config local development
unthrottled. The limiter is thread-safe; state is in-process (no external store),
which is the right scope for a single-node loopback gateway.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    last: float


class RateLimiter:
    """Token-bucket rate limiter, one bucket per principal."""

    def __init__(self, default_rpm: int, *, clock=time.monotonic):
        self._default_rpm = max(0, int(default_rpm))
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self._clock = clock

    def allow(self, principal: str, rpm: int | None = None) -> tuple[bool, float]:
        """Consume one token for ``principal``.

        Returns ``(allowed, retry_after_seconds)``. ``retry_after_seconds`` is 0
        when allowed. A per-principal ``rpm`` overrides the default; a limit of 0
        means unlimited.
        """
        limit = self._default_rpm if rpm is None else max(0, int(rpm))
        if limit <= 0:
            return True, 0.0

        rate = limit / 60.0  # tokens per second
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(principal)
            if bucket is None:
                # New principals start with a full burst allowance.
                self._buckets[principal] = _Bucket(tokens=float(limit) - 1.0, last=now)
                return True, 0.0

            elapsed = now - bucket.last
            bucket.tokens = min(float(limit), bucket.tokens + elapsed * rate)
            bucket.last = now

            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True, 0.0

            retry_after = (1.0 - bucket.tokens) / rate
            return False, retry_after
