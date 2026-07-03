"""SIEM export: forward every authorization decision to a webhook, off the hot path.

``decisions.jsonl`` is already a SIEM-ingestible record for pipelines that pull; this
module is the *push* half — one JSON event per decision POSTed to an HTTP collector
(Splunk HEC, Elastic, a syslog gateway, anything that accepts JSON), so enforcement
telemetry reaches the SOC without a file shipper.

Design constraints, in order:

1. **Never touch the request path.** Events go through a bounded in-memory queue
   consumed by a single daemon thread; when the collector is slow or down the queue
   fills and new events are *dropped and counted* — enforcement latency is never
   traded for telemetry completeness.
2. **Integrity over the wire.** With a shared secret configured, each POST carries an
   ``X-Signature-256: sha256=<hmac>`` header over the exact body, GitHub-webhook
   style, so the collector can reject forged or tampered events. The secret is read
   from an environment variable named in policy — the policy file itself never holds
   secret material (same rule as API-key hashes).
3. **Honest accounting.** ``stats()`` exposes delivered / failed / dropped, and the
   gateway surfaces them as ``gateway_siem_events_total{outcome=…}``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import threading
import urllib.request
from typing import Callable

_STOP = object()


class SiemForwarder:
    """Bounded-queue, single-thread webhook forwarder for decision events."""

    def __init__(
        self,
        webhook_url: str,
        *,
        secret: str | None = None,
        timeout: float = 3.0,
        queue_size: int = 1000,
        on_outcome: Callable[[str], None] | None = None,
    ) -> None:
        self._url = webhook_url
        self._secret = (secret or "").encode("utf-8") or None
        self._timeout = timeout
        self._queue: queue.Queue = queue.Queue(maxsize=max(1, queue_size))
        self._on_outcome = on_outcome
        self._lock = threading.Lock()
        self._stats = {"delivered": 0, "failed": 0, "dropped": 0}
        self._worker = threading.Thread(
            target=self._run, name="siem-forwarder", daemon=True
        )
        self._worker.start()

    # -- producer side (called from the request path; must never block) ----------

    def emit(self, event: dict) -> None:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self._count("dropped")

    # -- consumer side ------------------------------------------------------------

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                return
            self._deliver(item)

    def _deliver(self, event: dict) -> None:
        body = json.dumps(
            {"event_type": "authorization_decision", **event},
            separators=(",", ":"),
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._secret:
            digest = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
            headers["X-Signature-256"] = f"sha256={digest}"
        request = urllib.request.Request(
            self._url, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout):  # nosec B310
                self._count("delivered")
        except Exception:  # noqa: BLE001 — telemetry must never raise into the plane
            self._count("failed")

    def _count(self, outcome: str) -> None:
        with self._lock:
            self._stats[outcome] += 1
        if self._on_outcome is not None:
            try:
                self._on_outcome(outcome)
            except Exception:  # noqa: BLE001  # nosec B110 — deliberate: metrics callback must never kill the worker
                pass

    # -- introspection / lifecycle -------------------------------------------------

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def close(self, timeout: float = 5.0) -> None:
        """Drain and stop the worker (tests and orderly shutdown)."""
        self._queue.put(_STOP)
        self._worker.join(timeout=timeout)


def from_policy(
    webhook_url: str | None,
    secret_env: str | None,
    *,
    on_outcome: Callable[[str], None] | None = None,
) -> SiemForwarder | None:
    """Build a forwarder from policy values, or ``None`` when export is off."""
    if not webhook_url:
        return None
    secret = os.environ.get(secret_env, "") if secret_env else ""
    return SiemForwarder(webhook_url, secret=secret or None, on_outcome=on_outcome)


def verify_signature(secret: str, body: bytes, header: str) -> bool:
    """Collector-side check for ``X-Signature-256`` (used by tests and integrators)."""
    if not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(header[len("sha256="):], expected)
