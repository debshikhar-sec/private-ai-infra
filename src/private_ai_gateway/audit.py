"""Structured decision audit for the governance plane.

The human-readable audit.log is good for tailing; a governance plane also needs a
machine-parseable record of *authorization decisions* (who, what, allow/deny, why)
that a SIEM or log pipeline can ingest. This module appends one JSON object per
decision to ``decisions.jsonl``.

Auditing must never break the request path: any failure to write is swallowed.
"""

from __future__ import annotations

import json
import time
from typing import Any


class DecisionLog:
    """Append-only JSONL writer for authorization decisions.

    ``forwarder`` is an optional push sink (see :mod:`private_ai_gateway.siem`): any
    object with a non-blocking ``emit(event: dict)``. Forwarding failures are the
    forwarder's problem; the log never lets them reach the request path.
    """

    def __init__(self, path: str, forwarder=None):
        self._path = path
        self._forwarder = forwarder

    def record(
        self,
        *,
        request_id: str,
        principal: str | None,
        method: str,
        path: str,
        model: str | None,
        decision: str,
        reason: str,
        status: int,
    ) -> None:
        event: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "request_id": request_id,
            "principal": principal,
            "method": method,
            "path": path,
            "model": model,
            "decision": decision,
            "reason": reason,
            "status": status,
        }
        try:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, separators=(",", ":")) + "\n")
        except OSError:
            # Never let audit-logging failure break the request path.
            pass
        if self._forwarder is not None:
            try:
                self._forwarder.emit(event)
            except Exception:  # noqa: BLE001  # nosec B110 — deliberate: telemetry export must never break the request path
                pass

    def tail(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return up to ``limit`` most-recent decisions, newest first.

        Reads only the end of the file (bounded, so a large audit history cannot
        be used to stall the gateway) and skips lines that fail to parse — the
        reader must tolerate a torn final line from a concurrent append.
        """
        limit = max(1, min(int(limit), 500))
        try:
            with open(self._path, "rb") as fh:
                fh.seek(0, 2)
                size = fh.tell()
                # Generous per-line budget; decisions are ~200 bytes each.
                window = min(size, limit * 1024)
                fh.seek(size - window)
                chunk = fh.read(window)
        except OSError:
            return []

        lines = chunk.split(b"\n")
        if window < size and lines:
            lines = lines[1:]  # first line may be torn by the window boundary

        events: list[dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict):
                events.append(event)
        return list(reversed(events[-limit:]))
