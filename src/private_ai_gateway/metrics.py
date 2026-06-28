"""Minimal Prometheus-style metrics for the gateway.

A governance plane has to be observable: operators need to see decision volume,
denials, throttling, and guardrail activity without grepping logs. This module is
a tiny in-process counter registry that renders the Prometheus 0.0.4 text
exposition format. It is hand-rolled on purpose — the gateway stays dependency-free
(no ``prometheus_client``), and counters are the only metric type we need.

Counters are labelled; series are keyed by the sorted tuple of label pairs so the
same name with different labels accumulates independently. The registry is
thread-safe.
"""

from __future__ import annotations

import threading


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class Metrics:
    """In-process counter registry with Prometheus text exposition."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: dict[str, dict[tuple, float]] = {}
        self._help: dict[str, str] = {}

    def register(self, name: str, help_text: str) -> None:
        """Pre-declare a counter so it renders (at 0) before its first increment."""
        with self._lock:
            self._counters.setdefault(name, {})
            self._help[name] = help_text

    def inc(self, name: str, labels: dict | None = None, value: float = 1.0) -> None:
        key = tuple(sorted((labels or {}).items()))
        with self._lock:
            series = self._counters.setdefault(name, {})
            series[key] = series.get(key, 0.0) + value

    def render(self) -> str:
        """Render all counters in Prometheus text exposition format."""
        lines: list[str] = []
        with self._lock:
            for name, series in self._counters.items():
                help_text = self._help.get(name)
                if help_text:
                    lines.append(f"# HELP {name} {help_text}")
                lines.append(f"# TYPE {name} counter")
                if not series:
                    lines.append(f"{name} 0")
                    continue
                for key, val in series.items():
                    if key:
                        labelstr = ",".join(f'{k}="{_escape(str(v))}"' for k, v in key)
                        lines.append(f"{name}{{{labelstr}}} {val:g}")
                    else:
                        lines.append(f"{name} {val:g}")
        return "\n".join(lines) + "\n"
