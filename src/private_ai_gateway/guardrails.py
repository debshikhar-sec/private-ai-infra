"""Output guardrails: secret-egress control for model responses.

Authorization decides whether a principal may *invoke* a model. Guardrails decide
whether a given *response* may leave the gateway. Even a fully authorized caller
should not be able to exfiltrate credentials that the model happened to surface
(from its training data, a pasted config, or a prompt-injection payload).

This is policy-driven egress filtering with three actions:

  * ``off``    — disabled (default; no behaviour change).
  * ``redact`` — replace each matched secret with a ``[REDACTED:<kind>]`` marker.
  * ``block``  — withhold the whole response and return a refusal.

The pattern set is deliberately high-precision (low false-positive) — recognizable
credential shapes rather than generic entropy heuristics — so it is safe to enable
by default in a deployment without mangling ordinary prose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# (kind, compiled pattern). High-precision credential shapes only.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"),
    ),
]

_VALID_ACTIONS = ("off", "redact", "block")


@dataclass(frozen=True)
class GuardrailResult:
    """Outcome of scanning a response."""

    text: str
    triggered: tuple[str, ...]

    @property
    def fired(self) -> bool:
        return bool(self.triggered)


class Guardrails:
    """Scan model output for secret-like content and apply the configured action."""

    def __init__(self, action: str = "off"):
        self.action = action if action in _VALID_ACTIONS else "off"

    def scan(self, text: str) -> GuardrailResult:
        if self.action == "off" or not text:
            return GuardrailResult(text or "", ())

        found: list[str] = []
        redacted = text
        for kind, pattern in _PATTERNS:
            if pattern.search(redacted):
                found.append(kind)
                redacted = pattern.sub(f"[REDACTED:{kind}]", redacted)

        if not found:
            return GuardrailResult(text, ())

        if self.action == "block":
            kinds = ", ".join(sorted(set(found)))
            message = (
                "Response withheld by egress guardrail: the model output matched a "
                f"credential pattern ({kinds}) and was blocked by policy."
            )
            return GuardrailResult(message, tuple(found))

        return GuardrailResult(redacted, tuple(found))
