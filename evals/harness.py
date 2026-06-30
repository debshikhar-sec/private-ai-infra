"""Core eval types and runner.

An ``EvalCase`` is one adversarial probe: it ``run``s against a ``Context`` (the gateway
transport and/or the egress guardrail) and ``check``s that the control held. A control
*holding* is a **PASS**; a control that let the attack through is a **FAIL**. A case that
cannot run in this environment (e.g. a gateway probe with no gateway available) is
**SKIP** — never silently passed.

The harness is transport-agnostic on purpose: the real run drives the live gateway via a
Flask test client, but the harness logic is exercised in CI with a fake transport, so the
attack catalogue and the scoring are validated without needing MLX.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

PASS = "pass"  # nosec B105 — eval-status enum value, not a credential
FAIL = "fail"
SKIP = "skip"


@dataclass
class Observation:
    """What a probe saw back from the control under test."""

    status: int | None = None
    code: str = ""  # error `code` from the gateway body, or a synthetic tag
    body: str = ""  # response / redacted text
    note: str = ""


class Transport(Protocol):
    """Drives a single HTTP-style request and returns an Observation."""

    def __call__(
        self,
        method: str,
        path: str,
        *,
        headers: dict | None = None,
        json: dict | None = None,
    ) -> Observation: ...


class EgressScanner(Protocol):
    """Scans model-output text for secret egress (the gateway's `Guardrails`)."""

    def scan(self, text: str): ...


@dataclass
class Context:
    """Everything a probe may reach: the gateway transport and the egress guardrail."""

    transport: Transport | None = None
    guardrails: EgressScanner | None = None

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        headers: dict | None = None,
        json: dict | None = None,
    ) -> Observation:
        if self.transport is None:
            raise RuntimeError("no gateway transport configured for a request-level eval")
        h = dict(headers or {})
        if token is not None:
            h["Authorization"] = f"Bearer {token}"
        return self.transport(method, path, headers=h, json=json)

    def scan_egress(self, text: str) -> Observation:
        if self.guardrails is None:
            raise RuntimeError("no egress guardrail configured for an egress eval")
        res = self.guardrails.scan(text)
        return Observation(
            body=res.text,
            code="fired" if res.fired else "clean",
            note=",".join(res.triggered),
        )


@dataclass
class EvalCase:
    """One adversarial probe of a single enforced control."""

    id: str
    category: str
    owasp: str  # the OWASP LLM / agentic risk it exercises
    attack: str  # what the attacker tries
    expectation: str  # the safe outcome the control must produce
    run: Callable[[Context], Observation]
    check: Callable[[Observation], bool]
    needs_gateway: bool = True  # request-level (vs. egress, which needs only guardrails)
    atlas: str = ""  # the MITRE ATLAS technique it exercises (AML.T####), where one maps


@dataclass
class EvalResult:
    case: EvalCase
    observation: Observation
    status: str  # PASS / FAIL / SKIP

    @property
    def ok(self) -> bool:
        return self.status != FAIL


def run_case(case: EvalCase, ctx: Context) -> EvalResult:
    """Run one case, mapping a held control to PASS and a breach (or error) to FAIL."""
    if case.needs_gateway and ctx.transport is None:
        return EvalResult(
            case, Observation(note="no gateway transport (MLX unavailable)"), SKIP
        )
    try:
        obs = case.run(ctx)
    except Exception as exc:  # a probe that errors is treated as a failed control, not a pass
        return EvalResult(case, Observation(note=f"probe error: {exc}"), FAIL)
    held = bool(case.check(obs))
    return EvalResult(case, obs, PASS if held else FAIL)


def run_suite(cases: list[EvalCase], ctx: Context) -> list[EvalResult]:
    return [run_case(c, ctx) for c in cases]


@dataclass
class Identity:
    """A test principal the harness drives the gateway as.

    The runner configures the gateway's policy with exactly these identities before the
    suite runs, so the attacks are evaluated against the *real* enforcement code.
    """

    name: str
    token: str
    allowed_models: tuple[str, ...]
    max_autonomy_level: int | None = None
    requests_per_minute: int | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    allowed_skills: tuple[str, ...] = field(default_factory=tuple)
    allowed_tools: tuple[str, ...] = field(default_factory=tuple)
