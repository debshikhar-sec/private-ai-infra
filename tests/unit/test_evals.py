"""Tests for the adversarial security eval harness.

The harness *scoring* is validated with canned transports (no MLX). The egress probes run
for real against the pure `Guardrails`. A final MLX-gated test drives the live gateway and
asserts every attack is repelled — the security regression gate.
"""

from __future__ import annotations

import json

import pytest
from evals import run as evalrun
from evals.cases import AGENTIC_CASES, ALL_CASES, EGRESS_CASES
from evals.harness import (
    FAIL,
    PASS,
    SKIP,
    Context,
    EvalCase,
    Observation,
    run_case,
    run_suite,
)
from evals.report import build_report


def _fixed_transport(status, code):
    def t(method, path, *, headers=None, json=None):
        return Observation(status=status, code=code)

    return t


def _denial_case(needs_gateway=True) -> EvalCase:
    return EvalCase(
        id="X-1",
        category="test",
        owasp="LLM06",
        attack="declares too-high autonomy",
        expectation="403 autonomy_exceeded",
        run=lambda ctx: ctx.request("POST", "/v1/chat/completions", token="k"),
        check=lambda obs: obs.status == 403 and obs.code == "autonomy_exceeded",
        needs_gateway=needs_gateway,
    )


# --------------------------------------------------------------- harness scoring
def test_pass_when_control_holds():
    ctx = Context(transport=_fixed_transport(403, "autonomy_exceeded"))
    assert run_case(_denial_case(), ctx).status == PASS


def test_fail_when_control_breached():
    # the attack got a 200 — the control did NOT hold
    ctx = Context(transport=_fixed_transport(200, ""))
    assert run_case(_denial_case(), ctx).status == FAIL


def test_skip_when_gateway_required_but_absent():
    ctx = Context(transport=None)
    assert run_case(_denial_case(needs_gateway=True), ctx).status == SKIP


def test_probe_error_is_failure_not_pass():
    def boom(ctx):
        raise RuntimeError("probe blew up")

    case = EvalCase("E-1", "test", "LLM06", "a", "b", run=boom, check=lambda o: True)
    ctx = Context(transport=_fixed_transport(200, ""))
    assert run_case(case, ctx).status == FAIL


# --------------------------------------------------------------- egress (real)
def test_egress_probes_pass_against_real_guardrails():
    from private_ai_gateway.guardrails import Guardrails

    ctx = Context(guardrails=Guardrails("redact"))
    results = run_suite(EGRESS_CASES, ctx)
    assert results, "expected egress cases"
    assert all(r.status == PASS for r in results), [
        (r.case.id, r.observation.note) for r in results if r.status != PASS
    ]


# --------------------------------------------------------------- agentic (OWASP ASI)
def test_agentic_cases_wired_and_memory_poisoning_probe_holds():
    from private_ai_gateway.guardrails import Guardrails

    # the agentic threat-model group is part of the full attack catalogue
    ids = {c.id for c in ALL_CASES}
    assert {"AGENTIC-001", "AGENTIC-002", "AGENTIC-003"} <= ids

    # the memory/context-poisoning exfil probe is egress-only, so it runs everywhere
    # (incl. Linux CI): a captured model still cannot push a secret past the guardrail.
    egress_agentic = [c for c in AGENTIC_CASES if not c.needs_gateway]
    results = run_suite(egress_agentic, Context(guardrails=Guardrails("redact")))
    assert results and all(r.status == PASS for r in results), [
        (r.case.id, r.observation.note) for r in results if r.status != PASS
    ]


# --------------------------------------------------------------- report
def test_report_verdict_and_exit_code():
    ctx_pass = Context(transport=_fixed_transport(403, "autonomy_exceeded"))
    ctx_fail = Context(transport=_fixed_transport(200, ""))
    good = build_report([run_case(_denial_case(), ctx_pass)])
    assert good.verdict == "PASS" and good.exit_code() == 0
    bad = build_report([run_case(_denial_case(), ctx_fail)])
    assert bad.verdict == "FAIL" and bad.exit_code() == 1


def test_report_json_is_serializable_and_tagged():
    ctx = Context(transport=_fixed_transport(403, "autonomy_exceeded"))
    report = build_report([run_case(_denial_case(), ctx)])
    data = json.loads(report.to_json())
    assert data["verdict"] == "PASS"
    assert data["results"][0]["owasp"] == "LLM06"
    assert data["results"][0]["status"] == PASS


def test_report_markdown_escapes_pipes():
    case = EvalCase("Z", "c", "LLM06", "a | with pipe", "exp", lambda ctx: Observation(), lambda o: True)
    md = build_report([run_case(case, Context(transport=_fixed_transport(1, "")))]).to_markdown()
    row = [ln for ln in md.splitlines() if "`Z`" in ln][0]
    assert "\\|" in row


# --------------------------------------------------------------- CLI
def test_cli_without_gateway_runs_egress_and_skips_requests(capsys):
    # No gateway -> request-level probes SKIP, egress PASS -> no failures -> exit 0
    code = evalrun.main(["--format", "text"], transport_factory=lambda: None)
    out = capsys.readouterr()
    assert code == 0
    assert "SKIP" in out.out
    assert "skipped" in out.err.lower()


def test_cli_require_gateway_errors_when_absent():
    code = evalrun.main(["--require-gateway"], transport_factory=lambda: None)
    assert code == 2


def test_cli_json_output_to_file(tmp_path):
    out = tmp_path / "evals.json"
    code = evalrun.main(
        ["--format", "json", "--output", str(out)], transport_factory=lambda: None
    )
    assert code == 0
    assert json.loads(out.read_text())["component"] == "security-evals"


# --------------------------------------------------------------- live gateway gate
def test_live_gateway_repels_every_attack():
    """The real enforcement path must pass the full suite (incl. the autonomy-bypass)."""
    pytest.importorskip("mlx", reason="MLX is only available on Apple Silicon")
    transport = evalrun.build_gateway_transport()
    assert transport is not None
    ctx = Context(transport=transport, guardrails=evalrun._build_guardrails())
    report = build_report(run_suite(ALL_CASES, ctx))
    assert report.verdict == "PASS", "\n" + report.to_text()
    # nothing should be skipped when the gateway is actually present
    assert report.counts()[SKIP] == 0
