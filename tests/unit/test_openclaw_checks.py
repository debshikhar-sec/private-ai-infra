"""Tests for the OpenClaw assurance controls."""

from __future__ import annotations

from openclaw import checks
from openclaw.checks import FAIL, INCONCLUSIVE, PASS, Evidence
from openclaw.evidence import (
    ApplyReportView,
    AuditEvent,
    AuditLog,
    EvalReportView,
    IsolationReport,
    MetricSample,
    MetricSet,
    PolicyView,
)


def _event(**kw) -> AuditEvent:
    base = dict(
        ts="t",
        request_id="r",
        principal="a",
        method="POST",
        path="/v1/chat/completions",
        model="strategy",
        decision="allow",
        reason="ok",
        status=200,
        raw={},
    )
    base.update(kw)
    return AuditEvent(**base)


def _log(events) -> AuditLog:
    return AuditLog(events=list(events), source="audit.jsonl")


# ---------------------------------------------------------- AC-AUDIT-INTEGRITY
def test_audit_integrity_pass():
    f = checks.check_audit_integrity(Evidence(audit=_log([_event()])))
    assert f.status == PASS


def test_audit_integrity_fails_on_malformed():
    log = AuditLog(events=[_event()], malformed=[7], source="a")
    f = checks.check_audit_integrity(Evidence(audit=log))
    assert f.status == FAIL and f.severity == "high"


def test_audit_integrity_fails_on_unknown_decision():
    f = checks.check_audit_integrity(Evidence(audit=_log([_event(decision="escalate")])))
    assert f.status == FAIL


def test_audit_integrity_inconclusive_when_empty():
    f = checks.check_audit_integrity(Evidence(audit=_log([])))
    assert f.status == INCONCLUSIVE


# --------------------------------------------------------- AC-AUTONOMY-CEILING
def test_autonomy_pass_when_all_denied_403():
    log = _log([_event(decision="deny", reason="autonomy_exceeded: L3>L1", status=403)])
    f = checks.check_autonomy_ceiling(Evidence(audit=log))
    assert f.status == PASS


def test_autonomy_fails_when_over_ceiling_allowed():
    log = _log([_event(decision="allow", reason="autonomy_exceeded leaked", status=200)])
    f = checks.check_autonomy_ceiling(Evidence(audit=log))
    assert f.status == FAIL and f.severity == "high"


def test_autonomy_inconclusive_when_never_exercised():
    f = checks.check_autonomy_ceiling(Evidence(audit=_log([_event()])))
    assert f.status == INCONCLUSIVE


# ------------------------------------------------------------ AC-AUTHZ-MODEL
def test_authz_model_inconclusive_without_policy():
    f = checks.check_authz_model(Evidence(audit=_log([_event()])))
    assert f.status == INCONCLUSIVE


def test_authz_model_pass_with_policy():
    policy = PolicyView(principals={"a": {"allowed_models": ["strategy"]}}, source="p")
    f = checks.check_authz_model(Evidence(audit=_log([_event()]), policy=policy))
    assert f.status == PASS


def test_authz_model_fails_on_allow_outside_allowlist():
    policy = PolicyView(principals={"a": {"allowed_models": ["engineering"]}}, source="p")
    f = checks.check_authz_model(Evidence(audit=_log([_event(model="strategy")]), policy=policy))
    assert f.status == FAIL and f.severity == "high"


def test_authz_model_fails_when_model_denial_not_403():
    log = _log([_event(decision="allow", reason="model_not_allowed", status=200)])
    f = checks.check_authz_model(Evidence(audit=log))
    assert f.status == FAIL


def test_authz_model_skips_principal_absent_from_policy():
    # break-glass owner not listed in policy -> not judgeable -> still PASS
    policy = PolicyView(principals={}, source="p")
    f = checks.check_authz_model(Evidence(audit=_log([_event(principal="owner")]), policy=policy))
    assert f.status == PASS


# -------------------------------------------------------------- AC-RATELIMIT
def test_ratelimit_pass():
    log = _log([_event(decision="deny", reason="rate_limited", status=429)])
    f = checks.check_ratelimit(Evidence(audit=log))
    assert f.status == PASS


def test_ratelimit_fails_when_not_429():
    log = _log([_event(decision="deny", reason="rate_limited", status=403)])
    f = checks.check_ratelimit(Evidence(audit=log))
    assert f.status == FAIL


def test_ratelimit_inconclusive_when_absent():
    f = checks.check_ratelimit(Evidence(audit=_log([_event()])))
    assert f.status == INCONCLUSIVE


# ------------------------------------------------------- AC-GUARDRAIL-EGRESS
def test_guardrail_pass():
    log = _log([_event(decision="filter", reason="guardrail_redacted: aws_key", status=200)])
    f = checks.check_guardrail_egress(Evidence(audit=log))
    assert f.status == PASS


def test_guardrail_fails_without_reason():
    log = _log([_event(decision="filter", reason="", status=200)])
    f = checks.check_guardrail_egress(Evidence(audit=log))
    assert f.status == FAIL


def test_guardrail_inconclusive_when_absent():
    f = checks.check_guardrail_egress(Evidence(audit=_log([_event()])))
    assert f.status == INCONCLUSIVE


# ---------------------------------------------------- AC-METRICS-RECONCILE
def _metrics(pairs) -> MetricSet:
    return MetricSet(samples=[MetricSample(name=n, labels={}, value=v) for n, v in pairs])


def test_metrics_reconcile_inconclusive_without_metrics():
    f = checks.check_metrics_reconcile(Evidence(audit=_log([_event()])))
    assert f.status == INCONCLUSIVE


def test_metrics_reconcile_pass_when_metric_ge_audit():
    log = _log([_event(decision="deny", reason="model_not_allowed", status=403)])
    metrics = _metrics([("gateway_authz_denials_total", 5)])
    f = checks.check_metrics_reconcile(Evidence(audit=log, metrics=metrics))
    assert f.status == PASS


def test_metrics_reconcile_fails_when_metric_below_audit():
    log = _log(
        [
            _event(decision="deny", reason="model_not_allowed", status=403),
            _event(decision="deny", reason="autonomy_exceeded", status=403),
        ]
    )
    metrics = _metrics([("gateway_authz_denials_total", 1)])  # audit has 2
    f = checks.check_metrics_reconcile(Evidence(audit=log, metrics=metrics))
    assert f.status == FAIL and f.severity == "medium"


def test_metrics_reconcile_inconclusive_when_no_matching_counter():
    metrics = _metrics([("some_other_total", 9)])
    f = checks.check_metrics_reconcile(Evidence(audit=_log([_event()]), metrics=metrics))
    assert f.status == INCONCLUSIVE


# -------------------------------------------------- AC-OPENCODE-ISOLATION
def test_isolation_pass():
    rep = IsolationReport(
        fields={"ISOLATION_RESULT": "PASS", "SECRET_SCAN_RESULT": "PASS", "OPENCODE_EXIT": "0"},
        source="rep",
    )
    f = checks.check_opencode_isolation(Evidence(audit=_log([]), isolation=rep))
    assert f.status == PASS


def test_isolation_fails_when_result_not_pass():
    rep = IsolationReport(fields={"ISOLATION_RESULT": "FAIL"}, source="rep")
    f = checks.check_opencode_isolation(Evidence(audit=_log([]), isolation=rep))
    assert f.status == FAIL and f.severity == "high"


def test_isolation_fails_on_nonzero_exit():
    rep = IsolationReport(
        fields={"ISOLATION_RESULT": "PASS", "OPENCODE_EXIT": "1"}, source="rep"
    )
    f = checks.check_opencode_isolation(Evidence(audit=_log([]), isolation=rep))
    assert f.status == FAIL


def test_isolation_inconclusive_when_absent():
    f = checks.check_opencode_isolation(Evidence(audit=_log([])))
    assert f.status == INCONCLUSIVE


# --------------------------------------------------------------- AC-APPLY-INTEGRITY
def _apply(**kw) -> ApplyReportView:
    base = dict(status="applied", approver="alice", committed=True,
                declared_files=["a.py"], changed_files=["a.py"], source="apply.json")
    base.update(kw)
    return ApplyReportView(**base)


def test_apply_integrity_pass_when_approved_and_confined():
    f = checks.check_apply_integrity(Evidence(audit=_log([]), apply_report=_apply()))
    assert f.status == PASS and "alice" in f.detail


def test_apply_integrity_fails_when_applied_without_approver():
    f = checks.check_apply_integrity(
        Evidence(audit=_log([]), apply_report=_apply(approver=None))
    )
    assert f.status == FAIL and f.severity == "high"


def test_apply_integrity_fails_on_undeclared_change():
    f = checks.check_apply_integrity(
        Evidence(audit=_log([]), apply_report=_apply(changed_files=["a.py", "b.py"]))
    )
    assert f.status == FAIL and "never declared" in f.detail


def test_apply_integrity_fails_on_failed_status():
    f = checks.check_apply_integrity(
        Evidence(audit=_log([]), apply_report=_apply(status="failed"))
    )
    assert f.status == FAIL and f.severity == "high"


def test_apply_integrity_pass_when_gate_blocked_change():
    for status in ("refused", "rejected"):
        f = checks.check_apply_integrity(
            Evidence(audit=_log([]), apply_report=_apply(status=status, approver=None))
        )
        assert f.status == PASS, status


def test_apply_integrity_fails_on_malformed():
    f = checks.check_apply_integrity(
        Evidence(audit=_log([]), apply_report=ApplyReportView(malformed=True, source="a"))
    )
    assert f.status == FAIL


def test_apply_integrity_inconclusive_when_absent():
    f = checks.check_apply_integrity(Evidence(audit=_log([])))
    assert f.status == INCONCLUSIVE


def test_apply_integrity_inconclusive_on_unknown_status():
    f = checks.check_apply_integrity(
        Evidence(audit=_log([]), apply_report=_apply(status="weird"))
    )
    assert f.status == INCONCLUSIVE


# --------------------------------------------------------------- AC-SECURITY-EVALS
def test_security_evals_pass_when_all_repelled():
    rep = EvalReportView(verdict="PASS", passed=12, failed=0, skipped=0, source="e.json")
    f = checks.check_security_evals(Evidence(audit=_log([]), eval_report=rep))
    assert f.status == PASS
    assert "12" in f.detail


def test_security_evals_fail_on_failing_probe():
    rep = EvalReportView(
        verdict="FAIL",
        passed=11,
        failed=1,
        skipped=0,
        failed_probes=["AUTONOMY-004 (LLM06): header L1 + body L6"],
        source="e.json",
    )
    f = checks.check_security_evals(Evidence(audit=_log([]), eval_report=rep))
    assert f.status == FAIL and f.severity == "high"
    assert "AUTONOMY-004" in f.detail


def test_security_evals_fail_counts_alone_trigger_fail():
    # A truthful failed count must fail even if the verdict string was tampered to PASS.
    rep = EvalReportView(verdict="PASS", passed=10, failed=2, skipped=0, source="e.json")
    f = checks.check_security_evals(Evidence(audit=_log([]), eval_report=rep))
    assert f.status == FAIL


def test_security_evals_fail_on_malformed_report():
    rep = EvalReportView(malformed=True, source="e.json")
    f = checks.check_security_evals(Evidence(audit=_log([]), eval_report=rep))
    assert f.status == FAIL and f.severity == "high"


def test_security_evals_inconclusive_when_all_skipped():
    rep = EvalReportView(verdict="PASS", passed=0, failed=0, skipped=12, source="e.json")
    f = checks.check_security_evals(Evidence(audit=_log([]), eval_report=rep))
    assert f.status == INCONCLUSIVE


def test_security_evals_inconclusive_when_absent():
    f = checks.check_security_evals(Evidence(audit=_log([])))
    assert f.status == INCONCLUSIVE


def test_security_evals_notes_skip_coverage_gap_but_passes():
    rep = EvalReportView(verdict="PASS", passed=8, failed=0, skipped=4, source="e.json")
    f = checks.check_security_evals(Evidence(audit=_log([]), eval_report=rep))
    assert f.status == PASS
    assert "skipped" in f.detail.lower()


# ----------------------------------------------------------------- run_all
def test_run_all_returns_one_finding_per_control():
    findings = checks.run_all(Evidence(audit=_log([_event()])))
    assert len(findings) == len(checks.ALL_CHECKS)
    assert {f.control_id for f in findings} == {
        "AC-AUDIT-INTEGRITY",
        "AC-AUTONOMY-CEILING",
        "AC-AUTHZ-MODEL",
        "AC-RATELIMIT",
        "AC-GUARDRAIL-EGRESS",
        "AC-METRICS-RECONCILE",
        "AC-OPENCODE-ISOLATION",
        "AC-APPLY-INTEGRITY",
        "AC-SECURITY-EVALS",
    }
