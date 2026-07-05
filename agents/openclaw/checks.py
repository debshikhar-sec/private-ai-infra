"""Assurance controls: pure functions over evidence that each return one Finding.

A control answers a single question about whether a governance control held, using the
evidence OpenClaw was given. The rules across all controls:

  - **PASS**         — there is evidence the control held and none that it failed.
  - **FAIL**         — there is evidence the control was violated, or an integrity
                       problem (e.g. a malformed audit record).
  - **INCONCLUSIVE** — there is no evidence either way (e.g. the control was never
                       exercised, or the source needed to judge it was not supplied).

Every control is a plain function of an ``Evidence`` bundle, so each is trivially unit
testable without a running gateway.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from openclaw.evidence import (
    AppliedEvidenceView,
    ApplyReportView,
    AuditLog,
    EvalReportView,
    IsolationReport,
    MetricSet,
    PolicyView,
    load_apply_result_from_sink,
)

PASS = "pass"  # nosec B105 — control-status enum value, not a credential
FAIL = "fail"
INCONCLUSIVE = "inconclusive"


@dataclass
class Finding:
    """One control's result."""

    control_id: str
    title: str
    status: str
    severity: str  # info | low | medium | high
    detail: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class Evidence:
    """Everything a control set may draw on. Optional sources may be ``None``.

    The final block wires the verifier-owned evidence sink (design step 4): ``evidence_sink``
    is the injected, verifier-owned log; ``run_id``/``approval_id`` select the record that
    concerns this run; ``require_signed_apply_evidence`` flips the apply verdict from
    file-mode (self-attested ``apply_report.json``) to fail-closed *signed-evidence* mode.
    All default so every existing ``Evidence(...)`` call site stays valid (additive only).
    """

    audit: AuditLog
    metrics: MetricSet | None = None
    policy: PolicyView | None = None
    isolation: IsolationReport | None = None
    eval_report: EvalReportView | None = None
    apply_report: ApplyReportView | None = None
    # --- signed apply_result evidence (design step 4) ---
    evidence_sink: Any = None
    run_id: str | None = None
    approval_id: str | None = None
    require_signed_apply_evidence: bool = False
    applied_evidence: AppliedEvidenceView | None = None


# --------------------------------------------------------------------- AC-AUDIT-INTEGRITY
def check_audit_integrity(ev: Evidence) -> Finding:
    cid, title = "AC-AUDIT-INTEGRITY", "Decision audit is well-formed"
    audit = ev.audit
    if not audit.events and not audit.malformed:
        return Finding(cid, title, INCONCLUSIVE, "info", "No audit records to verify.")
    if audit.malformed:
        sample = ", ".join(str(n) for n in audit.malformed[:10])
        return Finding(
            cid,
            title,
            FAIL,
            "high",
            f"{len(audit.malformed)} audit line(s) failed to parse or were missing "
            f"required fields (lines: {sample}). The audit trail is a security artifact; "
            "an unparseable record is an integrity gap.",
            evidence=[audit.source],
        )
    unknown = sorted({e.decision for e in audit.events if e.decision not in {"allow", "deny", "filter"}})
    if unknown:
        return Finding(
            cid, title, FAIL, "high",
            f"audit contains unknown decision value(s): {', '.join(unknown)}",
            evidence=[audit.source],
        )
    return Finding(
        cid, title, PASS, "info",
        f"all {len(audit.events)} audit record(s) parsed with required fields and a "
        "known decision value.",
        evidence=[audit.source],
    )


# -------------------------------------------------------------------- AC-AUTONOMY-CEILING
def check_autonomy_ceiling(ev: Evidence) -> Finding:
    cid, title = "AC-AUTONOMY-CEILING", "Autonomy ceiling was never exceeded"
    events = ev.audit.matching_reason("autonomy")
    if not events:
        return Finding(
            cid, title, INCONCLUSIVE, "info",
            "No autonomy-ceiling decisions in the audit — the gate was not exercised in "
            "this window, so there is no evidence to confirm enforcement.",
        )
    violations = [e for e in events if e.decision != "deny" or e.status != 403]
    if violations:
        v = violations[0]
        return Finding(
            cid, title, FAIL, "high",
            f"{len(violations)} autonomy decision(s) were not a 403 deny "
            f"(e.g. request {v.request_id}: decision={v.decision} status={v.status}). "
            "An over-ceiling request must be denied before any model loads.",
            evidence=[ev.audit.source],
        )
    return Finding(
        cid, title, PASS, "info",
        f"all {len(events)} autonomy-ceiling decision(s) were 403 denials — no "
        "over-ceiling request was allowed.",
        evidence=[ev.audit.source],
    )


# ----------------------------------------------------------------------- AC-AUTHZ-MODEL
def check_authz_model(ev: Evidence) -> Finding:
    cid, title = "AC-AUTHZ-MODEL", "Allowed requests stayed within model allowlists"
    # Model-denial integrity is checkable from the audit alone.
    denials = ev.audit.matching_reason("model_not_allowed")
    bad_denials = [e for e in denials if e.decision != "deny" or e.status != 403]
    if bad_denials:
        b = bad_denials[0]
        return Finding(
            cid, title, FAIL, "high",
            f"a model_not_allowed decision was not a 403 deny "
            f"(request {b.request_id}: decision={b.decision} status={b.status}).",
            evidence=[ev.audit.source],
        )
    # Positive cross-check needs the policy.
    if ev.policy is None:
        base = "model-denial records are consistent" if denials else "no model decisions"
        return Finding(
            cid, title, INCONCLUSIVE, "info",
            f"{base}; no policy supplied, so allowed requests could not be cross-checked "
            "against each principal's allowlist.",
            evidence=[ev.audit.source],
        )
    breaches: list[str] = []
    for e in ev.audit.with_decision("allow"):
        if e.principal is None or e.model is None:
            continue
        allowed = ev.policy.allowed_models(e.principal)
        if allowed is None:
            continue  # principal not in policy (e.g. break-glass owner) — not judgeable
        if e.model not in allowed:
            breaches.append(f"{e.principal} -> {e.model} (req {e.request_id})")
    if breaches:
        return Finding(
            cid, title, FAIL, "high",
            f"{len(breaches)} allowed request(s) used a model outside the principal's "
            f"allowlist: {', '.join(breaches[:5])}.",
            evidence=[ev.audit.source, ev.policy.source],
        )
    return Finding(
        cid, title, PASS, "info",
        "every allowed request used a model within its principal's allowlist, and all "
        "model denials were 403.",
        evidence=[ev.audit.source, ev.policy.source],
    )


# ------------------------------------------------------------------------- AC-RATELIMIT
def check_ratelimit(ev: Evidence) -> Finding:
    cid, title = "AC-RATELIMIT", "Rate-limit decisions were enforced as 429"
    events = [
        e
        for e in ev.audit.events
        if "rate" in (e.reason or "").lower() or e.status == 429
    ]
    if not events:
        return Finding(
            cid, title, INCONCLUSIVE, "info",
            "No rate-limit decisions in the audit — limiter not exercised in this window.",
        )
    bad = [e for e in events if e.decision != "deny" or e.status != 429]
    if bad:
        b = bad[0]
        return Finding(
            cid, title, FAIL, "medium",
            f"a rate-limit decision was not a 429 deny "
            f"(request {b.request_id}: decision={b.decision} status={b.status}).",
            evidence=[ev.audit.source],
        )
    return Finding(
        cid, title, PASS, "info",
        f"all {len(events)} rate-limit decision(s) were 429 denials.",
        evidence=[ev.audit.source],
    )


# ------------------------------------------------------------------- AC-GUARDRAIL-EGRESS
def check_guardrail_egress(ev: Evidence) -> Finding:
    cid, title = "AC-GUARDRAIL-EGRESS", "Egress-guardrail events are well-formed"
    filters = ev.audit.with_decision("filter")
    if not filters:
        return Finding(
            cid, title, INCONCLUSIVE, "info",
            "No guardrail (filter) decisions in the audit — no secret-shaped egress was "
            "redacted/blocked in this window.",
        )
    missing = [e for e in filters if not e.reason]
    if missing:
        return Finding(
            cid, title, FAIL, "low",
            f"{len(missing)} guardrail decision(s) recorded without a reason.",
            evidence=[ev.audit.source],
        )
    return Finding(
        cid, title, PASS, "info",
        f"{len(filters)} egress-guardrail decision(s) recorded, each with a reason.",
        evidence=[ev.audit.source],
    )


# ---------------------------------------------------------------- AC-METRICS-RECONCILE
def check_metrics_reconcile(ev: Evidence) -> Finding:
    cid, title = "AC-METRICS-RECONCILE", "Audit and metrics counters agree"
    if ev.metrics is None:
        return Finding(
            cid, title, INCONCLUSIVE, "info",
            "No metrics supplied — the audit could not be reconciled against the "
            "independent counter stream.",
        )
    # (metric name, audit predicate) pairs to reconcile.
    checks = [
        (
            "gateway_authz_denials_total",
            len([e for e in ev.audit.events if e.decision == "deny" and e.status == 403]),
        ),
        (
            "gateway_rate_limited_total",
            len([e for e in ev.audit.events if e.status == 429]),
        ),
        (
            "gateway_guardrail_events_total",
            len(ev.audit.with_decision("filter")),
        ),
    ]
    divergences: list[str] = []
    judged = 0
    for name, audit_count in checks:
        if not ev.metrics.has(name):
            continue
        judged += 1
        metric_count = int(ev.metrics.total(name))
        # The audit is the lower bound: a counter may legitimately exceed it if the audit
        # file was rotated. A counter *below* the audit count means a missing/dropped
        # metric increment — a real signal worth surfacing.
        if metric_count < audit_count:
            divergences.append(
                f"{name}: metric={metric_count} < audit={audit_count}"
            )
    if judged == 0:
        return Finding(
            cid, title, INCONCLUSIVE, "info",
            "Metrics supplied but none of the reconcilable counters were present.",
        )
    if divergences:
        return Finding(
            cid, title, FAIL, "medium",
            "metrics under-count the audit (possible dropped increment or audit/metric "
            f"skew): {'; '.join(divergences)}.",
            evidence=[ev.audit.source],
        )
    return Finding(
        cid, title, PASS, "info",
        f"all {judged} reconcilable counter(s) are consistent with the audit "
        "(metric ≥ audit count).",
        evidence=[ev.audit.source],
    )


# --------------------------------------------------------------- AC-OPENCODE-ISOLATION
def check_opencode_isolation(ev: Evidence) -> Finding:
    cid, title = "AC-OPENCODE-ISOLATION", "OpenCode sandbox stayed isolated"
    rep = ev.isolation
    if rep is None:
        return Finding(
            cid, title, INCONCLUSIVE, "info",
            "No OpenCode isolation report supplied — sandbox containment not verified "
            "in this run.",
        )
    problems: list[str] = []
    if rep.result != "PASS":
        problems.append(f"ISOLATION_RESULT={rep.result!r} (expected PASS)")
    if rep.secret_scan and "PASS" not in rep.secret_scan:
        problems.append(f"SECRET_SCAN_RESULT={rep.secret_scan!r}")
    if rep.opencode_exit not in (None, "0"):
        problems.append(f"OPENCODE_EXIT={rep.opencode_exit}")
    if rep.fail_lines:
        problems.append(f"{len(rep.fail_lines)} FAIL line(s): {rep.fail_lines[0]}")
    if problems:
        return Finding(
            cid, title, FAIL, "high",
            "OpenCode run did not prove clean isolation: " + "; ".join(problems) + ".",
            evidence=[rep.source],
        )
    return Finding(
        cid, title, PASS, "info",
        "OpenCode reported ISOLATION_RESULT=PASS with a clean secret scan and exit 0 — "
        "no out-of-sandbox writes.",
        evidence=[rep.source],
    )


# ---------------------------------------------------------------- AC-APPLY-INTEGRITY
def check_apply_integrity(ev: Evidence) -> Finding:
    cid, title = "AC-APPLY-INTEGRITY", "OpenCode applies were gated and confined"
    rep = ev.apply_report
    if rep is None:
        return Finding(
            cid, title, INCONCLUSIVE, "info",
            "No act-step apply report supplied — the OpenCode write path was not exercised "
            "or recorded in this window, so there is no evidence its approval gate held.",
        )
    if rep.malformed:
        return Finding(
            cid, title, FAIL, "high",
            "the act-step apply report could not be parsed or was missing its status. "
            "An unreadable record of a write action is an integrity gap — fail closed.",
            evidence=[rep.source],
        )
    status = (rep.status or "").lower()
    if status == "failed":
        return Finding(
            cid, title, FAIL, "high",
            "an OpenCode apply was recorded as FAILED — its own verification found a change "
            "outside the declared files (a confinement breach). Investigate before any apply.",
            evidence=[rep.source],
        )
    if status == "applied":
        # An applied (let alone committed) write must carry the approver that authorized it:
        # capability to apply is only ever granted by an explicit approval.
        if not rep.approver:
            return Finding(
                cid, title, FAIL, "high",
                "an OpenCode apply reached APPLIED with no approver recorded — a tree-mutating "
                "action with no authorizing approval is an authority bypass.",
                evidence=[rep.source],
            )
        # Independent cross-check: the report's own changed set must stay within what it
        # declared (defence in depth against a tampered or inconsistent record).
        undeclared = sorted(set(rep.changed_files) - set(rep.declared_files))
        if undeclared:
            return Finding(
                cid, title, FAIL, "high",
                f"an APPLIED report lists changed file(s) it never declared: {undeclared}. "
                "Declared and changed sets must match — the record is inconsistent.",
                evidence=[rep.source],
            )
        scope = "committed to the target" if rep.committed else "verified in sandbox"
        return Finding(
            cid, title, PASS, "info",
            f"the OpenCode apply was approved (by {rep.approver}), {scope}, and changed only "
            f"its {len(rep.declared_files)} declared file(s).",
            evidence=[rep.source],
        )
    if status in ("refused", "rejected"):
        why = "no granted approval (gate held)" if status == "refused" else "a confinement/consistency violation"
        return Finding(
            cid, title, PASS, "info",
            f"the act step correctly blocked a change ({status}: {why}) — the approval/confinement "
            "gate worked and nothing was written.",
            evidence=[rep.source],
        )
    return Finding(
        cid, title, INCONCLUSIVE, "info",
        f"apply report has an unrecognized status {rep.status!r} — cannot judge it.",
        evidence=[rep.source],
    )


# ---------------------------------------------------------------- AC-SECURITY-EVALS
def check_security_evals(ev: Evidence) -> Finding:
    cid, title = "AC-SECURITY-EVALS", "Adversarial security evals held"
    rep = ev.eval_report
    if rep is None:
        return Finding(
            cid, title, INCONCLUSIVE, "info",
            "No security-eval report supplied — the adversarial suite was not folded into "
            "this assurance pass, so there is no evidence the enforced controls actually "
            "repel attack (absence of a report is not proof the controls hold).",
        )
    if rep.malformed:
        return Finding(
            cid, title, FAIL, "high",
            "the security-eval report could not be parsed or was missing its verdict/counts. "
            "An unreadable assurance artifact is itself an integrity gap — fail closed.",
            evidence=[rep.source],
        )
    if rep.verdict == "FAIL" or rep.failed > 0:
        sample = "; ".join(rep.failed_probes[:5]) or f"{rep.failed} probe(s)"
        return Finding(
            cid, title, FAIL, "high",
            f"the adversarial security suite reported {rep.failed} failing probe(s) — a "
            f"governance control let an attack through: {sample}. New work is gated until "
            "the control is restored.",
            evidence=[rep.source],
        )
    if rep.passed == 0:
        return Finding(
            cid, title, INCONCLUSIVE, "info",
            f"the security-eval report drove no probe to a verdict ({rep.skipped} skipped) — "
            "no attack was actually exercised, so enforcement is unverified here.",
            evidence=[rep.source],
        )
    detail = f"all {rep.passed} adversarial probe(s) were repelled (verdict {rep.verdict})"
    if rep.skipped:
        detail += f"; {rep.skipped} probe(s) skipped — a coverage gap, not a failure"
    return Finding(cid, title, PASS, "info", detail + ".", evidence=[rep.source])


# ------------------------------------------------------------ AC-APPLY-EVIDENCE-CHAIN
def _apply_evidence_conflicts(
    report: ApplyReportView, view: AppliedEvidenceView
) -> list[str]:
    """Fields where the self-attested file and the signed sink record materially disagree."""
    out: list[str] = []
    if (report.status or "").lower() != (view.status or "").lower():
        out.append(f"status file={report.status!r} vs signed={view.status!r}")
    if report.approver != view.approver:
        out.append(f"approver file={report.approver!r} vs signed={view.approver!r}")
    if report.committed != view.committed:
        out.append(f"committed file={report.committed} vs signed={view.committed}")
    if sorted(report.declared_files) != sorted(view.declared_files):
        out.append("declared_files differ")
    if sorted(report.changed_files) != sorted(view.changed_files):
        out.append("changed_files differ")
    return out


def check_apply_evidence_chain(ev: Evidence) -> Finding:
    """Judge the OpenCode apply from a *signed, chained* sink record rather than a raw file.

    This closes the self-attestation gap (threat T1): where ``check_apply_integrity`` trusts an
    unsigned ``apply_report.json`` at an executor-chosen path, this control trusts only a record
    the verifier-owned sink validated and chained. It is additive: with no sink and
    ``require_signed_apply_evidence`` off it is INCONCLUSIVE (never changing an old verdict);
    with signed evidence *required*, an unsigned file alone can no longer reach PASS.
    """
    cid, title = "AC-APPLY-EVIDENCE-CHAIN", "OpenCode apply is backed by signed, chained sink evidence"
    required = ev.require_signed_apply_evidence
    view = ev.applied_evidence
    if view is None:
        view = load_apply_result_from_sink(
            ev.evidence_sink, run_id=ev.run_id, approval_id=ev.approval_id
        )

    # No sink supplied.
    if not view.configured:
        if required:
            return Finding(
                cid, title, FAIL, "high",
                "signed apply evidence is required but no evidence sink was supplied — an "
                "unsigned apply_report.json alone cannot authorize a verified apply. Fail closed.",
            )
        return Finding(
            cid, title, INCONCLUSIVE, "info",
            "no evidence sink supplied — the signed-apply-result path was not exercised; "
            "file-mode apply integrity (AC-APPLY-INTEGRITY) is judged separately.",
        )

    src = [view.record_hash] if view.record_hash else []

    # Chain integrity: the whole log must re-derive before any record is trusted.
    if view.chain_error:
        return Finding(
            cid, title, FAIL, "high",
            f"the evidence sink's chain did not verify ({view.reason}) — the log's integrity "
            "cannot be established, so no record it holds can be trusted.",
            evidence=src,
        )

    # No matching signed record.
    if view.missing:
        if required:
            return Finding(
                cid, title, FAIL, "high",
                "no signed apply_result record matches this run in the evidence sink, but signed "
                "evidence is required — absence of the required record is fail-closed, not a pass.",
            )
        return Finding(
            cid, title, INCONCLUSIVE, "info",
            "the evidence sink holds no signed apply_result for this run — nothing to verify "
            "here (signed evidence not required in this pass).",
        )

    # Malformed payload on an otherwise-valid chain.
    if view.malformed:
        return Finding(
            cid, title, FAIL, "high",
            "a signed apply_result record was found but its payload is malformed or missing its "
            "status — an unreadable record of a write action is an integrity gap. Fail closed.",
            evidence=src,
        )

    # Cross-check the self-attested file against the signed record when both are present.
    if ev.apply_report is not None and not ev.apply_report.malformed:
        conflicts = _apply_evidence_conflicts(ev.apply_report, view)
        if conflicts:
            return Finding(
                cid, title, FAIL, "high",
                "the self-attested apply_report.json disagrees with the signed sink record "
                f"({'; '.join(conflicts)}). The signed record is authoritative; a conflict is a "
                "tamper signal. Fail closed.",
                evidence=src,
            )

    # Judge the validated, signed payload — same authority rules as file mode.
    status = (view.status or "").lower()
    if status == "failed":
        return Finding(
            cid, title, FAIL, "high",
            "the signed apply_result records status=FAILED — the executor's own verification "
            "found a change outside the declared files (a confinement breach).",
            evidence=src,
        )
    if status == "applied":
        if not view.approver:
            return Finding(
                cid, title, FAIL, "high",
                "a signed apply_result reached APPLIED with no approver — a tree-mutating action "
                "with no authorizing approval is an authority bypass.",
                evidence=src,
            )
        undeclared = sorted(set(view.changed_files) - set(view.declared_files))
        if undeclared:
            return Finding(
                cid, title, FAIL, "high",
                f"a signed APPLIED record lists changed file(s) it never declared: {undeclared}. "
                "Declared and changed sets must match — the record is inconsistent.",
                evidence=src,
            )
        scope = "committed to the target" if view.committed else "verified in sandbox"
        return Finding(
            cid, title, PASS, "info",
            f"the OpenCode apply is backed by a signed, chained apply_result record (seq {view.seq}): "
            f"approved by {view.approver}, {scope}, and changed only its {len(view.declared_files)} "
            "declared file(s).",
            evidence=src,
        )
    if status in ("refused", "rejected"):
        return Finding(
            cid, title, PASS, "info",
            f"a signed apply_result record shows the act step blocked a change ({status}) — the "
            "approval/confinement gate held and nothing was written.",
            evidence=src,
        )

    # Unrecognized status on an otherwise-valid signed record.
    if required:
        return Finding(
            cid, title, FAIL, "high",
            f"a signed apply_result has an unrecognized status {view.status!r}; signed evidence is "
            "required and this cannot be affirmed as a gated apply. Fail closed.",
            evidence=src,
        )
    return Finding(
        cid, title, INCONCLUSIVE, "info",
        f"a signed apply_result has an unrecognized status {view.status!r} — cannot judge it.",
        evidence=src,
    )


ALL_CHECKS = [
    check_audit_integrity,
    check_autonomy_ceiling,
    check_authz_model,
    check_ratelimit,
    check_guardrail_egress,
    check_metrics_reconcile,
    check_opencode_isolation,
    check_apply_integrity,
    check_security_evals,
]


def run_all(ev: Evidence) -> list[Finding]:
    """Run every control against the evidence and return the findings.

    ``check_apply_evidence_chain`` is **not** in ``ALL_CHECKS``: it is gated so that a run with
    no evidence sink configured (and not requiring signed evidence) produces exactly the
    historical control set — byte-for-byte, no extra finding, no verdict drift. It participates
    only once the signed-evidence path is engaged (a sink is injected, or signed evidence is
    required), which is design step 4's whole surface.
    """
    findings = [check(ev) for check in ALL_CHECKS]
    if ev.evidence_sink is not None or ev.require_signed_apply_evidence:
        findings.append(check_apply_evidence_chain(ev))
    return findings
