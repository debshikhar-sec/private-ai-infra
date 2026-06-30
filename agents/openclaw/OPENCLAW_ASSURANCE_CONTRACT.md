# OpenClaw assurance contract

OpenClaw is the **assurance** component of the control plane. Its mandate is to
**verify that the governance plane's controls actually held**, using only the evidence
those controls already emit. It is a verifier, not an actor.

## Standing rules

1. **Observe only (autonomy L0).** OpenClaw reads evidence and reports. It never
   modifies state, never remediates, never calls a model to "fix" anything. If it ever
   talks to the gateway, it does so as the `openclaw` principal at autonomy **L0** and
   only to *read* (`GET /metrics`).
2. **Evidence-based.** Every finding cites the evidence it rests on. A control with no
   evidence to judge it is reported **INCONCLUSIVE** — never silently PASS. Absence of
   a denial is not proof the control works; it is absence of evidence.
3. **Independent cross-checks.** Where two evidence streams describe the same fact
   (e.g. the decision audit *and* the metrics counters both count denials), OpenClaw
   reconciles them. Divergence is itself a finding — it can mean an audit gap, a metric
   undercount, or tampering.
4. **Fail closed on integrity.** A malformed audit line, an unknown decision value, or
   a missing required field is a **FAIL**, not a parse-and-ignore. The audit trail is a
   security artifact; its integrity is a control in its own right.
5. **No authority to clear a finding.** OpenClaw cannot mark its own findings resolved.
   A FAIL is surfaced to the owner; only a change to the system (and fresh evidence)
   clears it.

## What it checks (controls)

| Control | Verifies | Evidence |
|---|---|---|
| `AC-AUDIT-INTEGRITY` | Every audit record parses and carries the required fields with a known `decision`. | decision audit |
| `AC-AUTONOMY-CEILING` | Every autonomy-ceiling decision in the audit is a `deny` at `403` — an over-ceiling request was never allowed. | decision audit |
| `AC-AUTHZ-MODEL` | Every `allow` used a model inside that principal's `allowed_models`; every model denial is `deny` `403`. | decision audit + policy |
| `AC-RATELIMIT` | Every rate-limit decision is a `deny` at `429`. | decision audit |
| `AC-GUARDRAIL-EGRESS` | Egress-guardrail (`filter`) decisions are well-formed and counted. | decision audit |
| `AC-METRICS-RECONCILE` | Audit deny/throttle/filter counts reconcile with the metrics counters. | decision audit + metrics |
| `AC-OPENCODE-ISOLATION` | OpenCode's last run reported `ISOLATION_RESULT=PASS` with a clean secret scan and exit 0. | isolation report |
| `AC-APPLY-INTEGRITY` | Every OpenCode act-step apply was gated and confined: an APPLIED change carries the approver that authorized it and changed only its declared files; a FAILED apply (undeclared write) fails the control; a REFUSED/REJECTED apply is the gate correctly holding. | apply report |
| `AC-SECURITY-EVALS` | The adversarial eval suite repelled every probe — no governance control let an attack through. A failing probe (or an unreadable report) fails the control. | security-eval report |

## Verdict

The report's overall verdict is **FAIL** if any control fails, otherwise **PASS**.
INCONCLUSIVE controls do not fail the run but are listed explicitly, so the gaps in
coverage are visible rather than hidden. As a CI gate, OpenClaw exits non-zero only on
FAIL.
