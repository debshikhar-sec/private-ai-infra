# OpenClaw — assurance plane

OpenClaw is the **assurance** component of the control plane. Where Hermes *plans* and
OpenCode *reviews*, OpenClaw **verifies that the governance plane's controls actually
held** — and it does so without authority to change anything.

It runs **observe-only (autonomy L0)**: it reads the evidence the gateway already emits,
cross-checks independent streams against each other, and writes a structured assurance
report. Nothing it does mutates state; its output is evidence, not action. See
[`OPENCLAW_ASSURANCE_CONTRACT.md`](OPENCLAW_ASSURANCE_CONTRACT.md) for the standing rules.

## Why a verifier, first

The project's roadmap is explicit that **assurance should precede wider execution** — the
verifier is defined before the implementer's authority is broadened. OpenClaw is that
verifier: it turns the audit log, the metrics, and OpenCode's isolation manifests from
artifacts-that-exist into artifacts-that-are-checked.

## What it checks

| Control | Verifies | Needs |
|---|---|---|
| `AC-AUDIT-INTEGRITY` | every audit record parses, has the required fields, and a known decision | audit |
| `AC-AUTONOMY-CEILING` | every autonomy-ceiling decision is a `403 deny` (over-ceiling never allowed) | audit |
| `AC-AUTHZ-MODEL` | every `allow` used a model in the principal's allowlist; model denials are `403` | audit + policy |
| `AC-RATELIMIT` | every rate-limit decision is a `429 deny` | audit |
| `AC-GUARDRAIL-EGRESS` | egress-guardrail (`filter`) decisions are well-formed | audit |
| `AC-METRICS-RECONCILE` | the metrics counters are consistent with the audit (metric ≥ audit count) | audit + metrics |
| `AC-OPENCODE-ISOLATION` | OpenCode's last run reported `ISOLATION_RESULT=PASS`, clean secret scan, exit 0 | isolation report |
| `AC-APPLY-INTEGRITY` | every act-step apply was approved and confined (APPLIED carries an approver and changed only declared files; FAILED = undeclared write; REFUSED/REJECTED = gate held) | apply report |
| `AC-SECURITY-EVALS` | the adversarial eval suite repelled every probe — no control let an attack through | security-eval report |

A control with no evidence to judge it is reported **INCONCLUSIVE** — never silently
PASS. The overall verdict is **FAIL** if any control fails, else **PASS**; as a CI gate,
OpenClaw exits non-zero only on FAIL.

## Run it

The CLI lives under `agents/`, so put that on the path:

```bash
# audit-only pass — no gateway required
PYTHONPATH=agents python -m openclaw.run \
  --audit agents/openclaw/examples/decisions.sample.jsonl

# full pass — reconcile against metrics, cross-check policy, verify isolation
PYTHONPATH=agents python -m openclaw.run \
  --audit agents/openclaw/examples/decisions.sample.jsonl \
  --policy config/policy.example.toml \
  --metrics-file agents/openclaw/examples/metrics.sample.prom \
  --opencode-report agents/opencode_sandbox/examples/isolated_review.report.txt \
  --eval-report evals/examples/security-eval.report.json \
  --apply-report agents/openclaw/examples/apply.report.json \
  --format markdown
```

To reconcile against a **live** gateway instead of a metrics file, use
`--metrics-url http://127.0.0.1:8081` and set `PRIVATE_AI_OPENCLAW_TOKEN` to the
`openclaw` principal's key. OpenClaw issues a single `GET /metrics` as an L0 principal.

A rendered example report is in
[`examples/assurance.report.txt`](examples/assurance.report.txt).

## Layout

```text
__init__.py                    # version
OPENCLAW_ASSURANCE_CONTRACT.md # the assurance mandate / standing rules
evidence.py                    # loaders: audit JSONL, Prometheus text, isolation report, policy
checks.py                      # the controls (pure functions over evidence -> Finding)
report.py                      # AssuranceReport: verdict + text/json/markdown rendering
client.py                      # read-only GET /metrics client (L0)
run.py                         # CLI
examples/                      # sample evidence + a rendered report
```

## Scope (honest)

This first increment is **model-free**: OpenClaw verifies evidence; it does not yet run
offensive-security probes or model-driven review. The `openclaw` principal
(`allowed_models`, autonomy ceiling **L0**) already exists in policy for when those
model-driven checks are added behind the same boundary. Feeding live findings back into
Hermes' memory so consecutive plans build on *verified* state is the next step.
