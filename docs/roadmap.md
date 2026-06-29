# Roadmap

The value of this project is not that a model can run locally — it is the control
boundary around it. The roadmap reflects that: harden the boundary first, broaden
capability second.

## Done — boundary hardening

- **Fail-closed auth** — the gateway refuses to start without `PRIVATE_AI_AUTH_TOKEN`,
  compares the bearer token in constant time, and no longer logs the `Authorization`
  header.
- **Request-size limit** — `MAX_CONTENT_LENGTH` bounds the input side.
- **Policy-as-code identity & authorization** — principals from a TOML policy of API-key
  hashes, per-principal model allowlists and token caps, structured decision audit.
- **Per-principal rate limiting** — token-bucket limiter; over-limit → `429` + `Retry-After`.
- **Secret-egress guardrails** — responses scanned for credential shapes and redacted/blocked
  by policy.
- **Observability** — Prometheus `/metrics` counters and `/v1/whoami` introspection.
- **Autonomy-ceiling enforcement** — per-principal L0–L6 ladder enforced on inference requests
  (`403 autonomy_exceeded`); the keystone of the orchestration control plane.
- **OpenCode isolated review sandbox** — capability-denied (edit/bash/network off), isolated
  XDG config, reviews a copy, before/after manifests prove no out-of-sandbox writes
  (`agents/opencode_sandbox/`).
- **Hermes stateful planner** — delegates one planning cycle to the gateway as the `hermes`
  principal (autonomy ceiling **L1**), then persists `PROJECT_STATE.json` / `RUN_HISTORY.md` /
  `NEXT_ACTIONS.md` with atomic writes and pre-write backups (`agents/hermes/`).
- **OpenClaw assurance verifier** — read-only (autonomy **L0**) verifier that reads the
  decision audit, `/metrics` counters, OpenCode isolation manifests, and policy, runs seven
  controls over them, and emits a PASS/FAIL/INCONCLUSIVE assurance report; exits non-zero only
  on FAIL so it can gate CI (`agents/openclaw/`).
- **Closed assurance → planning loop** — `hermes.verify` runs OpenClaw and folds the verdict
  back into Hermes' memory (an `assurance` block + run-history entry + a remediation gate on
  FAIL), so the next planning cycle plans from *verified* state and a failing control gates new
  work (`agents/hermes/verify.py`).
- **Security-path tests** — auth, policy, rate-limit, guardrail, metrics, autonomy, the Hermes
  memory/plan/verify paths, and the OpenClaw evidence/controls/report/runner paths covered.

## Next major scope — orchestration control plane (Phase 2)

The control plane is designed in [orchestration.md](orchestration.md); the enforcement
substrate (above) is live, the running agents are next:

- **OpenClaw probes** — *next:* add model-driven offensive-security / code-review checks for the
  `openclaw` principal (its `allowed_models` and L0 ceiling already exist in policy), on top of
  today's evidence-verification controls.
- **OpenCode** — OS-level hardening: run the existing capability-denied review sandbox under a
  kernel jail (seccomp/namespaces) and add an approval-gated apply path — the **act** step of
  the now-closed plan → act → verify → record loop.
- **Approval gates** — `APPROVAL REQUIRED` for any L4+ action, surfaced to the owner.

## Near-term — remaining hardening

- **More security-path coverage** — alias routing and the tool-call-block fallback.
- **Key lifecycle** — rotation/expiry for policy principals (keys are static today).

## Medium-term — packaging and streaming

- True token-by-token streaming (the current SSE path emits a single chunk).
- Container packaging and a documented deploy path.
- Grafana dashboard / alerting examples over the `/metrics` counters.

## Longer-term — capability, behind the same boundary

- Local RAG over project documentation.
- A model-output safety eval harness (regression tests for the sanitizer against
  adversarial outputs).
- An optional, explicitly-gated tool registry — only if it can be added without
  weakening the "model output is not authority" guarantee.

## Non-goals

- Multi-tenant SaaS operation.
- Public/internet exposure (this is loopback-first by design).
- Autonomous agent loops driving execution without an operator in the loop.
