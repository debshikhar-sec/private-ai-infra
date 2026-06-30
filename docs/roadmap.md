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
  decision audit, `/metrics` counters, OpenCode isolation manifests, policy, and the adversarial
  eval report, runs eight controls over them, and emits a PASS/FAIL/INCONCLUSIVE assurance
  report; exits non-zero only on FAIL so it can gate CI (`agents/openclaw/`).
- **Closed assurance → planning loop** — `hermes.verify` runs OpenClaw and folds the verdict
  back into Hermes' memory (an `assurance` block + run-history entry + a remediation gate on
  FAIL), so the next planning cycle plans from *verified* state and a failing control gates new
  work (`agents/hermes/verify.py`).
- **Adversarial security eval harness** — an active suite (`evals/`) that attacks the enforced
  controls (autonomy bypass, model authorization, fail-closed auth, rate limiting, secret egress),
  tagged by OWASP LLM risk, emitting a PASS/FAIL report that gates CI. It caught and fixed a real
  autonomy-ceiling bypass (conflicting header/body declaration) and now regression-tests it.
- **Eval verdict feeds assurance → gates planning** — OpenClaw's `AC-SECURITY-EVALS` control
  reads the eval report as evidence, so a failing probe becomes a failing assurance control that
  Hermes folds into memory and treats as a remediation gate on the next planning cycle. The
  third thread (`evals → OpenClaw → Hermes`) of the plan → act → verify → record loop is closed.
- **OpenCode act step** — an approval-gated, confined, verified apply path
  (`agents/opencode_sandbox/apply.py`, CLI `opencode_sandbox.act`): a proposed change carries no
  approval, is refused without an explicit owner approval (fail closed, ≥ L3, no under-declaring),
  is applied only into a sandbox copy, and is verified by sha256 manifests to change exactly the
  files it declared — the **act** step of the plan → act → verify → record loop. Pure-stdlib and
  unit-tested.
- **Security-path tests** — auth, policy, rate-limit, guardrail, metrics, autonomy, the Hermes
  memory/plan/verify paths, the OpenClaw evidence/controls/report/runner paths, the eval
  harness, and the OpenCode act-step (gate/confinement/verify/CLI) covered.

## Next major scope — orchestration control plane (Phase 2)

The control plane is designed in [orchestration.md](orchestration.md); the enforcement
substrate (above) is live, the running agents are next:

- **OpenClaw probes** — *next:* add model-driven offensive-security / code-review checks for the
  `openclaw` principal (its `allowed_models` and L0 ceiling already exist in policy), on top of
  today's evidence-verification controls.
- **OpenCode OS-level jail** — run both the review sandbox and the act-step apply under a kernel
  jail (seccomp/namespaces / `sandbox-exec`). The protocol-level gate and filesystem verification
  are done; the remaining hardening is the OS boundary.
- **Approval gates** — surface `APPROVAL REQUIRED` to the owner for L4+ gateway actions, reusing
  the act step's approval model.

## Near-term — remaining hardening

- **More security-path coverage** — alias routing and the tool-call-block fallback.
- **Key lifecycle** — rotation/expiry for policy principals (keys are static today).

## Medium-term — packaging and streaming

- True token-by-token streaming (the current SSE path emits a single chunk).
- Container packaging and a documented deploy path.
- Grafana dashboard / alerting examples over the `/metrics` counters.

## Next — extend the eval harness

- Add **prompt-injection / tool-misuse** probes once an explicitly-gated tool path exists.
  (Feeding the eval verdict into OpenClaw's assurance so a failed eval gates the planning loop
  is now **done** — see boundary hardening above.)

## Longer-term — capability, behind the same boundary

- Local RAG over project documentation.
- An optional, explicitly-gated tool registry — only if it can be added without
  weakening the "model output is not authority" guarantee.

## Non-goals

- Multi-tenant SaaS operation.
- Public/internet exposure (this is loopback-first by design).
- Autonomous agent loops driving execution without an operator in the loop.
