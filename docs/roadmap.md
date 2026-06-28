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
- **Security-path tests** — auth, policy, rate-limit, guardrail, metrics, and autonomy paths
  covered (50 tests, 83% coverage).

## Next major scope — orchestration control plane (Phase 2)

The control plane is designed in [orchestration.md](orchestration.md); the enforcement
substrate (above) is live, the running agents are next:

- **Hermes** — a running planner that emits the structured plan and issues delegations through
  the gateway as distinct principals (one identity per component, no shared god token).
- **OpenCode** — graduate the read-only operator wrapper into a real sandbox: network-isolated,
  scoped filesystem, resource-limited, with an approval-gated apply path.
- **OpenClaw** — offensive-security / code-review / telemetry tasks feeding `/metrics` and the
  decision audit.
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
