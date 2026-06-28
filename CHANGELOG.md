# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-06-28

### Added
- **Autonomy-ceiling enforcement (orchestration keystone).** New `autonomy.py` defines the
  L0–L6 autonomy ladder (observe → suggest → dry-run → owner-run → monitored → continuous →
  unbounded). Each principal carries a `max_autonomy_level` (with an `[autonomy]`
  `default_max_level` fallback); a request declaring a higher level via the
  `X-Autonomy-Level` header or `autonomy_level` body field is denied `403 autonomy_exceeded`
  **before any model loads**, and the denial is audited. Gating is opt-in (off when no ceiling
  is configured). This converts the project's original prompt-level autonomy governance into
  an enforced control.
- **Orchestration control plane, documented.** `docs/orchestration.md` defines the
  multi-agent control plane — **Hermes** (planning/orchestration), **OpenCode** (sandboxed
  code execution), **OpenClaw** (security/observability) — as components governed by the
  enforced governance plane, with an explicit current-vs-planned status. `/v1/whoami` now
  reports the caller's `max_autonomy_level`.
- Tests for the ladder, policy loading, and endpoint enforcement (suite 42 → 50; coverage
  82% → 83%).

### Changed
- The owner break-glass identity sits at the top of the ladder (L6).
- README, architecture, and security model reframed around the orchestration control plane
  (capability is not authority — now enforced, not requested).

## [0.3.0] - 2026-06-27

### Added
- **Per-principal rate limiting.** Token-bucket limiter (`ratelimit.py`) keyed by
  principal; a per-principal `requests_per_minute` overrides a policy-wide default
  (`[ratelimit]`). Over-limit requests are rejected with `429` and a `Retry-After`
  header before any model load — a runaway key is throttled cheaply.
- **Output guardrails (secret-egress control).** `guardrails.py` scans every model
  response for credential-shaped content (AWS keys, private-key blocks, OpenAI/Slack/
  GitHub tokens, JWTs) and applies a policy action (`[guardrails] action` =
  `off`/`redact`/`block`). Egress filtering applies regardless of how authorized the
  caller is — authority to *invoke* a model is not authority to *exfiltrate* secrets.
- **Observability.** Hand-rolled Prometheus counter registry (`metrics.py`, no new
  dependency) exposed at `GET /metrics`: request decisions, authz denials, rate-limit
  rejections, and guardrail events. `GET /v1/whoami` returns the caller's effective
  permissions (principal, allowed models, token cap, rate limit).
- Tests for rate limiting, guardrails, metrics, and the new endpoints (suite 22 → 42;
  coverage 62% → 82%).

### Changed
- Guardrail and rate-limit activity is recorded to the structured decision audit
  (`decisions.jsonl`) alongside authz decisions.

## [0.2.0] - 2026-06-27

### Added
- **Governance plane (policy-as-code).** Externalized policy (`config/policy.toml`, TOML via
  stdlib `tomllib`) defining principals (API-key identities). Keys are stored as SHA-256
  hashes, never plaintext.
- **Identity + authorization.** Each request is resolved to a principal; the requested model
  alias is authorized against that principal's allowlist (403 on denial), and the effective
  output-token cap is the tightest of request / per-model / per-principal limits.
- **Structured decision audit** (`logs/decisions.jsonl`): one JSON record per authorization
  decision (request_id, principal, model, allow/deny, reason, status) for SIEM ingestion.
- Tests for the policy layer and authz paths (suite 4 → 17).

### Changed
- Gateway now launches as a module (`python -m private_ai_gateway.app`) for clean
  intra-package imports; start/stop scripts updated accordingly.
- Single static token mode is preserved as an "owner" break-glass principal when no policy
  file is present (zero-config local development).

### Security
- Fail-closed auth (refuses to start without `PRIVATE_AI_AUTH_TOKEN`), constant-time bearer
  comparison, Authorization header no longer logged, and a request-body size limit
  (`MAX_CONTENT_LENGTH`).

### Tooling
- CI split into a lint/scan job (ruff, Bandit SAST, pip-audit dependency CVE scan, shellcheck)
  and a test+coverage job on Apple-Silicon runners (so MLX tests actually execute).
- CodeQL security analysis workflow; coverage gate (`make cov`), `make sast`, `make audit`,
  and `make check`; README CI/CodeQL/Python/License badges.

## [0.1.0] - 2026-06-27

### Added
- OpenAI-compatible MLX gateway (`/v1/chat/completions`, `/v1/completions`, `/v1/models`, `/health`)
  with model routing/aliasing, lazy model swapping, bearer auth, audit logging, output
  sanitization, and per-model max-token clamping.
- nginx loopback reverse proxy with long-inference timeouts.
- Operational scripts (start/stop/status/benchmark/validate) and agent wrappers.
- Production project layout: `src/` package, `tests/`, `deploy/`, `docs/`, CI, and packaging.

### Changed
- Restructured from a flat working tree into a `src/`-layout package.
- Gateway log directory and nginx paths are now relative/derived (no hardcoded user paths).
