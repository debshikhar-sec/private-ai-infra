# Private AI Gateway

<!-- If the GitHub slug differs from debsqui88/private-ai-infra, update it in the badge URLs below. -->
[![CI](https://github.com/debsqui88/private-ai-infra/actions/workflows/ci.yml/badge.svg)](https://github.com/debsqui88/private-ai-infra/actions/workflows/ci.yml)
[![CodeQL](https://github.com/debsqui88/private-ai-infra/actions/workflows/codeql.yml/badge.svg)](https://github.com/debsqui88/private-ai-infra/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

A **local-first AI governance plane** for Apple Silicon (MLX): an OpenAI-compatible gateway that
mediates access to local models with **policy-as-code identity, authorization, output guardrails,
and a structured decision audit** — behind an nginx loopback boundary.

The thesis is that **AI capability should not automatically become AI authority**. The value
isn't that a model runs locally — it's the enforceable control boundary around it: who may call
which model, under what limits, with every allow/deny decision recorded.

## Architecture

```text
client (OpenAI SDK / agent CLI)         Authorization: Bearer <api-key>
  ▼
nginx loopback proxy        127.0.0.1:8081   deploy/nginx/nginx.conf
  ▼
Flask gateway + governance  127.0.0.1:8080   src/private_ai_gateway/
  • identity + authorization (policy.py)   • rate limiting (ratelimit.py)
  • output guardrails (guardrails.py)      • decision audit (audit.py)
  • metrics + introspection (metrics.py)
  ▼
MLX inference → local model  Apple Silicon   mlx-community/*
```

Requests route by a stable **alias** so clients never hardcode model names:

| alias | model |
|-------|-------|
| `strategy` | `mlx-community/Qwen3.6-27B-OptiQ-4bit` |
| `engineering` | `mlx-community/Qwen3-Coder-30B-A3B-Instruct-8bit` |
| `offsec` | `mlx-community/Llama-3-70B-Instruct-Gradient-1048k-4bit` |

The gateway lazily swaps models on demand (clearing the MLX cache between loads), strips visible
thinking/tool-call/control markers from output, refuses to fake tool execution, and clamps
output tokens per model.

## Governance

Authorization is **policy-as-code**. A TOML policy file defines principals (API-key
identities); keys are stored as **SHA-256 hashes**, never plaintext:

```toml
# config/policy.toml  (gitignored; copy from config/policy.example.toml)
[[principals]]
name = "analyst"
key_sha256 = "…"          # printf '%s' 'the-key' | shasum -a 256
allowed_models = ["strategy", "engineering"]
max_output_tokens = 2048
requests_per_minute = 30

[ratelimit]
default_requests_per_minute = 60

[guardrails]
action = "redact"          # off | redact | block
```

- **Identity** — the bearer token is hashed and resolved to a principal.
- **Authorization** — a model outside the principal's `allowed_models` returns `403`; the
  effective token cap is the tightest of request / per-model / per-principal.
- **Autonomy ceiling** — each principal is capped on the L0–L6 autonomy ladder
  (`max_autonomy_level`); a request declaring a higher level (via `X-Autonomy-Level`) is
  denied `403 autonomy_exceeded` before any model loads. See
  [Orchestration](#orchestration-control-plane).
- **Rate limiting** — a per-principal token bucket (`requests_per_minute`, with a policy-wide
  default); over-limit requests get `429` + `Retry-After` before any model loads.
- **Output guardrails** — responses are scanned for credential-shaped content (AWS keys,
  private-key blocks, API tokens, JWTs) and `redact`ed or `block`ed by policy. Authority to
  *invoke* a model is not authority to *exfiltrate* secrets.
- **Decision audit** — every allow/deny/throttle/filter is appended to `logs/decisions.jsonl`
  (request id, principal, model, reason) for SIEM ingestion.
- **Observability** — `GET /metrics` (Prometheus text) exposes decision/denial/throttle/guardrail
  counters; `GET /v1/whoami` returns the caller's effective permissions.

With no policy file, the gateway runs single-principal using `PRIVATE_AI_AUTH_TOKEN` (an owner
identity allowed every model), so local development stays zero-config.

## Orchestration control plane

The gateway is the enforcement layer for a multi-agent control plane whose guiding rule is
that **AI capability is not AI authority** — a planner may reason about anything, but what
*executes* is decided and recorded by the governance plane. Three components, each
authenticating as its **own principal** with its own model allowlist, caps, and autonomy
ceiling:

| Component | Mandate |
|---|---|
| **Hermes** | Planning / orchestration — decompose an objective, route each sub-task. Plans; does not execute. |
| **OpenCode** | Code-execution agent — inspect/test/(approval-gated) modify code inside an isolated environment. |
| **OpenClaw** | Security / observability — offsec checks, code review, telemetry feeding the audit + metrics. |

Delegated work is classified on an **autonomy ladder** (L0 observe → L1 suggest → L2 dry-run →
L3 owner-run → L4 monitored → L5 continuous → L6 unbounded). The gateway enforces each
principal's ceiling on every request, so a component can't be handed work above its mandate even
if the plan asks for it. Autonomy enforcement, identity/authorization, rate limiting, and
egress guardrails are **live today**; the running orchestrator and the sandboxed agents are the
next phase. Full design and current-vs-planned status: **[docs/orchestration.md](docs/orchestration.md)**.

## Quickstart

```bash
python -m venv venv && source venv/bin/activate
make install                       # runtime deps (Apple Silicon / MLX)
cp .env.example .env               # set PRIVATE_AI_AUTH_TOKEN
make start                         # launch Flask + nginx
make status

curl -s http://127.0.0.1:8081/v1/models \
  -H "Authorization: Bearer $PRIVATE_AI_AUTH_TOKEN" | python3 -m json.tool

make stop
```

## Project layout

```text
src/private_ai_gateway/   # gateway (app.py) + governance (policy, ratelimit, guardrails, metrics, audit)
config/                   # policy.example.toml — governance policy-as-code
deploy/nginx/             # nginx loopback reverse-proxy config
scripts/                  # operational entrypoints (start/stop/status/benchmark)
agents/                   # owner-run operator wrappers (least-privilege, monitoring/inspection)
tests/                    # unit/ (pytest) + integration/ (stack smoke test)
docs/                     # architecture, security model, orchestration, runbook, roadmap
```

## Security

Fail-closed bearer auth (constant-time), policy-as-code identity & authorization, per-principal
rate limiting, secret-egress guardrails, output sanitization, per-principal token caps,
request-size limits, loopback-only binding, and a structured decision audit. Tool execution is
intentionally **not** trusted. See
[SECURITY.md](SECURITY.md) and [docs/security-model.md](docs/security-model.md).

## Development

```bash
make install-dev
make lint        # ruff
make test        # pytest (MLX-dependent tests auto-skip off Apple Silicon)
```

## Status & limitations

- Gateway is text-compatible, not real tool-execution-compatible (by design).
- TLS is planned, not active; the gateway is intended for loopback use.
- MLX is Apple-Silicon only.

See [docs/roadmap.md](docs/roadmap.md) for direction.

## License

[MIT](LICENSE)
