# Orchestration control plane

> **Thesis:** an AI system's *capability* to plan an action must not, by itself, be
> *authority* to perform it. This project separates the two: a planning layer may
> reason about anything, but what actually executes is decided — and recorded — by an
> enforceable governance plane.

Most agent demos show the capability side (a model that plans and calls tools) and
hand-wave the control side. The point of this project is the control side: the
boundary that decides which agent, acting as which principal, may take which action,
at which autonomy level, against which model.

## Components

The control plane is three cooperating components. They are **components defined by
behaviour**, not roles or job titles — each is a concrete process with a specific
mandate and a specific autonomy ceiling.

| Component | Mandate | Acts through |
|---|---|---|
| **Hermes** | Planning / orchestration. Decomposes an objective into a structured plan, decides which component should handle each sub-task, and routes the delegation. Hermes plans; it does not execute. | The gateway, as an identified principal |
| **OpenCode** | Code-execution agent. Inspects, tests, and (under approval) modifies code. Intended to run inside an isolated environment (network-restricted, scoped filesystem, resource-limited). | A sandbox, invoked as a constrained principal |
| **OpenClaw** | Security / observability agent. Offensive-security checks, code review, telemetry, and security-signal collection that feeds the decision audit and metrics. | Read/monitor surfaces and the gateway |

Each component authenticates to the gateway as its **own principal** (its own API
key, its own `allowed_models`, token cap, rate limit, and autonomy ceiling in
`config/policy.toml`). There is no shared "god" identity in normal operation — the
owner token is a break-glass admin (L6), not the orchestrator's day-to-day identity.

## The autonomy ladder (L0–L6)

Delegated work is classified by how much autonomy it requires. The gateway enforces a
ceiling per principal, so a component cannot be delegated work above its mandate even
if the plan asks for it.

| Level | Name | Meaning |
|---|---|---|
| L0 | observe | read / observe only |
| L1 | suggest | propose text or plans; take no action |
| L2 | dry_run | dry-run / no-op execution (`bash -n`, schema validation) |
| L3 | owner_run | owner-initiated local execution |
| L4 | monitored_auto | finite, monitored automation |
| L5 | continuous_auto | continuous automation |
| L6 | unbounded | unbounded autonomy (break-glass / owner only) |

A request declares its intended level via the `X-Autonomy-Level` header or an
`autonomy_level` body field (`"L3"`, `"3"`, or `3` are accepted). The gateway compares
it to the principal's ceiling (`max_autonomy_level`, else the `[autonomy]`
`default_max_level`). If the request exceeds the ceiling it is denied **before any
model loads** with `403 autonomy_exceeded`, and the denial is written to the decision
audit. When no ceiling is configured anywhere, gating is off (opt-in).

This is the keystone: it converts the original prompt-level autonomy governance
(a boot prompt that *asked* the model to behave) into a control that is *enforced in
code*.

## Delegation flow

```text
objective
  │
  ▼
Hermes (plan)  ── decomposes into sub-tasks, each tagged with a required autonomy level
  │
  ▼  delegate sub-task as a sub-task principal, X-Autonomy-Level: Ln
gateway / governance plane
  ├─ identity        who is this principal?            (policy.py)
  ├─ authorization   may it use the requested model?   (403 model_not_allowed)
  ├─ autonomy        is Ln ≤ its ceiling?              (403 autonomy_exceeded)
  ├─ rate limit      within its budget?                (429 + Retry-After)
  ├─ inference       run the model
  ├─ guardrails      scan response for secret egress   (redact / block)
  └─ decision audit  append allow/deny/filter to logs/decisions.jsonl
  │
  ▼
OpenCode (sandboxed exec)  /  OpenClaw (security + telemetry)
```

Every delegation is an *authorization decision*, and every decision is recorded. The
audit trail (`logs/decisions.jsonl`) is therefore a complete record of which component
was permitted to do what — the artifact a reviewer or SIEM actually wants.

## Status — what is enforced today vs. planned

Honesty about the boundary is part of the design.

**Enforced now (in this repo):**

- Per-principal identity, model authorization, token caps, and rate limits.
- **Autonomy-ceiling enforcement** (L0–L6) on inference requests.
- Secret-egress guardrails on responses.
- Structured decision audit + Prometheus metrics for every decision.

**Planned (Phase 2, behind the same boundary):**

- **Hermes** as a running planner that emits the structured plan and issues delegations
  through the gateway as distinct principals.
- **OpenCode** graduated from the current read-only, project-root-jailed wrapper
  (`agents/wrappers/opencode.sh`) into a real sandbox: no network, scoped filesystem,
  resource limits, and an approval-gated apply path.
- **OpenClaw** offensive-security / code-review / telemetry tasks feeding `/metrics`
  and the decision audit.
- Approval gates (`APPROVAL REQUIRED`) for any L4+ action, surfaced to the owner.

See [roadmap.md](roadmap.md) for sequencing. The operator wrappers in
[`agents/`](../agents) are the present-day, deliberately-minimal stand-ins for the
OpenCode and OpenClaw surfaces.
