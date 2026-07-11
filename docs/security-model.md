# Security Model

## Thesis

A model's ability to produce text is not authority to act. This gateway exists to make
that boundary explicit: local models are reachable only over loopback, behind
authentication, and their output is treated as untrusted — in particular, the gateway
**refuses to fake tool execution**.

This is a defensive lab design, not a compliance claim.

## Scope

In scope: the Flask gateway (`src/private_ai_gateway/app.py`) and its nginx loopback
boundary (`deploy/nginx/nginx.conf`).

Out of scope: the model weights themselves, the host OS, and any client that calls the
gateway. The operator wrappers (`agents/wrappers/`) are owner-run and covered briefly
below.

## Trust boundaries

Controls are layered (defense in depth): an attacker must cross every ring, and each ring
fails closed and is logged. The diagram shows where each boundary sits relative to the
untrusted client and the model:

```mermaid
flowchart TB
    ATK(["🌐 untrusted client / network"])

    subgraph R1["① loopback — 127.0.0.1 only"]
      subgraph R2["② fail-closed auth + identity"]
        subgraph R3["③ authorization — model allowlist · autonomy ceiling · rate limit · token caps"]
          subgraph R4["④ egress guardrails — scan output for secrets"]
            MODEL["🧠 local model<br/><sub>MLX</sub>"]
          end
        end
      end
    end

    ATK -->|"bearer token"| R1
    AUD[("📋 every crossing → decision audit + /metrics<br/><sub>Authorization header never logged</sub>")]
    R2 -.-> AUD
    R3 -.-> AUD
    R4 -.-> AUD

    classDef ring fill:#0d1117,stroke:#1f6feb,color:#c9d1d9;
    classDef store fill:#9a6700,stroke:#633c01,color:#fff;
    class R1,R2,R3,R4 ring;
    class AUD store;
```

| Boundary | Control | Status |
|---|---|---|
| Network | bind to `127.0.0.1` only (Flask + nginx) | active |
| Authentication | constant-time bearer check; fail-closed (won't start without a token) | active, see limits |
| Identity | bearer token resolved to a principal via policy-as-code (API-key SHA-256 hashes) | active |
| Authorization | per-principal model allowlist; unauthorized model → 403 | active |
| Autonomy | per-principal L0–L6 ceiling; request above ceiling → 403 `autonomy_exceeded` | active (opt-in via policy) |
| A2A delegation | per-principal `allowed_skills`; ungranted skill → 403 `skill_not_allowed`; over-ceiling delegation → 403 `autonomy_exceeded` | active (opt-in via policy) |
| MCP tool access | per-principal `allowed_tools` + per-tool autonomy floor; ungranted/over-privileged tool → 403 | active (opt-in via policy) |
| Request rate | per-principal token-bucket limiter; over-limit → 429 + `Retry-After` | active |
| Secret egress | response guardrails redact/block credential-shaped output | active (opt-in via policy) |
| Model output | sanitizer strips thinking / tool / control markers | active (defense-in-depth) |
| Tool execution | not performed by the gateway; tool-call output blocked + text fallback | active |
| Input volume | request body capped via `MAX_CONTENT_LENGTH` (default 8 MiB) | active |
| Output volume | tightest of request / per-model / per-principal token cap | active |
| Observability | text audit log + structured decision audit (`decisions.jsonl`) + Prometheus `/metrics`; Authorization header never logged | active |
| Operator wrappers | project-root jail, read-only inspection, monitoring-only ops | active |

## Risks addressed (OWASP LLM / MITRE ATLAS framing)

This gateway targets a focused subset rather than claiming broad coverage:

- **LLM01 Prompt injection / LLM06 Excessive agency** — the gateway never grants the
  model execution authority; tool-call output is blocked, not forwarded. A compromised
  prompt cannot turn into an action through this path. Beyond that, the **autonomy ceiling**
  caps each principal on an L0–L6 ladder, so even an authorized agent cannot be delegated
  work above its mandate — capability is bounded by enforced authority, not by prompt text.
- **Broken access control / least privilege** — identity and authorization are
  policy-as-code: each API key maps to a principal constrained to specific model aliases
  and token caps. A leaked low-privilege key cannot reach a model it was never granted,
  and every allow/deny decision is recorded for audit.
- **LLM02 Insecure output handling** — model output is sanitized before it reaches the
  client (thinking wrappers, fake tool calls, stray control tokens removed).
- **LLM02 Sensitive information disclosure (egress)** — output guardrails scan responses
  for credential-shaped content (cloud keys, private-key blocks, API tokens, JWTs) and
  redact or block them by policy, so an authorized caller cannot exfiltrate secrets the
  model surfaced.
- **Model denial-of-service (output / volume)** — per-model output-token caps bound runaway
  generations, and a per-principal token-bucket rate limiter bounds request volume so one
  key cannot saturate the single-process gateway.
- **Unbounded autonomy** — there is no agent loop in the gateway; the operator runs
  deterministic commands.
- **Audit confidentiality (ASI03 Identity and Privilege Abuse)** — the decision audit
  reveals every principal's allow/deny history, so reading it (`GET /v1/decisions`) is its
  own policy grant: `can_read_audit`, deny by default. A denied read is itself audited and
  counted — watching the watchers is a governed action. The Governance Console (`/console`)
  is a static, data-free shell pinned by a strict CSP (`default-src 'none'`, same-origin
  `connect-src` only); it holds no credential and displays only what the pasted token is
  authorized to fetch.

## MITRE ATLAS technique coverage

Where OWASP frames the *risk*, [MITRE ATLAS](https://atlas.mitre.org/) (adversarial ML
ATT&CK, v5.4.0) frames the *adversary technique* — and the project's stance is the same
either way: assume the technique lands on the model, and contain its effect at the
identity boundary. Only techniques that are **actually reachable on this architecture** are
listed; the out-of-scope set below is the more important half of the analysis.

| ATLAS technique | Tactic | What this project does about it | Status | Proven by |
|---|---|---|---|---|
| **AML.T0051.000** LLM Prompt Injection: Direct | Initial Access | a hijacked model still can't exceed its model allowlist or autonomy ceiling; tool exec is refused | bounds | `AGENTIC-002` · sanitizer |
| **AML.T0051.001** LLM Prompt Injection: Indirect | Initial Access | a poisoned tool/RAG result can't switch the model or raise autonomy — authority is off the prompt path | bounds | `AGENTIC-001` |
| **AML.T0054** LLM Jailbreak | Defense Evasion | jailbreak changes what the model *says*, never what its principal is *authorized* to reach | bounds | `AUTHZ-001` · `AUTONOMY-*` |
| **AML.T0057** LLM Data Leakage | Exfiltration | egress guardrail redacts credential-shaped output before it leaves the gateway | partial | `EGRESS-001…004` · `AGENTIC-003` |
| **AML.T0024** Exfiltration via AI Inference API | Exfiltration | fail-closed auth + per-principal rate limits bound API-abuse extraction; egress scan on the way out | partial | `AUTHN-*` · `RATELIMIT-001` |
| **AML.T0086** Exfiltration via AI Agent Tool Invocation | Exfiltration | the gateway performs no tool execution; the OpenCode apply path is approval-gated and sandbox-confined | partial | `AC-APPLY-INTEGRITY` |
| **AML.T0110** AI Agent Tool Poisoning | Persistence | OpenCode reviews a *copy*, sha256-verified to touch only declared files; no third-party tool marketplace | partial | `AC-OPENCODE-ISOLATION` |
| **AML.T0043** Craft Adversarial Data | AI Attack Staging | the adversarial eval suite *crafts these on purpose* and fails CI if a control regresses | exercised | `evals/` |

The eval cases carry the ATLAS technique ID in their report output (`atlas` field), so the
OWASP ↔ ATLAS mapping is executable, not just narrated.

### Out of scope — and why (critical analysis)

A framework is only useful if you say honestly where it *doesn't* apply. These ATLAS
techniques are **not pertinent** to this project as built, and claiming them would be theatre:

- **AML.T0020 Poison Training Data · backdoor/poison a trained model** — the gateway serves a
  **pre-trained** local model and never trains or fine-tunes, so there is no training pipeline
  to poison. *(The one related surface — Hermes agent memory / future RAG — is addressed
  separately by the tamper-evident-memory item on the roadmap, not here.)*
- **Model extraction / stealing (reconstruct weights via mass queries)** — single-user,
  loopback-only, with the model file already local; there is no remote model-theft threat.
  Rate limiting raises query cost incidentally, but defending model IP is not a design goal.
- **Evade AI Model / adversarial examples** — there is no classifier or CV/decision model to
  evade; this is a text inference gateway, so perturbation attacks on a decision boundary
  don't apply.
- **ML supply-chain compromise (poisoned public model artifacts)** — *partially* covered:
  `pip-audit` / `bandit` / CodeQL gate the dependency supply chain in CI, but model-artifact
  provenance (sigstore/cosign signing) is roadmapped, not done — so it is listed as a gap,
  not a win.

The common thread: this is an **authority/containment** plane, not a model-integrity or
model-IP product, and the ATLAS mapping is scoped to match.

## Evidence integrity (in progress)

The controls above decide *authority*; a parallel, in-progress effort hardens the
*evidence* of what was authorized and what then happened — because OpenClaw historically
reaches its verdict by reading artifacts authored by the very components it verifies
(the decision audit, the executor's apply report). Merged so far:

- **Owner-gated execute authority loop (D2).** Execute requires a durable, **single-use**,
  **owner-approved** decision bound to the plan's **canonical hash** (`run_id` +
  `approval_id`); the gateway recomputes the hash and consumes the approval **before** any
  mutation. An inline request-body approver grants nothing — authority is a separate input
  from capability.
- **Verifier-owned evidence sink core.** An append-only, per-emitter **HMAC-signed**,
  **hash-chained** record store (`agents/openclaw/sink.py`): append validates schema,
  target sink, emitter signature, payload binding, and replay before chaining; `verify_chain`
  re-derives the whole log from scratch, so tampering, reordering, or replay is detectable.
- **OpenCode signs its `apply_result`.** After a confined apply, the executor emits a signed
  record into the sink, bound to the run, instead of relying only on a self-attested
  `apply_report.json` at a path it chose.
- **OpenClaw consumes and validates the sink.** OpenClaw can now validate signed OpenCode
  `apply_result` evidence from an injected `EvidenceSink` when signed evidence is required:
  it verifies the chain + signatures, finds the matching signed record, and derives the apply
  verdict from it. Unsigned `apply_report.json` alone is insufficient when signed evidence is
  required (`agents/openclaw/evidence.py`, `checks.py`, `worker.py`).

**Honest scope of this claim:**

- The sink is **tamper-evident, not non-repudiation.** The MVP uses **symmetric HMAC**, so a
  holder of an emitter's key could forge that emitter's record. It defends against an external
  editor and honest-but-broken components — not against a party who holds the key. Asymmetric
  keys / KMS / key separation (which would give non-repudiation) are **future**, not built.
- **OpenClaw's consume/validation is component-level, not end-to-end.** It is unit-proven
  against an injected sink; the end-to-end gateway-issued `run_id` / `approval_id` wiring is
  **future**, so this proves component-level consume/verification, not full end-to-end runtime
  enforcement.
- **No gateway authorization emit, no fail-closed runtime enforcement on evidence yet**, no
  `evidence_refs`, no trust ledger, no earned autonomy. Autonomy remains fixed-ceiling by
  policy.
- **Still no training/fine-tuning pipeline** (consistent with the ATLAS scoping above): the
  local model is pre-trained and served, and Hermes captures no training traces today.

Full design and sequencing: [evidence-sink-design.md](evidence-sink-design.md),
[roadmap.md](roadmap.md).

## Limitations and non-goals (read this)

Honesty about what is *not* yet hardened is part of the design:

- **API keys are static** — identities come from a policy file of API-key hashes, but
  there is no automatic key rotation or expiry yet, and the owner (`PRIVATE_AI_AUTH_TOKEN`)
  token is an all-models break-glass identity. Treat this as a loopback governance gate,
  not a public IdP-backed auth system.
- **The output sanitizer and egress guardrails are regex denylists.** They are
  defense-in-depth for *known* marker and credential shapes, not a guarantee against novel
  or obfuscated ones. The guardrail patterns are high-precision (tuned to avoid mangling
  ordinary prose), which means they favor low false positives over exhaustive recall — do
  not rely on either as a sole control.
- **Rate limiting is in-process and per-node.** The token-bucket state lives in the single
  gateway process, which is the correct scope for a loopback single-node service but is not
  a distributed quota.
- **No TLS.** The gateway is intended for loopback use only; do not expose it.
- **Single-user by construction** (one global model reference, single-threaded) — this
  is not a multi-tenant service.

These are tracked as hardening work in [roadmap.md](roadmap.md).

## Operator wrappers

`agents/wrappers/opencode.sh` and `openclaw.sh` are owner-run helpers, intentionally
least-privilege: a realpath-based project-root jail, read-only inspection and syntax
tests only, no process control or service restarts, and patch application is a no-op
behind an explicit `--confirm`. They are not wired into the gateway as autonomous tools.
