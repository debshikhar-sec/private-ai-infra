# Private AI Gateway

<!-- If the GitHub slug differs from debsqui88/private-ai-infra, update it in the badge URLs below. -->
[![Live demo](https://img.shields.io/website?url=https%3A%2F%2Fdebsqui88.github.io%2Fprivate-ai-infra%2F&up_message=online&up_color=8b5cf6&down_message=offline&label=live%20demo)](https://debsqui88.github.io/private-ai-infra/)
[![CI](https://github.com/debsqui88/private-ai-infra/actions/workflows/ci.yml/badge.svg)](https://github.com/debsqui88/private-ai-infra/actions/workflows/ci.yml)
[![CodeQL](https://github.com/debsqui88/private-ai-infra/actions/workflows/codeql.yml/badge.svg)](https://github.com/debsqui88/private-ai-infra/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

> ## AI capability is not AI authority.
>
> A **local-first AI governance plane** for Apple Silicon (MLX): an OpenAI-compatible
> gateway that mediates every call to a local model — **policy-as-code identity, model
> authorization, an enforced L0–L6 autonomy ceiling, egress guardrails, and a structured
> decision audit**, behind an nginx loopback boundary.
>
> A leaked low-privilege key can't reach a model it was never granted; an agent capped at
> *suggest* can't be handed work that *executes*. Enforced in code, **before any model
> loads** — not asserted in a README — with every allow/deny recorded and independently
> re-verified.

<!-- DEMO: regenerate with `vhs demo/enforce.tape` -->
<p align="center">
  <img src="docs/assets/enforce.gif" alt="Live demo: a principal capped at autonomy L1 is denied 403 when it declares L6, and denied 403 for a model outside its allowlist — enforced before any model loads." width="860">
</p>

<p align="center"><sub>A principal capped at <b>L1 (suggest)</b> is refused <code>403</code> the instant it asks for more — autonomy it doesn't have, or a model it was never granted. Enforced <i>before</i> the model even loads. <a href="#see-it-enforce-no-gif">Text version ↓</a></sub></p>

---

## How it enforces

Every request crosses the loopback boundary and runs a fixed gauntlet of checks. Each
gate fails **closed** with a specific status, and every outcome — allow or deny — is
written to the decision audit and the metrics counters.

```mermaid
flowchart TB
    C["Client<br/>OpenAI SDK · agent · curl"]

    subgraph BOUND["🔒 nginx loopback boundary — binds 127.0.0.1 only"]
      NG["nginx&nbsp;:8081"] --> FL["Flask gateway&nbsp;:8080"]
    end

    C -->|"Authorization: Bearer &lt;key&gt;"| NG

    subgraph GOV["Governance plane — policy-as-code"]
      direction TB
      A1{"Authenticated?<br/><sub>constant-time</sub>"}
      A2["Identity<br/><sub>token → principal (SHA-256)</sub>"]
      A3{"Model in<br/>allowlist?"}
      A4{"Autonomy ≤<br/>principal ceiling?"}
      A5{"Within rate<br/>budget?"}
      INF["MLX inference<br/><sub>lazy model load</sub>"]
      G{"Secret-shaped<br/>output?"}
      OUT["Response"]

      A1 -->|no| D401["401 — fail closed"]
      A1 -->|yes| A2 --> A3
      A3 -->|no| D403m["403 model_not_allowed"]
      A3 -->|yes| A4
      A4 -->|no| D403a["403 autonomy_exceeded"]
      A4 -->|yes| A5
      A5 -->|no| D429["429 + Retry-After"]
      A5 -->|yes| INF --> G
      G -->|yes| RB["redact / block"]
      G -->|no| OUT
    end

    FL --> A1
    D401 --> AUD
    D403m --> AUD
    D403a --> AUD
    D429 --> AUD
    RB --> AUD
    OUT --> AUD
    AUD[("📋 Decision audit<br/>logs/decisions.jsonl · /metrics")]

    classDef deny fill:#b3261e,stroke:#7f1d1d,color:#fff;
    classDef ok fill:#1a7f37,stroke:#0f5323,color:#fff;
    classDef store fill:#9a6700,stroke:#633c01,color:#fff;
    class D401,D403m,D403a,D429,RB deny;
    class OUT,INF ok;
    class AUD store;
```

Note the ordering: **authz, autonomy, and rate-limit denials all happen *before* the
model loads** — an unauthorized or runaway request is rejected cheaply, never paying for
inference it wasn't allowed to run.

## Proven, not asserted

The differentiator isn't that these controls exist — it's that they are **attacked** by
an adversarial eval suite that fails CI on regression, and **independently re-verified**
by a read-only assurance agent (OpenClaw) that reconciles the audit, metrics, and policy.
Each row is a control, the attack against it, and where that attack is proven to fail:

| Control | Attack it repels | Enforced in | Proven by |
|---|---|---|---|
| Fail-closed auth | unauthenticated / wrong token | `app.py` (constant-time) | `evals` AUTHN-001/002 · `test_auth` |
| Identity + model authz | low-priv key reaches an ungranted model | `policy.py` → `403` | `evals` AUTHZ-001 · `test_policy` |
| **Autonomy ceiling** | agent declares more autonomy than its mandate | `autonomy.py` → `403` | `evals` AUTONOMY-001/002 · `test_autonomy` |
| Autonomy **under-declare** | low level in header, high in body | `declared_level` (most-privileged-wins) | `evals` **AUTONOMY-004** — the real bug it caught |
| Rate limiting | one key saturates the gateway | `ratelimit.py` → `429` | `evals` RATELIMIT-001 · `test_ratelimit` |
| Secret egress | model surfaces an AWS key / JWT / PEM | `guardrails.py` redact/block | `evals` EGRESS-001…004 · `test_guardrails` |
| Apply integrity | an apply runs ungated or escapes its sandbox | `opencode_sandbox/apply.py` | OpenClaw `AC-APPLY-INTEGRITY` · `test_opencode_act` |

→ Run the attacks yourself: `make evals` · Re-verify the controls: `make` + see [docs/threat-model.md](docs/threat-model.md).

## Orchestration control plane

The gateway is the enforcement substrate for a three-component agent control plane. Each
component authenticates as its **own principal** with its own model allowlist and autonomy
ceiling — there is no shared "god" identity. They form a closed **plan → act → verify →
record** loop where a model may *reason* about anything, but what *executes* is decided
and recorded by the governance plane.

```mermaid
flowchart LR
    H["🧭 <b>Hermes</b><br/>stateful planner<br/><sub>autonomy L1 · plans, never executes</sub>"]
    ACT["🛠️ <b>OpenCode</b><br/>isolated reviewer + apply<br/><sub>approval-gated · confined · verified</sub>"]
    OC["🔍 <b>OpenClaw</b><br/>assurance verifier<br/><sub>autonomy L0 · read-only</sub>"]
    EV["⚔️ Adversarial evals<br/><sub>OWASP-LLM tagged</sub>"]
    GW[("Gateway evidence<br/><sub>audit · metrics · isolation</sub>")]
    MEM[("🧠 Hermes memory")]

    H -->|"plan (suggest)"| ACT
    ACT -->|"apply report"| OC
    EV -->|"eval report"| OC
    GW --> OC
    OC -->|"verdict: PASS / FAIL"| MEM
    MEM -.->|"a failing control gates the next plan"| H

    classDef l0 fill:#0969da,stroke:#0a3069,color:#fff;
    classDef l1 fill:#8250df,stroke:#3e1f79,color:#fff;
    classDef act fill:#1a7f37,stroke:#0f5323,color:#fff;
    class OC l0;
    class H l1;
    class ACT act;
```

Full design and current-vs-planned status: **[docs/orchestration.md](docs/orchestration.md)**.

## See it enforce (no GIF)

With a policy active, the `hermes` token resolves to a principal capped at **L1 (suggest),
models `["strategy"]`**. Every attempt to exceed that mandate is refused on the wire,
before any model loads:

```console
$ curl -s -XPOST :8081/v1/chat/completions -H "Authorization: Bearer $HERMES" \
       -H "X-Autonomy-Level: 6" -d '{"model":"strategy","messages":[...]}'
{"error":{"code":"autonomy_exceeded","message":"Principal 'hermes' is capped at
 autonomy L1 (suggest); request declared L6 (unbounded)","type":"permission_error"}}
HTTP 403

$ curl ... -d '{"model":"offsec","messages":[...]}'          # not in its allowlist
{"error":{"code":"model_not_allowed","message":"Principal 'hermes' is not permitted
 to use model 'offsec'","type":"permission_error"}}
HTTP 403

$ curl ... -H "X-Autonomy-Level: 1" -d '{"autonomy_level":6,...}'   # under-declare
{"error":{"code":"autonomy_exceeded", ...}}    # most-privileged-wins: still 403
HTTP 403
```

The denials land in `logs/decisions.jsonl` and `/metrics`; OpenClaw then reconciles them
(`AC-AUTONOMY-CEILING` / `AC-AUTHZ-MODEL` → PASS). That's the whole thesis, observable on
`127.0.0.1`. Reproduce it: [docs/runbook.md](docs/runbook.md#live-enforcement-demo).

## Quickstart

```bash
python -m venv venv && source venv/bin/activate
make install                       # runtime deps (Apple Silicon / MLX)
cp .env.example .env               # set PRIVATE_AI_AUTH_TOKEN
make start && make status          # launch Flask + nginx (loopback)

curl -s http://127.0.0.1:8081/v1/models \
  -H "Authorization: Bearer $PRIVATE_AI_AUTH_TOKEN" | python3 -m json.tool

make stop
```

With no policy file the gateway runs single-principal (owner, all models) so local dev is
zero-config. Drop in `config/policy.toml` to enable the per-principal ceilings shown above.

## Documentation

| Doc | What it covers |
|---|---|
| [Architecture](docs/architecture.md) | request path, planes, model routing |
| [Security model](docs/security-model.md) | trust boundaries, OWASP-LLM/ATLAS framing, honest limits |
| [**Threat model**](docs/threat-model.md) | STRIDE per trust boundary → control → the eval that proves it |
| [Orchestration](docs/orchestration.md) | the control plane, autonomy ladder, closed loop |
| [Runbook](docs/runbook.md) | operating the stack + the live enforcement demo |
| [Roadmap](docs/roadmap.md) | what's hardened, what's next |

## Project layout

```text
src/private_ai_gateway/   # gateway (app.py) + governance (policy, ratelimit, guardrails, metrics, audit, autonomy)
config/                   # policy.example.toml — governance policy-as-code
deploy/nginx/             # nginx loopback reverse-proxy config
agents/                   # control plane: hermes/ (planner), opencode_sandbox/ (reviewer + gated apply), openclaw/ (assurance)
evals/                    # adversarial security evals — attack the controls, OWASP-LLM tagged
tests/                    # unit/ (pytest) + integration/ (stack smoke test)
docs/                     # architecture, security & threat model, orchestration, runbook, roadmap
```

## Status & limitations (honest)

- Gateway is **text-compatible, not tool-execution-compatible** — by design; it refuses to fake tool calls.
- Autonomy/egress gating is **opt-in via policy**; with no policy file the owner token is all-models break-glass.
- Guardrails are high-precision **regex denylists** (defense-in-depth, not exhaustive recall).
- API keys are **static** (no rotation/expiry yet); rate limiting is **in-process, per-node**.
- **No TLS** — loopback use only. **MLX is Apple-Silicon only.**

## License

[MIT](LICENSE)
