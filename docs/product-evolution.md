# Product evolution — from a governance lab to an authority plane

> **Thesis:** AI *capability* is not AI *authority*. A model may reason about anything;
> what it is allowed to **reach, run, and emit** is decided out-of-band of the prompt, by
> policy bound to an identity, and is independently re-verified. This document is the
> product story: where the project sits against the 2026 agent-security field, how its
> existing controls map onto the newest threat taxonomy, and how it evolves — read through
> a black-box attacker's lens, not a marketing one.

## 1. The attacker's stance

Everything here assumes the model is **already hostile**. Not "might be jailbroken
someday" — assume the prompt-injection / context-poisoning attack has *already landed* and
the model now says and decides whatever the attacker wants. That is the only honest
starting point in 2026: black-box red-team agents now solve the majority of indirect
prompt-injection challenges autonomously, with tools like AgentVigil reporting ~70% attack
success against frontier-model agents, and a handful of poisoned RAG documents can steer a
model's answer >90% of the time. Defenses that depend on the model "behaving" are not
controls; they are hopes.

So the design question is not *"can we stop the model from being tricked?"* (you can't, not
reliably) but *"when it is tricked, what can it actually do?"* The blast radius is the
product. Everything below is judged on whether it shrinks that radius.

## 2. The wedge

The market has converged on **AI gateways** — LiteLLM, Portkey, Cloudflare AI Gateway,
Kong AI Gateway, Helicone — that unify routing, caching, observability, and (increasingly)
content guardrails across many model providers. They are very good at *traffic*. They are
mostly silent on *authority*: which identity is allowed to use which model, at what
autonomy, with what blast radius when its credential leaks.

That gap is not theoretical. A 2026 survey of 900+ practitioners found **93% of AI-agent
projects still run on unscoped API keys** and **74% of agents end up with more access than
they need**. The standards bodies have noticed — OWASP shipped a dedicated *Top 10 for
Agentic Applications* in December 2025, and the identity world is racing to fit agents
into SPIFFE/SVID workload identity, OAuth 2.1 scoped delegation (RFC 8707 resource
indicators), and the composed AIMS framework. The wedge for this project is the thing the
gateways punt on: **enforcement-first, identity-bound, locally verifiable authority.**

## 3. Honest positioning

| | Cloud AI gateways (LiteLLM / Portkey / Cloudflare / Kong) | `private-ai-infra` |
|---|---|---|
| Primary job | route + observe + cache across providers | **decide and prove authority** for each call |
| Identity model | API key → project/budget | principal → model allowlist + **L0–L6 autonomy ceiling** |
| Guardrails | prompt-injection / PII scanners (often paid tier) | egress secret-redaction + autonomy/authz **before** inference |
| Trust posture | "trust the gateway" | adversarial evals + an **independent read-only verifier** reconcile audit ↔ metrics ↔ policy |
| Deployment | managed cloud / self-host | local-first, loopback-only, Apple Silicon (today) |

This is **not** a LiteLLM competitor and the docs should never pretend otherwise — it has
one provider backend, no multi-region, no UI. What it demonstrates, end to end, is the
control most of them under-build: a request that is **denied on identity grounds before a
model loads**, recorded, and re-verified. The honest framing is "a reference implementation
of agent *authority* you could bolt in front of, or into, a gateway" — not "a gateway."

## 4. Coverage map — OWASP Top 10 for Agentic Applications (2026)

How today's enforced controls already answer the newest taxonomy, and where the gaps are.
`enforced` = there is code **and** a test/eval that proves it; `partial` = real but narrow;
`roadmap` = named below, not yet built. No row claims more than the code does.

| ASI risk (2026) | What the attacker does | This project's answer | Status | Proven by |
|---|---|---|---|---|
| **ASI01** Agent Goal Hijack | injected/poisoned content redirects the agent | routing & model authz decided from the **principal**, not the prompt | enforced | `AGENTIC-001`, `AUTHZ-001` |
| **ASI02** Tool Misuse & Exploitation | agent abuses a connected tool | OpenCode apply is capability-denied, approval-gated, sandbox-confined | partial | `AC-OPENCODE-ISOLATION`, `AC-APPLY-INTEGRITY` |
| **ASI03** Identity & Privilege Abuse | agent inherits/escalates privilege | per-principal identity, no shared "god" token, **autonomy ceiling** | enforced | `AGENTIC-002`, `AUTONOMY-001/002/004` |
| **ASI04** Agentic Supply Chain | compromised dep/plugin/model | `pip-audit` + `bandit` + CodeQL in CI; pinned deps | partial | CI gates (no SBOM/signing yet) |
| **ASI05** Unexpected Code Execution | agent runs code/commands unsafely | apply confined to a copy, sha256-verified to touch only declared files | partial | `test_opencode_act`, `AC-APPLY-INTEGRITY` |
| **ASI06** Memory & Context Poisoning | poison memory / RAG to steer later behavior | egress secret-redaction (last boundary); audit integrity check | partial | `AGENTIC-003`, `EGRESS-001…004`, `AC-AUDIT-INTEGRITY` |
| **ASI07** Insecure Inter-Agent Comms | spoof/tamper between agents | each agent is its own principal over a loopback boundary | partial | `AC-AUTHZ-MODEL` (no signed messages yet) |
| **ASI08** Cascading Failures | small errors propagate across the loop | fail-closed gates; autonomy ceiling halts runaway; metrics reconcile | partial | `AC-METRICS-RECONCILE` |
| **ASI09** Human-Agent Trust Exploitation | user over-trusts agent output | nothing executes on a model's say-so; OpenClaw re-derives verdicts | enforced | `AC-*` reconcile suite |
| **ASI10** Rogue Agents | a captured agent acts while looking legitimate | independent L0 verifier reconciles audit ↔ metrics ↔ policy | partial | OpenClaw assurance run |

The pattern across every "enforced" row is identical: **authority is decided off the prompt
path.** That is the one idea the product is built to prove.

## 5. Evolution roadmap

Phased by horizon. Each item names the threat it closes, so the roadmap reads as a
shrinking blast radius, not a feature wishlist.

### Now — close the credential gap (ASI03, ASI06)
- **Key expiry & rotation.** Today's keys are static SHA-256 hashes; add per-principal
  `expires` + a rotation runbook so a leaked key dies on a clock. Directly answers the
  "93% unscoped, never-rotated key" reality.
- **Response hardening** *(shipped in this change)*: per-request correlation id
  (`X-Request-Id`) tied to the decision audit, plus strict security headers — so every
  governed response is traceable and uncacheable.
- **Indirect-injection eval expansion** *(started in this change)*: the `AGENTIC-*` group
  treats the model as captured and proves the authority boundary holds; grow it toward the
  full ASI catalogue (tool-result poisoning, memory replay, exfil via markdown/links).

### Next — identity that a standards body would recognize (ASI03, ASI07)
- **Short-lived, sender-constrained credentials.** Move principals from static bearer
  tokens toward SPIFFE/SVID-style workload identity and OAuth 2.1 scoped delegation
  (RFC 8707 resource indicators): the agent gets a token minted for *exactly the next
  action*, not a standing key that "multiple services might accept."
- **Delegation chains.** Record the *(delegating human → workflow → declared intent)*
  triple in the audit so authority proves the **reason**, not just the runtime — the AIMS
  framing of agent identity.
- **Signed inter-agent messages (mTLS / detached signatures)** so Hermes→OpenCode→OpenClaw
  hops can't be spoofed or tampered, closing ASI07 beyond "same loopback host."

### Next — make the verifier deeper (ASI06, ASI08, ASI10)
- **Tamper-evident memory.** Hash-chain Hermes memory and the decision audit (append-only,
  Merkle-style) so context poisoning and after-the-fact log edits are *detectable*, then
  add an OpenClaw control that fails on a broken chain.
- **OpenTelemetry GenAI semantic conventions.** Emit the decision audit and metrics as OTLP
  spans/metrics using the standard GenAI attributes, so this drops into a real SOC/SIEM
  instead of a bespoke JSONL file.
- **Cascading-failure brakes.** Per-principal token *budgets* and circuit breakers so a
  looping or hijacked agent trips a ceiling and stops, rather than amplifying (ASI08).

### Later — productization & scale-out
- **Sandbox depth for apply (ASI05):** seccomp/Landlock (Linux) / sandbox-exec profiles for
  the OpenCode act step, beyond filesystem confinement.
- **Supply chain (ASI04):** generate an SBOM (CycloneDX), sign releases with sigstore/cosign,
  and gate on provenance — the same SBOM/SOP discipline used in regulated AppSec programs.
- **Distributed enforcement:** move rate limits and budgets to a shared store (Redis) so the
  controls hold across nodes, not just in-process.
- **Backend & transport portability:** a model-server abstraction (vLLM / TGI / Ollama
  alongside MLX), TLS/mTLS termination, and a container/Helm deploy so it runs off Apple
  Silicon — the step from "local lab" to "deployable control plane."
- **Policy authoring UX & a conformance kit:** a small TUI/lint for `policy.toml` and a
  portable "does your gateway enforce authority?" test suite others could run.

## 6. Non-goals (so the scope stays honest)

- It is **not** a multi-provider router and won't chase provider breadth — authority is the
  product, routing is incidental.
- It does **not** claim to *prevent* prompt injection inside the model. It assumes injection
  succeeds and bounds what a captured model can do. Anyone selling "injection-proof" is
  selling hope.
- Guardrails are **high-precision regex denylists** — defense-in-depth, not exhaustive
  recall — and the docs say so.

## Sources

- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) · [risk list mirror](https://www.promptfoo.dev/docs/red-team/owasp-agentic-ai/)
- [OWASP GenAI: Top 10 for Agentic AI release](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
- [SPIFFE: securing the identity of agentic AI](https://www.hashicorp.com/en/blog/spiffe-securing-the-identity-of-agentic-ai-and-non-human-actors) · [SPIFFE meets OAuth2](https://riptides.io/blog-post/spiffe-meets-oauth2-current-landscape-for-secure-workload-identity-in-the-agentic-ai-era/)
- [Agent authentication & delegated access — OAuth scoped tokens (2026)](https://zylos.ai/research/2026-04-11-agent-authentication-delegated-access-oauth-scoped-tokens) · [CSA: AI agent IAM gap (93% unscoped keys)](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_okta_ai_agent_iam_framework_enterprise_gap_20260318-csa-styled.pdf)
- [AgentVigil: black-box red-teaming for indirect prompt injection](https://arxiv.org/abs/2505.05849) · [LLM red teaming in 2026](https://kili-technology.com/blog/llm-red-teaming-in-2026)
- AI gateway landscape: [Top 5 AI gateways 2026](https://guptadeepak.com/tools/top-5-ai-gateways-2026/) · [LiteLLM vs Portkey/Kong/Cloudflare](https://contabo.com/blog/litellm-vs-ai-gateways/)
- [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
