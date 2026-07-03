# Starter kit — `private-ai-gateway demo`

One command demonstrates the whole thesis on any machine, with no model weights and no
network: **AI capability is not AI authority.**

![Console walkthrough](assets/console-walkthrough.gif)

*The full 16-step journey, with the reasoning behind each frame, is on the
[project site's product tour](https://debshikhar-sec.github.io/private-ai-infra/#tour).*

```bash
pip install .          # platform-agnostic (no MLX required)
private-ai-gateway demo
```

## What it does

1. **Loads the packaged demo policy** (`demo_policy.toml`) — a simulated
   financial-enterprise cast of agent principals, each an API-key identity with its own
   model allowlist, tool/skill grants, rate budget, and enforced autonomy ceiling:

   | Principal | Ceiling | Mandate |
   |---|---|---|
   | `research-copilot` | L2 | strategy model, research tools |
   | `kyc-screening-agent` | L3 | sanctions screening, document search |
   | `trading-assistant` | L1 | **suggest-only** — may draft, may never act |
   | `ops-automation` | L4 | granted `payments.initiate`… which floors at **L5** |
   | `auditor` | L0 | no models at all; `can_read_audit` |

2. **Swaps in the offline demo backend** — deterministic simulated completions, clearly
   labeled. The enforcement plane in front of it is the production code path.

3. **Replays 13 scripted steps of governed traffic** through the real enforcement code
   and prints the tally. The story covers every decision class the plane can produce:

   - routine allowed work (research summary, market snapshot, sanctions screen, A2A
     delegation of a granted skill);
   - `403 model_not_allowed` — a principal asks for a model outside its allowlist;
   - `403 autonomy_exceeded` — three distinct ways: a request declaring a level above
     its ceiling, a *granted* tool whose floor exceeds the caller's ceiling
     (`email.draft` at L1, `payments.initiate` at L4), proving **a grant does not
     outrank a tool's autonomy floor**;
   - `403 tool_not_allowed` / `403 skill_not_allowed` — never granted in the first place;
   - a prompt-injection that coaxes the simulated model into emitting a credential —
     **redacted by the egress guardrail on the wire**;
   - `403 audit_not_allowed` — and that denial is itself audited, before the `auditor`
     principal (holding the explicit grant) reads the full history.

4. **Serves the Governance Console** at `http://127.0.0.1:8080/console` and prints the
   demo tokens. Paste one in and explore: the overview stat cards and enforcement ratio,
   the live audit feed the script just populated, each identity's autonomy ladder, its
   granted tools with their floors, and the one-click boundary probes.

## Why the tools are simulated

The starter-kit tools (`market.snapshot`, `docs.search`, `kyc.sanctions_screen`,
`email.draft`, `payments.initiate`) are pure and deterministic — they return canned data
tagged `"simulated": true`. What is *not* simulated is the enforcement: their declared
autonomy floors are honest for the capability each represents, and every refusal above
is produced by the same code path that governs real traffic. `payments.initiate`'s
handler is a deliberate no-op: the control under demonstration is that callers below L5
are refused **before the handler ever runs**.

## Using the demo against a real model plane

The demo backend exists so the plane is demonstrable anywhere. To run the same policy
against real models, serve with the backend you have:

```bash
# any OpenAI-compatible endpoint (LLMaaS, vLLM, TGI, Ollama, LM Studio …)
private-ai-gateway serve --backend openai --upstream-base-url http://127.0.0.1:11434/v1

# or in-process MLX on Apple Silicon
pip install .[mlx] && private-ai-gateway serve --backend mlx
```

The demo traffic is also a CI smoke test: `private-ai-gateway demo --no-serve` exits
non-zero if any scripted step is not enforced exactly as the story claims.
