# Governed delegation & the defensive suite (v0.16.0)

Four capabilities added in 0.16.0, all built to the same rule as the rest of the plane:
**enforced in code and attacked in tests, not asserted in prose.** Each is honestly
scoped — where something is heuristic, curated, or measure-only, this document says so.

---

## 1. Governed agent-to-agent delegation

A2A *agent cards* (`a2a.py`) let agents discover each other. This is the layer that
governs what happens next — one agent handing work to another — because delegation is
exactly where capability quietly becomes authority.

### The two-axis rule

| Axis | Grant | Meaning |
|---|---|---|
| **Skill possession** | `allowed_skills` | the right to *hold or route* a task type |
| **Autonomy ceiling** | `max_autonomy_level` | the right to *execute* at a level |

A delegator may only route a skill **it holds** (the confused-deputy guard); a delegatee
may only be handed a skill **it holds**; and the requested level must fit inside the
**delegatee's own** policy ceiling. Consequently a low-autonomy planner (L1) can route an
L3 task to an executor that policy grants L3 — the executor's authority comes from policy,
not from the planner — but **no request can amplify authority**.

### Chain custody (`delegation.py`)

- **Chains only narrow.** A sub-task cannot carry more authority than its parent grant
  (`delegation_widening` refused).
- **Depth is bounded.** `[delegation] max_depth` in policy (`delegation_too_deep`).
- **Only the holder sub-delegates.** A task can be split only by its current delegatee
  (`not_task_holder`).
- **Only the delegatee reports**, exactly once (`already_reported`).

Every decision is written to the same decision audit as inference, with a stable code.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/a2a/agents` | policy-derived directory: every principal's card + `max_delegation_depth` |
| `POST` | `/a2a/tasks` | delegate to a named peer (`delegatee`, `autonomy_level`, `parent_task`) |
| `GET` | `/a2a/tasks` | this principal's inbox (`role=delegator` for outbox; `all=true` needs `can_read_audit`) |
| `GET` | `/a2a/tasks/<id>` | one delegation + its full custody chain (participants or auditors only) |
| `POST` | `/a2a/tasks/<id>/result` | the delegatee reports `completed`/`failed` |

### The autonomous loop

`agents/interop` is the shared client every agent uses; discovery prefers the
**least-privileged capable peer**. `python -m hermes.orchestrate` (or `make orchestrate`)
runs the full loop offline through the real enforcement plane:

1. **Understand** — Hermes reads the agent directory (enforced facts, not self-claims).
2. **Plan** — a governed L1 model call under Hermes' own principal.
3. **Delegate** — `code.apply` routed to the lowest-ceiling peer that advertises it.
4. **Execute & sub-delegate** — OpenCode applies in a confined sandbox (still
   approval-gated) and sub-delegates `assurance.verify` inside its grant.
5. **Verify** — OpenClaw verifies from gateway evidence, reports PASS/FAIL up the chain.
6. **Probe** — the same wire is abused on purpose (amplification, routing an unheld
   skill, over-deep chains, forged results) and every abuse is refused with its exact
   code.

Proven by `tests/unit/test_delegation.py` (ledger semantics + wire behaviour) and
`tests/unit/test_orchestrate.py` (the full driver, all-green assertion).

---

## 2. Ingress AI-firewall (`ingress.py`)

The inbound mirror of the egress guardrail: prompt-injection / jailbreak / PII detection
on the way **in**, scoped to **OWASP LLM01:2025 Prompt Injection**.

**Honest scope:** it is *heuristic, not a model* — transparent rules with stable ids, so
a decision is explainable and auditable. A detector you cannot explain is one a security
reviewer cannot trust.

### What makes it more than a blocklist: the normalization pass

Real payloads hide trigger words with Unicode. The scanner folds the text **before**
matching — NFKC, strip zero-width/invisible characters, drop Unicode *tag* characters
(U+E0000–U+E007F), map a curated subset of the [Unicode confusables](https://www.unicode.org/reports/tr39/)
back to ASCII, remove combining marks — and matches on the normalized form. So
`іgnоre prev​ious instructions` (Cyrillic i/o + a zero-width space) is caught, and the
evasion attempt itself **escalates severity**.

Rules cover instruction override, role/jailbreak (incl. named personas like DAN/developer
mode), system-prompt exfiltration, and delimiter injection. PII rules (email/SSN/card/IBAN)
match raw text with a **Luhn check** for card precision and mask matches in findings.

### Policy & enforcement

`[ingress]` table: `action` (`off` | `flag` | `block`) and `block_threshold`. `flag`
audits and continues; `block` refuses at/above the threshold with `403
prompt_injection_blocked`, **before inference**. Metric `gateway_ingress_events_total` by
category. Off by default. Proven by `test_ingress.py` and evals `INGRESS-001…003`
(including the Unicode-evasion case).

> Reference: OWASP LLM01:2025; character-level evasion taxonomy arXiv:2504.11168.

---

## 3. AI-stack dependency CVE intelligence (`vulnintel.py`)

Governing the agent while the runtime under it is trivially exploitable is theatre. Much
of the 2024–2025 real-world damage landed in the AI supply chain, so this scanner
(Snyk/SonarQube-inspired) targets it.

- **PEP 440-aware** version-range matching, **CVSS → severity** tiers, and a configurable
  **quality gate** (fail at/above a threshold — the CI hook).
- **Curated snapshot** of four real, source-cited advisories (ranges pulled from OSV.dev):

  | CVE | Package | Class | CVSS |
  |---|---|---|---|
  | CVE-2023-48022 | ray | unauth RCE via Dashboard job API (ShadowRay) | 9.8 |
  | CVE-2024-34359 | llama-cpp-python | Jinja2 SSTI RCE at model load | 9.7 |
  | CVE-2024-3573 | mlflow | path traversal / LFI | 7.5 |
  | CVE-2025-62164 | vllm | `torch.load` deserialization (DoS/RCE) | 9.1 |

- **Live OSV.dev** `/v1/querybatch` client for current breadth (opt-in, `--live`).

CLI: `private-ai-gateway scan --manifest demo` (packaged deliberately-vulnerable
`demo_sbom.json`) / `--manifest <file>` / live env; `--gate`, `--live`, `--format`.
Exit 1 on gate failure. Proven by `test_vulnintel.py`.

> The snapshot is a high-signal seed, not a full DB; live OSV provides breadth.

---

## 4. Deterministic context optimizer (`contextopt.py`)

Every token sent costs money and latency, and long agent conversations accumulate
redundant tokens. This implements the **deterministic, model-free subset** of the
LLMLingua idea (Microsoft, EMNLP 2023, arXiv:2310.05736 / LongLLMLingua arXiv:2310.06839).

**Honest scope:** this is *not* the neural LLMLingua compressor (which needs a small LM to
score token perplexity) and *not* weight quantization. It is structural compression with
exact before/after token accounting, so the savings are real and reproducible:

- **Whitespace normalization** (lossless)
- **Cross-message dedup** of repeated context blocks — the common RAG anti-pattern
  (near-lossless: exact repeats only)
- **Budget windowing** — keep system + most-recent turns within a token budget (lossy,
  opt-in, reported)

**Default posture is measure, don't mutate.** The gateway always measures achievable
savings (metric `gateway_context_tokens_saved_total`) and only rewrites prompts when a
principal's `[context]` policy opts in — silently rewriting a caller's prompt is itself a
trust boundary. `private-ai-gateway optimize` shows ~37% reduction on a representative RAG
turn. Proven by `test_contextopt.py` (incl. both gateway postures).
