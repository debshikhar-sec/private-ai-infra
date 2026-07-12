# Market positioning — where this plane sits, honestly

*Last validated: 2026-07-03. Every market claim below is sourced; every gap is stated.
This is a positioning analysis, not a traction report — the project is pre-adoption and
says so.*

## The one-sentence wedge

Security vendors sell **detection around models** (firewalls, red-teaming, posture
scanning). Identity vendors sell **credentials for non-human identities**. This project
occupies the seam between them: a local-first gateway where an agent's *authority* —
autonomy ceiling, tool floors, delegable skills, narrowing-only sub-delegation — is a
policy object enforced on the wire, request by request, before inference. Capability is
not authority.

## Why the timing argument is real

The buyer-side consolidation of AI security in 2024–2026 is documented, not projected:

- **Palo Alto Networks acquired Protect AI** (closed July 2025, reported north of
  $500M) to anchor its Prisma AIRS AI-security platform.
- **Check Point acquired Lakera** (announced 2025) for pre-deployment assessment plus
  runtime guardrails; **CrowdStrike acquired Pangea** the same week.
- **Cisco acquired Robust Intelligence** (2024) for AI-model validation and firewalling.
- On the identity side, **Oasis Security raised a $120M Series B** for non-human
  identity and agentic access governance, and **GitGuardian raised $50M** (Feb 2026) to
  expand from secrets into NHI and AI-agent security. Around RSAC 2026, roughly **$392M
  of new agentic-AI-security funding landed in two weeks**.
- **Y Combinator's Summer 2026 Request for Startups** leads with agent infrastructure:
  "the next trillion users … will be AI agents," asking for machine-readable
  infrastructure (APIs, MCP, CLIs) that agents can use **without a human in the loop**
  — which is exactly the setting where enforced authority bounds stop being optional.

Every acquirer above bought *detection* or *identity*. None of the acquired products
enforces a per-request **autonomy ceiling** or **attenuation-only delegation chains**.
That is the open seam.

## Competitive map (as of mid-2026)

| Category | Representative players | What they enforce | What they don't |
|---|---|---|---|
| AI firewalls / guardrails | Lakera (Check Point), Prompt Security, Protect AI (PANW), NeMo Guardrails, LLM Guard | Content: injection, PII, toxicity | *Authority*: what an agent may do, at what autonomy, delegated to whom |
| AI gateways / routers | LiteLLM, Portkey, Kong AI Gateway, Cloudflare AI Gateway | Keys, quotas, routing, cost | Autonomy levels, tool floors, delegation custody |
| NHI / agent identity | Oasis, Astrix, GitGuardian | Credential lifecycle, discovery, secrets | Runtime task-level authorization on the inference path |
| Agent-security posture | Zenity, HiddenLayer | Configuration/posture of agent platforms | An enforcement point on the wire |

This plane's controls that none of the above ship together: L0–L6 autonomy ceilings
enforced pre-inference, per-tool minimum-autonomy floors that outrank grants, a
delegation ledger where chains can only narrow, policy-derived A2A agent cards, and an
audit trail in which every deny carries a stable machine-readable code.

## What the moat is — and is not

**Is:** the policy model itself (two-axis skill-vs-autonomy rule, attenuation-only
chains), proven by a large automated test suite (681 tests), an adversarial eval suite,
and a reproducible three-agent orchestration demo; a governed execute authority loop
(owner-gated, single-use, canonical-hash-bound approvals) and a verifier-owned,
tamper-evident evidence sink core now build on top; local-first architecture that
regulated buyers (the design persona is a bank) can run with zero data egress.

**Is not (yet):** network effects, proprietary data, or switching costs. A funded
competitor could rebuild the mechanism in a quarter. The durable version of this moat
is standardization (the delegation semantics becoming a protocol others implement) and
audit history (the compliance record accumulating inside a customer). Neither exists
today.

## Honest maturity statement

What exists: a working, tested, documented enforcement plane (past v0.18.0), a governed
execute authority loop, a verifier-owned **tamper-evident** evidence sink core with
signed OpenCode `apply_result` emission, OpenClaw consuming and validating that signed
evidence from an injected sink (component-level verification — unit-proven, so unsigned
`apply_result.json` alone is insufficient when signed evidence is required), the gateway
emitting a signed `execute_validated` authorization record when execution authority is
granted (component-level gateway authorization evidence emit — after approval validation
and `mark_used`, before `session.execute`, with a backward-compatible no-sink default and a
`REQUIRE_AUTHORIZATION_EVIDENCE` strict mode that denies before mutation), the gateway
emitting a signed `approval_decided` decision record when an owner approves or rejects
(component-level decision evidence emit — after the decision is stored and before the success
response, payload exactly `{decision, approver, canonical_plan_hash}`, with the same
backward-compatible no-sink default and `REQUIRE_AUTHORIZATION_EVIDENCE` strict mode that
invalidates the run and denies HTTP 503 `authorization_evidence_unavailable`), stable evidence
identity (`evidence_id` + chain-independent `evidence_digest` + typed `EvidenceRef`,
`SCHEMA_VERSION` 2) and a **signed evidence linkage graph**
(`approval_decided ← execute_validated ← apply_result`, carried by payload-embedded
`approval_ref`/`execute_ref` and verified end-to-end by OpenClaw), a Governance
Console (incl. a conversational `/chat`), an offline demo, CI with security gates, and
this analysis. What is **future, not built**: end-to-end gateway-issued `run_id` /
`approval_id` wiring, **durable evidence/approval storage**, reconciliation, fail-closed
runtime evidence enforcement across process crashes, a trust
ledger, earned autonomy, and any Hermes local training/offload — so this proves
component-level consume/verification, gateway authorization evidence emit, and a signed
linkage graph, not full runtime fail-closed enforcement, and this is **not** a fully
autonomous, production, or compliance-certified system, and does not claim non-repudiation.
(The canonical linkage is the payload-embedded signed `EvidenceRef` graph; the
`ApprovalRecord.evidence_refs` field remains an unused placeholder.) What does
**not** exist: users, revenue, design partners, a company, or a founding team. "YC-eligible" today
means *a founder with a working product and a defensible thesis can credibly apply* —
the application-strength evidence (Show HN reception, PyPI installs, 5–10 design-partner
conversations in regulated industries, a pricing hypothesis tested against a real
buyer) is the next milestone, and it cannot be engineered from inside this repo.

## Sources

- Palo Alto Networks / Protect AI: <https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-completes-acquisition-of-protect-ai>;
  deal size reporting: <https://www.bankinfosecurity.com/blogs/palo-alto-networks-eyeing-700m-buy-protect-ai-p-3852>
- Check Point / Lakera: <https://cyberscoop.com/check-point-lakera-acquistion-ai-security/>
- Agentic-AI security funding wave (Oasis $120M, RSAC-2026 window, M&A tally):
  <https://softwarestrategiesblog.com/2026/03/28/agentic-ai-security-startups-funding-mna-rsac-2026/>
- GitGuardian $50M for NHI + AI-agent security:
  <https://siliconangle.com/2026/02/11/gitguardian-raises-50m-expand-non-human-identity-ai-agent-security/>
- YC Summer 2026 RFS ("Software for Agents"): <https://www.ycombinator.com/rfs>
