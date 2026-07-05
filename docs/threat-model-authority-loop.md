# Threat Model — Authority Loop

Status: design draft. Describes the *target* boundary and the *current* gaps; several
controls below are not yet implemented and are marked accordingly.

## 1. Scope

**Covers:** the path by which a goal becomes an authorized action and a trust change —
goal intake → policy decision → approval → bounded execution → OpenClaw verification →
evidence record → (future) trust ledger → (future) autonomy change; and the integrity of
the evidence those decisions rest on.

**Does not cover:** model weight/supply-chain integrity, network transport security
(loopback only, no TLS), the OS/hardware TCB, the correctness of the model's reasoning,
the AI-stack CVE scanner (`vulnintel`), or third-party MCP/A2A servers beyond the
gateway's own decision on their responses.

## 2. Core Security Invariant

1. **Capability ≠ authority.** The ability to *plan* an action is never the authority to
   *perform* it; execution is decided and recorded by the governance plane, not the
   planner.
2. **Model text cannot grant authority.** No string produced by a model — plan, tool
   argument, or verdict-shaped output — may move trust or autonomy. Only a signed record
   from the designated writer can. Inert by construction, not by prompt discipline.
3. **Trust/autonomy changes come only from verified evidence plus governed approval.** An
   increase requires the human owner; the system may spend or lose authority on its own
   but never mint new authority for itself.

## 3. Assets

Policy decisions; approval records; evidence records (audit, metrics, isolation/apply
reports); OpenClaw verdicts; the future trust ledger and `TRUST_STATE`; the `run_id`
lifecycle correlating a full loop; sandbox before/after manifests; and public claims /
demo evidence (test counts, feature and `/chat` claims — an integrity asset because a
false one is a governance failure in miniature).

## 4. Adversaries

- **A. Malicious/compromised model output** — emits verdict-shaped text, injection, or
  scope-escalating plans.
- **B. Compromised OpenCode executor** — writes false isolation/apply reports and
  self-computed manifests about its own confinement.
- **C. Poisoned tool / peer / MCP / A2A response** — attempts to widen authority or
  smuggle instructions via metadata.
- **D. Local filesystem attacker** — edits evidence, state, or keyfiles directly.
- **E. Honest-but-broken gateway/executor** — bugs/regressions producing inconsistent
  evidence (non-malicious).
- **F. Over-eager human/operator** — approves an unsafe action, or approves plan A while
  plan A′ executes.

## 5. Trust Boundaries

client ↔ gateway · gateway ↔ model/backend · gateway ↔ evidence sink · executor ↔
evidence sink · OpenClaw ↔ evidence sink · ledger writer ↔ all other components · human
owner ↔ system. The sink and ledger-writer boundaries are the ones that must be
*authorship-separated*; the human-owner boundary is the only source of new authority.

## 6. Current Known Weakness (verified in code)

- The **gateway writes its own audit** (`audit.py` `DecisionLog.record`) and serves its
  own metrics; `AC-METRICS-RECONCILE` cross-checks two gateway-authored sources and so
  catches drift but not consistent lying.
- The **executor writes its own isolation/apply reports and computes its own manifests**
  (`opencode_sandbox/worker.py`, `apply.py`).
- **OpenClaw today verifies self-attested evidence** — parsing-independent, not
  trust-boundary-independent.
- Net: effective against **adversary E** (honest-but-broken); ineffective against
  **A/B/D** (compromise/forgery). No `run_id` exists — only per-hop `request_id`.

## 7. Target Evidence Boundary

Verifier-owned, append-only evidence sink; each record `{run_id, prev_hash, payload,
emitter_sig}` hash-chained; emitter signatures (per-emitter HMAC in MVP, asymmetric
later); **OpenClaw owns the chain head**. Gateway and executor may *append signed claims*
but cannot rewrite the chain or author the verifier's records — they cannot directly move
trust. Executor confinement claims are **re-derived verifier-side**, never trusted as
reported. Any signature failure or `prev_hash` break is fail-closed.

## 8. Approval Security

Approval record binds `{approval_id, run_id, exact plan/diff content hash, approver,
expiry, single-use}`. `apply` recomputes the hash and refuses on mismatch (defeats F's
plan-swap). Replay of a used approval fails; expired approval fails; **restart
invalidates all pending approvals**. Rejection is a governed, successful outcome that is
recorded — not an error path.

## 9. Trust / Autonomy Security

Trust ledger has a **single writer** (OpenClaw or a ledger service inside its boundary);
gateway and Hermes read, never write. `TRUST_STATE` is a **materialized view of ledger
replay** — a divergence between file and replay is fail-closed. **Autonomy increases are
governed actions** (policy → human approval → ledger commit) bounded by a per-task-class
ceiling and a max step size; **decay/demotion is automatic and immediate.** **L6 is
unreachable.** **BLOCK_NEXT is enforced at the gateway** at plan time — a planner
respecting its own restriction is not a control.

## 10. Restart / Failure Semantics

On restart: pending approvals invalidated; in-flight delegations dropped; rate-limit
state reset; **trust state re-derived from ledger replay**; everything else at floor.
Evidence-chain signature/replay failure → fail closed (no PASS, no trust update).
**OpenClaw unreachable → read-only planning/classification may proceed at floor, but any
action that mutates state, applies changes, updates trust, graduates autonomy, or affects
external resources must halt/fail closed.** Audit's current swallow-on-write-failure
behavior needs a fail-closed variant for trust-moving records specifically.

## 11. Stop Conditions

Halt and escalate to the human owner if any appear in a diff or design: model text
influences trust/autonomy; ledger writable by gateway/Hermes/executor; approval not bound
to a content hash; verifier and executor share write access to (or credentials for)
evidence; trust state editable independently of ledger replay; any autonomy increase
without human approval; BLOCK_NEXT honored by Hermes instead of enforced at the gateway;
L6 reachable; public claims (test counts, features, demos) shipped before runtime
verification — this has a prior (the stale `/chat` demo).

## 12. MVP vs Production Boundary

**MVP** (single host, single user, HMAC keyfiles) proves **tamper-evidence**: any
historical mutation breaks chain replay. It **does not** claim tamper-*resistance* — a
same-user or root compromise can rewrite both keys and head; this limit is stated, not
hidden. **Production** requires separate OS users / process boundary for the sink,
asymmetric signing with key separation (no party holds another's signing key), a
verifier-held (optionally externally anchored) chain, and verifier-side confinement
re-derivation.

## 13. Next Approved Work After This Threat Model

1. Retract the stale `/chat` claims (README + site) — honesty repair.
2. Runtime truth pass (pytest collect, demo boot, `/chat` exercise, restart test,
   wheel-gap, evidence write-path confirmation).
3. Design `run_id` lifecycle + hash-bound durable approval.
4. Design the evidence sink (chain + emitter signing + verifier-side re-derivation).
5. Trust ledger — **only after the evidence boundary is accepted.**
