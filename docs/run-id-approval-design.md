# Design Memo — run_id Lifecycle + Hash-Bound Durable Approval

Design only. No code. Grounded in the verified current flow (`/v1/orchestrate` →
`orchestration.run_phase` → `hermes.session.GovernedSession.plan/execute/probe`;
`apply.Approval(approver, reason, granted)`; `audit.DecisionLog.record`; per-hop
`g.request_id`). "Later" marks work deferred until a subsequent approved step.

Companion documents:

- **[docs/threat-model-authority-loop.md](threat-model-authority-loop.md)** — the adversaries,
  trust boundaries, and stop conditions this design serves.
- **[docs/canonical-plan-hashing.md](canonical-plan-hashing.md)** — the byte-exact
  canonicalization + hashing spec that defines `canonical_plan_hash`. This memo references
  that spec normatively; it does not restate the field set or normalization rules.

## 1. Purpose

- **Problem solved:** today a human "approval" is an ephemeral function argument passed
  inline to `execute`; there is nothing that (a) proves *which exact plan* was approved,
  (b) prevents approving plan A while plan A′ executes (plan-swap), (c) prevents
  reuse/replay of an approval, or (d) correlates the multi-request loop into one auditable
  unit. This memo designs the approval as a **durable, hash-bound, single-use record** keyed
  to a **`run_id`** that spans the whole loop.
- **Why approval first, before the trust ledger:** the approval is the *authority primitive*
  — the artifact that authorizes a state change. The ledger merely **records what approvals
  authorized**. Building the ledger first would record an authorization event that is itself
  forgeable and unbound. Fixing the approval (bound to content, single-use, run-scoped) is
  the prerequisite that makes any later ledger entry meaningful. It is also independent of
  the still-open evidence-write-path question (see the threat model), so it is safe to
  design now.

## 2. Current State

- **Approval is ephemeral:** `apply.Approval` is a dataclass (`approver`, `reason`,
  `granted`) constructed inside `GovernedSession.execute` from the request body. It is not
  stored, not identified, not bound to the plan, not expiring, not single-use.
- **No `run_id`:** each `/v1/orchestrate` call is effectively stateless — `run_phase` builds
  fresh peers and a fresh `GovernedSession` per call, so `plan` and `execute` share no
  server-side state. Approval is smuggled in the `execute` body instead of referencing a
  prior plan.
- **`request_id` is insufficient:** it is minted per HTTP hop in `before_request`
  (`g.request_id = uuid4().hex`). A single `execute` call fans out into many internal
  test-client sub-requests, each with its *own* `request_id`. Nothing ties `plan`'s request
  to `execute`'s request to the sub-delegations. `request_id` answers "which hop," never
  "which run."

## 3. Required Security Properties

1. Approval **binds to `run_id`** — an approval is valid only for the run it was issued in.
2. Approval **binds to the exact `canonical_plan_hash`** (and, in the hardened variant, the
   diff hash). The hash is computed strictly per
   [docs/canonical-plan-hashing.md](canonical-plan-hashing.md).
3. **Approval validation requires BOTH a matching `run_id` AND a matching
   `canonical_plan_hash`.** Neither alone authorizes execution.
4. **Same `canonical_plan_hash` with a different `run_id` MUST refuse** — a matching plan
   hash under a different run is not an authorization for that run.
5. Approval is **single-use** unless explicitly marked `single_use = false`.
6. **Expired** approval is refused (`expires_at` in the past).
7. **Replay** of a used approval is refused (`used_at` already set).
8. **Restart invalidates all pending approvals** (see §7).
9. **Rejection is a governed success** — recorded as a terminal outcome, not an error.
10. **Apply recomputes the plan/diff hash and refuses on mismatch** (fail closed).
11. **`canonicalization_version` and `plan_schema_version` mismatches fail closed** — an
    approval and an apply that disagree on either version are never reconciled or migrated;
    the apply refuses.
12. **No approval authorizes a broader action than the approved plan** — executor, skill,
    autonomy level, `resource_root_id`, `target_resources`, and the delegation chain are all
    inside the hash (per the hashing spec); anything not covered is denied.
13. **No approval is created from model text** — only an explicit human decision mints one.

## 4. run_id Lifecycle

- **Minted:** server-side, authoritatively, at the start of the **plan** phase (in
  `run_phase`/`GovernedSession.plan`). A fresh opaque id (e.g. `run-` + uuid4hex). The
  client never invents it.
- **Threaded:**
  - `plan` response returns `run_id` (+ `canonical_plan_hash`).
  - `execute` request **must** carry that `run_id` and the `approval_id`; the server rejects
    an `execute` whose `run_id` is unknown/closed.
  - `probe` may carry the `run_id` for correlation but remains read-only/denial-only (no
    approval, no mutation).
  - Internally, every sub-request the session makes (delegate, apply, verify) is tagged with
    the same `run_id`.
- **Relationship to `request_id`:** orthogonal and both retained. `run_id` = the loop;
  `request_id` = one hop within it. Authority-relevant audit records carry **both**;
  `request_id` may never be used where `run_id` is required (enforced by tests, §9).
- **In audit/evidence records:** `run_id` becomes a first-class field on
  `DecisionLog.record` output and on every future evidence record, so a full loop is
  reconstructable by `run_id`.
- **On restart:** open runs are considered closed; their pending approvals are invalidated
  (§7). A later `execute` referencing a pre-restart `run_id` fails closed (`run_not_found` /
  `approval_invalidated`).

## 5. Canonical Plan / Diff Hashing

The canonical plan object, its field set, normalization rules, and the SHA-256 digest are
governed **normatively** by [docs/canonical-plan-hashing.md](canonical-plan-hashing.md). Key
points this design depends on:

- The hash covers only authority-bearing fields — including `resource_root_id` /
  resource_namespace, so the same relative path under a different root is a different
  approved action.
- `constraints` are **policy/system-derived from an allowlisted schema**, never arbitrary
  model-generated text; adding a new authority-bearing constraint requires a
  `plan_schema_version` bump.
- Volatile fields (`request_id`, timestamps, tokens, approver identity, UI narration) are
  excluded, so benign non-authority changes do not break a valid approval.
- **Plan-swap prevention:** because `executor`, `skill`, `autonomy`, `resource_root_id`,
  `target_resources`, and the delegation chain are inside the hash, an `execute` that
  re-derives a different delegation yields a different digest and is refused. `execute` must
  **reconstruct** the plan and check it hashes to the approved value — it must not freely
  re-discover the executor (as `session.execute` does today via `find_peer`).
- **Hash-mismatch behavior:** `apply` recomputes the canonical hash from the plan it is
  about to run; if it ≠ `approval.canonical_plan_hash`, it refuses (`apply_hash_mismatch`),
  audits the refusal, and mutates nothing.
- **Diff hash (later):** when a dry-run produces the concrete diff *before* approval, bind
  `diff_hash` too and have `apply` re-derive it from the sandbox before/after manifests. MVP
  binds the **plan** hash; the diff-hash flow is the hardening follow-up, noted not built.

## 6. Approval Record Schema

```
approval_id            # opaque unique id (appr-…)
run_id                 # the run this approval is scoped to
principal_id           # principal that requested the action (e.g. hermes)
approver               # human identity that decided (owner)
task_class             # classified task type
requested_autonomy     # level the plan asked for
effective_autonomy     # level actually granted (≤ policy ceiling; never raised here)
tool_or_skill          # e.g. code.apply
target_resources       # explicit scope the approval covers (relative to resource_root_id)
canonical_plan_hash    # SHA-256 over the canonical plan object (see hashing spec)
diff_hash              # optional; set only in the hardened diff-bound variant
approval_status        # pending | approved | rejected | expired | used | invalidated
created_at             # issue time (UTC ISO-8601)
expires_at             # hard expiry; past ⇒ refused
decided_at             # when approved/rejected
single_use             # default true
used_at                # set when consumed; non-null ⇒ replay refused
rejection_reason       # set when rejected (governed success)
policy_rule_triggered  # which policy rule required this approval
evidence_refs          # placeholder; later points into the evidence sink / ledger
```

Notes: `effective_autonomy` is **computed from policy**, never taken from the request; an
approval can only authorize ≤ the principal's policy ceiling. `evidence_refs` is a forward
hook — empty in MVP, populated once the evidence sink exists.

## 7. State Storage Design

- **MVP storage location:** an in-process, module-level approval store in the Flask app (a
  keyed map `approval_id → record`, plus a `run_id → run` map). Durable **across the
  plan→execute HTTP calls within one process run** — the "durable" the loop needs today —
  without introducing a persisted, forgeable artifact.
- **Restart invalidation rule:** because the MVP store lives in process memory, a restart
  empties it; any pending approval is therefore gone and a subsequent `execute` fails closed.
  If a persisted variant is ever added before the evidence sink exists, startup MUST
  explicitly mark every non-terminal approval `invalidated`.
- **Durable vs intentionally invalidated:** *durable within a run* = the approval record
  from issue → decision → use. *Intentionally invalidated on restart* = all `pending` /
  `approved`-but-unused approvals.
- **Why pending approvals should not survive restart yet:** a file that survives restart is
  exactly the artifact a local filesystem attacker forges, and there is no integrity
  boundary to protect it until the verifier-owned evidence sink + signing exist (see the
  threat model). Non-persistence is the honest MVP: it cannot be tampered across restart
  because it does not exist across restart. Crash-durability is deferred to *after* the
  evidence boundary lands.
- **Connection to sink/ledger later:** once the verifier-owned, hash-chained evidence sink
  exists, approval issuance/decision/use become **signed events appended to it**, and
  `evidence_refs` links the approval to those entries; `TRUST_STATE` (later) is derived from
  that chain, never from the approval store directly.

## 8. API / Flow Changes (later)

- **plan** response gains `run_id` and `canonical_plan_hash` (and, hardened, a proposed
  `diff_hash`).
- **approval** becomes an explicit act (later endpoint/record) that mints/decides an approval
  record — not an inline `execute` body field. Rejection writes `approval_status = rejected`
  and returns a 200 governed outcome.
- **execute** requires `run_id` + `approval_id`; the server loads the approval, checks
  status/expiry/single-use, reconstructs the plan, recomputes the canonical hash, verifies
  **both** the `run_id` and the hash match, checks the version fields, and refuses on any
  mismatch. Execute-without-approval **still refuses** (preserving the verified behavior),
  now via `approval_missing`.
- **probe** unchanged: read-only, denial-only, no approval, no mutation.

## 9. Tests Required (specified, not written)

- `plan` creates a `run_id` (and returns a stable `canonical_plan_hash`).
- `execute` without an approval refuses (fail closed), no mutation.
- Approved plan applies **only if** the recomputed hash matches the approval.
- **Same `canonical_plan_hash` but different `run_id` → refuse** (approval binds both).
- **Plan-swap** (different executor/skill/level/root/target at execute) → hash mismatch →
  refused.
- **Replay** of a `single_use` approval already `used` → refused.
- **Expired** approval (`expires_at` in past) → refused.
- **Restart** invalidates a pending approval → subsequent `execute` refused.
- **Rejection** is recorded as a governed success and audited.
- `request_id` cannot substitute for `run_id` on an authority-relevant record.
- Approval cannot set `effective_autonomy` above the principal's policy ceiling.
- `canonicalization_version` mismatch between approval and apply → fail closed.
- `plan_schema_version` mismatch → fail closed.

## 10. Files Likely To Change Later (do not edit now)

- `agents/opencode_sandbox/apply.py` — `Approval` → durable, hash-bound record; `apply`
  recomputes and matches the canonical hash before any write.
- `agents/hermes/session.py` — `plan` mints/returns `run_id` + `canonical_plan_hash`;
  `execute` reconstructs the plan and verifies run_id + hash instead of freely re-discovering
  the executor.
- `src/private_ai_gateway/orchestration.py` — thread `run_id` through `run_phase`;
  load/verify the approval record.
- `src/private_ai_gateway/app.py` — `/v1/orchestrate` carries `run_id`/`approval_id`; a later
  approval endpoint; `run_id` added to `g` and to audit calls.
- `src/private_ai_gateway/audit.py` — add `run_id` to the decision record schema.
- **New (later):** a canonicalizer module implementing the hashing spec; an approval-store
  module; `tests/unit/test_approval_binding.py`.

## 11. Risks / Stop Conditions

Halt and escalate if any appears in a diff or design:

- Approval **not bound to a content hash** (run_id alone is insufficient).
- Approval **validated on run_id or hash alone** (both are required).
- Approval **authorizes a broader action than approved** (any authority-bearing field
  outside the hash).
- Pending approval **survives restart unintentionally** (before the evidence boundary
  exists).
- **Model text creates or decides an approval** (must be an explicit human act).
- **Model-generated / non-allowlisted `constraints`** entering the canonical object.
- Approval **changes autonomy directly** (approvals authorize a bounded action; they do not
  mint or raise autonomy — that is the separate, human-gated graduation path).
- **Missing `run_id`** on any authority-relevant record (plan, approval, apply, verify,
  audit).
- **Version mismatch accepted** (`canonicalization_version` / `plan_schema_version`) instead
  of failing closed.
- `execute` re-derives the plan freely instead of reconstructing-and-hash-checking the
  approved one.

## 12. Safe Next Action

This memo is design-only and changes nothing executable. Recommended next design-only
artifact: a **one-file implementation plan** binding this design and the hashing spec to the
approval record and `run_id` threading — the module boundary for a canonicalizer +
in-process approval store, the two call sites that must recompute-and-compare (`plan` issue,
`apply` check), and the audit-field additions — for review before any code.
