# Step 7B.1 / 7B.2 implementation contract

**Audience:** implementers and reviewers of the Step 7B increments.
**Status: Step 7B is COMPLETE.** Part I (7B.1, append-first reservation) and Part II
(7B.2, startup cross-store reconciliation) are both **shipped and merged**; they are
retained here as the *specification of what was built* and the reasoning behind each
binding decision, not as pending work. Part III (Tracks C/D) remains future, carries no
authority, and is unblocked. Step 7C remains future and out of scope.

Do not reinterpret the architecture; if the repository reveals a genuine correctness
blocker, stop and surface it instead.

Ground truth this contract assumes:

- `main` contains merged Step 7B.0: `PRIVATE_AI_EVIDENCE_MODE=durable` opens the evidence
  DB as a live `SqliteEvidenceSink` under assurance-owned key custody
  (`agents/openclaw/assurance.py`), all three records (`approval_decided`,
  `execute_validated`, `apply_result`) land in one durable chain, and OpenClaw verifies
  fail-closed with `require_signed_apply_evidence` + `require_signed_linkage`.
- Authority ordering is the append-first sequence shipped in Step 7B.1:
  `validate_for_execute` → emit `execute_validated` (durable reservation) → `mark_used` →
  `session.execute` (mutation) → `apply_result` — see
  `src/private_ai_gateway/orchestration.py::_run_execute`. At most one reservation can
  exist per `approval_id`, enforced by a per-approval critical section.
- Startup runs one cross-store reconciliation pass
  (`src/private_ai_gateway/reconciliation.py::reconcile`) after both stores have
  independently passed their own integrity validation. It classifies before it acts, and
  its only action is `invalidate_run`.
- Two separate SQLite stores (never merged): `authority.sqlite3`
  (`SqliteApprovalStore`) and `evidence.sqlite3` (`SqliteEvidenceSink`), both
  exclusively owned via `flock` sidecar locks, both integrity-checked at the
  constructor.

Test commands (run from the repo root, `source venv/bin/activate` first):

```bash
python -m pytest -q
python -m pytest -q --cov=private_ai_gateway --cov=hermes --cov=openclaw \
  --cov=opencode_sandbox --cov=interop --cov=evals --cov-fail-under=85
ruff check .
bandit -c pyproject.toml -r src agents
```

Workflow invariants: feature branch → PR → required checks green → squash-merge with
branch delete; never push `main` directly; no co-author trailer; deterministic tests only
(no sleeps).

---

## Part I — Step 7B.1: append-first reservation · **SHIPPED**

### The ordering change (historical: this is what 7B.1 changed)

Before 7B.1 (`_run_execute`):

```text
validate_for_execute
→ mark_used                  (authority consumed)
→ emit execute_validated     (durable record appended)
→ session.execute            (mutation)
```

Shipped:

```text
validate_for_execute
→ emit execute_validated     (durable RESERVATION appended first)
→ mark_used                  (authority consumed)
→ session.execute            (mutation)
→ apply_result               (unchanged: emitted by the executor)
```

### Binding decisions

1. **Reuse `execute_validated` as the reservation record.** Do NOT add an
   `execute_reserved` record type, and do not change the frozen enums in
   `approvals.py` / `sink.py`. The record's meaning becomes "the gateway validated this
   approval and reserved the execution"; its payload keeps
   `{canonical_plan_hash, validated, approval_ref}` unchanged.
2. **Idempotency key is `approval_id`.** A duplicate execute for the same approval
   converges on the existing governed `replay` refusal
   (`approvals.REASON_REPLAY`) — never a second reservation, never HTTP 500.
3. **Fail-closed emit.** Under the wired durable runtime, a failed reservation emit
   refuses the execute BEFORE `mark_used` — the approval must remain APPROVED (this
   removes 7B.0's accepted fail-closed cost of a spent approval on emit failure).
4. **Refusal semantics unchanged.** Every existing refusal reason keeps its meaning and
   its HTTP-200 governed shape.
5. **At most one reservation per `approval_id`, ever.** ⚠️ This is *not* satisfied by a
   naive call reorder — see the next section.

### Reservation uniqueness (the non-obvious part)

Append-first breaks an invariant the old ordering got for free. Previously `mark_used`
came first, so only its single winner could emit; now `validate_for_execute` and the
reservation both precede consumption, and two concurrent executes can each validate as
APPROVED and each append a reservation before either consumes:

```text
A: validate -> APPROVED          B: validate -> APPROVED
A: append execute_validated #1   B: append execute_validated #2
A: mark_used -> ok               B: mark_used -> replay
```

Authority is still consumed exactly once — but **two `execute_validated` records now exist
for one approval**. That is a correctness failure, not untidiness: OpenClaw locates the
authority record with `find_unique_record`, which fails on more than one match with
`REASON_REF_AMBIGUOUS` (deliberately *not* "latest wins"). The duplicate makes the
**winner's** otherwise-legitimate run fail verification.

The evidence database's `UNIQUE(evidence_id)` and `UNIQUE(emitter, nonce)` constraints do
**not** prevent this: both records are legitimately distinct rows. This is an
operation-level duplicate, so it must be prevented at the operation.

**Required guarantee:** for one `approval_id` — sequentially, concurrently, and across a
restart — at most one `execute_validated` reservation is ever appended, authority is
consumed at most once, at most one mutation runs, and the loser receives the governed
`replay` refusal.

**Shipped mechanism (7B.1).** Two pieces, no schema change:

- **Within a process:** a per-`approval_id` critical section
  (`orchestration._approval_execution_lock`) makes validate → reserve → consume
  indivisible. The mutation runs *outside* the lock; by then the approval is USED, so no
  other thread can proceed anyway. Entries are reference-counted and removed when the last
  holder leaves.
- **Across processes and restarts:** an in-process lock is sufficient *only* because both
  `authority.sqlite3` and `evidence.sqlite3` are held under an exclusive `flock` for the
  owning process's whole lifetime (`DatabaseOwnership`) — a second gateway on the same
  state directory cannot open it and fails closed. There is no second writer. The one
  remaining path, a reservation surviving a crash into a later process, is closed by the C2
  rule below, which invalidates such an approval before any new execute can validate.

**Do not** relax the verifier to tolerate duplicates, do not add "pick the latest
reservation" semantics, and do not add a durable idempotency table or schema migration
unless the exclusive-owner property above ever stops holding (for example a genuine
multi-writer or multi-node deployment) — at which point this decision must be revisited
before that deployment ships.

### The crash window this closes

In 7B.0, a crash between `mark_used` and the `execute_validated` emit leaves a spent
approval with **no durable trace** (audit window W4). After 7B.1 the durable record
exists before consumption, so on restart the state is classifiable.

### Startup rule (the 7B.1 half of reconciliation)

> If an `execute_validated` (reservation) record exists for `(run_id, approval_id)` AND
> the approval is still APPROVED, then `mark_used` cannot have completed, and therefore
> the mutation cannot have started. **Resolution: INVALIDATE.**

Shipped at durable startup. 7B.1 landed this as a standalone resolver
(`state.resolve_interrupted_reservations`); **Step 7B.2 subsumed it** as class 2 of the
general reconciler (`reconciliation.reconcile`), so there is now exactly one pass and it
observes the original cross-store shape before anything is repaired.

**Why invalidate rather than consume** (this supersedes the earlier
"consume-or-invalidate, pick one" wording): consuming would turn a state we *know* to be
pre-mutation into `USED` + reservation + no `apply_result` — which is byte-identical to
C3, the genuinely ambiguous shape that 7B.2 must conservatively treat as possibly-dirty.
Consuming therefore destroys information. Invalidating preserves it: the run is closed
out, no mutation happened, nothing is retried, and another attempt needs fresh authority.

It uses the existing `invalidate_run` semantics (run → `INVALIDATED`, its non-terminal
approvals → `INVALIDATED`) and adds no new states. Re-running over an already-resolved
database is a no-op, so it is idempotent across repeated restarts.

Never infer mutation success from the absence of a failure record. Never auto-retry an
execute when the mutation may have started.

### Crash-injection points and expected post-restart state

Inject crashes deterministically by monkeypatching the store/sink boundary (raise a
sentinel exception), then "restart" by closing and reopening the backend from the same
temp state dir — the exact pattern already used in
`tests/unit/test_assurance_wiring.py` (`_env`/`_open` helpers +
`test_populated_database_survives_restart`) and
`tests/unit/test_durable_startup_integrity.py` (raw-SQL `_corrupt`). No new test
framework; no sleeps.

| # | Crash point | Durable state at restart | Required classification |
|---|-------------|--------------------------|-------------------------|
| C1 | after `validate_for_execute`, before reservation emit | approval APPROVED, no reservation | clean — nothing happened; approval remains usable |
| C2 | after reservation emit, before `mark_used` | approval APPROVED + reservation present | **invalidate** (mutation provably not started) |
| C3 | after `mark_used`, before mutation completes | approval USED + reservation present, no `apply_result` | dirty — run must be invalidated and surfaced (7B.2 class 3) |
| C4 | after mutation + `apply_result` append | approval USED + full chain | complete — no action |

7B.1 must implement and test C1 and C2 (its own ordering guarantee). C3/C4
classification lands in 7B.2 but the 7B.1 tests must already assert the durable state
that makes them distinguishable.

### Acceptance criteria (7B.1) — met; see `tests/unit/test_append_first_reservation.py`

- Ordering change is visible in `_run_execute` with the reservation emit before
  `mark_used`, and `tests/unit/test_gateway_authorization_evidence.py`'s
  emit-before-execute guarantees still hold.
- Crash tests C1/C2 pass with close/reopen restarts (no sleeps).
- Double-execute (sequential and concurrent loser) still converges on `replay`.
- Emit failure before `mark_used` leaves the approval APPROVED (test it).
- **Exactly one reservation per approval under a forced concurrent race**, with the
  verifier's own `find_unique_record` agreeing, and the property surviving a restart.
- Full suite green; coverage gate ≥ 85 % holds.

**Status: shipped.** The concurrency test was falsified before being trusted — with the
critical section disabled it reproduces 2 reservations for one approval,
`find_unique_record` raises `ref_ambiguous`, and the *winning* run's verdict degrades from
PASS to FAIL. With the critical section restored: one reservation, one PASS, one governed
`replay`.

---

## Part II — Step 7B.2: startup cross-store reconciliation · **SHIPPED**

Shipped as `src/private_ai_gateway/reconciliation.py::reconcile`, called from
`state.open_backend` once both stores are open and each has independently passed its own
integrity validation. It **subsumes** the 7B.1 reserved-but-unconsumed resolver as class 2
— deliberately not run as a separate repair beforehand, which would have erased the
original cross-store shape the general classifier needs to observe.

The pass reads the authority snapshot (`snapshot_approvals`) and the verified evidence
chain, builds immutable findings for **every** approval, and only then applies actions.
Its sole action is `invalidate_run`; it creates nothing, deletes nothing, retries nothing,
and has no access to an executor. Any failure to inspect either store raises
`ReconciliationError`, surfaced by `state.open_backend` as a fail-closed `StateError` —
"unable to inspect" is never treated as "clean".

Classes:

| Class | Authority state | Evidence state | Resolution |
|-------|-----------------|----------------|------------|
| 1 | APPROVED | no reservation | no-op (clean) |
| 2 | APPROVED | reservation present | **invalidate** — the mutation provably never started (this *is* the 7B.1 C2 rule, subsumed here) |
| 3 | USED | reservation present, no `apply_result` | dirty run: invalidate (`RunStatus.INVALIDATED`), surface disposition, fail closed |
| 4 | USED | full chain (reservation + `apply_result`) | complete (clean) |
| 5 | no matching approval | evidence records exist | fail closed: surface for human disposition — evidence never regrants authority |
| 6 | USED | no reservation | pre-7B.1 legacy or tampering: fail closed, human disposition |

### Binding decisions

- Automatic repair is permitted ONLY for class 2 (classes 1 and 4 are clean no-ops).
  Classes 3, 5, 6 fail closed with a surfaced finding — 3 and 6 by invalidating the run,
  5 by surfacing the inconsistency without ever synthesizing authority.
- **Classify first, act second.** The complete cross-store scan produces immutable
  findings before the first mutation, so a repair can never erase the shape a later
  classification depends on. This is why the 7B.1 resolver had to be *subsumed* rather
  than left as a preceding pass.
- **"Unable to inspect" is not "clean".** Any failure to read either store raises
  `ReconciliationError`, surfaced as a fail-closed `StateError` from `open_backend`.
- **Ambiguity is never normalized.** More than one reservation for an approval, or
  conflicting `apply_result` records, fails closed — never pick latest, never pick first,
  never silently discard.
- **Class 4 requires real signed linkage**, resolved with OpenClaw's own
  `resolve_evidence_ref`: presence of an `apply_result` is never sufficient. No weaker
  parallel verifier exists.
- **No automatic double-apply, ever.** Reconciliation never re-runs a mutation.
- **No evidence-derived regrant.** Evidence records prove what happened; they never
  become authority to do anything again.
- **Late evidence never resurrects an invalidated run.** An `apply_result` appended
  after invalidation appends validly to the chain (append-only holds) but the run stays
  `INVALIDATED`.
- Use the existing `RunStatus.INVALIDATED` as the terminal bar. Do NOT pull 7C's
  `run_disposition` / `verification_result` forward.
- **Pending-approval expiry: deliberately DEFERRED, not implemented.** The repository
  provides no grounded source for a pending lifetime: `expires_at` is set only by
  `decide_approval` (the *approved* TTL), the only policy-level TTL is
  `[delegation] ttl_seconds` which governs A2A delegation grants rather than approvals,
  and startup coherence explicitly *rejects* a pending approval that carries expiry data.
  Closing this LOW-severity item would therefore mean inventing a TTL, weakening a
  coherence rule, or adding a schema migration for it — none of which 7B.2 correctness
  needs. It stays open until a policy/config source for a pending lifetime exists.

### Acceptance criteria (7B.2) — met; see `tests/unit/test_reconciliation.py`

- A startup classifier with one deterministic test per class (classes 1–4 produced by
  driving the governed loop and crashing it; 5–6 by constructing the durable shape).
- Classes 3/5/6 produce a fail-closed outcome whose finding names the class, run and
  approval — an operator can act without reading source.
- Class-2 repair is idempotent (repeated restarts classify the run as already resolved).
- The 7B.1 crash tests C3/C4 assert the classifier's verdicts.
- Full suite green; coverage gate holds.

**Status: shipped.** Three load-bearing guarantees were falsified before being trusted:
neutralizing the linkage check makes class 3 collapse into class 4 (4 tests fail);
resolving ambiguity by picking the first reservation fails the duplicate test; and
returning an empty index on an unreadable chain fails the unreadable-input test.

### Explicit 7C exclusion (both steps)

Do not add: `verification_result`, `run_disposition`, rollback, containment, trust
ledger, earned autonomy, signed verifier verdicts, autonomous execution lanes,
asymmetric crypto, KMS/HSM, multi-node, tenancy — until 7B is complete and evaluated.

### Delivery order

7B.1 as its own PR → merge → 7B.2 as its own PR. Do not mix them.

---

## Part III — Track C / Track D: local-model shadow engineering (parallel after 7B.1)

These tracks may run in parallel with 7B.2 once 7B.1 has merged, provided no
architecture dependency is discovered. They grant NO new authority.

Doctrine: **local models gain capability early; authority expands only after proof.**
The paid model (Claude) moves worker → reviewer → teacher → exception handler. The local
model becomes the routine candidate generator first.

### Track C — shadow engineering harness

```text
goal
→ Hermes/local `strategy` plan            (already live: MLX planning at L1)
→ teacher records local plan vs its own expected plan
→ evaluation trace stored teacher-side    (OUTSIDE the governance plane)
```

- The teacher client submits objectives to `/v1/orchestrate` under the existing demo /
  hermes principals. It holds NO owner token and never bypasses the gateway.
- Safe retries only; refusals are data, not failures to route around.
- Signed evidence traces require the durable mode (`scripts/demo_durable.sh` shows the
  ephemeral-key configuration; `.env.example` documents the real one).

### Track D — candidate proposal adapter

```text
local `engineering` model output
→ schema validation against the opencode_sandbox proposal JSON
  (schema lives in agents/opencode_sandbox/apply.py)
→ isolated sandbox only, approval-gated
→ deterministic tests
→ OpenClaw verification
→ teacher comparison
```

Hard bounds for both tracks until 7B.1 + 7B.2 are merged and evaluated:

```text
NO external mutation · NO autonomous merge · NO autonomous deployment
```

### Evaluation trace schema (specify later, build later — do NOT implement training)

Each trace record should carry, at minimum: `trace_id`, ISO-8601 `created_at`,
`objective`, `model_id` (the pinned policy route target — this is why
`[models.routes]` is policy-hash-covered), `local_output`, `teacher_expected`,
`schema_valid` (Track D), `governed_outcome` (the gateway's verdict/refusal code),
`teacher_grade`, and free-text `teacher_notes`. Storage is teacher-side (plain JSONL is
fine); it is evaluation data, not evidence, and must never be written into the
governance plane's stores.
