# Step 7B.1 / 7B.2 implementation contract

**Audience:** the next implementing model/engineer (Opus 5 handoff).
**Status:** binding contract, ratified by the pre-7B architecture audit and the 7B.0
implementation (PR #40). This is not a roadmap — it specifies exactly what to build,
what to reuse, and what is out of bounds. Do not reinterpret the architecture; if the
repository reveals a genuine correctness blocker, stop and surface it instead.

Ground truth this contract assumes:

- `main` contains merged Step 7B.0: `PRIVATE_AI_EVIDENCE_MODE=durable` opens the evidence
  DB as a live `SqliteEvidenceSink` under assurance-owned key custody
  (`agents/openclaw/assurance.py`), all three records (`approval_decided`,
  `execute_validated`, `apply_result`) land in one durable chain, and OpenClaw verifies
  fail-closed with `require_signed_apply_evidence` + `require_signed_linkage`.
- Authority ordering is still: `validate_for_execute` → `mark_used` →
  emit `execute_validated` → `session.execute` (mutation) — see
  `src/private_ai_gateway/orchestration.py::_run_execute`.
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

## Part I — Step 7B.1: append-first reservation

### Current vs target ordering

Current (`_run_execute`):

```text
validate_for_execute
→ mark_used                  (authority consumed)
→ emit execute_validated     (durable record appended)
→ session.execute            (mutation)
```

Target:

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

### The crash window this closes

In 7B.0, a crash between `mark_used` and the `execute_validated` emit leaves a spent
approval with **no durable trace** (audit window W4). After 7B.1 the durable record
exists before consumption, so on restart the state is classifiable.

### Startup rule (the 7B.1 half of reconciliation)

> If an `execute_validated` (reservation) record exists for `(run_id, approval_id)` AND
> the approval is still APPROVED, then `mark_used` cannot have completed, and therefore
> the mutation cannot have started. Resolution: consume-or-invalidate — either is safe,
> pick ONE and test it; the mutation provably never began.

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
| C2 | after reservation emit, before `mark_used` | approval APPROVED + reservation present | consume-or-invalidate (mutation provably not started) |
| C3 | after `mark_used`, before mutation completes | approval USED + reservation present, no `apply_result` | dirty — run must be invalidated and surfaced (7B.2 class 3) |
| C4 | after mutation + `apply_result` append | approval USED + full chain | complete — no action |

7B.1 must implement and test C1 and C2 (its own ordering guarantee). C3/C4
classification lands in 7B.2 but the 7B.1 tests must already assert the durable state
that makes them distinguishable.

### Acceptance criteria (7B.1)

- Ordering change is visible in `_run_execute` with the reservation emit before
  `mark_used`, and `tests/unit/test_gateway_authorization_evidence.py`'s
  emit-before-execute guarantees still hold.
- Crash tests C1/C2 pass with close/reopen restarts (no sleeps).
- Double-execute (sequential and concurrent loser) still converges on `replay`.
- Emit failure before `mark_used` leaves the approval APPROVED (test it).
- Full suite green; coverage gate ≥ 85 % holds.

---

## Part II — Step 7B.2: startup cross-store reconciliation

At durable startup (after both stores' own integrity validation), join the authority
scan (reuse the pass `SqliteApprovalStore._validate_on_open` already makes) against the
evidence chain filtered by `(run_id, approval_id)` and classify:

| Class | Authority state | Evidence state | Resolution |
|-------|-----------------|----------------|------------|
| 1 | APPROVED | no reservation | no-op (clean) |
| 2 | APPROVED | reservation present | automatic safe repair: consume-or-invalidate (same rule as 7B.1 C2) |
| 3 | USED | reservation present, no `apply_result` | dirty run: invalidate (`RunStatus.INVALIDATED`), surface disposition, fail closed |
| 4 | USED | full chain (reservation + `apply_result`) | complete (clean) |
| 5 | no matching approval | evidence records exist | fail closed: surface for human disposition — evidence never regrants authority |
| 6 | USED | no reservation | pre-7B.1 legacy or tampering: fail closed, human disposition |

### Binding decisions

- Automatic repair is permitted ONLY for classes 1, 2, 4 (2 being the only one that
  acts). Classes 3, 5, 6 fail closed with a surfaced disposition.
- **No automatic double-apply, ever.** Reconciliation never re-runs a mutation.
- **No evidence-derived regrant.** Evidence records prove what happened; they never
  become authority to do anything again.
- **Late evidence never resurrects an invalidated run.** An `apply_result` appended
  after invalidation appends validly to the chain (append-only holds) but the run stays
  `INVALIDATED`.
- Use the existing `RunStatus.INVALIDATED` as the terminal bar. Do NOT pull 7C's
  `run_disposition` / `verification_result` forward.
- Pending-approval expiry semantics land here (with the staleness handling), not in
  7B.1.

### Acceptance criteria (7B.2)

- A startup classifier with one deterministic test per class (raw-SQL/state fixtures to
  construct each shape, close/reopen to trigger).
- Classes 3/5/6 produce a fail-closed startup outcome whose message names the run and
  the class — an operator can act without reading source.
- Class-2 repair is idempotent (a second restart classifies the same run as clean).
- The 7B.1 crash tests C3/C4 now assert the classifier's verdicts.
- Full suite green; coverage gate holds.

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
