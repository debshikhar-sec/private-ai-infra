# Verifier-Owned Evidence Sink — Design (MVP)

> **Status:** partially implemented. The sink **core** (`agents/openclaw/sink.py`), the
> OpenCode **`apply_result` emit** (`agents/opencode_sandbox/evidence_emit.py`),
> **OpenClaw's consume/validation** of that signed evidence from an injected sink
> (`agents/openclaw/evidence.py`, `checks.py`, `worker.py`), and the gateway
> **`execute_validated` and `approval_decided` authorization evidence emits**
> (`src/private_ai_gateway/orchestration.py`, `app.py`) are now built and unit-proven —
> component-level verification and gateway authorization evidence emit, not yet end-to-end
> gateway-issued `run_id` / `approval_id` wiring, and the gateway and OpenCode records are
> not yet linked through `evidence_refs`. The remaining steps in this spec —
> **`evidence_refs` population** and **fail-closed runtime integration** — are still
> design-only and gated behind later, separately-authorized increments.

> **Scope discipline.** This is the *evidence-integrity* increment. It does **not** build a
> trust ledger, earned autonomy, or production key management. See §10 and §14.

Related: [`threat-model-authority-loop.md`](threat-model-authority-loop.md) (§6 weakness, §7
target, §10 fail-closed, §12 MVP/prod boundary), [`run-id-approval-design.md`](run-id-approval-design.md)
(the `evidence_refs` forward-hook), [`orchestration.md`](orchestration.md).

---

## 1. Purpose

**The weakness.** OpenClaw (the assurance/verifier component) reaches its PASS/FAIL verdict
by *reading artifacts that the very components it verifies produced*. It never imports those
components — it is **parsing-independent** — but it is **not trust-boundary-independent**: the
bytes it reasons over are authored by the gateway (the decision audit, metrics) and the
executor (the isolation and apply reports). A component that is compromised or simply buggy
can emit favorable evidence, and OpenClaw would accept it.

**Authorization integrity vs. evidence integrity.**

- *Authorization integrity* — "was this state change actually authorized?" — is what **D2
  closed**: execute requires a durable, owner-gated, canonical-hash-bound, single-use
  approval; an inline request-body approver grants nothing; `mark_used` runs before any
  mutation; `run_id` correlates the loop and refusals are audited.
- *Evidence integrity* — "can we trust the record of what was authorized and what then
  happened?" — is **still open**. The approval store is in-process/ephemeral, and the
  after-the-fact artifacts (audit, apply report) are unsigned, unchained, self-attested, and
  not linked to `run_id`/`approval_id`.

**This document addresses only the second.** D2 made the *decision* trustworthy; the evidence
sink makes the *record of the decision and its outcome* tamper-evident and independent of the
components being judged. It does not change any authorization behavior.

---

## 2. Current evidence flow (as built today)

| Artifact | Written by | Read by | How OpenClaw obtains it |
|---|---|---|---|
| Decision audit `logs/decisions.jsonl` | **Gateway** — `audit.py:DecisionLog.record` (called from `app.py`) | OpenClaw, SIEM | Pulled **through the gateway**: `peer.decisions()` under OpenClaw's own `can_read_audit` grant (`openclaw/worker.py`), buffered to a temp file, parsed by `evidence.load_audit`. Governed access, but **gateway-authored bytes**. |
| Metrics (Prometheus text) | **Gateway** — `/metrics` | OpenClaw | `peer.metrics_text()` → `evidence.parse_metrics`. Governed access, gateway-authored. |
| Isolation report | **OpenCode** review harness | OpenClaw | `evidence.load_isolation_report(path)`. Executor-authored. |
| Apply report `apply_report.json` | **OpenCode executor** — `opencode_sandbox/worker.py` writes `report.to_json()` | OpenClaw | The **path is handed to OpenClaw inside the task string** (`apply_report=<path>`) and read by `evidence.load_apply_report`. Executor-authored, arbitrary path, **unsigned**. |
| Policy view | `policy.toml` | OpenClaw | `evidence.load_policy`. |
| Eval report | `evals.run` | OpenClaw | `evidence.load_eval_report`. |

**Self-attested today:** the decision audit (gateway), the isolation report and the **apply
report** (executor). OpenClaw's controls (`openclaw/checks.py`) reason over these via
`openclaw/evidence.py` loaders and emit findings via `openclaw/report.py`.

**Note on the audit path.** Pulling audit/metrics *through the gateway surface* is fine as an
access mechanism (least-privilege, governed). The trust gap is not the transport — it is that
the **content is authored by the audited party** and nothing binds/signs it.

---

## 3. Threat model (what this increment must defend against)

| # | Threat | Today's exposure |
|---|---|---|
| T1 | **Compromised/buggy executor forges `apply_report.json`** (`status:"applied"`, empty `violations`) | OpenClaw's `ApplyReportView` control accepts it verbatim; no signature, no cross-check. |
| T2 | **Gateway omits or rewrites audit evidence** | OpenClaw reconciles against gateway-authored records; an under-reported denial has no independent trace. |
| T3 | **Swallowed audit write failure** (`audit.py` deliberately ignores `OSError` on write) | A decision can silently fail to record; no signal reaches the verifier. |
| T4 | **Apply report not bound to `run_id`/`approval_id`** | `apply_report.json` carries `approver`/`status`/files but **no `run_id`, no `approval_id`** — evidence cannot be tied to the specific authorized run; wrong-run evidence is indistinguishable. |
| T5 | **Post-hoc byte tampering** | Any on-disk artifact can be edited after emission with no detection. |
| T6 | **Replay of stale evidence** | A prior run's favorable report can be re-presented for a new run; nothing pins a record to a fresh, ordered position. |
| T7 | **Sink unavailable during a mutating action** | Undefined today (no sink); the design must specify fail-closed behavior so a mutation is never treated as verified without recorded evidence. |

**MVP honesty.** MVP uses **symmetric HMAC** (see §7). It proves **tamper-evidence** against
T1–T6 for an *external* editor and against honest-but-broken components. It does **not** defend
against an attacker who holds the emitter's HMAC key (that requires asymmetric keys + key
separation — §10 "production"). This limitation is stated, not hidden.

---

## 4. MVP design

- **A verifier-owned, append-only evidence sink.** The store and its validation logic live
  **inside OpenClaw's trust boundary** (the verifier), not the gateway's or the executor's.
- **Emitters push signed records in; the sink validates and appends.** This inverts today's
  "OpenClaw reads a file the executor wrote at a path the executor chose." Emitters (gateway,
  executor) construct a record, HMAC-sign it with their own key, and submit it; the sink
  verifies the emitter signature and the chain **before** appending.
- **Records carry `run_id` and `approval_id`** where applicable (§5), finally populating the
  `ApprovalRecord.evidence_refs` forward-hook.
- **Integrity primitives (MVP):** **per-emitter HMAC** + **`prev_hash` chaining**. Together
  they make the log tamper-evident (any edit/reorder/replay breaks a signature or the chain).
- **No asymmetric signing / KMS yet.** Deferred to production (§7, §10).
- **Single-host / single-user boundary.** Consistent with `threat-model §12`: MVP HMAC
  keyfiles on one host prove tamper-evidence; it is not a multi-tenant trust root.
- **Fail-closed for authority-bearing mutation evidence.** A mutating apply is **not**
  considered verified unless its required, signed, chained records are present and valid
  (§9). Read-only planning/classification may still proceed at floor.

**Transport (MVP).** The push may be an in-process call within the same process tree the
orchestration already uses (the demo drives all agents in-process), or a file drop that the
sink validates on ingest. The design requires only that the sink — not the emitter — decides
what is accepted and appended; the concrete transport is an implementation choice for the
sink-core commit and must not let an emitter write the log directly.

---

## 5. Record schema (proposed)

One JSON object per record. Field order below is the canonical order for hashing (see notes).

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | int | Pins the record shape; unknown version → reject (fail closed). MVP = `1`. |
| `seq` | int | Monotonic per-sink sequence number, assigned **by the sink** on append (not by the emitter). |
| `sink_id` | str | Identifies the sink instance/log (so records can't be cross-replayed between sinks). |
| `run_id` | str | The governed run this record belongs to (`run-…`). Required for all MVP event types. |
| `approval_id` | str \| null | The authorizing approval (`appr-…`); required for `execute_validated`/`apply_result`, null for records with no approval. |
| `emitter` | str | Logical emitter identity: `gateway`, `opencode`, or `openclaw`. Selects the HMAC key. |
| `event_type` | str | One of §6. |
| `payload` | object | Event-specific body (§6). Contains **no secrets/tokens**. |
| `payload_hash` | str | `sha256:<hex>` over the canonical serialization of `payload`. |
| `prev_hash` | str | `record_hash` of the previous record in this sink (`sha256:…`), or a fixed genesis constant for `seq = 0`. |
| `record_hash` | str | `sha256:<hex>` over the canonical serialization of all fields **except** `record_hash` and `emitter_sig` (i.e. over the chained, sequenced core). |
| `emitter_sig` | str | `hmac-sha256:<hex>` computed by the **emitter** over `record_hash` (or over the same canonical core), using the emitter's key. Binds authorship. |
| `created_at` | str | Emitter timestamp, ISO-8601 UTC (`…Z`). Advisory; ordering authority is `seq`/chain, not the clock. |

**Notes / decisions to pin in the sink-core commit.**
- **Canonicalization must be explicit and byte-exact** (sorted keys, compact separators, UTF-8),
  reusing the doctrine already proven in [`canonical-plan-hashing.md`](canonical-plan-hashing.md).
  *Do not import `canonical.py`* — it is frozen for plan hashing; a small, dedicated serializer
  for records avoids coupling. (Stop condition if reuse would require editing `canonical.py`.)
- **`seq`, `sink_id`, and `prev_hash` are assigned by the sink**, so an emitter cannot choose
  its position (defends replay/reorder, T6). The emitter signs `payload`+identity fields; the
  sink signs/chains position. Two-layer authorship: emitter authenticity (HMAC) + sink ordering
  (chain). The exact split (does `emitter_sig` cover `seq`/`prev_hash`, or only the emitter core?)
  is pinned in the sink-core commit; the safe default is **emitter signs its own core; the sink
  computes `record_hash`/`prev_hash` over emitter-core + assigned position**, so tampering with
  either layer is detectable.

---

## 6. Event types (MVP)

| `event_type` | Emitter | Payload (indicative) | MVP status |
|---|---|---|---|
| `approval_decided` | `gateway` | `{decision: approve\|reject, approver, canonical_plan_hash}` (emitted after the approval decision is stored, before the success response) | **Built** (component-level gateway *decision* evidence emit). Payload is exactly `{decision, approver, canonical_plan_hash}`; `run_id`/`approval_id` are envelope fields; the free-text rejection reason is excluded. Backward-compatible no-sink default; under `REQUIRE_AUTHORIZATION_EVIDENCE` a failed emit invalidates the run and active approvals and denies with HTTP 503 `authorization_evidence_unavailable`. Not yet linked via `evidence_refs`. |
| `execute_validated` | `gateway` | `{canonical_plan_hash, validated: true}` (emitted after `validate_for_execute` + `mark_used`, before mutation) | **Built** (component-level gateway authorization evidence emit; backward-compatible no-sink default; `REQUIRE_AUTHORIZATION_EVIDENCE` denies before mutation). Not yet full fail-closed pre-apply gating (§9b). |
| `apply_result` | `opencode` | `{status, declared_files, changed_files, violations, committed}` | **Required (MVP core).** This is the artifact that most directly replaces the self-attested `apply_report.json` and closes T1/T4. |
| `assurance_verdict` | `openclaw` | `{verdict: PASS\|FAIL, counts, notes}` | **Optional** in first implementation; useful for a self-recorded, chained verdict. |

**First-implementation minimum:** `apply_result` (executor→sink) + OpenClaw consuming it from
the sink. `execute_validated` and `approval_decided` have since landed (gateway emit);
`assurance_verdict` still follows in a later self-recorded-verdict commit, and
`evidence_refs` linking + fail-closed runtime integration remain future (§13). Consuming
controls must treat an absent-but-required record as **fail closed**, not INCONCLUSIVE (§9).

---

## 7. Emitter ownership and keys

**Emitters (MVP):**
- **`gateway`** — authorization emitter (`approval_decided`, `execute_validated`).
- **`opencode`** — executor emitter (`apply_result`).
- **`openclaw`** — verifier emitter (`assurance_verdict`); also the **owner** of the sink and
  the sole validator/appender.

**HMAC key loading (MVP):**
- Each emitter loads its key from a **file path or environment variable** resolved at startup
  (e.g. `PRIVATE_AI_EVIDENCE_KEY_<EMITTER>` or a keyfile directory). The concrete names are
  pinned in the sink-core/emit commits.
- **No hardcoded secrets, ever.** The key material must not appear in source, tests, or
  fixtures (tests generate ephemeral keys in `tmp_path`).
- **Missing/unreadable key → fail closed at that emitter:** the emitter cannot produce a valid
  record, so the corresponding authority-bearing step must **halt/refuse** rather than proceed
  unrecorded (§9). The verifier, missing its validation key, must **not** return PASS.
- The sink holds the *verification* side of each emitter key. In MVP (symmetric HMAC) that
  means the verifier can technically recompute an emitter's MAC — an accepted MVP limitation
  (§3, §10); it proves tamper-evidence, not non-repudiation.

**Production (future, out of scope here):** asymmetric per-emitter keys with **key
separation** (no party holds another party's signing key), a KMS/secret store, and rotation.
Only then does the sink provide non-repudiation across a real trust boundary.

---

## 8. Integration points (first two shipped; the rest future — described, not implemented)

- **(shipped)** **`src/private_ai_gateway/app.py`, `v1_approvals`** — after `decide_approval`
  returns, emit an `approval_decided` record (`run_id`, `approval_id`, decision, approver, hash).
- **(shipped)** **`src/private_ai_gateway/orchestration.py`, `_run_execute`** — after
  `validate_for_execute` succeeds and `mark_used` runs, and **before** `session.execute`, emit
  `execute_validated`.
- **`agents/opencode_sandbox/worker.py`, `_start`** — after `apply_proposal` returns
  (currently writes `apply_report.json`), also emit an `apply_result` record carrying
  `run_id`/`approval_id`. Keep the file initially for back-compat; the sink record becomes the
  authoritative one.
- **`agents/openclaw/worker.py` + `checks.py` + `evidence.py`** — during `verify`, read the
  apply/authorization evidence **from the sink** (validate chain + HMAC) rather than the
  handed `apply_report` path; a new control in `checks.py` asserts chain integrity and
  required-record presence; `report.py` surfaces a chain-integrity finding.
- **`src/private_ai_gateway/approvals.py`** — populate `ApprovalRecord.evidence_refs` with the
  sink `seq`/`record_hash` of the records linked to that approval (the documented forward-hook).
- **Gateway audit mirroring** — **deferred** (not MVP). Mirroring `decisions.jsonl` into the
  sink as signed `gateway`-emitter records would extend tamper-evidence to the full audit; MVP
  restricts scope to the **mutation path** (`apply_result` + authorization) to keep the change
  small and reviewable.

Threading `run_id`/`approval_id` into the executor emit must be **additive** to existing
signatures; if it cannot be (§12), stop and re-scope.

---

## 9. Fail-closed rules

a. **A mutating apply is not "verified" unless its required evidence is present, signed, and
   chained.** A missing required `apply_result` (or a missing `execute_validated` once that
   record is required) → OpenClaw returns **non-PASS**. Absence is fail-closed, not
   INCONCLUSIVE, for the mutation path.
b. **Invalid `emitter_sig` → refuse verification** (non-PASS). The record's author cannot be
   authenticated.
c. **Broken `prev_hash` chain (or `seq` gap/reorder) → refuse verification** (non-PASS). The
   log's integrity cannot be established.
d. **Sink unavailable during an authority-bearing mutation** → the mutating step **halts/fails
   closed**: either the pre-apply `execute_validated` cannot be recorded (so execute refuses),
   or the `apply_result` cannot be recorded (so the run is reported unverified). No mutation is
   ever reported as verified without its recorded, valid evidence. (Consistent with
   `threat-model §10`.)
e. **Read-only planning/classification may still proceed at floor** when the sink is
   unavailable — only actions that mutate state, apply changes, or would update trust are
   gated. (Also `threat-model §10`.)
f. **Unknown `schema_version` or emitter → reject the record** (fail closed).

---

## 10. MVP vs. future split

- **Evidence sink MVP (this increment):** verifier-owned append-only log; per-emitter HMAC;
  `prev_hash` chaining; `apply_result` (required) + authorization records; `run_id`/`approval_id`
  binding; `evidence_refs` population; fail-closed verification. Single host, HMAC keyfiles.
- **Later — hash-chained trust ledger:** derived, per-principal trust state built *on top of*
  the sink. **Out of scope here.** (The sink is the prerequisite; the ledger records what the
  sink proves.)
- **Later — earned/graduated autonomy:** consumes the ledger. **Out of scope.**
- **Later — production key management:** asymmetric per-emitter keys, key separation, KMS,
  rotation → non-repudiation. **Out of scope.**
- **Later — gateway audit mirroring:** signing/chaining the full decision audit into the sink.
  **Deferred** (see §8); may be a follow-up commit or a separate increment.

---

## 11. Testing plan

- **Unit:** append + `prev_hash`/`seq` correctness; per-emitter HMAC sign/verify; record schema
  incl. `run_id`/`approval_id`; genesis record; unknown `schema_version`/emitter → reject;
  malformed record recorded/flagged, not silently dropped (mirror `evidence.py` doctrine).
- **Integration:** full `plan → approve → execute → apply → apply_result recorded → OpenClaw
  reads sink → PASS`; `run_id`/`approval_id` thread end-to-end into `evidence_refs`.
- **Tamper tests:** mutate a recorded `payload` (T5) → `payload_hash`/`record_hash` mismatch
  detected; edit any chained field → chain break detected → non-PASS.
- **Replay tests:** re-submit a prior run's record / a stale `apply_result` (T6) → rejected by
  `seq`/`sink_id`/`run_id` binding.
- **Sink-unavailable tests:** authority-bearing mutation with the sink down (T7) → halts/fails
  closed; read-only planning still proceeds.
- **Self-attestation regression (the headline test):** an executor-written `apply_report.json`
  that is **not** a signed, chained sink record is **insufficient** for a PASS (T1). This is the
  direct regression proving OpenClaw no longer trusts self-attested executor bytes.

Keys in all tests are **ephemeral**, generated under `tmp_path`; no key material in the repo.

---

## 12. Stop conditions (must halt implementation and report)

1. A hardcoded secret/key would be required anywhere → stop; resolve key loading first.
2. The sink would be owned by (or directly writable without validation by) the **executor or
   gateway** instead of the verifier → stop; verifier ownership is the entire point.
3. MVP would ship **without** per-emitter HMAC **and** `prev_hash` chaining → stop; a plain
   persisted log reintroduces the exact forgeable artifact `approvals.py` warns against.
4. Threading `run_id`/`approval_id` or emitting records would require **non-additive** signature
   changes to `apply.apply_proposal`/`session.execute` → stop and re-scope.
5. The implementation would weaken any **D2 approval semantics** (hash binding, single-use,
   owner-gating, `mark_used`-before-mutation) → stop.
6. **Trust ledger** or **earned autonomy** work tries to enter this increment → stop; those are
   downstream (§10).
7. Reuse would require editing frozen `canonical.py` → stop; use a dedicated record serializer.

---

## 13. Recommended implementation sequence (small commits)

1. **Sink core only** — append-only log + `seq`/`sink_id`/`prev_hash` chaining + per-emitter
   HMAC sign/verify + record serializer. Standalone module in the verifier boundary; **no
   wiring** (mirrors how `canonical.py`/`approvals.py` landed isolated first).
2. **Sink tests** — unit + tamper + replay + schema/reject + missing-key fail-closed.
3. **Executor emit** — `opencode_sandbox/worker.py` pushes a signed `apply_result` (keep
   `apply_report.json` for back-compat) + tests.
4. **Verifier consume** — OpenClaw validates chain+sigs and uses sink records for the apply
   control; fail-closed on sig/chain break; **self-attestation regression test** (§11).
5. **Gateway authorization emit** — the `execute_validated` record is **built** (emitted
   after approval validation and `mark_used`, before `session.execute`; payload
   `{canonical_plan_hash, validated: true}`; backward-compatible no-sink default;
   `REQUIRE_AUTHORIZATION_EVIDENCE` denies before mutation) + tests. `approval_decided`
   has **also landed** (emitted at `POST /v1/approvals` after the decision is stored and
   before the success response; payload exactly `{decision, approver, canonical_plan_hash}`;
   backward-compatible no-sink default; under `REQUIRE_AUTHORIZATION_EVIDENCE` a failed emit
   invalidates the run and active approvals and denies HTTP 503
   `authorization_evidence_unavailable`) + tests.
6. **`evidence_refs` population** — link approvals to sink records in `approvals.py` + tests.
   **Future.**
7. **Fail-closed integration** — pre-apply authorization must record before mutation, else
   halt; end-to-end integration + sink-unavailable refusal tests.

Each is its own commit; steps 1–2 are the safest first landing.

### CI hermeticity (test-infrastructure note)

So these evidence increments stay reproducible, normal CI runs are **hermetic**: the
application backend is pinned to `demo` (`PRIVATE_AI_BACKEND=demo`) and Hugging Face /
Transformers network access is disabled, so *installing* MLX does not cause unit tests to
select a real model backend or load model weights. The macOS leg still verifies MLX
installation and compatibility using deterministic/fake-loader tests, and feature branches
run CI through the pull-request event (avoiding duplicate push + pull-request runs). This is
**CI hermeticity only** — a test-infrastructure guarantee, not a production model-isolation
claim.

---

## 14. Explicit non-goals

This increment does **not**:

- build a **trust ledger** (derived trust state) — that is the next increment, on top of this;
- implement **earned/graduated autonomy**;
- add **production KMS / asymmetric signing / key rotation** (MVP is single-host HMAC, honestly
  tamper-evident but not non-repudiable);
- migrate the **CLI orchestration** path;
- change the **`/chat` UI**;
- change any **approval authorization behavior** established in D2;
- (MVP) mirror the full **gateway decision audit** into the sink — deferred.

The sink described here is a *tamper-evidence* MVP for the mutation path. It is a prerequisite
for — not a substitute for — the trust ledger and the production key separation that give real
non-repudiation.
