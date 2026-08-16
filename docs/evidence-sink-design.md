# Verifier-Owned Evidence Sink — Design (MVP)

> **Status:** partially implemented. The sink **core** (`agents/openclaw/sink.py`), the
> OpenCode **`apply_result` emit** (`agents/opencode_sandbox/evidence_emit.py`),
> **OpenClaw's consume/validation** of that signed evidence from an injected sink
> (`agents/openclaw/evidence.py`, `checks.py`, `worker.py`), the gateway
> **`execute_validated` and `approval_decided` authorization evidence emits**
> (`src/private_ai_gateway/orchestration.py`, `app.py`), **stable evidence identity**
> (`evidence_id` + chain-independent `evidence_digest` + typed `EvidenceRef`, `SCHEMA_VERSION`
> is `2`), and the **signed evidence linkage graph**
> (`approval_decided ← execute_validated ← apply_result`, carried by payload-embedded
> `approval_ref`/`execute_ref`, verified end-to-end by OpenClaw) are built, and — as of
> Step 7B.0 — wired **end-to-end at runtime** under the durable configuration
> (`PRIVATE_AI_EVIDENCE_MODE=durable`): the gateway-issued `run_id`/`approval_id` thread
> through all three records into one durable, exclusively-owned SQLite chain (Steps 7A/7A.1)
> that OpenClaw verifies fail-closed and that reopens/re-verifies across restarts. The
> shipped linkage is the **payload-embedded signed `EvidenceRef` graph** (§6a); the
> `ApprovalRecord.evidence_refs` field remains an **unused, non-authoritative placeholder**
> and is *not* that graph. **Append-first reservation ordering (7B.1) has since shipped**:
> the `execute_validated` record is now appended as a durable reservation *before*
> `mark_used`, so wherever this document says it is emitted "after `validate_for_execute` +
> `mark_used`" it is describing the superseded Step-5 ordering — the current sequence is
> `validate → reserve (execute_validated) → mark_used → mutate`, with at most one reservation
> per approval and a fail-closed startup invalidation for one that outlives a crash. See
> [step-7b1-7b2-implementation-contract.md](step-7b1-7b2-implementation-contract.md). The
> Cross-store reconciliation (**7B.2**, hardened in **7B.2.1**) and the **signed verifier
> verdict (7C.1)** have since landed: OpenClaw signs its own `verification_result` with its
> own emitter key, binds a PASS to the exact `apply_result` it judged, and cannot produce a
> signed PASS over a broken authorization graph. **Terminal disposition (7C.2)** has also
> landed: a `run_disposition` record, emitted by the gateway under owner authority, bound to
> one *specific* basis the human names. **Rollback/containment (7C.3)** has landed too, in
> two parts: a bounded pre-image captured before the mutation (7C.3A) and an owner-approved,
> reserved, independently-verified sandbox rollback (7C.3B). Rollback outside the sandbox —
> git, deployment, system configuration — remains out of scope.

> **Scope discipline.** This is the *evidence-integrity* increment. It does **not** build a
> trust ledger, earned autonomy, or production key management. See §10 and §14.

Related: [`threat-model-authority-loop.md`](threat-model-authority-loop.md) (§6 weakness, §7
target, §10 fail-closed, §12 MVP/prod boundary), [`run-id-approval-design.md`](run-id-approval-design.md)
(the `evidence_refs` placeholder — superseded as the linkage mechanism by the §6a signed
graph), [`orchestration.md`](orchestration.md).

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
| `schema_version` | int | Pins the record shape; unknown version → reject (fail closed). **Shipped: `SCHEMA_VERSION` is `2`** (the identity-carrying envelope of §6a). |
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

**Shipped realization.** The implemented envelope (`agents/openclaw/sink.py`,
`SCHEMA_VERSION = 2`) carries `record_type` (not `event_type`), an advisory `ts` (not
`created_at`), a per-emitter `nonce` (the anti-replay token — separate from any evidence
identity), and a dedicated `evidence_id`. The emitter signs the whole envelope (`to_mapping`);
the sink assigns and chains `seq`/`prev_hash`/`record_hash`. Stable identity and cross-record
linkage are documented in §6a below.

---

## 6. Event types (MVP)

| `event_type` | Emitter | Payload (indicative) | MVP status |
|---|---|---|---|
| `approval_decided` | `gateway` | `{decision: approve\|reject, approver, canonical_plan_hash}` (emitted after the approval decision is stored, before the success response) | **Built** (component-level gateway *decision* evidence emit). Payload is exactly `{decision, approver, canonical_plan_hash}` — unchanged; `run_id`/`approval_id` are envelope fields; the free-text rejection reason is excluded. Backward-compatible no-sink default; under `REQUIRE_AUTHORIZATION_EVIDENCE` a failed emit invalidates the run and active approvals and denies with HTTP 503 `authorization_evidence_unavailable`. It is the **root** of the §6a signed graph. |
| `candidate_attributed` | `gateway` | `{route_alias, model_fingerprint, backend, resolved_model, revision, quantization, task_class, policy_hash, candidate_digest}` (emitted at plan, once the candidate exists) | **Built.** Names the model build that *generated* the candidate, at the moment it generated it. Every field is server-derived; no request field reaches it. Its envelope carries `run_id` but **no `approval_id`** — generation precedes approval, and an approval link here would be invented. Deliberately best-effort and *not* gated on `REQUIRE_AUTHORIZATION_EVIDENCE`: attribution is descriptive and grants nothing, so failing to record it must not deny a plan that authority already permits. |
| `execute_validated` | `gateway` | `{canonical_plan_hash, validated: true, approval_ref, attribution, attribution_recorded}` (appended after `validate_for_execute` and **before** `mark_used`, as the durable execution reservation — Step 7B.1) | **Built** (component-level gateway authorization evidence emit; backward-compatible no-sink default; `REQUIRE_AUTHORIZATION_EVIDENCE` denies before mutation). Carries `approval_ref` — a signed `EvidenceRef` to the `approval_decided` record (§6a) — and the run's `attribution`, **read back from its `candidate_attributed` record rather than recomputed from the live route map**, so a route change between plan and execute cannot move the attribution. A run with no such record carries the explicit `model_not_recorded` shape (`attribution_recorded: false`) and is never backfilled. Not yet full fail-closed pre-apply gating (§9b). |
| `apply_result` | `opencode` | `{status, declared_files, changed_files, violations, committed, execute_ref}` | **Built (MVP core).** Replaces the self-attested `apply_report.json` and closes T1/T4. Retains its existing outcome fields and now also carries `execute_ref` — a signed `EvidenceRef` to the `execute_validated` record (§6a). When no `execute_ref` is threaded, the record is byte-identical to before (default/no-linkage compatibility). |
| `assurance_verdict` | `openclaw` | `{verdict: PASS\|FAIL, counts, notes}` | **Optional** in first implementation; useful for a self-recorded, chained verdict. |
| `verification_result` | `openclaw` | `{verdict, control_counts, failed_control_ids, inconclusive_control_ids, apply_ref, evidence_graph_verified}`, plus `rollback_ref` since 7C.3B | **Built (7C.1).** The verifier signs its own verdict with its own emitter key. A signed PASS binds to the exact `apply_result` it judged and is unreachable over a broken graph. Deliberately **plural and non-terminal** — several may exist for one run. 7C.3B reuses the type rather than adding one: the record still means "OpenClaw's signed judgment about one thing that happened"; only the typed reference naming the subject changes. |
| `rollback_validated` | `gateway` | `{canonical_plan_hash, validated, origin_run_id, origin_approval_id, snapshot_id, snapshot_digest, apply_ref}` | **Built (7C.3B).** The rollback's own reservation, appended before its single-use approval is consumed. Its envelope `run_id` is the *rollback* run — a distinct governed run from the one being reversed. |
| `rollback_result` | `opencode` | `{status, origin_run_id, restored_files, snapshot_id, snapshot_digest, contained, rollback_ref, apply_ref, detail}` | **Built (7C.3B).** What the executor did, signed by the executor. Only `restored` is a success, and it requires a post-restore re-hash against the pre-image. A failure sets `contained` and never reports partial success. Whether the restoration was *correct* is OpenClaw's separate signed verdict. |
| `run_disposition` | `gateway` | `{disposition, basis_type, basis_ref, human_actor}` | **Built (7C.2).** The human's terminal closure of a run, signed by the authority plane. `basis_type` is exactly one of `verification_result` or `execute_validated`, and `basis_ref` is a typed `EvidenceRef` the server re-resolves (recomputed digest, type, authoring emitter, run/approval binding). At most one per run; a second attempt is refused `already_disposed`. `closed_unknown` asserts nothing about whether the mutation landed. |

**First-implementation minimum:** `apply_result` (executor→sink) + OpenClaw consuming it from
the sink. `execute_validated` and `approval_decided` have since landed (gateway emit), the
three are cross-linked into the §6a signed graph, and the durable runtime configuration now
lands all three in one durable chain (7B.0). The verifier's self-recorded verdict has since
landed as `verification_result` (7C.1, emitter `openclaw`), and crash-safe ordering and
cross-store reconciliation landed as 7B.1 / 7B.2 (+7B.2.1, §13). Terminal disposition of a
dirty run landed as `run_disposition` (7C.2, emitter `gateway`), and sandbox-confined
rollback as `rollback_validated`/`rollback_result` (7C.3B). Consuming controls must treat an absent-but-required record as **fail
closed**, not INCONCLUSIVE (§9).

---

## 6a. Stable evidence identity and signed evidence linkage (shipped)

Two increments landed on top of the event types above: a **stable evidence identity** (so a
record can be referenced portably) and a **signed linkage graph** (so authorization and
execution evidence point at one another under signature).

**Evidence identity.** Each signed envelope (`SCHEMA_VERSION` is `2`) carries a dedicated
`evidence_id` — the literal prefix `ev-` followed by UUIDv4 hexadecimal text — generated
**before** signing and included in the signed envelope. It is distinct from `nonce`, which
remains the per-emitter replay-defence value only.

**Evidence digest.** `evidence_digest` is a **chain-independent** `sha256:` digest that binds:

- the complete signing-envelope mapping (`to_mapping`, including `schema_version`,
  `evidence_id`, `payload_hash`, and `nonce`); and
- the emitter signature `emitter_sig`.

It deliberately **excludes** the sink-assigned `seq`, the previous-record hash, the chain-local
`record_hash`, the raw payload, and any extra metadata — so the same signed attestation has the
same digest regardless of which sink it lands in or where in the chain it sits. `record_hash`
remains the sink-local chain-position and integrity hash; it is **never** a portable evidence
identity.

**EvidenceRef.** The typed, stable reference is:

```text
evidence_id
evidence_digest
record_type
sink_id
```

`sink_id` is a **locator / origin hint** only. Sequence numbers and `record_hash` are **not**
portable evidence identities and never appear in a reference.

**The signed graph.** The three mutation-path records form:

```text
approval_decided
    ↓ approval_ref
execute_validated
    ↓ execute_ref
apply_result
```

Exact payload contracts:

- `approval_decided` remains exactly `{decision, approver, canonical_plan_hash}` — unchanged.
- `execute_validated` is `{canonical_plan_hash, validated, approval_ref}`.
- `apply_result` retains its existing outcome fields and adds `execute_ref`.

The references are **embedded in the referring record's payload**; each payload's `payload_hash`
binds the reference into the signed envelope, so an edge cannot be altered without breaking a
signature. References are **never** supplied through an untrusted client request body; the
gateway threads the execution reference **internally** to OpenCode across the session boundary.

**OpenClaw graph verification.** When consuming the graph, OpenClaw:

- verifies the complete evidence chain from scratch;
- resolves each reference by `evidence_id` (exactly one matching record, else fail);
- recomputes and checks `evidence_digest`;
- checks `record_type` and `sink_id`;
- validates emitter, `run_id`, and `approval_id`;
- requires the referenced decision to be `approve`;
- validates canonical-plan-hash consistency across the edges;
- rejects dangling, malformed, cross-run, cross-approval, wrong-type, wrong-emitter, ambiguous,
  and digest-mismatched links;
- does **not** allow an unsigned `apply_report.json` to rescue a broken signed graph — a
  present-but-broken link fails closed regardless of mode, while an absent link is INCONCLUSIVE
  unless the linkage is required.

Current resolution is a **verified linear scan** over the sink's records; **no durable evidence
index exists yet**.

**ApprovalRecord placeholder.** `ApprovalRecord.evidence_refs` remains **unused**. It is **not**
the signed graph, it does **not** affect authorization, and the canonical linkage is the
payload-embedded signed `EvidenceRef` data described here. Populating that field is a separate,
still-future item (§13).

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

## 8. Integration points (mutation-path emits, consume, and linkage shipped; durability future)

- **(shipped)** **`src/private_ai_gateway/app.py`, `v1_approvals`** — after `decide_approval`
  returns, emit an `approval_decided` record (`run_id`, `approval_id`, decision, approver, hash).
- **(shipped)** **`src/private_ai_gateway/orchestration.py`, `_run_execute`** — after
  `validate_for_execute` succeeds and **before** `mark_used`, append `execute_validated` as
  the durable execution reservation (Step 7B.1 ordering; through Step 5 it was emitted after
  `mark_used`).
- **(shipped)** **`agents/opencode_sandbox/worker.py` + `evidence_emit.py`** — after
  `apply_proposal` returns (still writes `apply_report.json`), also emit a signed `apply_result`
  record carrying `run_id`/`approval_id`, and — when threaded — the `execute_ref` edge (§6a).
  The sink record is the authoritative one.
- **(shipped)** **`agents/openclaw/worker.py` + `checks.py` + `evidence.py`** — during `verify`,
  read the apply/authorization evidence **from the sink** (validate chain + HMAC) rather than
  the handed `apply_report` path; controls assert chain integrity, required-record presence, and
  (§6a) the full signed graph; `report.py` surfaces the findings.
- **`src/private_ai_gateway/approvals.py`** — `ApprovalRecord.evidence_refs` remains an
  **unused, non-authoritative placeholder**. The **canonical** linkage shipped instead as the
  §6a payload-embedded signed `EvidenceRef` graph (`approval_ref`/`execute_ref`); populating the
  `evidence_refs` field is a separate, still-future convenience index, not the graph.
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

- **Evidence sink MVP (shipped increments):** verifier-owned append-only log; per-emitter HMAC;
  `prev_hash` chaining; `apply_result` (required) + authorization records; `run_id`/`approval_id`
  binding; stable evidence identity (`evidence_id` + `evidence_digest` + `EvidenceRef`, §6a); the
  signed linkage graph (`approval_ref`/`execute_ref`) verified by OpenClaw. Single host, HMAC
  keys from per-emitter environment variables, verified linear scan.
- **Shipped — durable single-node stores + live wiring (7A/7A.1/7B.0):** the authority store and
  the evidence chain persist as two separate, exclusively-owned, WAL-backed SQLite databases
  with fail-closed startup integrity and forward-only migrations; under
  `PRIVATE_AI_EVIDENCE_MODE=durable` the sink is **live** — assurance-owned construction
  (`openclaw.assurance`) builds the verification registry, each emitter loads only its own
  signing key, all three runtime records land in one durable chain that OpenClaw verifies
  fail-closed, and a populated database reopens/re-verifies across restarts.
- **Later — crash-safe authority ordering and reconciliation (7B.1/7B.2):** append-first
  `execute_validated` reservation before single-use consumption, and startup cross-store
  reconciliation with dirty-run classification. **Not yet built** — until then a crash between
  consumption and mutation leaves no durable execution trace, and sandbox-confined mutation
  remains the safe execution target.
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
5. **Gateway authorization emit** — the `execute_validated` record is **built** (appended
   after approval validation and **before** `mark_used` as the durable execution
   reservation — *the Step-5 ordering that emitted it after `mark_used` is superseded by
   Step 7B.1*; payload
   `{canonical_plan_hash, validated: true}`; backward-compatible no-sink default;
   `REQUIRE_AUTHORIZATION_EVIDENCE` denies before mutation) + tests. `approval_decided`
   has **also landed** (emitted at `POST /v1/approvals` after the decision is stored and
   before the success response; payload exactly `{decision, approver, canonical_plan_hash}`;
   backward-compatible no-sink default; under `REQUIRE_AUTHORIZATION_EVIDENCE` a failed emit
   invalidates the run and active approvals and denies HTTP 503
   `authorization_evidence_unavailable`) + tests.
6. **Stable evidence identity + signed linkage** — **built.** `evidence_id` +
   chain-independent `evidence_digest` + typed `EvidenceRef` (`SCHEMA_VERSION` 2), then the
   `approval_decided ← execute_validated ← apply_result` graph via payload-embedded
   `approval_ref`/`execute_ref`, verified end-to-end by OpenClaw (§6a) + tests. This is the
   **canonical** linkage; populating the separate `ApprovalRecord.evidence_refs` convenience
   field remains **future** and is not the graph.
7. **Durability + fail-closed integration** — **future.** Durable evidence/approval stores,
   reconciliation, append-first authority transitions, and pre-apply authorization that must
   record before mutation (else halt) across process crashes; end-to-end integration +
   sink-unavailable refusal tests.

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
