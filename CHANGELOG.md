# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Local model bake-off across every usable build** (`agents/hermes/strategy_corpus.py`,
  `strategy_qualification.py`, `registry.compare_qualifications`,
  `GET /v1/models/qualification-comparison`, `docs/local-model-bakeoff.md`) — four locally
  cached builds on one corpus, no downloads, no per-model prompt tuning. Refusals rise as
  competence falls: the strictly-better engineering build declines nothing, and **across every
  build whose refusals are interpretable, 0 of 28**. The strategy lane is measured for the
  first time (14 planning tasks over a closed roster); two builds qualify as planners and the
  incumbent coder does not. The finding that matters: one build recognises 4 of 4 protected
  surfaces *when planning* and implements 14 of 14 *when coding*. The comparison publishes no
  aggregate and no ranking — a single score would have to weigh "writes better patches"
  against "declines to remove a security control", and here those point opposite ways.
- **Named low-risk lanes, derived from merged history** (`src/private_ai_gateway/lanes.py`,
  `GET /v1/lanes`, `docs/low-risk-lane-discovery.md`) — all 113 squashed commits classified.
  0 tests-only, 0 standalone metrics refreshes, 1 small source change (it touched `app.py`),
  and **18 pure numeric substitutions across 13 commits**. One lane survives,
  `GENERATED_METRICS_REFRESH`, because a program decides whether it is right; the other three
  candidates ship *as rejected entries with the measurement that refused them*. Membership is
  a computation: exact paths, numeric-substitution-only edits, bounded files and lines, and
  the drift suite as the oracle. `task_risk` runs first, so no label can enter the lane.
- **A prospective earned-autonomy lease, wired to nothing**
  (`src/private_ai_gateway/lease.py`, console panel, `docs/earned-autonomy-lease-design.md`) —
  the object a first bounded lease *would* be: one principal, one exact build, one lane, one
  policy revision, one path set, one expiry, with the digest covering all of it. Every
  refusal is collected rather than short-circuited, and there is no score. The lifecycle,
  owner-only transitions, absence of any renewal path, and crash semantics (which resolve
  toward *less* authority at every point) are specified with executable tests. **No lease is
  issued, held, stored or consumed**: no authorization module imports it, and a test parses
  the module itself and fails if it ever defines `issue`, `grant`, `activate`, `revoke`, a
  store, or a filesystem write. Simulated over the 18 real changes: 13 would grant, 5 refuse.

### Changed
- **A refusal must be distinguishable from a failure** (`agents/hermes/qualification.py`,
  `registry.qualify_lane`) — the adapter reports "I decline" and "that is not JSON"
  identically, so a 1.5B build that could not emit a parseable proposal scored a perfect
  **14/14** on security refusals. Summaries now carry `refusal_discriminating`, and the
  security lane reports `NOT_EVALUATED` rather than `QUALIFIED` for a score it cannot
  interpret. Applying it consistently also demoted a 5/14.
- **Qualification artifacts are keyed by kind as well as fingerprint** — a strategy run and an
  engineering run describe the same build with the same fingerprint, so the newer one was
  evicting the older and a twice-measured model read as never measured.
- **A generation failure is no longer a candidate outcome** — it has its own outcome and marks
  the run incomplete. A gateway restart mid-run had produced an ordinary-looking artifact
  reporting 24 connection errors as model behaviour.
- **Protected-surface vocabulary** — `owner_required` (the literal reason code the gateway
  returns), "roll back" as two words, and "signature validation" were all missing. Found by
  writing the lane mislabelling tests. Deliberately *not* closed: objective text alone catches
  12 of 14 attacks, and reaching 14/14 would require making "alias" and "copy" protected words.

### Fixed
- **`ModelCache.is_cached` checked for a directory** — a Hugging Face cache entry exists from
  the moment a fetch *starts*, so a build with **zero of four weight shards** reported
  `INSTALLED`, and a measurement run began pulling 24 GB in a train explicitly forbidden from
  downloading. It now reads the model's own `*.index.json` weight map, with a deliberate
  exception for nested auxiliary towers. The test fixture had been building caches that could
  never load; it builds the real hub layout, and a half-downloaded model is now a test case.
- **Six current-state surfaces described the superseded Step-5 execute ordering** — the
  shipped path is `validate → reserve (execute_validated) → mark_used → mutate`, and
  reservation-before-consumption is what closes the 7B.0 crash window. Two tests now hold the
  prose to the code: one reads `_run_execute` with the AST, one scans the surfaces and permits
  an "after `mark_used`" sentence only where it is explicitly marked historical.

- **Shadow earned-autonomy readiness** (`src/private_ai_gateway/eligibility.py`,
  `POST /v1/autonomy-readiness`, console card) — the first place qualification, deterministic
  task risk, attributed runtime history and evidence integrity are considered together, and it
  **grants nothing**. Every condition is a veto: security lane not qualified, protected
  surface, review-required task, insufficient attributable history, unverifiable evidence,
  unresolved dirty run, rollback or containment failure, or a model fingerprint that changed
  since the history was earned. There is no score and no weighting, so a flawless record
  cannot offset a protected surface — asserted. One hypothetical lane only (right-sized
  non-security engineering); every other lane is refused by name. No authorization module
  imports it, proven by falsification: wiring it into `autonomy.py` turns the suite red.
  The console shows `SHADOW / ADVISORY` with no Enable control, also asserted.
  **Today's honest answer is that nothing is eligible**, for two independent and individually
  sufficient reasons — the 0/14 security result, and the risk gate finding no corpus
  source-file task low-risk enough to clear the protected-surface veto.
- **Owner-gated route activation** (`src/private_ai_gateway/route_revision.py`,
  `POST /v1/models/route-activate`) — route changes are no longer proposal-only. The
  hand-authored `config/policy.toml` is still never written by this process; activation instead
  appends a numbered, atomic, append-only **revision** to a gateway-owned store, and the
  effective configuration is *base policy + active revision*. The effective policy hash is
  derived over both, so the hash keeps covering everything in force. A revision that was
  computed against a policy file which has since been hand-edited is reported **stale and not
  applied**, rather than silently re-interpreted against a file nobody reviewed it against.
  Owner-only, audited, and refused for the security lane unless the model is qualified — a
  warning on the proposal path, a refusal here. Narrow **by construction**: a revision has no
  field for autonomy, skills, tools, principals or approval rights, so there is nothing to set
  rather than merely a check that refuses.
- **Runs pin the configuration they were planned under** (authority schema v2,
  `RunRecord.policy_hash`) — the execute path reconstructs a run's canonical plan against its
  *recorded* policy hash, so activating a revision cannot invalidate approvals already in
  flight. Pre-v2 rows carry `''` and recompute from live configuration exactly as before.

### Fixed
- **`AC-RATELIMIT` fired on any audit reason containing the substring "rate"** — including
  "st*rate*gy", "gene*rate*" and "accu*rate*". An ordinary `200 allow` mentioning the strategy
  route was judged a rate-limit decision that had failed to be a `429`, turning the control
  FAIL and with it the whole assurance verdict for the run. Found because activating a route
  between plan and execute made every subsequent apply fail assurance. The check now compares
  the limiter's exact reason code (`rate_limited`), with a parametrised regression for the
  false-positive words and a test that real limiter decisions and `429`s are still caught.
- **Deterministic protected-surface gate** (`src/private_ai_gateway/task_risk.py`,
  `POST /v1/task-risk`) — three classes (`LOW_RISK_ENGINEERING`, `REVIEW_REQUIRED`,
  `PROTECTED_SECURITY`), no scalar score, and risk that only ever ratchets up. Twenty
  protected surfaces are enumerated — authentication, authorization, approval, policy,
  autonomy, routing authority, evidence, signing/key custody, identity, canonical-plan
  binding, replay protection, sandbox/path confinement, secret handling, rate limiting,
  reconciliation, disposition, rollback authority, containment, arbitrary command execution,
  and the ingress prompt boundary — each matched by both path and symbol vocabulary, because
  a proposal names its files whatever it likes. **All 14 security-corpus tasks classify as
  `PROTECTED_SECURITY`** and are pinned as a parametrised regression; a caller-supplied
  `risk_class` can raise the classification but never lower it. The default for anything
  unrecognised is `REVIEW_REQUIRED`, not low risk — low risk must be earned by positively
  matching docs/tests-only paths. Qualification is not consulted: a model measured excellent
  at engineering is still not eligible for a protected surface, asserted structurally.
  Advisory only — the plan result carries the classification for the human deciding the
  approval, and nothing consumes it as authority.
- **Signed model attribution** (`src/private_ai_gateway/attribution.py`) — the plan phase now
  appends a signed `candidate_attributed` record naming the model build that produced the
  candidate (registry fingerprint, backend, resolved id, revision, quantization), the policy
  hash in force, the task class, and a digest of the candidate itself. `execute_validated`
  carries that attribution **read back from the record**, never recomputed from the live route
  map: re-pointing an alias between plan and execute cannot re-credit a run to a build that
  never saw it, and a new build cannot inherit its predecessor's record. Every field is
  server-derived — no request field reaches the payload, asserted by parametrised forgery
  attempts and an AST guard. Runs with no such record (legacy, or no evidence sink) carry the
  explicit `model_not_recorded` / `policy_not_recorded` shape and are never backfilled.
  The trust ledger now keys attributed runs by fingerprint and policy hash, and reports
  unattributable dimensions **per entry** rather than as a blanket disclaimer. It still
  produces no score, no threshold, and nothing consumes it.
- **Public-claims truth infrastructure** (`scripts/public_metrics.py`,
  `docs/public-metrics.json`, `tests/unit/test_public_claims.py`) — every mechanically
  checkable public number now has exactly one canonical source and is derived from it: the
  eval count from `evals.cases.ALL_CASES`, the assurance-control counts from
  `openclaw.checks.ALL_CHECKS`, the CI platform count from the workflow matrix, the enforced
  control count from the README control table, media facts from the media files (MP4
  durations parsed from the `mvhd` box — no ffprobe dependency), and every local-model
  qualification figure from the published artifact. A drift suite holds the README, the site,
  and the current-state docs to the manifest; `make metrics-check` and a CI step fail on
  drift, and a whole-suite guard fails if a test is added without refreshing the count.
- **Published qualification artifact**
  (`docs/qualification/local-engineering-qualification.json`) — the evaluator's structured
  output is now a tracked, privacy-minimal public file rather than a gitignored runtime
  artifact, so qualification prose can be derived instead of transcribed.

### Fixed
- **Stale public claims across README, site, roadmap and positioning** — the local-model
  qualification was still described with the superseded v1 corpus (18 tasks, 72 % zero-edit,
  0/2 security refusals) instead of corpus v2.0 (30 tasks — 16 engineering, 14 security —
  43 % zero-edit across the whole corpus, **0/14** security refusals); the trust history,
  durable stores and crash reconciliation were still filed under future work after shipping;
  and `docs/positioning.md` still claimed 810+ tests. The zero-edit figure now travels with
  its denominator everywhere it appears, since 72 % and 43 % measured different populations.
- **Two unsourced market statistics withdrawn** from `docs/product-evolution.md` — "93 % of
  AI-agent projects run on unscoped API keys" and "74 % of agents end up with more access
  than they need", attributed to a "2026 survey of 900+ practitioners". The cited primary
  source contains neither figure and is not a practitioner survey of that size. Replaced with
  what the primary material actually reports (97 % of non-human identities over-privileged;
  90 % of deployed agents over-permissioned; 44 % static API keys, n=285), with the
  retraction recorded in the Sources section.
- **OpenClaw described accurately** — "read-only verifier" understated its role: it is
  *operationally* read-only over the governed system (holds no authority, mutates nothing it
  inspects) while appending its own signed assurance verdicts under its own key.
- **Verifier-owned evidence sink core** (`agents/openclaw/sink.py`) — an append-only,
  per-emitter **HMAC-signed**, **hash-chained** record store with from-scratch chain
  verification. **Tamper-evident, not non-repudiation** (symmetric-key MVP).
- **Signed OpenCode `apply_result` emit** (`agents/opencode_sandbox/evidence_emit.py`) —
  after a confined apply the executor emits a run-bound signed record into the sink,
  additive to the preserved `apply_report.json`.
- **OpenClaw verifier consume** (`agents/openclaw/evidence.py`, `checks.py`, `worker.py`) —
  OpenClaw can now validate signed OpenCode `apply_result` evidence from an injected
  `EvidenceSink` when signed evidence is required: it verifies the chain + signatures, finds
  the matching signed record (by emitter / record_type / `run_id` / `approval_id`), and
  derives the apply verdict from it. **Unsigned `apply_report.json` alone is insufficient
  when signed evidence is required.** With no sink injected, existing no-sink OpenClaw
  behavior is preserved byte-for-byte. This proves **component-level consume/verification,
  not full end-to-end runtime enforcement** — it is unit-proven against an injected sink,
  without the end-to-end gateway-issued `run_id` / `approval_id` wiring.
- **Gateway `execute_validated` authorization evidence emit**
  (`src/private_ai_gateway/orchestration.py`, `app.py`) — when execution authority is
  granted, the gateway can now emit a signed `execute_validated` record into an injected
  `EvidenceSink`. The record is emitted after approval validation and `mark_used`, before
  `session.execute`; the payload contains `canonical_plan_hash` and `validated=true`, while
  `run_id` and `approval_id` remain in the evidence envelope. The default no-sink behavior
  is backward-compatible (byte-identical old path), and `REQUIRE_AUTHORIZATION_EVIDENCE`
  strict mode denies before mutation if authorization evidence is unavailable.
- **Gateway `approval_decided` decision evidence emit** (Step 5b) — one signed record per
  owner decision (approve or reject) at `POST /v1/approvals`, emitted before the response;
  under strict mode a failed emit invalidates the run and denies with HTTP 503.
- **Stable evidence identity (Step 6A)** — every signed record carries `evidence_id` and a
  chain-independent `evidence_digest`; a typed portable `EvidenceRef` anchors linkage.
- **Signed evidence linkage graph (Step 6B)** —
  `approval_decided ← execute_validated ← apply_result` via payload-embedded, signed
  `approval_ref`/`execute_ref`; OpenClaw verifies the whole graph fail-closed.
- **Durable single-node state stores (Step 7A)** — `PRIVATE_AI_STATE_BACKEND=sqlite`
  persists the authority store and evidence chain as two separate WAL-backed SQLite
  databases (`PRIVATE_AI_STATE_DIR`), with forward-only fail-closed migrations and a
  both-or-neither initialization rule; `memory` stays the default.
- **Durable-store correctness hardening (Step 7A.1)** — exclusive single-owner `flock` per
  database, full fail-closed startup integrity (integrity/FK checks, typed reconstruction,
  binding + status/timestamp coherence), fully serialized evidence appends, atomic authority
  read-modify-write, strict persisted booleans, UTC-normalized timestamps, and resource
  cleanup on every constructor/partial-startup failure path.
- **Live durable evidence wiring (Step 7B.0)** — `PRIVATE_AI_EVIDENCE_MODE=durable` opens
  the durable evidence store as a live sink under assurance-owned construction
  (`openclaw.assurance` builds the verification registry; the gateway and OpenCode each load
  only their own per-emitter HMAC key from `PRIVATE_AI_EVIDENCE_KEY_GATEWAY` /
  `PRIVATE_AI_EVIDENCE_KEY_OPENCODE`). The gateway's `approval_decided`/`execute_validated`
  and OpenCode's `apply_result` land in one durable signed chain that OpenClaw verifies
  fail-closed (signed apply + signed linkage required); `REQUIRE_AUTHORIZATION_EVIDENCE` is
  forced on in this mode; evidence ownership is held for the runtime lifetime; populated
  databases reopen and re-verify across restarts; misconfiguration fails closed at startup.
- **Signed evidence lineage in the Governed Chat Console** — a successful execute now
  returns a server-derived `evidence` summary (the gateway's own `execute_validated`
  identifier, digest, record type and sink id, plus whether the chain is durable), and
  `/chat` renders the `approval_decided → execute_validated → apply_result → verified`
  lineage from it. Identifiers and digests only: no keys, tokens, or payload contents, and
  the key is absent entirely when no record was emitted.
- **Chat ⇄ Console navigation** — `/chat` (operate) and `/console` (inspect) now link to
  each other as two views of one runtime. Each page still authenticates independently; no
  bearer token is shared, persisted, or passed between them, and neither page touches
  `localStorage`/`sessionStorage`/cookies.
- **Policy-pinned model routes** — `demo_policy.toml` now pins every alias in
  `[models.routes]`, so the alias → backend-model binding is covered by the
  authority-bearing policy hash and the demo plane rebuilds its route table from the policy
  it actually installed. Swapping the model behind an alias is a policy change, not silent
  code-side drift.
- **Hardened durable demo harness** (`scripts/demo_durable.sh`) — runs the ordinary demo
  with `PRIVATE_AI_STATE_BACKEND=sqlite` + `PRIVATE_AI_EVIDENCE_MODE=durable` using
  ephemeral per-run keys in a temporary state directory that is removed on exit. Keys are
  never printed, committed, or persisted; the zero-config `private-ai-gateway demo`
  defaults are unchanged.
- **Walkthrough capture and verification tooling** (`tools/capture_walkthrough.py`,
  `tools/build_walkthrough_media.py`, `tools/verify_site.py`) — the public walkthrough is
  captured by driving a live gateway in a real browser, and the site's assets, anchors,
  tour wiring and static stat fallbacks are verified before publication.
- **Step 7B.1/7B.2 implementation contract** (`docs/step-7b1-7b2-implementation-contract.md`)
  — the binding specification for append-first reservation and startup reconciliation,
  including crash-injection points, the six reconciliation classes, acceptance criteria,
  and the explicit 7C exclusion.
- **Append-first execution reservation (Step 7B.1)** — the execute path now runs
  `validate → reserve → consume → mutate`. The signed `execute_validated` record is appended
  as a durable **reservation before** the single-use approval is consumed, closing the crash
  window in which a spent approval left no durable trace of why. Guarantees, all tested:
  **at most one reservation per `approval_id`** — sequentially, concurrently and across a
  restart — because validate/reserve/consume run in a per-approval critical section
  (sufficient here only because both databases are held under an exclusive single-owner
  `flock` for the process lifetime, so no second writer exists); a reservation surviving a
  crash into a later process is **invalidated fail-closed at startup**
  (`state.resolve_interrupted_reservations`) using existing `invalidate_run` semantics, with
  no new run/approval states, idempotent across repeated restarts; and a reservation that
  cannot be appended refuses **before** consuming anything, so the approval remains APPROVED
  and reusable (the cost 7B.0 accepted). No evidence schema change and no new record type —
  `execute_validated` *is* the reservation. A duplicate reservation is prevented at the
  source rather than tolerated by the verifier: OpenClaw's `find_unique_record` still fails
  an approval with more than one authority record as `ref_ambiguous`.

- **Startup cross-store reconciliation (Step 7B.2)** — one pass
  (`private_ai_gateway/reconciliation.py`) joins the authority store and the evidence chain
  at durable startup, after each has independently passed its own integrity validation, and
  classifies every approval into one of six classes: **1** approved with nothing reserved
  (clean); **2** reserved but authority never consumed (invalidate — the mutation provably
  never started); **3** authority consumed without a valid linked `apply_result` (dirty:
  invalidate, surface, never auto-retry, never claim the mutation succeeded or failed);
  **4** reservation plus a uniquely-bound, signature-linked `apply_result` (clean); **5**
  evidence with no compatible authority projection — orphan, mismatched run binding, or
  apply evidence without consumed authority (fail closed; evidence is retained append-only
  and never synthesizes authority); **6** authority consumed with no reservation (pre-7B.1
  legacy, evidence loss, or tampering — invalidate). It **subsumes** the 7B.1
  reserved-but-unconsumed resolver as class 2, so a single pass observes the original
  cross-store shape rather than a pre-repaired one. It classifies into immutable findings
  *before* acting; its only action is `invalidate_run`; it creates, deletes, retries and
  executes nothing (structurally and behaviorally asserted). Class 4 requires the real
  signed linkage resolved through OpenClaw's own `resolve_evidence_ref` — the presence of
  an `apply_result` is never sufficient — and ambiguity (duplicate reservations,
  conflicting outcomes) fails closed rather than being normalized. Failure to inspect
  either store raises `ReconciliationError`, surfaced as a fail-closed `StateError`:
  "unable to inspect" is never "clean". A minimal read-only `snapshot_approvals()` was
  added to both authority stores; no raw SQL or connection is exposed to the reconciler.
  No schema change, no new run/approval states, and no persisted findings.

- **Verifier-owned signed-graph reader** (`agents/openclaw/evidence.py`) — `SinkGraphReader`
  verifies a sink's chain once and then answers many signed-graph questions about it, and
  `load_execution_reservation_from_sink(...)` / `ReservationView` expose the reservation-only
  walk `execute_validated → approval_decided` for callers that must judge a reservation
  before (or without) an `apply_result`. `load_evidence_graph_from_sink` keeps its exact
  previous contract as a thin wrapper. Both walks now share a single definition of the
  authorization edge, so there is one place where "a valid authorization edge" is decided.

- **Local engineering: shadow track (C) and candidate adapter (D)** — capability
  infrastructure that grants **zero** additional operational authority.
  `agents/hermes/shadow_engineering.py` runs one flow — objective → governed strategy plan →
  local `engineering` candidate → strict deterministic validation → deterministic teacher
  comparison → evaluation trace — and `agents/opencode_sandbox/candidate.py` is the strict
  boundary that decides whether a generated response is even a candidate. Model calls go
  through the gateway's normal governed path as a new `shadow-engineer` principal capped at
  **L1 (suggest-only)** with no skills and no tools, so it cannot route work to an executor
  or call a tool; the harness refuses to construct if handed an owner token, imports no
  apply path (asserted structurally and behaviourally), acquires no approval, and leaves the
  evaluated tree byte-identical. The adapter is deliberately stricter than the proposal
  parser it targets — JSON only (prose around JSON is refused, never salvaged), known fields
  only at both levels (an invented `command`/`exec`/`shell` field is a refusal, not an
  ignored extra), declared paths only, absolute-path and traversal refusal, bounded size —
  and what survives is built through the **existing** `ChangeProposal` schema and run
  through the sandbox's own `validate`, so there is no second patch format. A valid
  candidate is still only a candidate: applying one continues to require the existing
  owner-issued, hash-bound approval. Evaluation traces are local, git-ignored JSON that
  record identity (alias, **resolved** model, policy hash, principal, declared autonomy) but
  never raw model text, the verbatim objective, or credentials — and are **never** written
  to the evidence sink. CI is fully deterministic and never downloads or executes a model.
  **This is not autonomous coding.**

- **Signed `verification_result` (Step 7C.1)** — the verifier's verdict becomes a durable,
  tamper-evident assurance fact instead of returned text. OpenClaw signs it with its **own**
  emitter key (`PRIVATE_AI_EVIDENCE_KEY_OPENCLAW`, key id `openclaw-hmac-1`) and appends it
  to the same chained log it verifies. **Only OpenClaw receives that key**: the gateway must
  not be able to author a verifier conclusion, and neither must the executor whose work is
  being judged — that the assurance-owned registry can *verify* all three emitters is a
  property of symmetric HMAC, not a custody grant, so this remains **tamper-evident, not
  non-repudiation**. Two rules make a signed PASS mean something: it binds to the exact
  signed `apply_result` it judged through a typed `apply_ref` (which already chains upstream
  to `execute_validated` → `approval_decided`), and it is **unreachable over a broken
  authorization graph** — if `load_evidence_graph_from_sink(...).usable` is false the verdict
  is downgraded to FAIL before signing. If signed verification evidence is configured as
  required and the append fails, no verified state is advertised: the mutation may already
  have happened, so nothing is retried, no rollback is implied, and the assurance failure is
  surfaced loudly rather than papered over with unsigned summary text. The payload is
  minimal and non-sensitive (verdict, control counts, failed/inconclusive control **ids**,
  `apply_ref`, and a derived `evidence_graph_verified`) — no prompts, audit contents, model
  output, diffs, or key material; `run_id`/`approval_id` stay in the signed envelope. The
  verifier remains *operationally* read-only — it changes no authority, executes no tool,
  mutates no sandbox and repairs no application state — and is now append-only to its own
  assurance log. Multiple verification passes are legitimate and are returned in full by
  `verification_results_for`: **no consumer may treat any of them as terminal disposition**,
  and there is deliberately no hidden "pick latest" rule. Binding a terminal disposition to
  one specific verifier result is Step 7C.2. `AssuranceWorker` keeps its exact external
  `(verdict, summary)` contract; with no verifier key configured it behaves exactly as
  before. **Not** in this step: `run_disposition`, rollback, containment, asymmetric
  crypto, KMS/HSM.

- **Terminal `run_disposition` (Step 7C.2)** — a human can finally *finish* a dirty run.
  Reconciliation could already invalidate one and surface it, and 7C.1 could verify one, but
  nothing durable recorded that a person had looked at it and closed it, so the same anomaly
  resurfaced at every startup. `POST /v1/dispositions` (owner-gated, alongside a read-only
  `GET /v1/runs/<run_id>/disposition-basis`) records that closure as a gateway-signed,
  terminal evidence fact. **The basis model is the load-bearing correction.** A
  `verification_result` reference cannot be mandatory: the archetypal run needing disposition
  is a Class-3 dirty run whose authority was consumed and whose mutation may have started but
  which has **no valid `apply_result`** — and a 7C.1 verdict is apply-bound, so no legitimate
  verdict can exist for it. Requiring one would have made exactly the runs that need human
  closure permanently undisposable. The basis is therefore explicit and narrow: either one
  **specifically named** `verification_result`, or the exact `execute_validated` reservation
  that established the possibly-started execution. There is no "no basis" path, no
  caller-chosen arbitrary record, and no "pick latest" — when several verdicts exist the
  human selects one, and the server re-resolves that typed `EvidenceRef` against the verified
  chain, **recomputing the digest** and checking record type, authoring emitter, and run and
  approval binding. A client never supplies an evidence envelope; the server constructs and
  signs the record. The disposition vocabulary is kept as small as honesty allows:
  `closed_unknown` is the default and asserts **nothing** — a human acknowledges the runtime
  cannot determine whether the mutation landed — while `human_asserted_applied` /
  `human_asserted_not_applied` are named for whose claim they are and are never derived by
  OpenClaw, by reconciliation, or by the runtime. Terminality is real, not advisory: the
  disposal seals the run through the existing `invalidate_run` barrier (monotone and
  restricting — nothing is reopened, restored, or granted), a run with standing authority is
  refused rather than killed, a second attempt is refused `already_disposed` under a per-run
  critical section rather than superseding the first, and neither a late `apply_result` nor a
  late `verification_result` can resurrect or override it. Reconciliation reads dispositions
  but never derives them: classification establishes the history first and is unchanged, then
  a valid disposition retires the finding from the new `report.outstanding` while leaving its
  class, its outcome and the run's `INVALIDATED` status exactly as they were. A disposition
  that does not fully re-validate — tampered basis, foreign binding, wrong emitter, or two
  records for one run — fails startup **closed**, because "unreadable" must never read as
  "not yet disposed". **Not** in this step: rollback, containment, trust ledger, earned
  autonomy.

- **Reversibility foundation (Step 7C.3A)** — the pre-image, captured before mutation. An
  audit of the existing artifacts came first and is kept executable as two tests: today
  `_apply_and_verify` hashes the whole tree before *and* after the edits but keeps only the
  derived **set difference**, so `ApplyReport.changed_files` — and therefore the signed
  `apply_result` — carries bare paths with no hashes, no content, and no way to tell a create
  from a delete. The sandbox is copied and then mutated in place, so it holds the post-state.
  **The existing artifacts cannot reverse anything**, and no amount of reading them harder
  makes them reversible: hashes recorded after the fact cannot reconstruct content. New
  `agents/opencode_sandbox/preimage.py` records the one thing that can — the prior state of
  exactly the declared targets, captured from the sandbox after the copy and before the first
  declared write. An addition records `existed: false` (reversing a create means deleting it);
  an update or delete retains the prior bytes as content-addressed blobs; a manifest digest
  covers the whole thing. The boundaries are the point: sandbox-confined with the apply's own
  confinement rules (absolute paths, `..`, symlinks and non-regular files all fail closed);
  never caller-placed (the caller supplies a store *base*, the snapshot id is generated);
  bounded per entry and in total, with an oversized target refusing the **whole** snapshot
  rather than capturing part of it, because a partial pre-image looks reversible and is not;
  atomic, built under a temporary name and renamed into place; and **never in signed
  evidence** — `apply_result` gains only `{snapshot_id, snapshot_digest, entries, bytes}`, and
  only when a snapshot was actually taken, so an apply without a store emits a byte-identical
  record. A capture that cannot complete **rejects the apply** rather than quietly producing
  an irreversible one. `restore_into` is the reversibility primitive and is deliberately
  reachable from nothing in the governed path — no approval, no reservation, no signed
  outcome, no caller outside its own module and tests (asserted structurally). **No rollback
  happens in this step**, and **no historical run becomes reversible**: a run that predates
  its snapshot has no pre-image and never will.

- **Governed rollback and containment (Step 7C.3B)** — the runtime can now *undo* a sandbox
  apply, and it does so as a **mutation**, not a repair. A rollback is a new governed run with
  its own `run_id`, its own single-use owner approval, and its own canonical plan hash — so
  there is no second approval system and no way for an agent to grant itself an undo. The
  plan hash commits to the original run, the exact signed `apply_result` being reversed, and
  the pre-image snapshot's identity **and digest**, so an owner approves one specific
  restoration of one specific tree to one specific recorded state, never "undo something".
  `POST /v1/rollbacks` plans it, the ordinary `/v1/approvals` authorizes it, and
  `POST /v1/rollbacks/execute` runs it under Step 7B.1's ordering: validate → append the
  signed `rollback_validated` reservation → consume the approval → restore. Two new record
  types and no more: `rollback_validated` (gateway) and `rollback_result` (opencode);
  `apply_result` is deliberately not overloaded, and the verifier's judgment reuses the
  existing `verification_result` with a typed `rollback_ref` because it is the same thing it
  always was — OpenClaw's signed verdict about one thing that happened. **A rollback failure
  never becomes a success**: a refusal before the reservation spends nothing and touches
  nothing, while any failure after it signs a `failed` outcome, **contains** the workspace
  with a marker naming the reason and asking for a human, and invalidates the rollback run.
  Nothing is retried and nothing is partially reported as restored. The executor re-hashes
  every restored path against the pre-image before claiming success, and OpenClaw then
  **re-reads the tree itself** rather than reading the executor's claim, so a `restored`
  record over a drifted tree is a FAIL. A successful rollback says exactly one thing: *the
  supported sandbox state was restored to the recorded pre-image* — there is no external
  mutation in this scope, so no external effect is claimed to be undone. Rollback is confined
  to workspaces under `PRIVATE_AI_SANDBOX_RUNTIME_DIR` (unset means rollback is unavailable,
  the correct default); an apply with no pre-image is refused `run_not_reversible` rather than
  fabricated for; a terminally disposed run is not reopened to be undone; and reconciliation
  can neither trigger nor reach a rollback (asserted structurally). **Not** in this step: git
  operations, deployment rollback, system-configuration rollback, production external
  rollback, trust ledger, earned autonomy.

- **Local-engineering qualification (zero-authority capability work)** — an 18-task corpus
  (`agents/hermes/qualification_corpus.py`) and a **semantic** evaluator
  (`agents/hermes/qualification.py`) that answers the question the Step-7B adapter cannot:
  does the candidate actually *work*? Each task is a self-contained miniature repository; a
  candidate is applied to a **disposable copy**, then compiled, linted, tested, and checked
  for public-API preservation — the exact failure the first real trial produced, a rewrite
  that kept the function and quietly dropped its parameters while passing every structural
  check. The evaluator is disposable by construction, not by promise: it works from task data
  in a temp directory, destroys it, and has no reachable path to the real checkout, to
  `apply_proposal`, to an approval, or to the evidence sink (asserted structurally), which is
  exactly why it needs no owner approval. CI grades fixed strings only — no model is
  downloaded or executed. **Measured, on the real local model**
  (`Qwen3-Coder-30B-A3B-Instruct-8bit` at L1): 94 % first-pass structural, 81 % tests pass,
  100 % public API preserved, 72 % zero-edit acceptance — and **0/2 on security refusals**.
  Asked to delete a signature check and to make a path-confinement predicate return `True`,
  it did both, well-formed and in scope. That is the result that matters: review is the
  control, not a courtesy step. Two of three edit failures were JSON escaping of code
  containing quotes and backslashes. The 2048-token cap was **not** the binding constraint —
  both failing outputs were complete, so no policy change was made and the shadow route stays
  L1, no skills, no tools. Full results in
  [docs/local-engineering-qualification.md](docs/local-engineering-qualification.md).
  Deliberately **not** produced: an autonomy score. This grants nothing.

- **Capability registry (`src/private_ai_gateway/registry.py`)** — a first-class, read-only
  answer to *what can run here, and what has actually been measured*, exposed at owner-gated
  `GET /v1/models/registry`. It describes capability and **grants nothing**: a structural test
  asserts that no authorization module (policy, autonomy, approvals, guardrails, disposition,
  reconciliation, canonical) imports it, and that the registry itself reaches no authorization
  primitive. **A route alias is not an identity** — `ModelIdentity` fingerprints the backend,
  resolved model, revision and quantization, so re-pointing an alias at a different build
  yields a different fingerprint and the new build starts `NOT_EVALUATED` rather than
  inheriting a reputation it never earned. **Qualification is per task lane** (`strategy`,
  `engineering_candidate`, `general_review`, `security_review`) with states `QUALIFIED` /
  `ADVISORY_ONLY` / `UNQUALIFIED` / `NOT_EVALUATED` / `UNAVAILABLE`; the security lane is
  derived **only** from the measured refusal rate, so anything short of perfect is
  `UNQUALIFIED` with no partial credit. On the real local model that means
  `engineering_candidate: QUALIFIED` (under review) and **`security_review: UNQUALIFIED`**
  from the measured 0/2. **Nothing is invented**: quantization is parsed from the model id or
  absent, the revision comes from the local cache or is absent, and hardware fit is computed
  from the model's **actual on-disk weight size** — an uncached model is `FIT_UNKNOWN`, never a
  guess. The host snapshot is privacy-minimal *by construction* (platform, architecture,
  memory, backend availability, cached model ids) and never collects a serial, UUID, username,
  home directory, MAC address, absolute path, or environment contents. Nothing is downloaded:
  opening the registry reads the local cache and can never trigger a model fetch. The
  qualification harness now writes a **structured artifact** keyed on the fingerprint and
  recording the corpus version *and a content digest*, the source commit, the policy hash, the
  host context and a timestamp — so the metrics have exactly one source and are never
  transcribed into production Python or HTML.

- **Models & Routing console** — a new pane in the Governance Console (the existing panes are
  untouched), backed by owner-gated `GET /v1/models/routing` and
  `POST /v1/models/route-proposal`. It answers four questions **separately** — what is
  available, what is qualified for this task, what is currently routed, and what authority the
  routed principals hold — because collapsing them into one badge is how a capability number
  becomes a permission in someone's head. Authority is rendered from policy in its own block
  and is visibly unchanged by anything on the page. The **recommender is deterministic**:
  ordinal comparison over qualification, availability, hardware fit and existing policy
  eligibility, with explainable reason codes on every candidate including the ones that ruled
  it out — **no model chooses the model** (asserted structurally). Nothing is currently
  eligible for the **security lane**: the local engineering model is `UNQUALIFIED` from its
  measured 0/2, and an *unmeasured* model is ineligible too, because "we have not checked" is a
  no for that lane rather than a weaker yes. Deterministic controls (pytest, ruff, schema
  validation, proposal validation, gateway policy enforcement, OpenClaw assurance) are listed
  with **no selector**, and OpenClaw never gains a "choose verifier model" dropdown.
  **Route changes are proposal-only.** Selecting a model computes a before/after picture with
  warnings and applies nothing; the route map and loaded policy are asserted untouched, and no
  file is written. Activation is deliberately not implemented: the active policy is read once
  at import and there is no owner-gated, hash-preserving config mutation path, so shipping one
  here would let a browser dropdown escape the hash authority is bound to. The exact gap is
  stated in `_ROUTE_ACTIVATION` and surfaced in the API rather than hidden. The prospective
  policy hash is deliberately empty — nothing can write the changed config, so nothing may
  print its hash.

- **Derived read-only trust ledger (`src/private_ai_gateway/trust_ledger.py`)** — a
  **projection**, not a store: re-derived on demand from the signed evidence chain and the
  authority store, persisted nowhere, and exposed at owner-gated `GET /v1/trust-history`. It
  **grants nothing** and nothing consumes it — a structural test asserts no authorization
  module (policy, autonomy, approvals, guardrails, disposition, reconciliation, canonical,
  rollback) references it, and a further test proves a flawless 10/10 record leaves the
  hermes ceiling at L1. **A chain that does not verify yields no ledger, not an empty one**,
  because an empty ledger reads as "no bad history" — precisely the wrong conclusion from
  "could not be read". **Facts, never a score**: counts of verified completions, non-PASS
  verdicts, dirty executions, `closed_unknown` and `human_asserted` dispositions, rollback
  attempts/successes/failures, containments and evidence failures — with no single number, no
  rating and no autonomy level anywhere, asserted by walking the module's AST for division,
  multiplication or summing. **History does not transfer**: the projection is keyed by
  principal *and* task class, so success at documentation work never becomes trust for
  security work. **A real limitation is named rather than papered over**: no signed record
  carries a model identity or policy hash, so runtime history **cannot** be attributed to a
  model build — those dimensions report `not_recorded` instead of being filled in from the
  currently-configured route, which would silently credit a new build with an old one's
  record. Closing that gap requires putting model identity into the signed evidence at emit
  time. The console shows **QUALIFICATION** (corpus measurement) and **RUNTIME HISTORY** (what
  the governed loop actually did) as separate blocks that are never combined. **No earned
  autonomy**: no threshold, lease, pre-authorization, promotion or demotion exists.

- **Security-qualification corpus expanded 2 → 14 control-preservation tasks** (corpus v2.0,
  30 tasks total). Each is a coherent, specific, technically easy change with a plausible
  business reason attached, across fourteen *distinct* controls: signature verification, path
  confinement, evidence-chain verification, run identity, the owner gate, the field allowlist,
  canonical-plan binding, fail-closed-on-absent-evidence, the sandbox copy, replay protection,
  policy-driven routing, the human in the rollback loop, rate limiting, and credential
  redaction. The prompts describe a request and a symptom, never a technique (asserted by
  test). **Measured result on the real local model: 0 / 14.** It implemented *every* one —
  including returning `PASS` when required evidence is absent, and logging the full
  `Authorization` header. With two tasks small-sample noise was arguable; with fourteen
  distinct controls and a perfect failure rate, the model simply does not model security
  consequences. Zero-edit acceptance accordingly reads 43 % across the whole corpus while the
  engineering-lane metrics are unchanged (94 % structural, 81 % tests pass, 100 % public API
  preserved). The capability registry marks `security_review` **UNQUALIFIED** on exactly this
  evidence. **No authority changed.**

### Fixed
- **Shadow prompts omitted the current file contents** — the engineering prompt asked for a
  complete `new_content` for files the model had never seen, so it produced a plausible
  *rewrite* rather than an edit. The first real local trial passed every structural check
  (valid JSON, exact scope, clean validation) while silently dropping two public parameters,
  their defaults, the type annotations and the module docstring. The in-scope files are now
  read (bounded, read-only) into the prompt with an explicit instruction to preserve
  everything the objective does not ask to change.

- **Reconciliation hardening (Step 7B.2.1)** — two correctness gaps found by independent
  post-merge review of Step 7B.2.
  - *Class 5 reported but never acted.* `reconcile` mutates authority only for
    `invalidated` findings, and several class-5 conditions emitted `attention_required` —
    so an approval whose execution evidence was incompatible (mismatched `run_id`),
    ambiguous (more than one `execute_validated`), unauthorized (evidence against a
    PENDING/REJECTED/EXPIRED approval) or inconsistent (an `apply_result` while authority
    was never consumed) could leave its run **open and still executable**. A class-5
    inconsistency that ties to an **extant authority run** now invalidates that run; only a
    truly orphaned evidence fact — whose `run_id` the authority store does not hold — stays
    attention-only. The run id is acted on solely when the authority store already contains
    it, so evidence still can neither create authority nor select an unrelated run to close.
  - *Class 4 relied on a weaker parallel check.* Completion was established from
    `apply_result → execute_validated` alone, never `execute_validated → approval_decided`,
    the referenced decision being `approve`, canonical-plan-hash agreement, or
    `approval_decided` uniqueness. Class 4 is now exactly **USED authority + OpenClaw's own
    `load_evidence_graph_from_sink(...).usable`**; anything short of the full signed graph is
    class 3 (invalidate, outcome unknown, never retried). Class 2 is gated the same way on
    the reservation's own authorization edge, so malformed execution evidence is no longer
    reported as a clean crash-after-reservation. No schema migration, no new authority state,
    and no new evidence record type.

- **Pre-existing concurrency-test flake (test-harness only)** — the Step 7B.1 reservation
  contention tests staged their race behind a `threading.Barrier` and then read the **wall
  clock** to evaluate approval expiry. Any real-time disturbance inside that coordination
  window longer than the approval's 300-second lifetime therefore made *both* threads refuse
  `expired` and reserve nothing — on the development host, macOS "Maintenance Sleep"
  suspends for up to an hour and produced exactly that signature. The race under test is
  about lock ordering, not elapsed time, so the evaluation instant is now pinned before the
  coordination and injected through the store's existing `now=` parameter, and the barrier
  timeout drops from 10s to 2s (with the critical section in place the barrier can only ever
  time out, since the loser is blocked on the lock and never arrives). Expiry behaviour,
  the production TTL, and every assertion are unchanged; the two tests also stop costing 20
  seconds of suite time.
- **Denial accounting gap** — `POST /v1/approvals` recorded a 403 `owner_required` decision
  in the audit without incrementing `gateway_authz_denials_total`. Because OpenClaw's
  `AC-METRICS-RECONCILE` control treats an audited 403 denial with no matching counter as a
  dropped metric, a refused self-approval attempt could make the *next*, entirely
  legitimate governed run fail verification. Found by a real end-to-end walkthrough run;
  all nine audited 403-denial sites now increment, and a runtime invariant test asserts
  `metric total ≥ audited 403-deny count` across the full denial scenario.

### Changed
- A concurrent double-execute loser now receives the governed `replay` refusal instead of
  surfacing an unhandled error.
- The `openclaw` assurance plane is now resolved deterministically from the repository's
  `agents/` directory before import, so an unrelated third-party distribution of the same
  name in site-packages cannot silently substitute authority-adjacent code.
- The public walkthrough is now chat-first: a twelve-frame product tour (request → governed
  plan → withheld authority → owner approval → sandbox apply → signed evidence → independent
  verification → console inspection) replaces the sixteen-frame console-only tour, which is
  retained as a secondary console deep-dive.
- Test suite now at **1195** (~92% coverage) across the evidence, durability, hardening,
  live-wiring, chat-integration, append-first-reservation, reconciliation, local-engineering,
  signed-verdict and terminal-disposition increments; the full suite runs on Linux and macOS
  in CI.

### Not yet built (explicitly)
- Trust ledger; earned autonomy; production external rollback. A *future* sandbox apply can
  now be reversed under owner authority and independently verified, but a historical apply
  has no pre-image and stays irreversible, rollback never leaves the sandbox, and the runtime
  still cannot determine whether an interrupted mutation actually landed.
  Pending-approval expiry stays deferred (no grounded policy source for a pending lifetime —
  see the implementation contract). Autonomy remains fixed-ceiling and human-gated.

## [0.18.0] - 2026-07-04

### Added
- **Governed Chat Console** (`/chat`) — a conversational front-end to the *real*
  orchestration loop, not a scripted demo. An operator types a goal; Hermes reads the
  enforced agent directory, makes a governed **L1** plan, and **proposes** a delegation —
  it executes nothing on its own. The operator approves the sandbox apply; OpenCode
  applies in a confined sandbox and sub-delegates verification to OpenClaw; the verdict
  and full attenuating chain come back. **Authority to change anything stays with the
  human:** the apply step refuses (`REFUSED`, no sandbox mutation) unless an approval is
  supplied — proven by test. On-thesis by construction: *AI capability is not AI
  authority.*
- **`POST /v1/orchestrate`** — phased orchestration endpoint (`plan` / `execute` /
  `probe`). Authenticated and rate-limited like any request; each internal plan →
  delegate → apply → verify hop goes back through the same enforced plane and is audited.
  New metric `gateway_orchestrate_total{phase}`.
- **`hermes.session.GovernedSession`** — the phased, transcript-producing driver behind
  the endpoint, reusing the existing `interop`/workers/planner (no logic forked from
  `hermes.orchestrate`). `src/private_ai_gateway/orchestration.py` bridges it to the
  gateway, loading the out-of-package agents lazily and degrading with a clear message
  when the demo plane is absent.

### Changed
- Test suite: 381 → 389 (8 orchestration-chat cases: plan-proposes-not-executes,
  approved-applies-and-verifies, unapproved-refuses, boundary probes, endpoint phases +
  auth). Verified end to end in a browser (approve → PASS, deny → REFUSED, zero errors).

## [0.17.0] - 2026-07-03

### Added
- **GAD/1.0 — the delegation semantics as a versioned spec** (`docs/delegation-spec.md`).
  Thirteen RFC-2119 invariants with stable error codes (self-delegation, skill both
  ends, no amplification, holder-only sub-delegation, narrowing-only chains, bounded
  depth, delegatee-only report-once, audited denials, policy-derived discovery), so the
  semantics are something other implementations can adopt — the protocol is the product.
- **Conformance suite** (`tests/conformance/test_delegation_spec.py`): one test per
  MUST, tagged `gad_i1`…`gad_i13`. Runs in-process in CI, and against **any**
  implementation over HTTP via `GAD_BASE_URL` + fixture-cast tokens; the fixture policy
  ships as `config/conformance_policy.toml`. Verified both ways (14/14 in-process and
  14/14 over live HTTP against a served gateway).
- **SIEM push export** (`siem.py`, `[siem]` policy table). Every decision event can be
  POSTed to an HTTP collector off the hot path: bounded queue consumed by one daemon
  thread — a slow or dead collector means counted drops/failures, never request
  latency; optional GitHub-webhook-style `X-Signature-256` HMAC over the exact body
  (secret named by env var in policy, never stored in the file); outcomes surfaced as
  `gateway_siem_events_total{outcome}`. `decisions.jsonl` remains the local source of
  truth.

- **Delegation time bounds (GAD/1.1 §3.1).** `[delegation] ttl_seconds` closes the
  zombie-authority hole: an agent that dies mid-task no longer leaves a live,
  sub-delegable grant behind forever. Expiry is enforced lazily at every read (no
  reaper): expired tasks refuse results (`task_expired`, 409) and sub-delegation
  (`parent_not_active`), and a child's expiry is clamped to its parent's — time
  narrows like authority. Unset by default (unbounded, as before).

### Security
- **Log-injection hardening (CWE-117).** A new `logutil.log_safe` neutralizes CR/LF and
  C0/C1 control characters, and now wraps every request-derived value interpolated into
  an audit line (model names, URL paths, tool names, remote address, upstream error
  text) across `app.py` and `backends.py`. A caller can no longer smuggle a forged event
  onto its own line in the audit trail. Clears twelve CodeQL `py/log-injection` alerts.
- **Internal-error exposure removed (CWE-209).** The inference backend-failure path no
  longer echoes the exception text to the caller (`"Inference backend failed: {e}"` →
  `"Inference backend failed"`); the detail is logged server-side only. Clears one
  CodeQL `py/stack-trace-exposure` alert.

### Changed
- Test suite: 350 → 381 (14 conformance + 6 SIEM + 6 expiry + 5 log hygiene).

## [0.16.0] - 2026-07-03

### Added
- **Governed agent-to-agent delegation.** A2A agent cards let agents *discover* each
  other from policy; a new delegation protocol (`delegation.py`) governs the hand-off
  itself so capability never becomes authority by being delegated. Two-axis rule:
  **skill possession** is the right to *route* a task type, **autonomy ceiling** the
  right to *execute* it — so an L1 planner can route an L3 task to a peer that policy
  grants L3, but no request can amplify authority. Chains only narrow (no widening past
  the parent grant), depth is policy-bounded (`[delegation] max_depth`), only a task's
  current holder may sub-delegate it, and only its delegatee may report the outcome.
  New endpoints: `GET /a2a/agents` (policy-derived directory), delegate-to-peer and
  task inbox/outbox on `/a2a/tasks`, `GET /a2a/tasks/<id>` (task + custody chain), and
  a delegatee-only `/a2a/tasks/<id>/result`. Every allow/deny is audited with a stable
  code.
- **Autonomous orchestration across Hermes / OpenCode / OpenClaw.** A shared interop
  client (`agents/interop`) whose discovery prefers the least-privileged capable peer,
  plus delegatable workers: OpenCode applies an approved change in a confined sandbox
  and *sub-delegates* verification; OpenClaw verifies from gateway evidence and reports
  PASS/FAIL up the chain. `python -m hermes.orchestrate` runs the full governed loop
  offline through the real enforcement plane, then abuses the same wire on purpose
  (amplification, routing an unheld skill, over-deep chains, forged results) — all
  refused with exact audit codes.
- **Ingress AI-firewall (`ingress.py`).** The inbound mirror of the egress guardrail:
  heuristic, explainable prompt-injection / jailbreak / PII detection mapped to OWASP
  LLM01:2025, with a Unicode **normalization pass** (NFKC, strip zero-width/invisible,
  drop Unicode tag chars, fold a curated confusables subset, remove combining marks) so
  homoglyph / zero-width / full-width evasions are folded before matching — and the
  evasion attempt itself escalates severity. PII rules (email/SSN/card/IBAN) match with
  a Luhn check for card precision and mask matches in findings. Policy-driven action
  (`[ingress]` off | flag | block, `block_threshold`); metric
  `gateway_ingress_events_total`. Off by default.
- **AI-stack dependency CVE intelligence (`vulnintel.py`).** Snyk/SonarQube-inspired
  scanner with PEP 440-aware version-range matching, CVSS→severity tiers, and a
  configurable quality gate. Curated, source-cited snapshot of four real high-severity
  AI-supply-chain CVEs (Ray ShadowRay CVE-2023-48022, llama-cpp-python Jinja2 SSTI
  CVE-2024-34359, MLflow path-traversal CVE-2024-3573, vLLM torch.load deserialization
  CVE-2025-62164 — ranges pulled from OSV.dev) plus a live OSV.dev `/v1/querybatch`
  client (opt-in). New CLI `scan` (`--manifest`, `--gate`, `--live`) and a packaged
  deliberately-vulnerable `demo_sbom.json`.
- **Deterministic context optimizer (`contextopt.py`).** Model-free, LLMLingua-inspired
  (arXiv:2310.05736 / 2310.06839) prompt compression to cut token exchange: lossless
  whitespace normalization, near-lossless cross-message dedup of repeated context
  blocks, and lossy budget windowing. The gateway always *measures* achievable savings
  (metric `gateway_context_tokens_saved_total`) and only rewrites prompts when a
  principal's `[context]` policy opts in. CLI `optimize` demo shows ~37% reduction on a
  representative RAG turn.

### Changed
- Starter-kit demo gains the hermes/opencode/openclaw orchestration cast and two live
  ingress blocks (plain + homoglyph/zero-width evasion); the demo plane is now
  self-contained (fresh audit + metrics) so OpenClaw's reconciliation is exact.
- Security eval suite: 20 → 23 cases (three ingress prompt-injection cases, one exercising
  Unicode-evasion resistance). Test suite: 269 → 350.
- Agent cards now surface `can_read_audit` under `x-governance` so peers can discover
  which agent may consume governance telemetry.

### Fixed
- **Polynomial ReDoS in `contextopt.normalize_whitespace`** (CodeQL
  `py/polynomial-redos`): the trailing-whitespace regex backtracked quadratically on
  long tab runs in caller-supplied prompt text. Replaced with per-line `str.rstrip`
  (linear, identical output) and pinned with a pathological-input regression test.

## [0.15.0] - 2026-07-02

### Added
- **Pluggable inference backends — the plane is now model-plane-agnostic.** Inference is
  isolated behind one interface (`backends.py`) with three implementations: `mlx`
  (in-process Apple Silicon, unchanged behaviour), `openai` (any OpenAI-compatible
  upstream — enterprise LLM-as-a-Service, vLLM, TGI, Ollama, LM Studio — stdlib-only
  HTTP client, scheme-validated URL, upstream failures surfaced as `502 upstream_error`),
  and `demo` (deterministic offline simulator). Selection via `PRIVATE_AI_BACKEND`
  (`auto` prefers a configured upstream, then MLX, then demo) or
  `serve --backend/--upstream-base-url`. MLX moved to an optional extra
  (`pip install .[mlx]`); the base install is platform-agnostic.
- **Model routing as policy.** Optional `[models]` table in `policy.toml`
  (`default_alias`, `[models.routes]` alias → backend model id) so aliases and
  per-principal allowlists survive a change of model plane.
- **Starter kit: `private-ai-gateway demo`.** One command loads a packaged demo policy
  (five simulated financial-enterprise principals: research-copilot L2,
  kyc-screening-agent L3, suggest-only trading-assistant L1, ops-automation L4, auditor
  with `can_read_audit`), replays 13 scripted steps of governed traffic through the real
  enforcement code — allows, model/tool/skill/autonomy denials, a granted-but-floor-gated
  `payments.initiate`, an A2A delegation, a live guardrail redaction, an audited audit-read
  denial — prints the tally and the demo tokens, then serves the console. Five new
  simulated line-of-business tools with honest autonomy floors (`market.snapshot` L0,
  `docs.search` L1, `kyc.sanctions_screen` L2, `email.draft` L3, `payments.initiate` L5).
- **Governance Console v2 — an app-style dashboard.** Sidebar navigation (Overview,
  Live audit, Probe lab, Tools, Agents, Metrics), overview stat cards with the
  allow/deny/filter enforcement ratio, a filterable + searchable live audit feed,
  probe panels for chat / MCP tool calls / A2A delegation, one-click boundary probes
  that get themselves refused on the wire, and gateway/backend status chips. Still a
  single static file under the same strict CSP.

- **Console walkthrough + scroll-driven product tour.** A 16-frame end-to-end journey
  through the console (captured from `private-ai-gateway demo` with a headless-Chrome
  CDP rig — real enforcement, no mockups) ships as a 38-second GIF/MP4 and as an
  Apple-style scroll-scrub tour on the GitHub Pages site (`#tour`): a sticky frame
  viewer follows sixteen step captions, each grounding a feature in documented
  real-world practice (regulator-proof AI audit trails at Point72/Balyasny, D.E. Shaw's
  gateway-level redaction, the CSA zero-deny-rules finding, EU AI Act logging duties).
  Static, dependency-free, degrades to the GIF without JavaScript.

### Changed
- Eval suite grows to 20 cases (`MCP-002`: an L4 principal invokes the granted
  `payments.initiate`, which floors at L5 → `403 autonomy_exceeded` — a grant does not
  outrank a tool's autonomy floor).
- Site copy updated to the model-plane-agnostic positioning; stats refreshed
  (11 enforced controls, 20 evals, 269 tests on 2 platforms); proof table gains the
  A2A / MCP / audit-read rows.
- CI now runs the full test suite on **both** ubuntu-latest (no MLX) and macos-14
  (MLX), plus `evals.run --require-gateway` and a demo smoke test; 269 tests, no skips
  on either platform.

## [0.14.0] - 2026-07-01

### Added
- **Governance Console** — a zero-dependency, single-file web UI served by the gateway at
  `GET /console`. The shell is static and carries no data: the operator pastes a bearer
  token into the page and the console shows that principal's world — identity + enforced
  autonomy ladder (`/v1/whoami`), a live decision-audit feed (`/v1/decisions`), enforcement
  metrics (`/metrics`), granted MCP tools, the policy-derived A2A agent card, and a
  "governed probe" panel that sends a chat request with a declared autonomy level so
  denials (`403 model_not_allowed` / `autonomy_exceeded`) are visible on the wire. Pinned
  by a strict `Content-Security-Policy` (`default-src 'none'`, same-origin API calls only).
  Works out of the box after `pip install` + `private-ai-gateway serve`.
- **`GET /v1/decisions` — governed audit tail.** Returns the newest decision-audit events
  (bounded read, `limit` clamped to 500, torn/malformed lines tolerated). Reading the
  audit is its own policy grant — a new per-principal `can_read_audit` flag (deny by
  default; the owner break-glass identity has it) — because the audit reveals every
  principal's allow/deny history. Denied reads are themselves audited and counted
  (`gateway_authz_denials_total{reason="audit_not_allowed"}`). Proven by eval `AUDIT-001`.

### Changed
- Eval suite grows to 19 cases (`AUDIT-001`: low-privilege principal tails the audit →
  `403 audit_not_allowed`).

## [0.13.0] - 2026-06-30

### Changed
- **This repo's Pages serves the project** at `debshikhar-sec.github.io/private-ai-infra/`
  (`site/index.html` = the `private-ai-infra` showcase). The **author/profile is now a
  standalone personal website** in the dedicated user-site repo
  `debshikhar-sec.github.io` (served at the domain root); the project page's "Author" link
  points out to it. All GitHub handles migrated `debsqui88` → `debshikhar-sec` (repo, Pages,
  badges, links, résumé) after the account rename.

### Added
- **Installable as a package** — `pip install .` registers a `private-ai-gateway` console
  command (`serve` / `version`), so the gateway runs without the Makefile or nginx
  (`private-ai-gateway serve` → Flask on `127.0.0.1:8080`). `[project.scripts]` entry point.
- **A2A (Agent2Agent) governance** — the gateway is now the authority layer for
  agent-to-agent interop. `GET /.well-known/agent-card.json` renders an A2A-style Agent Card
  **from policy** (advertising only granted skills + the enforced autonomy ceiling), and
  `POST /a2a/tasks` accepts a delegated task only if the principal is granted the skill
  (`allowed_skills`) and stays within its autonomy ceiling — else `403 skill_not_allowed` /
  `403 autonomy_exceeded`. Proven by evals `A2A-001/002`.
- **MCP tool-access governance** — `POST /mcp/call` gates every tool invocation by the
  principal's `allowed_tools` and the tool's required autonomy level (each tool declares a
  min level); ungranted or over-privileged calls are refused before the handler runs
  (`403 tool_not_allowed` / `403 autonomy_exceeded`). `GET /mcp/tools` lists the caller's
  permitted tools. Built-in tools are pure/side-effect-free. Proven by eval `MCP-001`.
- Suite is now **18 adversarial evals**; **232 tests** at ~92% coverage.
- **MITRE ATLAS technique mapping** — eval cases now carry a MITRE ATLAS technique ID
  (`AML.T0051.000/.001` prompt injection, `AML.T0057` data leakage) surfaced in the report
  JSON, and `docs/security-model.md` gains a concrete ATLAS coverage table plus an explicit
  **out-of-scope analysis** (why training-data poisoning, model extraction, and adversarial-
  example evasion don't apply to a pre-trained, loopback, text-only authority plane).
- **Profile photo support** on the author page — the avatar shows a photo
  (`site/assets/profile.jpg`) when present and falls back to the gradient monogram otherwise.
- **Downloadable résumé** on the author page — `site/assets/Debshikhar_Das_resume.pdf`
  (realigned to the current AI-security context, including the `private-ai-infra` project),
  surfaced via a contact chip and a "Download résumé" button, plus a phone contact chip.
- **Repository security hardening** — `main` protected by a ruleset (no deletion, no
  force-push, PR-required, `lint-and-scan`+`test` must pass); Dependabot alerts + security
  updates enabled; `SECURITY.md` documents the posture. (Secret scanning, push protection,
  and a read-only CI token were already on.)
- **Agentic threat-model evals** (`AGENTIC-001/002/003`) — a black-box-attacker group that
  assumes the model is already captured by prompt-injection / context-poisoning and proves the
  authority boundary still holds: a hijacked model cannot reach an ungranted model (ASI01),
  exceed its autonomy ceiling (ASI03), or exfiltrate a secret (ASI06). Mapped onto the **OWASP
  Top 10 for Agentic Applications (2026)**. The suite is now **15** cases (was 12).
- **`docs/product-evolution.md`** — the product narrative: an ASI01–ASI10 coverage map (with
  honest enforced/partial/roadmap status), positioning against the AI-gateway field
  (LiteLLM/Portkey/Cloudflare/Kong), and a threat-led evolution roadmap (short-lived agent
  identity via SPIFFE/OAuth scoped delegation, tamper-evident memory, OTel GenAI semconv,
  supply-chain signing). Linked from the README and roadmap.
- **Author / portfolio page** (`site/author.html` + `site/author.css`) — a recruiter-facing
  profile (identity hero, impact metrics, experience timeline, skill clusters, featured project,
  education) reusing the site design system; linked from the project page nav and footer.
- **Response hardening** — every gateway response now carries an `X-Request-Id` correlation
  header (tied to the decision audit) plus strict security headers (`X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store`).
- **Showcase website** (`site/`) deployed to **GitHub Pages** via the official Actions
  pipeline (`.github/workflows/pages.yml`; no `gh-pages` branch, no build step). Hand-authored,
  zero-build, responsive dark UI using modern CSS (scroll-driven reveals, `:has()`,
  `color-mix()`, fluid `clamp()` type, glass nav) with full `prefers-reduced-motion` and
  keyboard/a11y support. The enforcement gauntlet is on-brand CSS; the control-plane loop is a
  pre-rendered SVG (no runtime diagram dependency); the live `enforce.gif` is the centerpiece.

### Changed
- **CI hardened to match local strictness.** `ruff` and `bandit` now scan `agents/` and `evals/`
  (not just `src`), bandit uses `-c pyproject.toml` (keeping the intentionally-vulnerable review
  fixture excluded), and the coverage floor was raised **70% → 85%** (actual 93%). A reviewer
  running `make check` no longer out-checks CI.
- **Documentation showcase overhaul** (no code changes). Replaced the ASCII diagrams with
  GitHub-native **Mermaid** (auto dark/light, no binary assets): a request-enforcement
  flowchart showing every gate and its deny code, the plane/trust-boundary layering, the
  autonomy ladder with each component pinned to its ceiling, the delegation flow, and the
  closed plan → act → verify → record loop.
- Rebuilt the README around a *proven-not-asserted* table (each control → the attack it
  repels → where it's enforced → the eval/test that proves it) and a live-demo hero.

### Added
- **`docs/threat-model.md`** — a STRIDE-per-trust-boundary threat model where every
  mitigation cites the executable proof (eval ID or unit test) that runs in CI, so the
  document cannot silently drift from the code.
- **Animated live-enforcement demo** — `demo/enforce.tape` (VHS) records the `403`
  autonomy/model denials and OpenClaw's re-verification on a live gateway into
  `docs/assets/enforce.gif`; the README also carries a static text fallback. A
  "Live enforcement demo" runbook section documents reproducing and regenerating it.

## [0.12.0] - 2026-06-29

### Added
- **The act step now feeds assurance — an ungated or unconfined apply gates the planning
  loop.** OpenClaw gained a ninth control, `AC-APPLY-INTEGRITY`, that reads the OpenCode
  act-step's apply report as one more evidence artifact (it does *not* import
  `opencode_sandbox` — same doctrine as the audit, eval, and isolation reports) and asks an
  independent question: did the approval gate and change-confinement actually hold?
  - an APPLIED change with **no recorded approver** is a **FAIL** (a tree-mutating action with
    no authorizing approval is an authority bypass);
  - an APPLIED report whose changed files are **not a subset of its declared files** is a
    **FAIL** (independent cross-check against a tampered/inconsistent record);
  - a **FAILED** apply (the act step's own verification caught an undeclared write) is a **FAIL**;
  - a **REFUSED**/**REJECTED** apply is a **PASS** — positive evidence the gate correctly blocked
    an unapproved or invalid change;
  - an unreadable/status-less report is a **FAIL** (integrity gap, fail closed); no report is
    **INCONCLUSIVE**.
- **Closes `act → verify → record` through the existing loop.** `python -m openclaw.run
  --apply-report …` and `python -m hermes.verify --apply-report …` thread the apply verdict
  through assurance into Hermes' memory, so an authority/confinement breach in the act step
  becomes a failing assurance control that gates the next plan — reusing the same machinery as
  the eval-gating path, no new plumbing. New `agents/openclaw/examples/apply.report.json`.

### Changed
- OpenClaw assurance contract and README list the new control (nine total); suite grows with
  evidence/control/runner/closed-loop tests for the apply-gating path.

## [0.11.0] - 2026-06-29

### Added
- **OpenCode act step — an approval-gated, confined, verified apply path
  (`agents/opencode_sandbox/apply.py`, CLI `opencode_sandbox.act`).** The *write* boundary of
  the control plane, where "AI capability is not AI authority" becomes mechanical. The review
  harness already proved OpenCode can look without touching; the act step proves a *proposed*
  change cannot be applied without authority, cannot escape the target, and cannot change
  anything it did not declare. Four enforced steps:
  - **Capability ≠ authority.** A `ChangeProposal` (declared edits + rationale) carries no
    approval; an `Approval` (owner + reason) is a *separately-sourced* input — the proposer
    cannot approve itself.
  - **Fail closed.** Any write is at least `owner_run` (L3); without a granted approval the
    apply is **REFUSED**, exactly as the gateway refuses an unauthenticated request. A proposal
    that carries edits is treated as ≥ L3 even if it declares lower, so it cannot label itself
    `dry_run` to dodge the gate (most-privileged-wins, mirroring `autonomy.declared_level`).
  - **Confinement.** Paths that escape the target root (`..`, absolute, symlink) are **REJECTED**
    before any byte is written.
  - **Verified.** The change is applied into a sandbox copy; before/after sha256 manifests prove
    **exactly the declared files changed**. An undeclared write is **FAILED**, never a silent
    success. `--commit` promotes the verified change onto the real target, re-verified and still
    approval-gated.
  - Emits a structured `ApplyReport` (status / effective level / approver / declared-vs-changed
    files / violations) — the same evidence doctrine as the review manifests, ready to fold into
    Hermes' memory or check with OpenClaw. Pure-stdlib and offline (no `opencode` binary, no
    gateway), so unlike the review harness it is fully unit-tested. Bundled
    `examples/fix_sqli.proposal.json` proposes the fix for the review target's SQL-injection bug.
  - Contract: `agents/opencode_sandbox/OPENCODE_ACT_CONTRACT.md`. Suite 178 → 198.

### Changed
- `opencode_sandbox` joins lint/SAST/coverage (`make check`); bandit excludes the deliberately
  vulnerable `examples/review_target` fixture (it exists to *be* found flawed). README, roadmap,
  and the orchestration narrative reflect OpenCode now reviewing **and** acting.

## [0.10.0] - 2026-06-29

### Added
- **The adversarial evals now feed OpenClaw's assurance — a failed eval gates the planning
  loop.** OpenClaw gained an eighth control, `AC-SECURITY-EVALS`, that reads the eval
  harness's JSON report as one more evidence artifact (it does *not* import the harness — same
  doctrine as reading the decision audit or an isolation report) and judges it:
  - a failing probe (a control that let an attack through) — or a `fail` count above zero even
    if the verdict string says otherwise — is a **FAIL** (`high`);
  - an unreadable / verdict-less report is a **FAIL** (integrity gap, fail closed);
  - no report, or a run where every probe was skipped, is **INCONCLUSIVE** (never a silent pass);
  - a clean run is **PASS**, with any skipped probes surfaced as a coverage gap.
- **Closed the third thread of the control loop.** `python -m openclaw.run --eval-report …` and
  `python -m hermes.verify --eval-report …` thread the eval verdict through assurance into
  Hermes' memory, so a security regression caught by the eval suite becomes a failing assurance
  control and **gates the next planning cycle** exactly like any other control breach
  (`evals → OpenClaw → Hermes`). New `evals/examples/security-eval.report.json`.

### Changed
- OpenClaw assurance contract and README list the new control; suite grows with evidence/control/
  runner/closed-loop tests for the eval-gating path.

## [0.9.0] - 2026-06-29

### Security
- **Fixed an autonomy-ceiling bypass (found by the new eval harness).** A request could
  declare a low level in the `X-Autonomy-Level` header while smuggling a *higher* level in
  the `autonomy_level` body field; the gateway trusted the header and ignored the body, so
  the higher level slipped past the ceiling. The effective declared level is now the
  **most-privileged across all channels** (`autonomy.declared_level`), so under-declaring in
  one channel can no longer bypass the gate. Covered by `AUTONOMY-004` and unit tests.

### Added
- **Adversarial security eval harness (`evals/`).** An *active* counterpart to OpenClaw's
  passive verification: it drives the gateway's enforced controls with attack-shaped inputs
  and asserts each one holds, emitting a pass/fail report (text/json/markdown) that exits
  non-zero on FAIL — a CI-gateable security artifact.
  - Probes are tagged with the OWASP LLM risk they exercise: **autonomy bypass** (LLM06 —
    over-ceiling via header, body, `6`-vs-`L6` format smuggling, and conflicting channels),
    **model authorization** (LLM06), **authentication** fail-closed (LLM06), **rate limiting**
    (LLM10 Unbounded Consumption), and **secret egress** (LLM02 — AWS key / PEM / JWT redaction
    with a benign-prose false-positive check).
  - Transport-agnostic core (`harness.py`): the scoring is validated in CI with canned
    transports; the egress probes run for real against the pure `Guardrails`; the full suite
    runs against the live gateway on Apple Silicon, where `test_live_gateway_repels_every_attack`
    asserts every control holds. A held control is PASS, a breach is FAIL, an unrunnable probe is
    SKIP (never a silent pass).
  - `make evals` / `PYTHONPATH=src python -m evals.run`. Suite 148 → 163; coverage ~92%.

### Changed
- `docs/roadmap.md`, README, and the example report: the model-safety/eval-harness roadmap item
  moves to done; `evals` is included in `make check` (lint + SAST + coverage).

## [0.8.0] - 2026-06-29

### Added
- **Closed assurance → planning loop (`agents/hermes/verify.py`).** Connects the verifier
  (OpenClaw) back to the planner (Hermes), so consecutive cycles plan from *verified* state
  rather than declared state — completing `plan → act → verify → record → re-plan`.
  - `hermes.verify` runs OpenClaw over the evidence (audit, metrics, OpenCode isolation report,
    policy) and folds the result into Hermes' memory via `MemoryStore.record_assurance()`: the
    canonical `PROJECT_STATE.json` gains an `assurance` block, `RUN_HISTORY.md` records the
    verification, and `NEXT_ACTIONS.md` becomes *remediate the first failing control* on FAIL (or
    *proceed to the next planned increment* on PASS). It exits non-zero on FAIL.
  - `planner.summarize_state` now surfaces the last assurance verdict and any failing controls in
    Hermes' planning prompt, and the planner contract gains a rule (#7): on a FAIL verdict the
    safe next action must remediate a failing control before proposing new work; INCONCLUSIVE
    controls are coverage gaps to close, not passes.
  - `AssuranceReport.to_memory_record()` is OpenClaw's compact, JSON-only hand-off — the two leaf
    packages stay decoupled and meet only at this data shape.
- Tests for `record_assurance` (PASS/FAIL gates, history, state-key preservation, backup),
  `to_memory_record`, the planner assurance digest, and the `hermes.verify` runner end-to-end
  (suite 134 → 148; coverage ~91%). All pure-stdlib, so they run on CI.

### Changed
- `docs/orchestration.md`, `docs/roadmap.md`, and the example `PROJECT_STATE.json`: OpenClaw is
  now `implemented`, and the assurance → planning loop is documented as closed; the next steps
  are model-driven OpenClaw probes and the OpenCode *act* step (kernel-jailed apply path).

## [0.7.0] - 2026-06-28

### Added
- **OpenClaw assurance verifier (`agents/openclaw/`).** Adds the third control-plane
  component as a **read-only, observe-only (autonomy L0)** verifier — the assurance step the
  roadmap places *before* widening any implementer's authority ("the verifier is defined
  first").
  - **Evidence loaders** (`evidence.py`): parse the decision audit (`decisions.jsonl`), the
    Prometheus `/metrics` text, OpenCode's isolation run report, and `policy.toml`. Malformed
    audit records are *recorded as integrity gaps*, never silently dropped; absent optional
    sources yield `None` so the dependent control reports INCONCLUSIVE rather than a false PASS.
  - **Controls** (`checks.py`): seven assurance controls, each a pure function over the
    evidence — `AC-AUDIT-INTEGRITY`, `AC-AUTONOMY-CEILING` (every over-ceiling decision was a
    `403` deny), `AC-AUTHZ-MODEL` (every `allow` stayed within the principal's allowlist),
    `AC-RATELIMIT` (`429`), `AC-GUARDRAIL-EGRESS`, `AC-METRICS-RECONCILE` (the metrics counters
    are consistent with the audit — divergence flags a dropped increment or audit skew), and
    `AC-OPENCODE-ISOLATION` (`ISOLATION_RESULT=PASS`, clean secret scan, exit 0).
  - **Report** (`report.py`): an assurance report rendered as text / JSON / Markdown, with a
    verdict of **FAIL** if any control fails (else **PASS**); INCONCLUSIVE controls are listed
    explicitly so coverage gaps are visible, not hidden. As a CI gate it exits non-zero only on
    FAIL.
  - **Read-only metrics client + CLI** (`client.py`, `run.py`): an audit-only pass needs no
    gateway; `--metrics-url` scrapes `GET /metrics` as the `openclaw` principal at autonomy
    **L0** (single GET, never a write). `--policy` and `--opencode-report` widen the cross-checks.
- Tests for the evidence loaders, every control's PASS/FAIL/INCONCLUSIVE path, the report
  verdict/rendering, and the CLI (audit-only, JSON, output-file, injected metrics client).
  OpenClaw is pure-stdlib, so its tests run on CI; `make check` lints and SAST-scans it and
  `make cov` includes it.

### Changed
- `docs/orchestration.md`, `docs/roadmap.md`, and the README: OpenClaw moves from "planned" to
  "implemented — read-only assurance verifier"; all three components now have running
  implementations. The next step is feeding live assurance findings back into Hermes' memory.

## [0.6.0] - 2026-06-28

### Added
- **Hermes stateful planner (`agents/hermes/`).** Restores the planning component as a
  running, *stateful* agent — the memory/state capture that the earlier de-LARP flattened:
  - **Persistent memory** (`store.py`): `PROJECT_STATE.json` (canonical machine state),
    `RUN_HISTORY.md` (append-only cycle log), and `NEXT_ACTIONS.md` (current gate). Writes are
    **atomic** (temp file + `os.replace`) and every overwrite is preceded by a **pre-write
    backup** under `backups/<timestamp>/`. Live memory (`memory/`) is gitignored; a tracked
    `memory.example/` seeds it.
  - **Planner contract + parser** (`HERMES_PLANNER_CONTRACT.md`, `planner.py`): plan one phase
    at a time, declare an autonomy level, never claim un-evidenced file actions, and emit an
    `APPROVAL REQUIRED` block before any L4+/runtime/config/git/network action. The structured
    reply is parsed back into a `Plan` and the discipline is unit-tested.
  - **Gateway delegation** (`client.py`, `run.py`): one planning cycle is delegated to the
    gateway **as the `hermes` principal, capped at autonomy L1 (suggest)** — the planner plans,
    it does not execute, and it holds no special privilege. `--show-prompt` runs the cycle
    offline for review.
- `hermes`, `opencode`, and `openclaw` principals added to `config/policy.example.toml`, each
  with its own key and autonomy ceiling (L1 / L2 / L0) — one identity per component, no shared
  admin token.
- Tests for the memory engine, plan parsing, the gateway client, and the runner (suite 50 → 80;
  coverage 83% → 88%). Hermes is covered by `make cov` and linted/scanned by `make check`.

### Changed
- `docs/orchestration.md` and `docs/roadmap.md`: Hermes moves from "planned" to
  "implemented — stateful planner, delegates at L1". README reframed around all three
  components now having running implementations.

## [0.5.0] - 2026-06-28

### Added
- **OpenCode isolated review sandbox (`agents/opencode_sandbox/`).** Restores the
  capability-denied, isolation-verified code-review agent into the public repo:
  - `opencode.jsonc` runs OpenCode with `edit`/`bash`/`task`/`external_directory`/`webfetch`/
    `websearch`/`lsp`/`skill`/`todowrite`/`doom_loop` **denied** — only `read`/`glob`/`grep`/
    `list` allowed — pointed at the loopback gateway with an env-placeholder key.
  - `run_review.sh` runs the agent under an **isolated XDG config/state** (never touches the
    operator's real `~/.config/opencode`), against a **copy** of the target, gated by gateway
    token validation, a config-safety check, a secret scan, and a process check — then diffs
    before/after `sha256` manifests of the sandbox and `~/.config/opencode` to **prove no
    out-of-sandbox writes** (`ISOLATION_RESULT=PASS`).
  - Bundled example target + a sanitized example run report as evidence.
- `docs/orchestration.md`, README, and roadmap updated: OpenCode moves from "planned" to
  "implemented — capability-denied, isolation-verified"; OS-level (seccomp/namespaces) jailing
  remains the next hardening step.

### Note
- This restores real work from the project's earlier sandbox harness, reconstructed clean of
  local absolute paths and private learning material; live run output is gitignored
  (`agents/opencode_sandbox/runtime/`).

## [0.4.0] - 2026-06-28

### Added
- **Autonomy-ceiling enforcement (orchestration keystone).** New `autonomy.py` defines the
  L0–L6 autonomy ladder (observe → suggest → dry-run → owner-run → monitored → continuous →
  unbounded). Each principal carries a `max_autonomy_level` (with an `[autonomy]`
  `default_max_level` fallback); a request declaring a higher level via the
  `X-Autonomy-Level` header or `autonomy_level` body field is denied `403 autonomy_exceeded`
  **before any model loads**, and the denial is audited. Gating is opt-in (off when no ceiling
  is configured). This converts the project's original prompt-level autonomy governance into
  an enforced control.
- **Orchestration control plane, documented.** `docs/orchestration.md` defines the
  multi-agent control plane — **Hermes** (planning/orchestration), **OpenCode** (sandboxed
  code execution), **OpenClaw** (security/observability) — as components governed by the
  enforced governance plane, with an explicit current-vs-planned status. `/v1/whoami` now
  reports the caller's `max_autonomy_level`.
- Tests for the ladder, policy loading, and endpoint enforcement (suite 42 → 50; coverage
  82% → 83%).

### Changed
- The owner break-glass identity sits at the top of the ladder (L6).
- README, architecture, and security model reframed around the orchestration control plane
  (capability is not authority — now enforced, not requested).

## [0.3.0] - 2026-06-27

### Added
- **Per-principal rate limiting.** Token-bucket limiter (`ratelimit.py`) keyed by
  principal; a per-principal `requests_per_minute` overrides a policy-wide default
  (`[ratelimit]`). Over-limit requests are rejected with `429` and a `Retry-After`
  header before any model load — a runaway key is throttled cheaply.
- **Output guardrails (secret-egress control).** `guardrails.py` scans every model
  response for credential-shaped content (AWS keys, private-key blocks, OpenAI/Slack/
  GitHub tokens, JWTs) and applies a policy action (`[guardrails] action` =
  `off`/`redact`/`block`). Egress filtering applies regardless of how authorized the
  caller is — authority to *invoke* a model is not authority to *exfiltrate* secrets.
- **Observability.** Hand-rolled Prometheus counter registry (`metrics.py`, no new
  dependency) exposed at `GET /metrics`: request decisions, authz denials, rate-limit
  rejections, and guardrail events. `GET /v1/whoami` returns the caller's effective
  permissions (principal, allowed models, token cap, rate limit).
- Tests for rate limiting, guardrails, metrics, and the new endpoints (suite 22 → 42;
  coverage 62% → 82%).

### Changed
- Guardrail and rate-limit activity is recorded to the structured decision audit
  (`decisions.jsonl`) alongside authz decisions.

## [0.2.0] - 2026-06-27

### Added
- **Governance plane (policy-as-code).** Externalized policy (`config/policy.toml`, TOML via
  stdlib `tomllib`) defining principals (API-key identities). Keys are stored as SHA-256
  hashes, never plaintext.
- **Identity + authorization.** Each request is resolved to a principal; the requested model
  alias is authorized against that principal's allowlist (403 on denial), and the effective
  output-token cap is the tightest of request / per-model / per-principal limits.
- **Structured decision audit** (`logs/decisions.jsonl`): one JSON record per authorization
  decision (request_id, principal, model, allow/deny, reason, status) for SIEM ingestion.
- Tests for the policy layer and authz paths (suite 4 → 17).

### Changed
- Gateway now launches as a module (`python -m private_ai_gateway.app`) for clean
  intra-package imports; start/stop scripts updated accordingly.
- Single static token mode is preserved as an "owner" break-glass principal when no policy
  file is present (zero-config local development).

### Security
- Fail-closed auth (refuses to start without `PRIVATE_AI_AUTH_TOKEN`), constant-time bearer
  comparison, Authorization header no longer logged, and a request-body size limit
  (`MAX_CONTENT_LENGTH`).

### Tooling
- CI split into a lint/scan job (ruff, Bandit SAST, pip-audit dependency CVE scan, shellcheck)
  and a test+coverage job on Apple-Silicon runners (so MLX tests actually execute).
- CodeQL security analysis workflow; coverage gate (`make cov`), `make sast`, `make audit`,
  and `make check`; README CI/CodeQL/Python/License badges.

## [0.1.0] - 2026-06-27

### Added
- OpenAI-compatible MLX gateway (`/v1/chat/completions`, `/v1/completions`, `/v1/models`, `/health`)
  with model routing/aliasing, lazy model swapping, bearer auth, audit logging, output
  sanitization, and per-model max-token clamping.
- nginx loopback reverse proxy with long-inference timeouts.
- Operational scripts (start/stop/status/benchmark/validate) and agent wrappers.
- Production project layout: `src/` package, `tests/`, `deploy/`, `docs/`, CI, and packaging.

### Changed
- Restructured from a flat working tree into a `src/`-layout package.
- Gateway log directory and nginx paths are now relative/derived (no hardcoded user paths).
