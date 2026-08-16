# Roadmap

The value of this project is not that a model can run locally — it is the control
boundary around it. The roadmap reflects that: harden the boundary first, broaden
capability second.

> For the **product narrative** — how these controls map onto the OWASP Top 10 for
> Agentic Applications (2026), where the project sits against the AI-gateway field, and the
> threat-led evolution by horizon — see **[product-evolution.md](product-evolution.md)**.
> This file is the engineering checklist; that one is the strategy.

## Done — boundary hardening

- **Fail-closed auth** — the gateway refuses to start without `PRIVATE_AI_AUTH_TOKEN`,
  compares the bearer token in constant time, and no longer logs the `Authorization`
  header.
- **Request-size limit** — `MAX_CONTENT_LENGTH` bounds the input side.
- **Policy-as-code identity & authorization** — principals from a TOML policy of API-key
  hashes, per-principal model allowlists and token caps, structured decision audit.
- **Per-principal rate limiting** — token-bucket limiter; over-limit → `429` + `Retry-After`.
- **Secret-egress guardrails** — responses scanned for credential shapes and redacted/blocked
  by policy.
- **Observability** — Prometheus `/metrics` counters and `/v1/whoami` introspection.
- **Autonomy-ceiling enforcement** — per-principal L0–L6 ladder enforced on inference requests
  (`403 autonomy_exceeded`); the keystone of the orchestration control plane.
- **OpenCode isolated review sandbox** — capability-denied (edit/bash/network off), isolated
  XDG config, reviews a copy, before/after manifests prove no out-of-sandbox writes
  (`agents/opencode_sandbox/`).
- **Hermes stateful planner** — delegates one planning cycle to the gateway as the `hermes`
  principal (autonomy ceiling **L1**), then persists `PROJECT_STATE.json` / `RUN_HISTORY.md` /
  `NEXT_ACTIONS.md` with atomic writes and pre-write backups (`agents/hermes/`).
- **OpenClaw assurance verifier** — read-only (autonomy **L0**) verifier that reads the
  decision audit, `/metrics` counters, OpenCode isolation manifests, policy, and the adversarial
  eval report, and the act-step apply report, runs nine controls over them, and emits a
  PASS/FAIL/INCONCLUSIVE assurance
  report; exits non-zero only on FAIL so it can gate CI (`agents/openclaw/`).
- **Closed assurance → planning loop** — `hermes.verify` runs OpenClaw and folds the verdict
  back into Hermes' memory (an `assurance` block + run-history entry + a remediation gate on
  FAIL), so the next planning cycle plans from *verified* state and a failing control gates new
  work (`agents/hermes/verify.py`).
- **Adversarial security eval harness** — an active suite (`evals/`) that attacks the enforced
  controls (autonomy bypass, model authorization, fail-closed auth, rate limiting, secret egress),
  tagged by OWASP LLM risk, emitting a PASS/FAIL report that gates CI. It caught and fixed a real
  autonomy-ceiling bypass (conflicting header/body declaration) and now regression-tests it.
- **Eval verdict feeds assurance → gates planning** — OpenClaw's `AC-SECURITY-EVALS` control
  reads the eval report as evidence, so a failing probe becomes a failing assurance control that
  Hermes folds into memory and treats as a remediation gate on the next planning cycle. The
  third thread (`evals → OpenClaw → Hermes`) of the plan → act → verify → record loop is closed.
- **OpenCode act step** — an approval-gated, confined, verified apply path
  (`agents/opencode_sandbox/apply.py`, CLI `opencode_sandbox.act`): a proposed change carries no
  approval, is refused without an explicit owner approval (fail closed, ≥ L3, no under-declaring),
  is applied only into a sandbox copy, and is verified by sha256 manifests to change exactly the
  files it declared — the **act** step of the plan → act → verify → record loop. Pure-stdlib and
  unit-tested.
- **Act → verify → record closed** — OpenClaw's `AC-APPLY-INTEGRITY` control reads the act-step
  apply report as evidence (an ungated apply, an undeclared write, or a FAILED apply is a failing
  control; a REFUSED/REJECTED apply is the gate holding), so the apply verdict flows through the
  existing `hermes.verify` machinery into memory and gates the next plan — the fourth thread of
  the loop, reusing the eval-gating path.
- **Security-path tests** — auth, policy, rate-limit, guardrail, metrics, autonomy, the Hermes
  memory/plan/verify paths, the OpenClaw evidence/controls/report/runner paths, the eval
  harness, and the OpenCode act-step (gate/confinement/verify/CLI) covered.

- **A2A + MCP governance** — the gateway is the authority layer for both agent-to-agent
  interop and tool access. `GET /.well-known/agent-card.json` renders an A2A Agent Card from
  policy (granted skills + enforced autonomy ceiling); `POST /a2a/tasks` gates delegation by
  `allowed_skills` + ceiling; `POST /mcp/call` gates tool calls by `allowed_tools` + a per-tool
  autonomy floor. Proven by evals `A2A-001/002` and `MCP-001`.
- **Installable package** — `pip install .` registers the `private-ai-gateway` console command
  (`serve` / `version`), so the gateway runs without the Makefile or nginx.

## Done — governed authority loop & evidence-integrity core

- **Governed Chat Console (`/chat`)** — a conversational front-end to the real loop: type a
  goal, Hermes plans and *proposes*, you approve, OpenCode applies in a sandbox, OpenClaw
  verifies. Every hop is enforced and audited (`static/chat.html`, `POST /v1/orchestrate`).
- **Owner-gated execute authority loop (D2)** — execute requires a durable, **single-use**,
  **owner-approved** decision bound to the plan's **canonical hash** (`run_id` +
  `approval_id`). An inline request-body approver grants nothing; the server recomputes the
  canonical hash and consumes the approval **before** any mutation (`app.py` `v1_approvals`,
  `approvals.py`, `orchestration.py`).
- **Verifier-owned evidence sink core (1A/1B/1C)** — an append-only, per-emitter
  **HMAC-signed**, **hash-chained** record store with from-scratch chain verification
  (`agents/openclaw/sink.py`). Tamper-evident, not non-repudiation (symmetric-key MVP).
- **OpenCode `apply_result` emit** — after a confined apply, the executor emits a signed
  record into the sink, bound to the run (`agents/opencode_sandbox/evidence_emit.py`),
  additive to the preserved `apply_report.json`.
- **OpenClaw verifier consume** — OpenClaw can now validate signed OpenCode `apply_result`
  evidence from an injected `EvidenceSink` when signed evidence is required: it verifies the
  chain + signatures, finds the matching signed record, and derives the apply verdict from
  it rather than from a handed, self-attested `apply_report.json`
  (`agents/openclaw/evidence.py`, `checks.py`, `worker.py`; includes the self-attestation
  regression test). Unsigned `apply_report.json` alone is insufficient when signed evidence
  is required. This proves **component-level consume/verification, not full end-to-end
  runtime enforcement** — it is unit-proven against an injected sink, without the end-to-end
  gateway-issued `run_id` / `approval_id` wiring.
- **Gateway `execute_validated` authorization evidence emit** — when execution authority is
  granted, the gateway can now emit a signed `execute_validated` record into an injected
  `EvidenceSink` (`src/private_ai_gateway/orchestration.py`, `app.py`). The record is
  appended as the durable execution reservation after approval validation and **before**
  `mark_used` (Step 7B.1: validate → reserve → consume → mutate); the payload
  contains `canonical_plan_hash` and `validated=true`, while `run_id` and `approval_id`
  remain in the evidence envelope. The default no-sink behavior is backward-compatible, and
  `REQUIRE_AUTHORIZATION_EVIDENCE` strict mode denies before mutation if authorization
  evidence is unavailable. This is **component-level gateway authorization evidence emit, not
  full runtime fail-closed enforcement**; the `execute_validated` payload now also carries a
  signed `approval_ref` to its `approval_decided` (the signed evidence graph below).
- **Gateway `approval_decided` decision evidence emit** — at `POST /v1/approvals`, after the
  owner's approve/reject decision is stored and before the success response, the gateway can
  now emit a signed `approval_decided` record (`src/private_ai_gateway/app.py`,
  `orchestration.py`). The payload is exactly `{decision, approver, canonical_plan_hash}`;
  `run_id`/`approval_id` stay in the evidence envelope; the free-text rejection reason is
  excluded. The default no-sink behavior is backward-compatible, and under
  `REQUIRE_AUTHORIZATION_EVIDENCE` a failed emit **invalidates the run and its active
  approvals** and denies with HTTP 503 `authorization_evidence_unavailable`. Component-level
  decision evidence emit; it is the **root** of the signed evidence graph below.
- **Stable evidence identity + signed evidence linkage** — every signed record carries a
  dedicated `evidence_id` (`ev-` + a UUIDv4 hex, distinct from the replay `nonce`) and a
  chain-independent `evidence_digest` binding the whole signed envelope and its `emitter_sig`
  (never the sink-local `seq`/`prev_hash`/`record_hash`). A typed `EvidenceRef` (`evidence_id`,
  `evidence_digest`, `record_type`, `sink_id`) is the portable anchor. The three mutation-path
  records form a signed graph — `approval_decided ← execute_validated ← apply_result` — via
  payload-embedded `approval_ref`/`execute_ref` bound through each `payload_hash`; no untrusted
  client supplies a reference (the gateway threads the execution reference internally to
  OpenCode). OpenClaw verifies the whole graph (chain, `evidence_id` resolution, recomputed
  `evidence_digest`, `record_type`/`sink_id`, emitter/`run_id`/`approval_id`, decision must be
  `approve`, canonical-plan-hash consistency), rejecting dangling/malformed/cross-run/
  cross-approval/wrong-type/wrong-emitter/ambiguous/digest-mismatched links and never letting an
  unsigned report rescue a broken graph. Verified linear scan; no durable index yet
  (`SCHEMA_VERSION` 2).

## Shipped — durable single-node substrate (Steps 7A / 7A.1 / 7B.0)

- **Durable authority + evidence stores (7A)** — `PRIVATE_AI_STATE_BACKEND=sqlite` persists
  the authority store (runs/approvals) and the evidence chain as **two separate,
  WAL-backed SQLite databases** under `PRIVATE_AI_STATE_DIR`, with forward-only fail-closed
  migrations and a both-or-neither initialization rule. `memory` remains the default.
- **Correctness hardening (7A.1)** — exclusive single-owner `flock` per database (a second
  live owner fails closed), full startup integrity (`integrity_check`, `foreign_key_check`,
  typed reconstruction of every row, binding/coherence consistency — corruption fails at the
  constructor), fully serialized evidence appends, atomic authority read-modify-write, strict
  persisted booleans, UTC-normalized timestamps, and resource cleanup on every failure path.
- **Live durable evidence wiring (7B.0)** — `PRIVATE_AI_EVIDENCE_MODE=durable` (requires the
  sqlite backend + per-emitter HMAC keys) opens the durable evidence store as a **live sink**
  under assurance-owned construction (`openclaw.assurance` builds the verification registry;
  the gateway holds only a sink handle and its own signing key). The gateway's
  `approval_decided`/`execute_validated` and OpenCode's `apply_result` land in **one durable
  signed chain** that OpenClaw verifies fail-closed (signed apply + signed linkage required),
  `REQUIRE_AUTHORIZATION_EVIDENCE` is forced on, evidence ownership is held for the process
  lifetime, and a populated database reopens and re-verifies across restarts.
- **Append-first execution reservation (7B.1)** — the execute path runs
  `validate → reserve → consume → mutate`. The signed `execute_validated` record is appended
  as a durable reservation **before** the single-use approval is spent, closing the crash
  window where a consumed approval left no durable trace. At most one reservation can exist
  per approval (a duplicate would make the verifier fail the winner's run as ambiguous):
  validate/reserve/consume run in a per-approval critical section, and a reservation that
  survives a crash into a later process is invalidated fail-closed at startup — the run is
  closed out, no mutation had started, nothing is retried, and another attempt needs fresh
  authority. A reservation that cannot be appended refuses before consuming anything.
- **Startup cross-store reconciliation (7B.2)** — one pass joins the authority store and the
  evidence chain at startup (after each independently validates itself), classifies every
  approval into the six ratified classes, and only then acts. Automatic repair is limited to
  the provably-safe class; a crash during the mutation is failed closed as dirty (invalidated
  and surfaced, never auto-retried, never claimed successful); evidence with no compatible
  authority never becomes authority; ambiguity fails closed rather than being normalized;
  and a store that cannot be inspected aborts startup instead of reading as clean. It
  subsumes the 7B.1 class-2 resolver, so one pass sees the original cross-store shape.
- **Reconciliation hardening (7B.2.1)** — closes two gaps found by post-merge review.
  (1) *Failing closed means acting.* A class-5 inconsistency tied to an extant authority run
  now invalidates that run; only an orphan evidence fact with no corresponding authority run
  stays report-only, because acting on an evidence-supplied identifier the authority store
  does not hold would be evidence selecting authority. (2) *Complete means the full graph.*
  Class 4 is now exactly `openclaw.evidence.load_evidence_graph_from_sink(...).usable` —
  `apply_result → execute_validated → approval_decided` with emitter identity, record
  uniqueness, `decision == approve` and canonical-plan-hash agreement — instead of a weaker
  gateway-side link check; anything short of it is dirty. Class 2 is gated the same way on
  the reservation's own authorization edge
  (`load_execution_reservation_from_sink`). The verifier still imports nothing from the
  gateway.
- **Local engineering: shadow track (C) + candidate adapter (D)** — capability
  infrastructure that grants **zero** additional operational authority. One flow:
  objective → governed strategy plan → local `engineering` candidate → strict deterministic
  validation → deterministic teacher comparison → evaluation trace. Model calls go through
  the gateway's normal governed path as a new `shadow-engineer` principal capped at **L1
  (suggest-only)** with no skills and no tools; the harness refuses to construct if handed
  an owner token. The adapter (`opencode_sandbox/candidate.py`) is deliberately stricter
  than the proposal parser it targets — JSON only (prose around JSON is refused, never
  salvaged), known fields only (an invented `command`/`exec` field is a refusal, not an
  ignored extra), declared paths only, bounded size — and what survives is built through the
  **existing** `ChangeProposal` schema and run through the sandbox's own `validate`.
  A candidate remains a candidate: applying one still needs the existing owner-issued,
  hash-bound approval. Evaluation traces are local, git-ignored JSON and are **never**
  written to the evidence sink. CI is fully deterministic and never downloads or executes a
  model. This is **not** autonomous coding.

## Next — evidence integrity (verifier-owned), in sequence

Design: [evidence-sink-design.md](evidence-sink-design.md). Each step is separately gated.
Step 7B is complete; what it built, and the reasoning behind each binding decision, is
recorded in
[step-7b1-7b2-implementation-contract.md](step-7b1-7b2-implementation-contract.md).

- **`ApprovalRecord.evidence_refs` population** — *future.* An **unused, non-authoritative
  placeholder** today; it is *not* the signed graph (which shipped as payload-embedded
  `EvidenceRef` data). Populating it would be a convenience index over the sink records.
- **Determining whether an interrupted mutation actually landed** — *still not possible, and
  deliberately not faked.* 7B.1 + 7B.2 make an interrupted execution *classifiable* and fail
  it closed; 7C.1 makes the verifier's judgment of it a signed fact; 7C.2 lets a human close
  it terminally as `closed_unknown`. None of that tells you whether the mutation landed. A
  `human_asserted_*` disposition records a **person's** claim, clearly labelled as such, and
  never converts unknown system evidence into known fact.
- **Terminal disposition (Step 7C.2)** — *shipped.* A human's closure of a dirty run is now a
  gateway-signed terminal fact, bound to one **specific** basis the caller names: a chosen
  `verification_result`, or the exact `execute_validated` reservation for a run where no
  apply-bound verdict can legitimately exist. Multiple verdicts stay plural and none is
  inferred — there is no "pick latest".
- **Reversibility foundation (Step 7C.3A)** — *shipped.* The audit was negative: the shipped
  apply artifacts keep only `changed_files` as bare paths and cannot reverse anything. A
  bounded, sandbox-confined **pre-image** is now captured before the first declared write, and
  byte-exact restoration is proven by test. Signed evidence carries only the snapshot's
  identity and digest, never its contents.
- **Governed rollback / containment (Step 7C.3B)** — *shipped, sandbox-confined.* A rollback
  is itself a mutation, so it gets its own governed run, its own single-use owner approval
  bound to its own canonical plan hash, its own reservation, its own signed outcome, and an
  independent OpenClaw verdict that re-reads the tree. A failure after the reservation signs a
  `failed` outcome, contains the workspace, and invalidates the rollback run. Historical runs
  stay irreversible — no pre-image is fabricated for a run that predates one — and nothing
  outside the sandbox is ever touched.
- **Rollback outside the sandbox** — *future, and not casually.* Git operations, deployment
  rollback and system-configuration rollback are all out of scope: their pre-images are not
  files this runtime owns.
- **Local engineering qualification** — *shipped, zero authority.* A 30-task corpus (16
  engineering, 14 security) and a disposable semantic evaluator that runs the candidate
  rather than only shape-checking it. Measured: 94 % first-pass structural, 81 % tests pass,
  43 % accepted with zero edits across all 30 tasks — and **0/14 on refusing
  control-weakening changes**, which is why review stays a control rather than a formality.
  See [local-engineering-qualification.md](local-engineering-qualification.md). No autonomy
  score, no grant.
- **Capability registry** — *shipped, zero authority.* Model identity (fingerprinted by
  build, not alias), per-lane qualification, local availability, and measured hardware fit,
  behind an owner-gated read-only endpoint. Capability informs routing; it never informs
  authority, and a structural test keeps it that way.
- **Trust ledger** — *shipped read-only, grants nothing.* A derived projection over the
  signed chain: facts by principal, task class, model build and policy hash — no score, no
  threshold, nothing consuming it. A chain that does not verify yields no ledger rather than
  an empty one.
- **Signed model attribution** — *shipped.* The plan phase appends a signed
  `candidate_attributed` record naming the model build (fingerprint, not alias), the policy
  hash and a digest of the candidate. `execute_validated` carries that attribution **read
  back from the record**, never recomputed from the live route map — so re-pointing an alias
  between plan and execute cannot re-credit a run to a build that never saw it. Runs with no
  such record stay `model_not_recorded` rather than being backfilled.
- **Owner-gated route activation** — *shipped.* No longer proposal-only, and deliberately not
  by rewriting `policy.toml`: the hand-authored file stays hand-authored, and activation
  appends a numbered atomic revision to a gateway-owned store. Effective configuration is base
  policy + active revision, and the effective policy hash covers both. A revision whose base
  file has since been edited is **stale and not applied**. Owner-only, audited, refused for the
  security lane unless qualified, and narrow by construction — a revision has no field for
  autonomy, skills, tools or approval rights. Runs pin the policy hash they were planned under
  (authority schema v2), so an activation never invalidates an approval already in flight.
- **Protected-surface risk gate** — *shipped, advisory, grants nothing.* Three classes
  (`LOW_RISK_ENGINEERING` / `REVIEW_REQUIRED` / `PROTECTED_SECURITY`), no score, and risk that
  only ratchets up. Twenty controls are enumerated and matched by both path and symbol, so a
  change to a signature check is protected whether the file is called `sink.py` or
  `helper.py`. All **14** security-corpus tasks classify as protected, pinned as a
  regression, and a caller's own label can never lower a classification. The measured 0/14 is
  the reason it exists: model self-restraint is not a boundary, so the boundary is
  deterministic code outside the model. Honest limit — in this codebase *no* source-file task
  in the corpus reaches `LOW_RISK_ENGINEERING`; only documentation- and test-only changes do.
- **Earned-autonomy readiness (shadow)** — *shipped advisory, grants nothing.* Qualification,
  deterministic task risk, attributed runtime history and evidence integrity considered
  together for the first time, behind an owner-gated read. Every condition is a veto and there
  is no score, so a flawless record cannot offset a protected surface. One hypothetical lane
  (right-sized non-security engineering); all others refused by name. No authorization module
  imports it — proven by falsification. **Nothing is eligible today**, for two independent
  reasons: the 0/14 security result, and no corpus source-file task clearing the
  protected-surface veto.
- **Earned / graduated autonomy (an actual lease)** — *future.* Nothing consumes the readiness
  result; autonomy is fixed-ceiling by policy today, with no self-approval or earned
  escalation.
- **Hermes local training / eval-trace capture** — *future.* No training pipeline exists
  today; Claude-to-Hermes local-model offload is future work.

## Next major scope — orchestration control plane (Phase 2)

The control plane is designed in [orchestration.md](orchestration.md); the enforcement
substrate (above) is live, the running agents are next:

- **OpenClaw probes** — *next:* add model-driven offensive-security / code-review checks for the
  `openclaw` principal (its `allowed_models` and L0 ceiling already exist in policy), on top of
  today's evidence-verification controls.
- **OpenCode OS-level jail** — run both the review sandbox and the act-step apply under a kernel
  jail (seccomp/namespaces / `sandbox-exec`). The protocol-level gate and filesystem verification
  are done; the remaining hardening is the OS boundary.
- **Approval gates** — surface `APPROVAL REQUIRED` to the owner for L4+ gateway actions, reusing
  the act step's approval model.

## Near-term — remaining hardening

- **More security-path coverage** — alias routing and the tool-call-block fallback.
- **Key lifecycle** — rotation/expiry for policy principals (keys are static today).

## Medium-term — packaging and streaming

- True token-by-token streaming (the current SSE path emits a single chunk).
- Container packaging and a documented deploy path.
- Grafana dashboard / alerting examples over the `/metrics` counters.

## Next — extend the eval harness

- **Agentic threat-model probes** *(started)* — the `AGENTIC-*` group takes the black-box
  attacker's stance (assume the model is already captured by injection) and proves the
  authority boundary still holds: ASI01 (goal hijack → ungranted model), ASI03 (privilege
  abuse → autonomy ceiling), ASI06 (memory/context poisoning → secret egress). Maps onto the
  OWASP Top 10 for Agentic Applications (2026); grow toward the full ASI catalogue.
- Extend toward **tool-result poisoning, memory replay, and exfil-via-markdown** once an
  explicitly-gated tool path exists. (Feeding the eval verdict into OpenClaw's assurance so a
  failed eval gates the planning loop is already **done** — see boundary hardening above.)

## Longer-term — capability, behind the same boundary

- Local RAG over project documentation.
- An optional, explicitly-gated tool registry — only if it can be added without
  weakening the "model output is not authority" guarantee.

## Non-goals

- Multi-tenant SaaS operation.
- Public/internet exposure (this is loopback-first by design).
- Autonomous agent loops driving execution without an operator in the loop.
