# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
