# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
