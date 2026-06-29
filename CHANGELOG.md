# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
