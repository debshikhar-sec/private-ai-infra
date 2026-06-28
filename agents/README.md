# Operator Wrappers

Owner-run helper scripts that demonstrate a least-privilege boundary around local
operations. They are **not** wired into the gateway as autonomous tools — the operator
runs them deliberately.

These are the present-day, deliberately-minimal stand-ins for the **OpenCode** (code) and
**OpenClaw** (security/observability) surfaces of the orchestration control plane. The full
design — components, the L0–L6 autonomy ladder, and current-vs-planned status — is in
[docs/orchestration.md](../docs/orchestration.md). Phase 2 graduates `opencode.sh` into a real
sandbox and adds the Hermes planner; until then these wrappers stay read-only by design.

## Wrappers

- **`wrappers/opencode.sh`** — read-only engineering inspection and safe syntax tests.
  `inspect` previews project files; `test` runs `bash -n` and JSON validation;
  `suggest_patch` writes a placeholder; `apply_patch` is a no-op behind `--confirm`.
- **`wrappers/openclaw.sh`** — monitoring only: listener/health status, audit/nginx log
  tailing, a length-capped health loop, and audit-log summarization.

## Safety properties

These are the properties worth noting (and the reason the wrappers exist):

- **Project-root jail** — every target path is resolved with `realpath` and rejected if
  it escapes the project root.
- **Read-only by default** — no file modification; the patch path is a no-op until an
  explicit engine is added and approved.
- **Sensitive-file skip** — previews are refused for `.env`, `*.key`, `*.pem`, etc.
- **No process control** — no killing, no service restarts, no package installation.
- **Bounded loops** — the health loop is hard-capped (≤120s), no infinite loops.
- **Audited** — every invocation logs to `logs/agents.log`.

## Configuration

`openclaw.sh status` calls the gateway and reads
`PRIVATE_AI_AUTH_TOKEN` from the environment (see [.env.example](../.env.example)).
