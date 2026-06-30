# OpenCode isolated review sandbox

This is the **OpenCode** component of the orchestration control plane: a real,
runnable harness that runs [OpenCode](https://opencode.ai) as a **capability-denied,
read-only code reviewer** against a copy of a target directory, inside an isolated
config/state, and then **proves** — with before/after filesystem manifests — that the
agent modified nothing outside its sandbox.

The thesis in concrete form: an AI coding agent's *capability* to review code is not
*authority* to change your system. Here that is enforced and verified, not assumed.

## How it is confined

| Control | Mechanism |
|---|---|
| **No mutate / exec / network** | [`opencode.jsonc`](opencode.jsonc) denies `edit`, `bash`, `task`, `external_directory`, `webfetch`, `websearch`, `lsp`, `skill`, `todowrite`, `doom_loop`. Only `read`/`glob`/`grep`/`list` are allowed. |
| **No access to your real config** | The harness runs OpenCode under an isolated `XDG_CONFIG_HOME`/`HOME`, with the deny-config copied in — the agent never reads your `~/.config/opencode` or its credentials. |
| **No access to the real tree** | The agent reviews a **copy** of the target, never the working tree. |
| **Model stays local** | Its only provider is the loopback gateway (`127.0.0.1:8081`); the API key is an env placeholder, and the gateway enforces auth/policy independently. |
| **Verified, not assumed** | Before/after `sha256` manifests of the sandbox and of `~/.config/opencode` are diffed; a change to the real config is an `ISOLATION_RESULT=FAIL`. |

The run is also gated by prechecks: gateway token validation against `/v1/models`, a
config-safety check (apiKey is an env placeholder, loopback baseURL, no literal
credentials or user paths), a secret scan of the target, and a process check.

## Run it

```bash
make start                      # gateway must be up
export PRIVATE_AI_AUTH_TOKEN=...   # same token the gateway uses
agents/opencode_sandbox/run_review.sh [TARGET_DIR]   # defaults to examples/review_target
```

Output (report, review JSONL, manifests) lands in `runtime/run_<timestamp>/`, which is
gitignored. A sanitized example of a real run is in
[`examples/isolated_review.report.txt`](examples/isolated_review.report.txt).

## The act step — approval-gated, confined, verified apply

Review *finds* problems; the **act step** is how a fix is *applied* — the write boundary,
and the place the thesis has to be mechanical. The review half above proves OpenCode can
look without touching; the act half (`opencode_sandbox/apply.py`, CLI `opencode_sandbox.act`)
proves a proposed change cannot be applied without authority, cannot escape the target, and
cannot change anything it did not declare. Full rules: [`OPENCODE_ACT_CONTRACT.md`](OPENCODE_ACT_CONTRACT.md).

| Control | Mechanism |
|---|---|
| **Capability ≠ authority** | A `ChangeProposal` (declared edits + rationale) carries no approval; an `Approval` (owner + reason) is a *separate* input. The proposer cannot approve itself. |
| **Fail closed** | Any write is ≥ `owner_run` (L3); without a granted approval the apply is **REFUSED**, like the gateway refusing an unauthenticated request. |
| **No under-declaring** | A proposal with edits is treated as ≥ L3 even if it declares lower, so it cannot label itself `dry_run` to skip the gate (most-privileged-wins, same as the gateway). |
| **Confinement** | Every path must be relative and stay within the target (no `..`, absolute, or symlink escape) — checked **before** any write, else **REJECTED**. |
| **Verified** | The change is applied into a sandbox copy; before/after `sha256` manifests prove **exactly the declared files changed**. An undeclared write is **FAILED**, not a silent pass. |

```bash
# review only — print the diff, write nothing (exit 1: refused, pending approval)
PYTHONPATH=src:agents python -m opencode_sandbox.act \
  agents/opencode_sandbox/examples/fix_sqli.proposal.json --show-diff

# approve + apply into a confined sandbox copy (the real target stays untouched)
PYTHONPATH=src:agents python -m opencode_sandbox.act \
  agents/opencode_sandbox/examples/fix_sqli.proposal.json \
  --approve "alice:reviewed the diff, fixes the SQLi"

# approve + commit the verified change onto the real --target
PYTHONPATH=src:agents python -m opencode_sandbox.act PROPOSAL.json \
  --target path/to/tree --approve "alice:ship it" --commit
```

Unlike the review harness, the act step is **pure-stdlib and offline** (no `opencode`
binary, no gateway), so it is fully covered by the unit suite. The bundled
[`examples/fix_sqli.proposal.json`](examples/fix_sqli.proposal.json) proposes the fix for
the SQL-injection bug in the review target.

## Status & honesty

- The **review** harness is **real and runnable** today; it requires the `opencode` binary,
  a running gateway, and a model — so it is an operator tool, not part of the unit suite.
  The **act** step is pure-stdlib and unit-tested.
- Both confine OpenCode at the *agent-config* / *filesystem-isolation* / *apply-protocol*
  layers. Neither is a kernel sandbox (no seccomp/namespaces) yet; running the apply under
  an OS-level jail is the remaining hardening step. The current guarantees are capability-deny
  + isolated config/state + verified-no-out-of-sandbox-writes (review) and
  capability/authority separation + fail-closed approval + confinement + verified-no-undeclared-writes (act).
