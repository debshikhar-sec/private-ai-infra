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

## Status & honesty

- This harness is **real and runnable** today; it requires the `opencode` binary, a
  running gateway, and a model — so it is an operator tool, not part of the unit suite.
- It confines OpenCode at the *agent-config* and *filesystem-isolation* layers. It is
  not a kernel sandbox (no seccomp/namespaces); a future hardening step is to additionally
  run it under an OS-level jail. The current guarantees are capability-deny + isolated
  config/state + verified-no-out-of-sandbox-writes.
