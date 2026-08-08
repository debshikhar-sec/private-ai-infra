# Runbook

## Purpose

This runbook documents safe local operations for the Private AI Infrastructure Lab.

The runbook assumes all commands are executed by the human owner from:

~/private-ai-infra

## Baseline Checks

Run:

cd ~/private-ai-infra
pwd
arch
lsof -nP -iTCP:8080 -sTCP:LISTEN || true
lsof -nP -iTCP:8081 -sTCP:LISTEN || true

Expected:

- project path resolves to ~/private-ai-infra
- architecture is Apple Silicon compatible
- port 8080 may show Flask gateway when running
- port 8081 may show Nginx gateway when running

## Start Stack

Run:

cd ~/private-ai-infra
./scripts/start_local_ai_stack.sh

Expected:

- Flask starts on 127.0.0.1:8080
- Nginx starts on 127.0.0.1:8081
- model discovery through Nginx succeeds

## Stop Stack

Run:

cd ~/private-ai-infra
./scripts/stop_local_ai_stack.sh

Expected:

- Nginx stops
- Flask gateway stops

## Health Check

Run:

curl -sS http://127.0.0.1:8080/health | python3 -m json.tool

Expected:

- status is ok
- models include strategy, engineering, and offsec routing

## Model Discovery

Run:

curl -sS http://127.0.0.1:8081/v1/models -H "Authorization: Bearer YOUR_TOKEN" | python3 -m json.tool

Expected:

- strategy alias is listed
- engineering alias is listed
- offsec alias is listed
- resolved model names are listed

## Identity Introspection

Run:

curl -sS http://127.0.0.1:8081/v1/whoami -H "Authorization: Bearer YOUR_TOKEN" | python3 -m json.tool

Expected:

- principal name is reported
- allowed_models, max_output_tokens, and requests_per_minute reflect the active policy

## Metrics

Run:

curl -sS http://127.0.0.1:8081/metrics -H "Authorization: Bearer YOUR_TOKEN"

Expected:

- Prometheus text exposition (HELP/TYPE lines)
- gateway_requests_total, gateway_authz_denials_total, gateway_rate_limited_total, and
  gateway_guardrail_events_total counters are present

## Live enforcement demo

Demonstrates the core thesis on the wire: a principal capped at autonomy **L1** with
models `["strategy"]` is refused `403` the moment it asks for more — *before* any model
loads. This is what [`demo/enforce.tape`](../demo/enforce.tape) records into the README GIF.

**1. Enable a policy with a restricted principal.** Generate a demo key and its hash:

```bash
printf '%s' 'hermes-demo-key-001' | shasum -a 256     # -> put the hash in config/policy.toml
```

Add it to `config/policy.toml` (gitignored; copy from `config/policy.example.toml`):

```toml
[[principals]]
name = "hermes"
key_sha256 = "<hash from above>"
allowed_models = ["strategy"]
max_autonomy_level = "L1"
```

**2. Start the stack and exercise the ceilings:**

```bash
make start
H='Authorization: Bearer hermes-demo-key-001'

# (a) declares L6 — more autonomy than its mandate  -> 403 autonomy_exceeded
curl -s :8081/v1/chat/completions -H "$H" -H 'X-Autonomy-Level: 6' \
  -d '{"model":"strategy","messages":[{"role":"user","content":"hi"}]}' -w '\nHTTP %{http_code}\n'

# (b) requests a model outside its allowlist            -> 403 model_not_allowed
curl -s :8081/v1/chat/completions -H "$H" \
  -d '{"model":"offsec","messages":[{"role":"user","content":"hi"}]}' -w '\nHTTP %{http_code}\n'

# (c) under-declares: header L1, body L6 (smuggle)      -> 403 (most-privileged-wins)
curl -s :8081/v1/chat/completions -H "$H" -H 'X-Autonomy-Level: 1' \
  -d '{"model":"strategy","autonomy_level":6,"messages":[{"role":"user","content":"hi"}]}' -w '\nHTTP %{http_code}\n'
```

**3. Confirm the loop closed — the denials are audited and independently re-verified:**

```bash
PYTHONPATH=agents python -m openclaw.run --audit logs/decisions.jsonl --policy config/policy.toml \
  | grep -E 'verdict|AUTONOMY-CEILING|AUTHZ-MODEL'      # -> PASS
make stop
```

**Regenerate the README GIF** (requires `vhs`: `brew install vhs`) while the stack from
step 2 is running:

```bash
vhs demo/enforce.tape       # writes docs/assets/enforce.gif
```

## Durable State and Live Evidence (Steps 7A / 7B.0)

The default backend is `memory` (restart-forgetting; no configuration needed). To persist
authority and evidence across restarts, run from the repo checkout (the `agents/` packages
must be importable) with:

    export PRIVATE_AI_STATE_BACKEND=sqlite
    export PRIVATE_AI_STATE_DIR=~/private-ai-state     # existing, writable directory

This creates/opens `authority.sqlite3` and `evidence.sqlite3` as two separate,
exclusively-owned databases (a second concurrent gateway on the same state directory fails
closed by design; `<db>.lock` sidecar files are the ownership locks — never delete them
while a gateway runs).

The recommended **hardened** configuration additionally wires the live durable evidence
chain end to end:

    export PRIVATE_AI_EVIDENCE_MODE=durable
    export PRIVATE_AI_EVIDENCE_KEY_GATEWAY=$(openssl rand -hex 32)
    export PRIVATE_AI_EVIDENCE_KEY_OPENCODE=$(openssl rand -hex 32)

Keep the two key values stable across restarts (store them in your shell profile or a
secrets manager, never in the repo): the chain re-verifies against them on every startup.
In this mode signed authorization/apply evidence is required fail-closed
(`REQUIRE_AUTHORIZATION_EVIDENCE` is forced on), and OpenClaw refuses a PASS without a
verified signed chain.

Expected failures (all fail closed, by design):

- durable mode without the sqlite backend, or with a missing/short/non-hex key → startup
  refusal naming the variable;
- a populated `evidence.sqlite3` opened in `off` mode → startup refusal telling you to use
  durable mode with the configured keys;
- changed/wrong keys against an existing chain → signature verification failure at startup;
- corruption of either database → constructor-time integrity failure (restore from backup;
  nothing is auto-repaired).

To see the hardened configuration end to end without committing to persistent keys, run
`scripts/demo_durable.sh`. It starts the ordinary demo plane with the sqlite backend and
durable evidence mode using **ephemeral per-run keys** in a temporary state directory that
is deleted on exit — the keys are never printed, written to disk, or committed. Use it for
demos, captures, and verification sessions; use the exported configuration above for any
state you intend to keep.

## Strategy Benchmark

Run:

./scripts/benchmark_local_ai_stack.sh --model strategy

Expected:

- HTTP_STATUS=200
- STATUS=ok
- raw response contains BENCHMARK_OK
- logs/benchmark.csv receives a new row

## Log Summary

Run:

./scripts/log_summary.sh

Review:

- AUTH_SUCCESS
- AUTH_FAILURE
- MODEL_LOAD_SUCCESS
- MODEL_LOAD_FAILED
- INFERENCE_COMPLETE
- INFERENCE_FAILED
- MAX_TOKENS_CLAMPED
- SANITIZER_BLOCKED_TOOL_CALL

## Safe Wrapper Checks

Run:

./agents/wrappers/opencode.sh inspect ~/private-ai-infra
./agents/wrappers/opencode.sh test ~/private-ai-infra
./agents/wrappers/openclaw.sh summarize_logs 0

Expected:

- wrappers execute without syntax errors
- wrapper activity is logged to logs/agents.log
- no files are modified by inspect or test mode

## Failure Handling

### HTTP 401

Check the authorization header.

Required header:

Authorization: Bearer YOUR_TOKEN

### Model output contains thinking or tool tags

Stop the client workflow and revalidate the gateway sanitizer.

### Qwen template error

Check for multiple system messages. Gateway should merge Qwen system messages before template rendering.

### Slow first response

First load can be slow. Look for MODEL_LOAD_START and MODEL_LOAD_SUCCESS in logs/audit.log.

### Client emits fake tool calls

Stop the session and revalidate tool-call blocking.
