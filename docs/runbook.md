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
