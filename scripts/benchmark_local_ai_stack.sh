#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$HOME/private-ai-infra}"
BENCHMARK_CSV="$PROJECT_ROOT/logs/benchmark.csv"
MODEL_ALIAS="strategy"
RUN_ALL="false"

usage() {
  cat <<'HELP'
Usage:
  scripts/benchmark_local_ai_stack.sh [--model strategy|engineering|offsec] [--all]

Defaults:
  --model strategy

Safety:
  - Uses max_tokens=40
  - Records results to logs/benchmark.csv
  - Does not run --all unless explicitly requested
HELP
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --model)
      MODEL_ALIAS="${2:-}"
      shift 2
      ;;
    --all)
      RUN_ALL="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

case "$MODEL_ALIAS" in
  strategy|engineering|offsec)
    ;;
  *)
    echo "ERROR: invalid model alias: $MODEL_ALIAS"
    exit 2
    ;;
esac

mkdir -p "$PROJECT_ROOT/logs"

if [ ! -f "$BENCHMARK_CSV" ]; then
  echo "timestamp,model_alias,status,duration_seconds,response_chars" > "$BENCHMARK_CSV"
fi

run_one() {
  model="$1"
  tmp="$(mktemp)"

  start="$(python3 -c 'import time; print(time.time())')"

  code="$(curl -sS \
    -o "$tmp" \
    -w "%{http_code}" \
    http://127.0.0.1:8081/v1/chat/completions \
    -H "Authorization: Bearer ${PRIVATE_AI_AUTH_TOKEN:-private-portfolio-token}" \
    -H "Content-Type: application/json" \
    -d "{
      \"model\": \"$model\",
      \"messages\": [
        {\"role\": \"user\", \"content\": \"Return exactly: BENCHMARK_OK\"}
      ],
      \"max_tokens\": 40,
      \"temperature\": 0.0
    }" 2>/dev/null || true)"

  end="$(python3 -c 'import time; print(time.time())')"

  duration="$(python3 - "$start" "$end" <<'PY'
import sys
print(f"{float(sys.argv[2]) - float(sys.argv[1]):.3f}")
PY
)"

  if [ "$code" = "200" ]; then
    status="ok"
  else
    status="http_$code"
  fi

  chars="$(python3 - "$tmp" <<'PY'
import json
import sys

try:
    data = json.load(open(sys.argv[1]))
    content = data["choices"][0]["message"]["content"]
    print(len(content))
except Exception:
    print(0)
PY
)"

  printf '%s,%s,%s,%s,%s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$model" "$status" "$duration" "$chars" >> "$BENCHMARK_CSV"

  echo "MODEL=$model"
  echo "HTTP_STATUS=$code"
  echo "STATUS=$status"
  echo "DURATION_SECONDS=$duration"
  echo "RESPONSE_CHARS=$chars"
  echo "RAW_RESPONSE:"
  cat "$tmp"
  echo

  rm -f "$tmp"
}

if [ "$RUN_ALL" = "true" ]; then
  echo "WARNING: --all may trigger multi-model swaps and can be slow."
  echo "Proceeding because --all was explicitly requested."
  for model in strategy engineering offsec; do
    echo
    echo "===== BENCHMARK $model ====="
    run_one "$model"
  done
else
  run_one "$MODEL_ALIAS"
fi

echo
echo "BENCHMARK_CSV=$BENCHMARK_CSV"
tail -n 5 "$BENCHMARK_CSV"
