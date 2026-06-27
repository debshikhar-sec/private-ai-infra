#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$HOME/private-ai-infra}"
LOG_FILE="$PROJECT_ROOT/logs/agents.log"

mkdir -p "$PROJECT_ROOT/logs"

log() {
  printf '%s | openclaw | %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$*" >> "$LOG_FILE"
}

usage() {
  cat <<'EOF'
Usage:
  agents/openclaw.sh status [lines]
  agents/openclaw.sh tail_audit [lines]
  agents/openclaw.sh tail_nginx [lines]
  agents/openclaw.sh health_loop [seconds]
  agents/openclaw.sh summarize_logs [unused]

Safety:
  - Monitoring-only by default
  - No infinite loops
  - No process killing
  - No service restarts
  - Logs all invocations to logs/agents.log
EOF
}

subcommand="${1:-}"
arg="${2:-30}"

if [ -z "$subcommand" ]; then
  usage
  exit 1
fi

log "START subcommand=$subcommand arg=$arg"

if command -v openclaw >/dev/null 2>&1; then
  openclaw_status="available"
else
  openclaw_status="not_found"
fi

audit_log="$PROJECT_ROOT/logs/audit.log"
nginx_access="$PROJECT_ROOT/logs/nginx.access.log"
nginx_error="$PROJECT_ROOT/logs/nginx.error.log"

case "$subcommand" in
  status)
    lines="${arg:-30}"
    echo "OpenClaw wrapper: status mode"
    echo "openclaw binary: $openclaw_status"
    echo "Project root: $PROJECT_ROOT"
    echo
    echo "Listeners:"
    lsof -nP -iTCP:8080 -sTCP:LISTEN || true
    lsof -nP -iTCP:8081 -sTCP:LISTEN || true
    lsof -nP -iTCP:8443 -sTCP:LISTEN || true
    echo
    echo "Health:"
    curl -sS http://127.0.0.1:8080/health 2>/dev/null | python3 -m json.tool || true
    echo
    echo "Models:"
    curl -sS http://127.0.0.1:8081/v1/models \
      -H "Authorization: Bearer ${PRIVATE_AI_AUTH_TOKEN:-private-portfolio-token}" 2>/dev/null | python3 -m json.tool || true
    echo
    echo "Recent audit log:"
    tail -n "$lines" "$audit_log" 2>/dev/null || true
    ;;

  tail_audit)
    lines="${arg:-30}"
    tail -n "$lines" "$audit_log" 2>/dev/null || true
    ;;

  tail_nginx)
    lines="${arg:-30}"
    echo "Nginx access:"
    tail -n "$lines" "$nginx_access" 2>/dev/null || true
    echo
    echo "Nginx error:"
    tail -n "$lines" "$nginx_error" 2>/dev/null || true
    ;;

  health_loop)
    seconds="${arg:-30}"
    case "$seconds" in
      ''|*[!0-9]*)
        echo "ERROR: health_loop seconds must be an integer."
        exit 2
        ;;
    esac
    if [ "$seconds" -gt 120 ]; then
      echo "DENIED: health_loop capped at 120 seconds."
      log "DENY health_loop_too_long seconds=$seconds"
      exit 3
    fi

    end=$((SECONDS + seconds))
    while [ "$SECONDS" -lt "$end" ]; do
      printf '%s ' "$(date '+%H:%M:%S')"
      curl -sS http://127.0.0.1:8080/health 2>/dev/null || true
      echo
      sleep 5
    done
    ;;

  summarize_logs)
    echo "OpenClaw wrapper: summarize logs"
    echo "Audit log: $audit_log"
    echo
    for key in \
      AUTH_SUCCESS \
      AUTH_FAILURE \
      MODEL_LOAD_SUCCESS \
      MODEL_LOAD_FAILED \
      MODEL_REUSE \
      INFERENCE_COMPLETE \
      INFERENCE_FAILED \
      MAX_TOKENS_CLAMPED \
      SANITIZER_BLOCKED_TOOL_CALL
    do
      count="$(grep -c "$key" "$audit_log" 2>/dev/null || true)"
      printf '%-32s %s\n' "$key" "$count"
    done
    echo
    echo "Last active model:"
    grep -E "MODEL_REUSE|MODEL_LOAD_SUCCESS|INFERENCE_START" "$audit_log" 2>/dev/null | tail -n 5 || true
    echo
    echo "Last five errors:"
    grep -Ei "ERROR|FAILED|Traceback|Exception" "$audit_log" 2>/dev/null | tail -n 5 || true
    ;;

  *)
    echo "ERROR: unknown subcommand: $subcommand"
    usage
    log "DENY unknown_subcommand=$subcommand"
    exit 4
    ;;
esac

log "END subcommand=$subcommand arg=$arg"
