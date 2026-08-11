#!/usr/bin/env bash
# Hardened durable-evidence demo / capture harness.
#
# Runs the ordinary `private-ai-gateway demo` (same plane, same tokens, same console and
# chat) but with the Step 7A/7B.0 durable configuration switched on:
#
#     PRIVATE_AI_STATE_BACKEND=sqlite
#     PRIVATE_AI_EVIDENCE_MODE=durable
#
# using EPHEMERAL HMAC keys generated fresh for this process and a TEMPORARY state
# directory that is deleted on exit. Nothing is persisted beyond the run, no key is ever
# printed, committed, or written anywhere except this process's environment. The ordinary
# zero-config `private-ai-gateway demo` is deliberately left untouched — this script is
# the opt-in hardened variant for capture/verification sessions.
#
# Usage:  scripts/demo_durable.sh [--port 8080] [--keep-state]
set -euo pipefail

PORT=8080
KEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --keep-state) KEEP=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/private-ai-durable-demo.XXXXXX")"
cleanup() {
  if [[ "$KEEP" -eq 0 ]]; then
    rm -rf "$STATE_DIR"
  else
    echo "state kept at: $STATE_DIR (contains NO keys — only the two SQLite stores)"
  fi
}
trap cleanup EXIT

# Ephemeral per-run signing keys — generated, exported, never echoed.
PRIVATE_AI_EVIDENCE_KEY_GATEWAY="$(openssl rand -hex 32)"
PRIVATE_AI_EVIDENCE_KEY_OPENCODE="$(openssl rand -hex 32)"
PRIVATE_AI_EVIDENCE_KEY_OPENCLAW="$(openssl rand -hex 32)"
export PRIVATE_AI_EVIDENCE_KEY_GATEWAY PRIVATE_AI_EVIDENCE_KEY_OPENCODE
export PRIVATE_AI_EVIDENCE_KEY_OPENCLAW
export PRIVATE_AI_STATE_BACKEND=sqlite
export PRIVATE_AI_STATE_DIR="$STATE_DIR"
export PRIVATE_AI_EVIDENCE_MODE=durable

echo "durable demo plane: sqlite authority + signed durable evidence (ephemeral keys)"
echo "state dir (temporary): $STATE_DIR"
exec python -m private_ai_gateway.cli demo --port "$PORT"
