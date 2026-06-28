#!/usr/bin/env bash
#
# Isolated OpenCode review harness.
#
# Runs OpenCode as a CAPABILITY-DENIED, READ-ONLY reviewer (see opencode.jsonc) against
# a COPY of a target directory, inside an ISOLATED XDG config/state, and then VERIFIES
# via before/after filesystem manifests that nothing outside the sandbox was modified.
#
# The point is not "an agent that reviews code" — it is an agent that is *provably
# confined*: it cannot edit, shell out, reach the network, or touch your real OpenCode
# config, and the harness produces the manifests that prove it.
#
# Requirements: the `opencode` binary, a running gateway (`make start`), and
# PRIVATE_AI_AUTH_TOKEN in the environment. Runtime output lands in ./runtime/ (gitignored).
#
# Usage:  agents/opencode_sandbox/run_review.sh [TARGET_DIR]
#         TARGET_DIR defaults to the bundled examples/review_target.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_FILE="$SCRIPT_DIR/opencode.jsonc"
TARGET_DIR="${1:-$SCRIPT_DIR/examples/review_target}"

RUN_ID="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="$SCRIPT_DIR/runtime/run_$RUN_ID"
SANDBOX="$RUN_DIR/sandbox"          # the COPY the agent is allowed to see
XDG_ROOT="$RUN_DIR/xdg"             # isolated config/state/cache/data
REPORT="$RUN_DIR/report.txt"
REVIEW_OUT="$RUN_DIR/review.jsonl"
STDERR_LOG="$RUN_DIR/stderr.log"

GATEWAY_URL="${PRIVATE_AI_GATEWAY_URL:-http://127.0.0.1:8081}"
TOKEN="${PRIVATE_AI_AUTH_TOKEN:-}"

mkdir -p "$SANDBOX" "$XDG_ROOT/config/opencode"
: > "$REPORT"

say() { echo "$@" | tee -a "$REPORT"; }
fail() { say "FAIL: $*"; exit 1; }

say "RUN_ID=$RUN_ID"
say "TARGET=${TARGET_DIR#"$PROJECT_ROOT"/}"
say "RUN_DIR=${RUN_DIR#"$PROJECT_ROOT"/}"
say ""

# ----------------------------------------------------------------------------
say "===== PRECHECKS ====="
[ -f "$CONFIG_FILE" ] || fail "capability-deny config missing: $CONFIG_FILE"
[ -d "$TARGET_DIR" ] || fail "target dir not found: $TARGET_DIR"
command -v opencode >/dev/null 2>&1 || fail "opencode binary not found on PATH"
say "PASS: opencode binary found: $(command -v opencode) ($(opencode --version 2>/dev/null | head -1))"
[ -n "$TOKEN" ] || fail "PRIVATE_AI_AUTH_TOKEN is not set"
say "PASS: token present (length ${#TOKEN})"

# Copy the deny-config into the ISOLATED XDG config so the agent never reads the
# operator's real ~/.config/opencode.
cp "$CONFIG_FILE" "$XDG_ROOT/config/opencode/opencode.jsonc"
say "PASS: copied capability-deny config into isolated XDG config"
say ""

# ----------------------------------------------------------------------------
say "===== PROCESS CHECK (BEFORE) ====="
if pgrep -x opencode >/dev/null 2>&1; then
  fail "an opencode process is already running; refusing to start a second"
fi
say "PASS: no pre-existing opencode process"
say ""

# ----------------------------------------------------------------------------
say "===== GATEWAY TOKEN VALIDATION ====="
code="$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" "$GATEWAY_URL/v1/models" || echo 000)"
say "MODELS_HTTP_CODE=$code"
[ "$code" = "200" ] || fail "gateway token did not validate against /v1/models (got $code)"
say "PASS: gateway token validates against /v1/models"
say ""

# ----------------------------------------------------------------------------
say "===== CONFIG SAFETY CHECK ====="
cfg="$XDG_ROOT/config/opencode/opencode.jsonc"
grep -q '{env:' "$cfg"            || fail "apiKey is not an env placeholder in $cfg"
say "PASS: apiKey uses env placeholder"
grep -q '127.0.0.1' "$cfg"        || fail "local gateway baseURL not present in $cfg"
say "PASS: local gateway baseURL present"
if grep -nEi 'Bearer [A-Za-z0-9._-]{8,}|/Users/|/home/|AKIA|sk-[A-Za-z0-9]{20}' "$cfg"; then
  fail "config contains a literal credential or user path"
fi
say "PASS: no literal bearer/user-path/cloud-token references"
say ""

# ----------------------------------------------------------------------------
say "===== SECRET SCAN (TARGET) ====="
fatal=0
while IFS= read -r hit; do
  fatal=$((fatal + 1)); say "  HIT: $hit"
done < <(grep -rIlEi 'AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY|sk-[A-Za-z0-9]{20}' "$TARGET_DIR" 2>/dev/null || true)
say "FATAL_HIT_COUNT=$fatal"
[ "$fatal" -eq 0 ] || fail "target contains credential-shaped content; refusing to review"
say "SECRET_SCAN_RESULT=PASS_NO_FATAL_HITS"
say ""

# ----------------------------------------------------------------------------
# Copy target -> sandbox. The agent reviews the COPY, never the real tree.
cp -R "$TARGET_DIR/." "$SANDBOX/"

manifest() {  # manifest <dir> -> "sha256  relpath" lines, sorted, stable
  ( cd "$1" 2>/dev/null && find . -type f -not -path '*/.git/*' -print0 \
      | sort -z | xargs -0 shasum -a 256 2>/dev/null ) || true
}

GLOBAL_OPENCODE="${XDG_CONFIG_HOME_REAL:-$HOME/.config/opencode}"

say "===== SNAPSHOT (BEFORE) ====="
manifest "$SANDBOX"          > "$RUN_DIR/sandbox.before.txt"
manifest "$GLOBAL_OPENCODE"  > "$RUN_DIR/global_opencode.before.txt"
say "sandbox files: $(wc -l < "$RUN_DIR/sandbox.before.txt" | tr -d ' ')"
say "global opencode-state files: $(wc -l < "$RUN_DIR/global_opencode.before.txt" | tr -d ' ')"
say ""

# ----------------------------------------------------------------------------
say "===== RUN ISOLATED OPENCODE REVIEW ====="
PROMPT="You are a read-only code reviewer. Review the files in this directory and report \
risks, bugs, and security issues. You cannot edit files, run commands, or access the network."

set +e
env -i \
  PATH="$PATH" HOME="$XDG_ROOT" \
  XDG_CONFIG_HOME="$XDG_ROOT/config" \
  XDG_DATA_HOME="$XDG_ROOT/data" \
  XDG_CACHE_HOME="$XDG_ROOT/cache" \
  XDG_STATE_HOME="$XDG_ROOT/state" \
  PRIVATE_AI_AUTH_TOKEN="$TOKEN" \
  opencode run "$PROMPT" --cwd "$SANDBOX" \
  > "$REVIEW_OUT" 2> "$STDERR_LOG"
OPENCODE_EXIT=$?
set -e
say "OPENCODE_EXIT=$OPENCODE_EXIT"
say "review output: ${REVIEW_OUT#"$PROJECT_ROOT"/} ($(wc -l < "$REVIEW_OUT" | tr -d ' ') lines)"
say ""

# ----------------------------------------------------------------------------
say "===== ISOLATION VERDICT (AFTER) ====="
manifest "$SANDBOX"          > "$RUN_DIR/sandbox.after.txt"
manifest "$GLOBAL_OPENCODE"  > "$RUN_DIR/global_opencode.after.txt"

verdict_pass=1
if ! diff -q "$RUN_DIR/sandbox.before.txt" "$RUN_DIR/sandbox.after.txt" >/dev/null; then
  say "WARN: sandbox copy changed (edit is denied; investigate)"; verdict_pass=0
else
  say "PASS: sandbox copy unmodified (read-only review)"
fi
if ! diff -q "$RUN_DIR/global_opencode.before.txt" "$RUN_DIR/global_opencode.after.txt" >/dev/null; then
  say "FAIL: real ~/.config/opencode changed — isolation breach"; verdict_pass=0
else
  say "PASS: real ~/.config/opencode untouched — agent stayed in its isolated config"
fi

say ""
if [ "$verdict_pass" -eq 1 ]; then
  say "ISOLATION_RESULT=PASS"
else
  say "ISOLATION_RESULT=FAIL"
  exit 1
fi
say "Report: ${REPORT#"$PROJECT_ROOT"/}"
