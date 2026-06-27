#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$HOME/private-ai-infra}"
LOG_FILE="$PROJECT_ROOT/logs/agents.log"
PATCH_DIR="$PROJECT_ROOT/agents/patches"

mkdir -p "$PROJECT_ROOT/logs" "$PATCH_DIR"

log() {
  printf '%s | opencode | %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$*" >> "$LOG_FILE"
}

usage() {
  cat <<'USAGE'
Usage:
  agents/opencode.sh inspect <path> [note]
  agents/opencode.sh test <path> [note]
  agents/opencode.sh suggest_patch <path> [note]
  agents/opencode.sh apply_patch <path> --confirm [note]

Safety:
  - Only allows paths under ~/private-ai-infra
  - Supports both file and directory targets
  - Does not invoke OpenCode TUI, auth, MCP, ACP, server, web, GitHub, plugin, or db commands
  - Does not modify files unless a future patch engine is explicitly approved
  - apply_patch requires --confirm but is currently a no-op
  - Logs all invocations to logs/agents.log
USAGE
}

if [ ! -d "$PROJECT_ROOT" ]; then
  echo "ERROR: PROJECT_ROOT does not exist: $PROJECT_ROOT"
  exit 1
fi

real_project_root="$(cd "$PROJECT_ROOT" && pwd -P)"

subcommand="${1:-}"
if [ -z "$subcommand" ]; then
  usage
  exit 1
fi
shift || true

if [ "$#" -gt 0 ]; then
  target_path="$1"
  shift || true
else
  target_path="$PROJECT_ROOT"
fi

confirm_arg=""
if [ "$subcommand" = "apply_patch" ] && [ "${1:-}" = "--confirm" ]; then
  confirm_arg="--confirm"
  shift || true
fi

note="$*"

if [ ! -e "$target_path" ]; then
  echo "ERROR: target path does not exist: $target_path"
  log "DENY missing_path subcommand=$subcommand target=$target_path"
  exit 2
fi

real_target="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$target_path")"

if [ -d "$real_target" ]; then
  target_type="directory"
elif [ -f "$real_target" ]; then
  target_type="file"
else
  echo "ERROR: target is neither regular file nor directory: $real_target"
  log "DENY unsupported_target_type subcommand=$subcommand target=$real_target"
  exit 2
fi

case "$real_target" in
  "$real_project_root"|"$real_project_root"/*)
    ;;
  *)
    echo "DENIED: target path is outside project root."
    echo "PROJECT_ROOT=$real_project_root"
    echo "TARGET=$real_target"
    log "DENY outside_root subcommand=$subcommand target=$real_target"
    exit 3
    ;;
esac

log "START subcommand=$subcommand target=$real_target type=$target_type note=$note"

if command -v opencode >/dev/null 2>&1; then
  opencode_status="available"
else
  opencode_status="not_found"
fi

safe_file_preview() {
  local f="$1"
  local base
  base="$(basename "$f")"

  case "$base" in
    .env|.env.*|*.key|*.pem|*.p12|*.pfx)
      echo "Content preview skipped for sensitive-looking file: $base"
      return 0
      ;;
  esac

  echo "File metadata:"
  ls -la "$f"
  echo
  echo "File type:"
  file "$f" || true
  echo
  echo "First 80 lines:"
  sed -n '1,80p' "$f" 2>/dev/null || echo "Preview unavailable."
}

case "$subcommand" in
  inspect)
    echo "OpenCode wrapper: inspect mode"
    echo "opencode binary: $opencode_status"
    echo "Target: $real_target"
    echo "Target type: $target_type"
    if [ -n "$note" ]; then
      echo "Note: $note"
    fi
    echo

    if [ "$target_type" = "directory" ]; then
      echo "Top-level project files:"
      find "$real_target" -maxdepth 2 -type f \
        \( -name '*.md' -o -name '*.json' -o -name '*.py' -o -name '*.sh' -o -name '*.conf' \) \
        | sed "s#^$real_project_root/##" \
        | sort \
        | head -80
    else
      safe_file_preview "$real_target"
    fi
    ;;

  test)
    echo "OpenCode wrapper: safe test mode"
    echo "Target: $real_target"
    echo "Target type: $target_type"
    if [ -n "$note" ]; then
      echo "Note: $note"
    fi
    echo
    echo "Running bash syntax checks:"
    find "$real_project_root/scripts" "$real_project_root/agents" -maxdepth 1 -type f -name '*.sh' 2>/dev/null | sort | while read -r f; do
      echo "bash -n $f"
      bash -n "$f"
    done
    echo
    echo "Running JSON validation:"
    json_found=0
    while IFS= read -r jf; do
      json_found=1
      if python3 -m json.tool "$jf" >/dev/null 2>&1; then
        echo "valid: ${jf#"$real_project_root"/}"
      else
        echo "INVALID: ${jf#"$real_project_root"/}"
      fi
    done < <(find "$real_project_root" -maxdepth 2 -type f -name '*.json' -not -path '*/node_modules/*' 2>/dev/null)
    [ "$json_found" -eq 0 ] && echo "no JSON files found"
    ;;

  suggest_patch)
    patch_file="$PATCH_DIR/suggested_patch_$(date +%Y%m%d-%H%M%S).txt"
    {
      echo "# Suggested Patch Placeholder"
      echo
      echo "Created: $(date)"
      echo "Target: $real_target"
      echo "Target type: $target_type"
      echo "Note: $note"
      echo
      echo "No patch applied. This wrapper is suggest-only unless a future patch engine is explicitly approved."
    } > "$patch_file"
    echo "Patch suggestion placeholder created:"
    echo "$patch_file"
    ;;

  apply_patch)
    if [ "$confirm_arg" != "--confirm" ]; then
      echo "DENIED: apply_patch requires --confirm."
      log "DENY apply_patch_missing_confirm target=$real_target"
      exit 4
    fi

    echo "apply_patch confirmed, but no automatic patch engine is enabled."
    echo "Paste or review a patch manually before applying."
    log "APPLY_PATCH_NOOP target=$real_target"
    ;;

  *)
    echo "ERROR: unknown subcommand: $subcommand"
    usage
    log "DENY unknown_subcommand=$subcommand"
    exit 5
    ;;
esac

log "END subcommand=$subcommand target=$real_target type=$target_type"
