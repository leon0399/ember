#!/usr/bin/env bash
# PostToolUse hook: auto-format .rs files after Edit/Write
set -euo pipefail

FILE=$(jq -r '.tool_input.file_path // empty')
if [ -n "$FILE" ] && [[ "$FILE" == *.rs ]]; then
  rustfmt --quiet "$FILE" 2>/dev/null || true
fi
