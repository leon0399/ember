#!/usr/bin/env bash
# Stop hook: run fmt check + clippy before Claude finishes.
# CRITICAL: check stop_hook_active to avoid infinite loops.
set -euo pipefail

INPUT=$(cat)
if [ "$(echo "$INPUT" | jq -r '.stop_hook_active')" = "true" ]; then
  exit 0
fi

# Check formatting
if ! cargo fmt --all -- --check 2>&1; then
  echo "Formatting issues found. Run cargo fmt." >&2
  exit 2
fi

# Check clippy
if ! cargo clippy --all-targets --all-features -- -D warnings 2>&1; then
  echo "Clippy warnings found." >&2
  exit 2
fi
