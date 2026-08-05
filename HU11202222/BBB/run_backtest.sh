#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! command -v uv >/dev/null 2>&1; then
  echo "ERROR: uv was not found in PATH. Install it with:" >&2
  echo "  curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  set -- --start 2026-06-01 --end 2026-07-01
fi

cd "$SCRIPT_DIR"
uv run backtest-vpn "$@"
