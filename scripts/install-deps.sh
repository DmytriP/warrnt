#!/usr/bin/env bash
# Install the runtime deps into an existing venv.
#
# Portable on purpose: no absolute host paths. Run it from anywhere.
#   PY=/path/to/venv/bin/python  ./scripts/install-deps.sh
# Falls back from `uv pip` to plain `pip`.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PY="${PY:-$ROOT/.venv/bin/python}"

[ -x "$PY" ] || { echo "no interpreter at $PY - create the venv first:"; echo "  python3 -m venv .venv"; exit 1; }

if command -v uv >/dev/null 2>&1; then
  uv pip install -r "$ROOT/requirements.txt" --python "$PY"
else
  "$PY" -m pip install -r "$ROOT/requirements.txt"
fi
