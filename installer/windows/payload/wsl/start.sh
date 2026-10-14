#!/usr/bin/env bash
set -euo pipefail
INSTALL_ROOT="${PA_CONVERTER_ROOT:-/opt/pa-converter}"
MARKER=/var/lib/pa-converter/provisioned

if [ ! -f "$MARKER" ]; then
  exec bash "$INSTALL_ROOT/wsl/provision.sh"
fi

export PA_CONVERTER_ROOT="$INSTALL_ROOT"
export EXPEDITION_PORT="${EXPEDITION_PORT:-18443}"
export EXPEDITION_HTTP_PORT="${EXPEDITION_HTTP_PORT:-18080}"
bash "$INSTALL_ROOT/native/start.sh"
echo "[pa-converter] Started. UI: https://localhost:${EXPEDITION_PORT}"
