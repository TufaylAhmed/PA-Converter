#!/usr/bin/env bash
# Runs inside the PA-Converter WSL distro as root.
# Native install (no Docker Engine / Compose).
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
INSTALL_ROOT="${PA_CONVERTER_ROOT:-/opt/pa-converter}"
MARKER=/var/lib/pa-converter/provisioned

mkdir -p /var/lib/pa-converter /data /home/userSpace /PALogs
echo "[pa-converter] Provisioning native stack at $INSTALL_ROOT"

if [ ! -f "$INSTALL_ROOT/native/install.sh" ]; then
  echo "[pa-converter] ERROR: native/install.sh missing under $INSTALL_ROOT" >&2
  echo "[pa-converter] Re-run SETUP so engine.zip syncs into WSL." >&2
  exit 1
fi

export PA_CONVERTER_ROOT="$INSTALL_ROOT"
export EXPEDITION_PORT="${EXPEDITION_PORT:-18443}"
export EXPEDITION_HTTP_PORT="${EXPEDITION_HTTP_PORT:-18080}"
export DB_HOST=127.0.0.1
export RABBITMQ_HOST=127.0.0.1

echo "[pa-converter] Installing packages + Spark (first run can take several minutes)…"
bash "$INSTALL_ROOT/native/install.sh"

echo "[pa-converter] Starting services…"
bash "$INSTALL_ROOT/native/start.sh"

touch "$MARKER"
echo "[pa-converter] Stack is up (native, no containers)."
echo "[pa-converter] Open https://localhost:${EXPEDITION_PORT}  (admin / paloalto)"
