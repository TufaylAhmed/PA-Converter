#!/usr/bin/env bash
# Runs inside the PA-Converter WSL distro as root.
# Native install (no Docker Engine / Compose).
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
INSTALL_ROOT="${PA_CONVERTER_ROOT:-/opt/pa-converter}"
MARKER=/var/lib/pa-converter/provisioned

# Unbuffered progress so Windows SETUP Write-Progress updates live
export PYTHONUNBUFFERED=1

mkdir -p /var/lib/pa-converter /data /home/userSpace /PALogs

# shellcheck source=/dev/null
if [ -f "$INSTALL_ROOT/native/lib/common.sh" ]; then
  # shellcheck disable=SC1091
  source "$INSTALL_ROOT/native/lib/common.sh"
else
  pa_progress() {
    local pct="$1" phase="$2"; shift 2
    if [ ! -t 1 ] || [ -n "${PA_PROGRESS_MACHINE:-}" ]; then
      printf 'PA_PROGRESS|%s|%s|%s\n' "$pct" "$phase" "$*"
    fi
    local filled=$((pct / 5)) empty=$((20 - filled))
    local bar
    bar="$(printf '%*s' "$filled" '' | tr ' ' '#')"
    bar="${bar}$(printf '%*s' "$empty" '' | tr ' ' '-')"
    printf '[pa-converter] [%s] %3d%%  %s\n' "$bar" "$pct" "$*"
  }
  pa_log() { echo "[pa-converter] $*"; }
fi

pa_progress 1 provision "Provisioning native stack at $INSTALL_ROOT"

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

pa_progress 3 install "Installing packages + Spark (first run can take 10–20 minutes)..."
# stdbuf keeps apt/progress lines flushing to SETUP
if command -v stdbuf >/dev/null 2>&1; then
  stdbuf -oL -eL bash "$INSTALL_ROOT/native/install.sh"
else
  bash "$INSTALL_ROOT/native/install.sh"
fi

pa_progress 97 start "Starting Apache / MariaDB / RabbitMQ / agent..."
bash "$INSTALL_ROOT/native/start.sh"

touch "$MARKER"
pa_progress 100 ready "Stack is up - open https://localhost:${EXPEDITION_PORT}"
echo "[pa-converter] Stack is up (native, no containers)."
echo "[pa-converter] Open https://localhost:${EXPEDITION_PORT}  (admin / paloalto)"
