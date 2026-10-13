#!/usr/bin/env bash
set -euo pipefail
INSTALL_ROOT="${PA_CONVERTER_ROOT:-/opt/pa-converter}"
COMPOSE_FILE="$INSTALL_ROOT/docker/docker-compose.yml"
MARKER=/var/lib/pa-converter/provisioned

if [ ! -f "$MARKER" ]; then
  exec bash "$INSTALL_ROOT/wsl/provision.sh"
fi

if ! docker info >/dev/null 2>&1; then
  service docker start 2>/dev/null || true
  if ! docker info >/dev/null 2>&1; then
    nohup dockerd >/var/log/pa-converter-dockerd.log 2>&1 &
    sleep 2
  fi
fi

cd "$INSTALL_ROOT"
export COMPOSE_PROJECT_NAME=panw-expedition
export EXPEDITION_PORT="${EXPEDITION_PORT:-18443}"
export EXPEDITION_HTTP_PORT="${EXPEDITION_HTTP_PORT:-18080}"
docker compose -f "$COMPOSE_FILE" up -d
echo "[pa-converter] Started. UI: https://localhost:${EXPEDITION_PORT}"
