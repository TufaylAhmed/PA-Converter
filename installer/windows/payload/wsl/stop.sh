#!/usr/bin/env bash
set -euo pipefail
INSTALL_ROOT="${PA_CONVERTER_ROOT:-/opt/pa-converter}"
COMPOSE_FILE="$INSTALL_ROOT/docker/docker-compose.yml"
cd "$INSTALL_ROOT"
export COMPOSE_PROJECT_NAME=panw-expedition
docker compose -f "$COMPOSE_FILE" down || true
echo "[pa-converter] Stopped."
