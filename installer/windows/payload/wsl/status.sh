#!/usr/bin/env bash
set -euo pipefail
INSTALL_ROOT="${PA_CONVERTER_ROOT:-/opt/pa-converter}"
COMPOSE_FILE="$INSTALL_ROOT/docker/docker-compose.yml"
if ! docker info >/dev/null 2>&1; then
  echo "[pa-converter] Docker is not running inside WSL."
  exit 1
fi
cd "$INSTALL_ROOT"
export COMPOSE_PROJECT_NAME=panw-expedition
docker compose -f "$COMPOSE_FILE" ps
