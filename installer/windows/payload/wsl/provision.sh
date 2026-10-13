#!/usr/bin/env bash
# Runs inside the PA-Converter WSL distro as root.
# Installs Docker Engine + Compose and brings Expedition up.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
INSTALL_ROOT="${PA_CONVERTER_ROOT:-/opt/pa-converter}"
COMPOSE_FILE="$INSTALL_ROOT/docker/docker-compose.yml"
MARKER=/var/lib/pa-converter/provisioned

mkdir -p /var/lib/pa-converter /data /home/userSpace
echo "[pa-converter] Provisioning at $INSTALL_ROOT"

need_docker=0
if ! command -v docker >/dev/null 2>&1; then
  need_docker=1
elif ! docker compose version >/dev/null 2>&1; then
  need_docker=1
fi

if [ "$need_docker" -eq 1 ]; then
  echo "[pa-converter] Installing Docker Engine (open source) inside WSL…"
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg apt-transport-https lsb-release
  install -m 0755 -d /etc/apt/keyrings
  if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
  fi
  codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${codename} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y --no-install-recommends \
    docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-buildx-plugin
fi

# WSL often needs the daemon started manually (no systemd on older WSL)
if ! docker info >/dev/null 2>&1; then
  echo "[pa-converter] Starting dockerd…"
  mkdir -p /var/run
  if command -v service >/dev/null 2>&1; then
    service docker start || true
  fi
  if ! docker info >/dev/null 2>&1; then
    nohup dockerd >/var/log/pa-converter-dockerd.log 2>&1 &
    for i in $(seq 1 30); do
      docker info >/dev/null 2>&1 && break
      sleep 1
    done
  fi
fi

if ! docker info >/dev/null 2>&1; then
  echo "[pa-converter] ERROR: Docker engine failed to start inside WSL." >&2
  exit 1
fi

cd "$INSTALL_ROOT"
export COMPOSE_PROJECT_NAME=panw-expedition
export EXPEDITION_PORT="${EXPEDITION_PORT:-18443}"
export EXPEDITION_HTTP_PORT="${EXPEDITION_HTTP_PORT:-18080}"

echo "[pa-converter] Building and starting Expedition (first run can take several minutes)…"
docker compose -f "$COMPOSE_FILE" up -d --build

touch "$MARKER"
echo "[pa-converter] Stack is up."
echo "[pa-converter] Open https://localhost:${EXPEDITION_PORT}  (admin / paloalto)"
