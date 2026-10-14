#!/usr/bin/env bash
# Start native PA-Converter services (MariaDB, RabbitMQ, Apache + agent).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

if [ ! -f "$PA_MARKER" ]; then
  pa_log "Not installed yet — running install.sh…"
  bash "$SCRIPT_DIR/install.sh"
fi

pa_ensure_dirs
pa_detect_java
export JAVA_HOME SPARK_HOME PATH
export DB_HOST=127.0.0.1 RABBITMQ_HOST=127.0.0.1
export DB_USER DB_PASS MYSQL_ROOT_PASSWORD

# Apache envvars for PassEnv
ENVVARS=/etc/apache2/envvars
for kv in \
  "export RABBITMQ_HOST=127.0.0.1" \
  "export DB_HOST=127.0.0.1" \
  "export DB_USER=${DB_USER}" \
  "export DB_PASS=${DB_PASS}" \
  "export JAVA_HOME=${JAVA_HOME:-}" \
  "export SPARK_HOME=${SPARK_HOME:-/opt/Spark/spark}"
do
  key="${kv%%=*}"
  key="${key#export }"
  if [ -f "$ENVVARS" ] && ! grep -q "^export ${key}=" "$ENVVARS" 2>/dev/null; then
    echo "$kv" >> "$ENVVARS"
  fi
done

pa_log "Starting MariaDB…"
pa_service start mariadb || pa_service start mysql
pa_log "Starting RabbitMQ…"
pa_service start rabbitmq-server

# Prepare docroot / user defs / agent
bash "$SCRIPT_DIR/entrypoint-native.sh"

pa_log "Starting Apache…"
# Prefer apache2ctl for WSL (systemd often incomplete)
if command -v apache2ctl >/dev/null 2>&1; then
  apache2ctl configtest >/dev/null 2>&1 || true
  apache2ctl start 2>/dev/null || apache2ctl restart 2>/dev/null || pa_service start apache2
else
  pa_service start apache2 || pa_service start httpd
fi

# WSL: ensure Windows can reach ports (best-effort)
if grep -qi microsoft /proc/version 2>/dev/null; then
  pa_log "WSL detected — HTTPS https://localhost:${EXPEDITION_PORT} (Windows)"
fi

pa_log "Native stack started."
pa_log "  HTTPS: https://localhost:${EXPEDITION_PORT}"
pa_log "  HTTP:  http://localhost:${EXPEDITION_HTTP_PORT}"
pa_log "  Login: admin / paloalto"
