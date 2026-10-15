#!/usr/bin/env bash
# Stop native PA-Converter services.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

pa_log "Stopping panReadOrders..."
if [ -f "$PA_DATA_ROOT/panReadOrders.pid" ]; then
  kill "$(cat "$PA_DATA_ROOT/panReadOrders.pid")" 2>/dev/null || true
  rm -f "$PA_DATA_ROOT/panReadOrders.pid"
fi
pkill -f 'php .*readOrders.php' 2>/dev/null || true

pa_log "Stopping Apache..."
if command -v apache2ctl >/dev/null 2>&1; then
  apache2ctl -k stop 2>/dev/null || true
fi
pa_service stop apache2 || pa_service stop httpd || true

pa_log "Stopping RabbitMQ..."
pa_service stop rabbitmq-server || true

pa_log "Stopping MariaDB..."
pa_service stop mariadb || pa_service stop mysql || true

pa_log "Native stack stopped."
