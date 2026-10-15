#!/usr/bin/env bash
# One-shot repair for WSL installs where Apache fails to bind 18443/18080.
# Typical cause: duplicate Listen in the vhost + ports.conf, or apache2ctl->systemctl no-op.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

export EXPEDITION_PORT="${EXPEDITION_PORT:-18443}"
export EXPEDITION_HTTP_PORT="${EXPEDITION_HTTP_PORT:-18080}"
export APACHE_LOG_DIR="${APACHE_LOG_DIR:-/var/log/apache2}"
export PA_CONVERTER_ROOT="${PA_CONVERTER_ROOT:-/opt/pa-converter}"

pa_log "Repairing Apache site/ports and starting..."
pa_start_apache || true

if pa_wait_port "${EXPEDITION_PORT}" 15; then
  pa_log "OK - https://localhost:${EXPEDITION_PORT} should work from Windows"
  ss -ltn 2>/dev/null | grep -E ":${EXPEDITION_PORT}|:${EXPEDITION_HTTP_PORT}" || true
  exit 0
fi

pa_log "ERROR: still not listening. Dumping configtest + error log:"
apache2ctl configtest 2>&1 || true
tail -n 50 /var/log/apache2/error.log 2>/dev/null || true
exit 1
