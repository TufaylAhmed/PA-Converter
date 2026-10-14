#!/usr/bin/env bash
# Tail native PA-Converter logs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

FOLLOW=0
for a in "$@"; do
  case "$a" in
    -f|--follow) FOLLOW=1 ;;
  esac
done

FILES=()
for f in \
  /var/log/apache2/pa-converter-ssl-error.log \
  /var/log/apache2/pa-converter-http-error.log \
  /var/log/apache2/error.log \
  "$PA_USERSPACE/panReadOrders.log" \
  "$PA_LOG_DIR"/*.log
do
  [ -f "$f" ] && FILES+=("$f")
done

if [ ${#FILES[@]} -eq 0 ]; then
  pa_log "No log files found yet."
  exit 0
fi

if [ "$FOLLOW" -eq 1 ]; then
  tail -n 200 -F "${FILES[@]}"
else
  tail -n 200 "${FILES[@]}"
fi
