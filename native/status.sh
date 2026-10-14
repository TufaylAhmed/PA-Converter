#!/usr/bin/env bash
# Status of native PA-Converter services.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

ok() { printf "  %-12s UP\n" "$1"; }
dn() { printf "  %-12s DOWN\n" "$1"; }

echo "PA-Converter native status"
echo "  root: $PA_CONVERTER_ROOT"
echo "  installed: $([ -f "$PA_MARKER" ] && echo yes || echo no)"

# MariaDB
if mysqladmin ping -h127.0.0.1 -u"${DB_USER}" -p"${DB_PASS}" --silent 2>/dev/null; then
  ok mariadb
else
  dn mariadb
fi

# RabbitMQ
if rabbitmqctl status >/dev/null 2>&1 || pgrep -x rabbitmq-server >/dev/null 2>&1 || pgrep -f beam.smp >/dev/null 2>&1; then
  ok rabbitmq
else
  dn rabbitmq
fi

# Apache
if pgrep -x apache2 >/dev/null 2>&1 || pgrep -x httpd >/dev/null 2>&1; then
  ok apache
else
  dn apache
fi

# Agent
if pgrep -f 'php .*readOrders.php' >/dev/null 2>&1; then
  ok panReadOrders
else
  dn panReadOrders
fi

# Spark / Java
pa_detect_java || true
if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/java" ]; then
  ok "java11"
else
  dn "java11"
fi
if [ -x "${SPARK_HOME}/bin/spark-submit" ] || [ -x /opt/Spark/spark/bin/spark-submit ]; then
  ok spark
else
  dn spark
fi

echo "  UI: https://localhost:${EXPEDITION_PORT}"
