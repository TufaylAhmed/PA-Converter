#!/usr/bin/env bash
# Port of docker/web/entrypoint.sh for native (no containers).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

pa_ensure_dirs
pa_detect_java
export SPARK_HOME="${SPARK_HOME:-/opt/Spark/spark}"
export PATH="${SPARK_HOME}/bin:${PATH}"
export DB_HOST="${DB_HOST:-127.0.0.1}"
export RABBITMQ_HOST="${RABBITMQ_HOST:-127.0.0.1}"

chown -R www-data:www-data "$PA_USERSPACE" "$PA_DATA" "$PA_PALOGS" 2>/dev/null || true

cat > "$PA_USERSPACE/userDefinitions.php" <<EOF
<?php
define('DBServer', '${DB_HOST}');
define('DBUser', '${DB_USER}');
define('DBPass', '${DB_PASS}');
define('DBName', 'project_schema');
define('PARSER_max_execution_time', '10000');
define('PARSER_max_execution_memory', '1G');
define('PARSER_max_number_address_per_group', -1);
define('DBSQL_LOG_BIN', 0);
define('MAXSUPERUSERS', '3');
define('MAX_RULES_TO_ANALYZE', 600);
define('RECOMMENDED_PANOS_VERSION', 9.1);
define('DEVICE_CONNECTION_TIMEOUT', 900);
define('DEVICE_DEBUG_CONNECTION_ENABLED', '0');
EOF
chown www-data:www-data "$PA_USERSPACE/userDefinitions.php" 2>/dev/null || true

CPUS=$(nproc 2>/dev/null || echo 4)
SUGG=$(( CPUS * 80 / 100 ))
[ "$SUGG" -lt 1 ] && SUGG=1
MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 4000000)
SUGG_RAM_MB=$(( MEM_KB * 40 / 100 / 1024 ))
[ "$SUGG_RAM_MB" -lt 1024 ] && SUGG_RAM_MB=1024
[ "$SUGG_RAM_MB" -gt 4096 ] && SUGG_RAM_MB=4096

cat > "$PA_USERSPACE/environmentParameters.php" <<EOF
<?php
define('NumCPUs', ${SUGG});
define('TotalCPUs', ${CPUS});
define('SparkRAM', '${SUGG_RAM_MB}m');
EOF
chown www-data:www-data "$PA_USERSPACE/environmentParameters.php" 2>/dev/null || true

pa_log "Waiting for MariaDB at ${DB_HOST}…"
for i in $(seq 1 60); do
  if mysqladmin ping -h"${DB_HOST}" -u"${DB_USER}" -p"${DB_PASS}" --silent 2>/dev/null; then
    pa_log "MariaDB is up."
    break
  fi
  sleep 2
  if [ "$i" -eq 60 ]; then
    pa_log "ERROR: MariaDB not reachable" >&2
    exit 1
  fi
done

mysql -h"${DB_HOST}" -u"${DB_USER}" -p"${DB_PASS}" -e \
  "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','%'); FLUSH PRIVILEGES;" \
  2>/dev/null || true

mysql -h"${DB_HOST}" -u"${DB_USER}" -p"${DB_PASS}" pandbRBAC -e \
  "ALTER TABLE users ADD COLUMN IF NOT EXISTS api_key VARCHAR(255) NULL; ALTER TABLE users ADD COLUMN IF NOT EXISTS valid_til TIMESTAMP NULL;" \
  2>/dev/null || true

# Native: ML agent runs on same host — use a non-loopback IP if available (checkAlive treats 127.0.0.1 as unset)
ML_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [ -z "${ML_IP}" ] || [ "${ML_IP}" = "127.0.0.1" ]; then
  ML_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
fi
if [ -z "${ML_IP}" ]; then
  ML_IP="127.0.0.1"
fi

mysql -h"${DB_HOST}" -u"${DB_USER}" -p"${DB_PASS}" pandbRBAC -e \
  "INSERT INTO ml_settings (id, server, parquetPath, tempDataPath) VALUES (1, '${ML_IP}', '/data', '/data')
   ON DUPLICATE KEY UPDATE server='${ML_IP}', parquetPath='/data', tempDataPath='/data';" \
  2>/dev/null || true

pa_log "ML server set to ${ML_IP} (parquet/temp=/data)"

cat > "$PA_USERSPACE/tempEnvironmentParameters.php" <<EOF
<?php
\$suggestedEnvironmentParameters = [
 'NumCPUs'=>${SUGG},
 'TotalCPUs'=>${CPUS},
 'SparkRAM'=>'${SUGG_RAM_MB}m',
];
EOF
chown www-data:www-data "$PA_USERSPACE/tempEnvironmentParameters.php" 2>/dev/null || true

# panReadOrders agent
WWW_CONSOLE=""
for cand in "$PA_WWW/console/messaging/readOrders.php" /var/www/html/console/messaging/readOrders.php; do
  if [ -f "$cand" ]; then
    WWW_CONSOLE="$cand"
    break
  fi
done

if [ -n "$WWW_CONSOLE" ]; then
  pa_log "Starting panReadOrders agent (RabbitMQ=${RABBITMQ_HOST})…"
  : > "$PA_USERSPACE/panReadOrders.log"
  chown www-data:www-data "$PA_USERSPACE/panReadOrders.log" 2>/dev/null || true
  # Kill prior agent if any
  pkill -f 'php .*readOrders.php' 2>/dev/null || true
  if id www-data >/dev/null 2>&1; then
    su -s /bin/bash www-data -c \
      "export RABBITMQ_HOST='${RABBITMQ_HOST}'; export JAVA_HOME='${JAVA_HOME:-}'; export SPARK_HOME='${SPARK_HOME:-}'; export PATH='${PATH}'; exec php '${WWW_CONSOLE}' >> '${PA_USERSPACE}/panReadOrders.log' 2>&1" &
  else
    (
      export RABBITMQ_HOST JAVA_HOME SPARK_HOME PATH
      exec php "$WWW_CONSOLE" >> "$PA_USERSPACE/panReadOrders.log" 2>&1
    ) &
  fi
  echo $! > "$PA_DATA_ROOT/panReadOrders.pid"
fi
