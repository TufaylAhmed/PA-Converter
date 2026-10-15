#!/bin/bash
set -euo pipefail

DB_HOST="${DB_HOST:-db}"
DB_USER="${DB_USER:-root}"
DB_PASS="${DB_PASS:-paloalto}"

# Java / Spark for ML jobs (spark-submit)
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
if [ -d "/usr/lib/jvm/java-11-openjdk-${ARCH}" ]; then
  export JAVA_HOME="/usr/lib/jvm/java-11-openjdk-${ARCH}"
elif [ -d /usr/lib/jvm/java-11-openjdk-amd64 ]; then
  export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
fi
export SPARK_HOME=/opt/Spark/spark
export PATH="${SPARK_HOME}/bin:${PATH}"

mkdir -p /home/userSpace /data /PALogs
chown -R www-data:www-data /home/userSpace /data /PALogs 2>/dev/null || true

# Runtime DB settings (overrides packaged localhost/socket defaults)
cat > /home/userSpace/userDefinitions.php <<EOF
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
chown www-data:www-data /home/userSpace/userDefinitions.php

# Seed Spark/CPU params
CPUS=$(nproc 2>/dev/null || echo 4)
SUGG=$(( CPUS * 80 / 100 ))
[ "$SUGG" -lt 1 ] && SUGG=1
# Match Expedition checkCPUs.sh / getCPUs.sh: 80% of MemTotal (health check compares these)
MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 4000000)
SUGG_RAM_MB=$(( MEM_KB * 80 / 100 / 1024 ))
[ "$SUGG_RAM_MB" -lt 1024 ] && SUGG_RAM_MB=1024

cat > /home/userSpace/environmentParameters.php <<EOF
<?php
define('NumCPUs', ${SUGG});
define('TotalCPUs', ${CPUS});
define('SparkRAM', '${SUGG_RAM_MB}m');
EOF
chown www-data:www-data /home/userSpace/environmentParameters.php

# Wait for MariaDB
echo "Waiting for MariaDB at ${DB_HOST}…"
for i in $(seq 1 60); do
  if mysqladmin ping -h"${DB_HOST}" -u"${DB_USER}" -p"${DB_PASS}" --silent 2>/dev/null; then
    echo "MariaDB is up."
    break
  fi
  sleep 2
  if [ "$i" -eq 60 ]; then
    echo "ERROR: MariaDB not reachable" >&2
    exit 1
  fi
done

# Repair accidental host-specific root users (Expedition ML_Settings used to create USAGE-only root@container-ip)
mysql -h"${DB_HOST}" -u"${DB_USER}" -p"${DB_PASS}" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','%'); FLUSH PRIVILEGES;" 2>/dev/null || true

# Ensure parser/job API-key columns exist (older seeds omit them)
mysql -h"${DB_HOST}" -u"${DB_USER}" -p"${DB_PASS}" pandbRBAC -e \
  "ALTER TABLE users ADD COLUMN IF NOT EXISTS api_key VARCHAR(255) NULL; ALTER TABLE users ADD COLUMN IF NOT EXISTS valid_til TIMESTAMP NULL;" \
  2>/dev/null || true

# ML settings: use this container's IP (checkAlive treats 127.0.0.1 as unset)
ML_IP="$(hostname -i 2>/dev/null | awk '{print $1}')"
if [ -z "${ML_IP}" ] || [ "${ML_IP}" = "127.0.0.1" ]; then
  ML_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi
if [ -z "${ML_IP}" ]; then
  ML_IP="127.0.0.1"
fi

mysql -h"${DB_HOST}" -u"${DB_USER}" -p"${DB_PASS}" pandbRBAC -e \
  "INSERT INTO ml_settings (id, server, parquetPath, tempDataPath) VALUES (1, '${ML_IP}', '/data', '/data')
   ON DUPLICATE KEY UPDATE server='${ML_IP}', parquetPath='/data', tempDataPath='/data';" \
  2>/dev/null || true

echo "ML server set to ${ML_IP} (parquet/temp=/data)"

# Prevent broken tempEnvironmentParameters.php
cat > /home/userSpace/tempEnvironmentParameters.php <<EOF
<?php
\$suggestedEnvironmentParameters = [
 'NumCPUs'=>${SUGG},
 'TotalCPUs'=>${CPUS},
 'SparkRAM'=>'${SUGG_RAM_MB}m',
];
EOF
chown www-data:www-data /home/userSpace/tempEnvironmentParameters.php

# Background task agent (needs RabbitMQ service hostname in Compose)
export RABBITMQ_HOST="${RABBITMQ_HOST:-rabbitmq}"
if [ -f /var/www/html/console/messaging/readOrders.php ]; then
  echo "Starting panReadOrders agent (RabbitMQ=${RABBITMQ_HOST})…"
  : > /home/userSpace/panReadOrders.log
  chown www-data:www-data /home/userSpace/panReadOrders.log
  # exec so bash does not linger (health status expects a single php worker PID)
  su -s /bin/bash www-data -c \
    "export RABBITMQ_HOST='${RABBITMQ_HOST}'; export JAVA_HOME='${JAVA_HOME:-}'; export SPARK_HOME='${SPARK_HOME:-}'; exec php /var/www/html/console/messaging/readOrders.php >> /home/userSpace/panReadOrders.log 2>&1" &
fi

exec "$@"
