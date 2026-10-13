#!/bin/bash
set -euo pipefail

mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL
CREATE DATABASE IF NOT EXISTS pandb CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE DATABASE IF NOT EXISTS pandbRBAC CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE DATABASE IF NOT EXISTS BestPractices CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE DATABASE IF NOT EXISTS RealTimeUpdates CHARACTER SET utf8 COLLATE utf8_general_ci;

-- Ensure remote root works for Docker network clients (avoid host-specific root@172.* with USAGE-only)
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','%');
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}' WITH GRANT OPTION;
CREATE USER IF NOT EXISTS 'expedition'@'%' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';
GRANT ALL PRIVILEGES ON pandb.* TO 'expedition'@'%';
GRANT ALL PRIVILEGES ON pandbRBAC.* TO 'expedition'@'%';
GRANT ALL PRIVILEGES ON BestPractices.* TO 'expedition'@'%';
GRANT ALL PRIVILEGES ON RealTimeUpdates.* TO 'expedition'@'%';
FLUSH PRIVILEGES;
SQL

SQL_DIR=/docker-entrypoint-initdb.d/sql

mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" pandb < "${SQL_DIR}/pandb.sql"
mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" pandbRBAC < "${SQL_DIR}/pandbRBAC.sql"
mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" BestPractices < "${SQL_DIR}/BestPractices.sql"
mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" RealTimeUpdates < "${SQL_DIR}/RealTimeUpdates.sql"

# Schema drift: older installer seeds omit user API-key columns required by parsers/jobs
mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" pandbRBAC <<'SQL'
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS api_key VARCHAR(255) NULL,
  ADD COLUMN IF NOT EXISTS valid_til TIMESTAMP NULL;
SQL

# ML settings row used by Expedition UI health checks
mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" pandbRBAC -e \
  "INSERT IGNORE INTO ml_settings (id, server) VALUES (1, '127.0.0.1');" \
  2>/dev/null || true

echo "Expedition databases seeded."
