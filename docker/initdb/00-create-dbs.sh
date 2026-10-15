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

# Factory admin must be activated or Sentinel rejects login as bad password
if [ -f /docker-entrypoint-initdb.d/ensure-admin.sql ]; then
  mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" pandbRBAC < /docker-entrypoint-initdb.d/ensure-admin.sql
elif [ -f /docker-entrypoint-initdb.d/sql/../initdb/ensure-admin.sql ]; then
  mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" pandbRBAC < /docker-entrypoint-initdb.d/sql/../initdb/ensure-admin.sql || true
fi
# Inline fallback (same as ensure-admin.sql) if the extra file is not mounted
mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" pandbRBAC <<'SQL' || true
INSERT INTO users (
  id, email, password, permissions, last_login, first_name, last_name,
  created_at, updated_at, location_id, location_type, timezone, active
)
SELECT
  1, 'admin',
  '$2y$10$Nk2/jJmmirfgfLLPEGJ7.erkiaVCgRGUZvSPi5wG/gg8SqYFBvYPO',
  NULL, NOW(), 'admin', 'admin', NOW(), NOW(), 0, 'local', 'UTC', 1
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'admin' OR id = 1);
UPDATE users SET active = 1, location_type = 'local' WHERE email = 'admin' OR id = 1;
INSERT INTO activations (user_id, code, completed, completed_at, created_at, updated_at)
SELECT u.id, 'pa-converter-default', 1, NOW(), NOW(), NOW()
FROM users u
WHERE (u.email = 'admin' OR u.id = 1)
  AND NOT EXISTS (SELECT 1 FROM activations a WHERE a.user_id = u.id);
UPDATE activations a
INNER JOIN users u ON u.id = a.user_id AND (u.email = 'admin' OR u.id = 1)
SET a.completed = 1, a.completed_at = COALESCE(a.completed_at, NOW());
INSERT IGNORE INTO role_users (user_id, role_id, created_at, updated_at)
SELECT u.id, 3, NOW(), NOW() FROM users u WHERE u.email = 'admin' OR u.id = 1;
SQL

echo "Expedition databases seeded."
