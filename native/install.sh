#!/usr/bin/env bash
# Idempotent native install for Linux / WSL (no Docker).
# Requires root (sudo).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
pa_ensure_dirs
pa_log "Installing native stack into PA_CONVERTER_ROOT=$PA_CONVERTER_ROOT"

. /etc/os-release
CODENAME="${VERSION_CODENAME:-focal}"
ID_LIKE="${ID_LIKE:-}"

if [ "${ID:-}" != "ubuntu" ] && [ "${ID:-}" != "debian" ]; then
  pa_log "WARN: untested distro id=${ID:-unknown}; continuing with apt"
fi

apt-get update -y
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg lsb-release software-properties-common apt-transport-https \
  apache2 libapache2-mod-php rsync \
  mariadb-server mariadb-client \
  rabbitmq-server \
  openjdk-11-jre-headless \
  python3 python3-pip python3-pil python3-reportlab python3-matplotlib \
  unzip openssl ssl-cert net-tools procps util-linux bc \
  libzip-dev libpng-dev || true

# PHP 7.4 — default on Ubuntu 20.04; use ondrej PPA on newer
PHP_OK=0
if php -v 2>/dev/null | grep -qE 'PHP 7\.4'; then
  PHP_OK=1
fi

if [ "$PHP_OK" -ne 1 ]; then
  pa_log "Installing PHP 7.4 from ondrej/php PPA…"
  apt-get install -y --no-install-recommends software-properties-common
  add-apt-repository -y ppa:ondrej/php || true
  apt-get update -y
  apt-get install -y --no-install-recommends \
    php7.4 php7.4-cli php7.4-common libapache2-mod-php7.4 \
    php7.4-mysql php7.4-gd php7.4-soap php7.4-zip php7.4-bz2 \
    php7.4-ldap php7.4-bcmath php7.4-curl php7.4-xml php7.4-mbstring \
    php7.4-opcache || {
      pa_log "ERROR: could not install PHP 7.4. Use Ubuntu 20.04/22.04 WSL." >&2
      exit 1
    }
  a2dismod php8.1 php8.2 php8.3 2>/dev/null || true
  a2enmod php7.4 2>/dev/null || true
  update-alternatives --set php /usr/bin/php7.4 2>/dev/null || true
else
  apt-get install -y --no-install-recommends \
    php-mysql php-gd php-soap php-zip php-bz2 php-ldap php-bcmath php-curl php-xml php-mbstring \
    2>/dev/null || apt-get install -y --no-install-recommends \
    php7.4-mysql php7.4-gd php7.4-soap php7.4-zip php7.4-bz2 php7.4-ldap php7.4-bcmath php7.4-curl
fi

a2enmod rewrite ssl headers 2>/dev/null || true
# snakeoil certs for HTTPS
if [ ! -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]; then
  apt-get install -y --no-install-recommends ssl-cert
  make-ssl-cert generate-default-snakeoil >/dev/null 2>&1 || true
fi

# PHP ini overrides
PHP_INI_DIR="$(php -i 2>/dev/null | awk -F'=> ' '/Scan this dir for additional .ini/{print $2; exit}' | tr -d ' ')"
if [ -z "$PHP_INI_DIR" ] || [ ! -d "$PHP_INI_DIR" ]; then
  PHP_INI_DIR=/etc/php/7.4/apache2/conf.d
  mkdir -p "$PHP_INI_DIR"
fi
cat > "${PHP_INI_DIR}/99-pa-converter.ini" <<'EOF'
upload_max_filesize = 200M
post_max_size = 200M
memory_limit = 1G
max_execution_time = 10000
mysqli.allow_persistent = On
display_errors = Off
log_errors = On
EOF

# Sync app into docroot
pa_log "Syncing app → $PA_WWW"
if [ -d "$PA_CONVERTER_ROOT/app" ]; then
  rsync -a --delete "$PA_CONVERTER_ROOT/app/" "$PA_WWW/" 2>/dev/null \
    || (rm -rf "$PA_WWW"/* && cp -a "$PA_CONVERTER_ROOT/app/." "$PA_WWW/")
fi
chown -R www-data:www-data "$PA_WWW" "$PA_USERSPACE" "$PA_DATA" /PALogs 2>/dev/null || true

# Apache site on Expedition ports
APACHE_LOG_DIR="${APACHE_LOG_DIR:-/var/log/apache2}"
export APACHE_LOG_DIR
SITE_SRC="$SCRIPT_DIR/apache/pa-converter.conf"
SITE_DST=/etc/apache2/sites-available/pa-converter.conf
sed -e "s/\${EXPEDITION_HTTP_PORT}/${EXPEDITION_HTTP_PORT}/g" \
    -e "s/\${EXPEDITION_PORT}/${EXPEDITION_PORT}/g" \
    -e "s|\${APACHE_LOG_DIR}|${APACHE_LOG_DIR}|g" \
    "$SITE_SRC" > "$SITE_DST"
# Disable default sites that steal :80/:443 if present
a2dissite 000-default default-ssl 2>/dev/null || true
a2ensite pa-converter
# Ensure ports are not only 80/443
if ! grep -q "Listen ${EXPEDITION_HTTP_PORT}" /etc/apache2/ports.conf 2>/dev/null; then
  echo "Listen ${EXPEDITION_HTTP_PORT}" >> /etc/apache2/ports.conf
fi
if ! grep -q "Listen ${EXPEDITION_PORT}" /etc/apache2/ports.conf 2>/dev/null; then
  echo "Listen ${EXPEDITION_PORT}" >> /etc/apache2/ports.conf
fi

# MariaDB root password + seed DBs once
pa_service start mariadb || pa_service start mysql
sleep 2

# Set root password for TCP (unix_socket auth on localhost is common on Ubuntu)
mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}'; FLUSH PRIVILEGES;" 2>/dev/null \
  || mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "SELECT 1;" >/dev/null 2>&1 \
  || true
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "
  CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';
  GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION;
  FLUSH PRIVILEGES;
" 2>/dev/null || true

SEED_MARKER="$PA_DATA_ROOT/db-seeded"
if [ ! -f "$SEED_MARKER" ]; then
  pa_log "Seeding Expedition databases…"
  export MYSQL_ROOT_PASSWORD
  SQL_DIR="$PA_CONVERTER_ROOT/databases"
  mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 <<SQL
CREATE DATABASE IF NOT EXISTS pandb CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE DATABASE IF NOT EXISTS pandbRBAC CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE DATABASE IF NOT EXISTS BestPractices CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE DATABASE IF NOT EXISTS RealTimeUpdates CHARACTER SET utf8 COLLATE utf8_general_ci;
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','%');
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}' WITH GRANT OPTION;
FLUSH PRIVILEGES;
SQL
  mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 pandb < "${SQL_DIR}/pandb.sql"
  mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 pandbRBAC < "${SQL_DIR}/pandbRBAC.sql"
  mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 BestPractices < "${SQL_DIR}/BestPractices.sql"
  mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 RealTimeUpdates < "${SQL_DIR}/RealTimeUpdates.sql"
  mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 pandbRBAC -e \
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS api_key VARCHAR(255) NULL; ALTER TABLE users ADD COLUMN IF NOT EXISTS valid_til TIMESTAMP NULL;" \
    2>/dev/null || true
  mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 pandbRBAC -e \
    "INSERT IGNORE INTO ml_settings (id, server) VALUES (1, '127.0.0.1');" 2>/dev/null || true
  touch "$SEED_MARKER"
  pa_log "Databases seeded."
fi

# RabbitMQ
pa_service start rabbitmq-server || true

# Spark 2.4.3
pa_detect_java
mkdir -p /opt/Spark
if [ ! -e /opt/Spark/spark/bin/spark-submit ]; then
  pa_log "Installing Spark 2.4.3…"
  if [ -f "$PA_CONVERTER_ROOT/docker/spark/opt-Spark.tar.gz" ]; then
    tar -xzf "$PA_CONVERTER_ROOT/docker/spark/opt-Spark.tar.gz" -C / || true
  fi
  if [ ! -e /opt/Spark/spark/bin/spark-submit ]; then
    curl -fsSL "https://archive.apache.org/dist/spark/spark-2.4.3/spark-2.4.3-bin-hadoop2.7.tgz" \
      -o /tmp/spark-2.4.3.tgz
    mkdir -p /opt/Spark
    tar -xzf /tmp/spark-2.4.3.tgz -C /opt/Spark
    rm -f /tmp/spark-2.4.3.tgz
    ln -sfn /opt/Spark/spark-2.4.3-bin-hadoop2.7 /opt/Spark/spark
  fi
  if [ ! -e /opt/Spark/spark ] && [ -d /opt/Spark/spark-2.4.3-bin-hadoop2.7 ]; then
    ln -sfn /opt/Spark/spark-2.4.3-bin-hadoop2.7 /opt/Spark/spark
  fi
  mkdir -p /opt/Spark/extraLibraries
  if [ -d "$PA_WWW/OS/spark/extraLibraries" ]; then
    cp -an "$PA_WWW/OS/spark/extraLibraries/." /opt/Spark/extraLibraries/ 2>/dev/null || true
  fi
  chmod -R a+rX /opt/Spark
  rm -f /opt/Spark/spark/jars/log4j-1.2.17.jar 2>/dev/null || true
fi

# BPA pip helpers (best-effort)
pip3 install --no-cache-dir 'lxml' 2>/dev/null || true

# Environment profile for interactive shells
cat > /etc/profile.d/pa-converter.sh <<EOF
export JAVA_HOME="${JAVA_HOME:-}"
export SPARK_HOME=/opt/Spark/spark
export PATH="\$SPARK_HOME/bin:\$PATH"
export PA_CONVERTER_ROOT="$PA_CONVERTER_ROOT"
export DB_HOST=127.0.0.1
export RABBITMQ_HOST=127.0.0.1
EOF

touch "$PA_MARKER"
pa_log "Native install complete."
pa_log "Start with: sudo $SCRIPT_DIR/start.sh"
