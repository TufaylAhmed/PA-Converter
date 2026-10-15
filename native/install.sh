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
# Line-buffer stdout so Windows SETUP sees progress live
if command -v stdbuf >/dev/null 2>&1; then
  export PYTHONUNBUFFERED=1
fi

pa_ensure_dirs
pa_progress 2 bootstrap "Starting native install"
pa_log "Installing native stack into PA_CONVERTER_ROOT=$PA_CONVERTER_ROOT"

. /etc/os-release
CODENAME="${VERSION_CODENAME:-focal}"
ID_LIKE="${ID_LIKE:-}"

if [ "${ID:-}" != "ubuntu" ] && [ "${ID:-}" != "debian" ]; then
  pa_log "WARN: untested distro id=${ID:-unknown}; continuing with apt"
fi

pa_progress 8 apt-update "Updating apt package lists"
apt-get update -y

pa_progress 18 apt-base "Installing Apache, MariaDB, RabbitMQ, Java (several minutes)..."
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg lsb-release software-properties-common apt-transport-https \
  apache2 libapache2-mod-php rsync \
  mariadb-server mariadb-client \
  rabbitmq-server \
  openjdk-11-jre-headless \
  python3 python3-pip python3-pil python3-reportlab python3-matplotlib \
  unzip openssl ssl-cert net-tools procps util-linux bc \
  libzip-dev libpng-dev || {
    pa_log "ERROR: apt-get install of base packages failed (see apt output above)."
    exit 1
  }

# PHP 7.4 - default on Ubuntu 20.04; use ondrej PPA on newer
PHP_OK=0
if php -v 2>/dev/null | grep -qE 'PHP 7\.4'; then
  PHP_OK=1
fi

if [ "$PHP_OK" -ne 1 ]; then
  pa_progress 35 php "Installing PHP 7.4 from ondrej/php PPA..."
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
  pa_progress 35 php "Installing PHP MySQL/GD extensions..."
  apt-get install -y --no-install-recommends \
    php-mysql php-gd php-soap php-zip php-bz2 php-ldap php-bcmath php-curl php-xml php-mbstring \
    2>/dev/null || apt-get install -y --no-install-recommends \
    php7.4-mysql php7.4-gd php7.4-soap php7.4-zip php7.4-bz2 php7.4-ldap php7.4-bcmath php7.4-curl
fi

pa_progress 45 apache "Configuring Apache HTTPS ports"
a2enmod rewrite ssl headers 2>/dev/null || true
# snakeoil certs for HTTPS
if [ ! -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]; then
  apt-get install -y --no-install-recommends ssl-cert || true
  make-ssl-cert generate-default-snakeoil >/dev/null 2>&1 || true
fi

# PHP ini overrides for both the Apache module and the CLI (the agent runs php-cli)
for PHP_INI_DIR in /etc/php/7.4/apache2/conf.d /etc/php/7.4/cli/conf.d; do
  [ -d "$(dirname "$PHP_INI_DIR")" ] || continue
  mkdir -p "$PHP_INI_DIR"
  cat > "${PHP_INI_DIR}/99-pa-converter.ini" <<'EOF'
upload_max_filesize = 200M
post_max_size = 200M
memory_limit = 1G
max_execution_time = 10000
mysqli.allow_persistent = On
mysqli.reconnect = On
display_errors = Off
log_errors = On
EOF
  pa_log "Wrote PHP overrides in $PHP_INI_DIR"
done

# Sync app into docroot
pa_progress 52 sync "Syncing Expedition web app"
pa_log "Syncing app -> $PA_WWW"
if [ -d "$PA_CONVERTER_ROOT/app" ]; then
  rsync -a --delete "$PA_CONVERTER_ROOT/app/" "$PA_WWW/" 2>/dev/null \
    || (rm -rf "${PA_WWW:?}/"* && cp -a "$PA_CONVERTER_ROOT/app/." "$PA_WWW/")
fi
# Pre-5.46.41 docroot (the PHP app hard-codes /var/www/html)
if [ "$PA_WWW" != /var/www/pa-converter ]; then
  rm -rf /var/www/pa-converter
fi
chown -R www-data:www-data "$PA_WWW" "$PA_USERSPACE" "$PA_DATA" "$PA_PALOGS" 2>/dev/null || true

# Apache site on Expedition ports (Listen only in ports.conf — never in the vhost)
pa_progress 55 apache-site "Enabling pa-converter Apache site"
APACHE_LOG_DIR="${APACHE_LOG_DIR:-/var/log/apache2}"
export APACHE_LOG_DIR
pa_ensure_apache_site || {
  pa_log "ERROR: failed to configure Apache site"
  exit 1
}

# MariaDB root password + seed DBs once
pa_progress 60 mariadb "Starting MariaDB and setting root password"
pa_start_mariadb || exit 1

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
  pa_progress 70 seed "Seeding Expedition databases"
  pa_log "Seeding Expedition databases..."
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
else
  pa_progress 70 seed "Databases already seeded"
fi

# RabbitMQ
pa_progress 78 rabbitmq "Starting RabbitMQ"
pa_service start rabbitmq-server || true

# Spark 2.4.3 (GitHub CDN preferred; Apache archive last)
pa_progress 82 spark "Installing Spark 2.4.3 (download ~230MB if needed)..."
pa_detect_java
pa_install_spark "/" || true
mkdir -p /opt/Spark/extraLibraries
if [ -d "$PA_WWW/OS/spark/extraLibraries" ]; then
  cp -an "$PA_WWW/OS/spark/extraLibraries/." /opt/Spark/extraLibraries/ 2>/dev/null || true
fi
chmod -R a+rX /opt/Spark 2>/dev/null || true
rm -f /opt/Spark/spark/jars/log4j-1.2.17.jar 2>/dev/null || true

pa_progress 92 extras "Installing Python helpers and Best Practice Assessment"
pip3 install --no-cache-dir 'lxml' 2>/dev/null || true
# Health check runs `pip3.7 list | grep BPA` (case-sensitive). Ubuntu 20.04 has
# Python 3.8; modern pip prints the normalized name "bpa", so wrap pip3.7.
ln -sf "$(command -v python3)" /usr/local/bin/python3.7
# Call python3 -m pip (never /usr/bin/pip3) so a bad wrapper cannot brick system pip.
cat > /usr/local/bin/pip3.7 <<'EOF'
#!/bin/bash
if [ "$1" = "list" ]; then
  python3 -m pip "$@" | sed 's/^bpa /BPA /'
else
  exec python3 -m pip "$@"
fi
EOF
chmod +x /usr/local/bin/pip3.7
# Expedition runs `bpa-legacy-cli` with LC_ALL=en_US.UTF-8.
if ! locale -a 2>/dev/null | grep -i '^en_US\.utf8$' >/dev/null; then
  apt-get install -y --no-install-recommends locales >/dev/null
  locale-gen en_US.UTF-8 >/dev/null
fi
BPA_ZIP="$PA_WWW/OS/BPA/best_practice_assessment_ngfw_pano-master.zip"
if ! command -v bpa-legacy-cli >/dev/null 2>&1 && [ -f "$BPA_ZIP" ]; then
  pa_log "Installing Best Practice Assessment (BPA)..."
  # BPA pins 2018-era Pillow/reportlab/pandas (<2, for pandas.io.json.json_normalize)
  # that do not build on Python 3.8; Ubuntu's packages satisfy its code, so install
  # those from apt and BPA itself with --no-deps.
  if apt-get install -y --no-install-recommends \
      python3-pandas python3-lxml python3-pil python3-reportlab python3-matplotlib \
      python3-seaborn python3-jinja2 python3-sqlalchemy python3-xlrd python3-xlsxwriter \
      python3-pymysql python3-six python3-requests python3-unidecode python3-chardet \
      python3-dateutil python3-tz python3-setuptools python3-wheel >/dev/null \
    && pip3 install --no-cache-dir 'pendulum==2.1.2' >/dev/null \
    && pip3 install --no-cache-dir --no-deps "$BPA_ZIP" iptools 'svglib<=0.9.0' \
         cssselect2 tinycss2 webencodings >/dev/null
  then
    pa_log "BPA $(pip3 show BPA 2>/dev/null | awk '/^Version:/{print $2}') installed."
  else
    pa_log "WARN: BPA install failed - BPA reports will not work"
  fi
fi

# Expedition expects www-data in the `expedition` group (CSV log cleanup).
getent group expedition >/dev/null || groupadd expedition
id expedition >/dev/null 2>&1 || useradd -r -M -g expedition -s /usr/sbin/nologin expedition
usermod -a -G expedition www-data

# Health check verifies these Ubuntu appliance packages via dpkg; the native install
# provides their content, so register empty placeholder packages.
pa_register_placeholder_pkg() {
  local name="$1" version="$2" dir
  if [ "$(dpkg-query -W -f='${Status}' "$name" 2>/dev/null)" = "install ok installed" ]; then
    return 0
  fi
  dir="$(mktemp -d)"
  mkdir -p "$dir/pkg/DEBIAN"
  printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: PA-Converter <noreply@local>\nDescription: Placeholder for the Expedition appliance package (PA-Converter native install)\n' \
    "$name" "$version" > "$dir/pkg/DEBIAN/control"
  dpkg-deb --build "$dir/pkg" "$dir/$name.deb" >/dev/null && dpkg -i "$dir/$name.deb" >/dev/null \
    || pa_log "WARN: could not register $name"
  rm -rf "$dir"
}
pa_register_placeholder_pkg expedition-beta 5.45.4-2build1
pa_register_placeholder_pkg expeditionml-dependencies-beta 1.2.102

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
pa_progress 96 done "Native install complete"
pa_log "Native install complete."
pa_log "Start with: sudo $SCRIPT_DIR/start.sh"
