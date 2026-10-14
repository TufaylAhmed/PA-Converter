#!/usr/bin/env bash
# Native PA-Converter on macOS via Homebrew (no containers).
# Usage: install-macos.sh [install|start|stop|status|logs]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

ACTION="${1:-install}"
shift || true

PREFIX="${PA_MAC_PREFIX:-$HOME/Library/Application Support/PA-Converter}"
export PA_DATA_ROOT="${PA_DATA_ROOT:-$PREFIX/var}"
export PA_WWW="${PA_WWW:-$PREFIX/www}"
export PA_USERSPACE="${PA_USERSPACE:-$PREFIX/userSpace}"
export PA_DATA="${PA_DATA:-$PREFIX/data}"
export PA_LOG_DIR="${PA_LOG_DIR:-$PA_DATA_ROOT/logs}"
export PA_MARKER="${PA_MARKER:-$PA_DATA_ROOT/installed}"
export SPARK_HOME="${SPARK_HOME:-$PREFIX/opt/Spark/spark}"

# Homebrew Apache often listens on 8080; we bind Expedition ports separately.
HTTPD_CONF_D=""
PHP_FPM_LABEL=""

need_brew() {
  if ! command -v brew >/dev/null 2>&1; then
    pa_log "ERROR: Homebrew is required. Install from https://brew.sh" >&2
    exit 1
  fi
}

brew_prefix() {
  brew --prefix 2>/dev/null || echo /usr/local
}

do_install() {
  need_brew
  pa_ensure_dirs
  mkdir -p "$PREFIX/opt" "$PA_LOG_DIR"

  pa_log "Installing Homebrew packages (MariaDB, RabbitMQ, OpenJDK 11, httpd)…"
  brew update || true
  brew install mariadb rabbitmq openjdk@11 httpd curl || true

  # PHP 7.4 via shivammathur/php
  if ! brew list php@7.4 >/dev/null 2>&1; then
    pa_log "Tapping shivammathur/php for PHP 7.4…"
    brew tap shivammathur/php || true
    brew install shivammathur/php/php@7.4 || brew install php@7.4 || true
  fi

  # Link php 7.4 for CLI
  if [ -x "$(brew_prefix)/opt/php@7.4/bin/php" ]; then
    export PATH="$(brew_prefix)/opt/php@7.4/bin:$PATH"
  fi

  if ! php -v 2>/dev/null | grep -qE 'PHP 7\.4'; then
    pa_log "WARN: PHP 7.4 not on PATH — enable with: brew link php@7.4 --force --overwrite"
  fi

  # Spark
  mkdir -p "$PREFIX/opt/Spark"
  if [ ! -x "$PREFIX/opt/Spark/spark/bin/spark-submit" ]; then
    pa_log "Downloading Spark 2.4.3…"
    curl -fsSL "https://archive.apache.org/dist/spark/spark-2.4.3/spark-2.4.3-bin-hadoop2.7.tgz" \
      -o /tmp/spark-2.4.3.tgz
    tar -xzf /tmp/spark-2.4.3.tgz -C "$PREFIX/opt/Spark"
    rm -f /tmp/spark-2.4.3.tgz
    ln -sfn "$PREFIX/opt/Spark/spark-2.4.3-bin-hadoop2.7" "$PREFIX/opt/Spark/spark"
  fi
  export SPARK_HOME="$PREFIX/opt/Spark/spark"

  pa_detect_java
  if [ -z "${JAVA_HOME:-}" ]; then
    if [ -d "$(brew_prefix)/opt/openjdk@11/libexec/openjdk.jdk/Contents/Home" ]; then
      export JAVA_HOME="$(brew_prefix)/opt/openjdk@11/libexec/openjdk.jdk/Contents/Home"
    fi
  fi

  # Sync app
  pa_log "Syncing app → $PA_WWW"
  mkdir -p "$PA_WWW"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "$PA_CONVERTER_ROOT/app/" "$PA_WWW/"
  else
    rm -rf "$PA_WWW"/* 2>/dev/null || true
    cp -a "$PA_CONVERTER_ROOT/app/." "$PA_WWW/"
  fi

  # Configure Homebrew httpd for Expedition ports + PHP
  local bp
  bp="$(brew_prefix)"
  local httpd_conf="$bp/etc/httpd/httpd.conf"
  local vhost="$bp/etc/httpd/extra/pa-converter.conf"
  mkdir -p "$bp/etc/httpd/extra"

  cat > "$vhost" <<EOF
Listen ${EXPEDITION_HTTP_PORT}
Listen ${EXPEDITION_PORT}
LoadModule ssl_module lib/httpd/modules/mod_ssl.so
LoadModule rewrite_module lib/httpd/modules/mod_rewrite.so
LoadModule proxy_module lib/httpd/modules/mod_proxy.so
LoadModule proxy_fcgi_module lib/httpd/modules/mod_proxy_fcgi.so

<VirtualHost *:${EXPEDITION_HTTP_PORT}>
  DocumentRoot "${PA_WWW}"
  <Directory "${PA_WWW}">
    Options FollowSymLinks
    AllowOverride All
    Require all granted
  </Directory>
  DirectoryIndex index.html index.php
  <FilesMatch \.php$>
    SetHandler "proxy:fcgi://127.0.0.1:9074"
  </FilesMatch>
  ErrorLog "${PA_LOG_DIR}/httpd-error.log"
  CustomLog "${PA_LOG_DIR}/httpd-access.log" common
</VirtualHost>

<VirtualHost *:${EXPEDITION_PORT}>
  DocumentRoot "${PA_WWW}"
  SSLEngine on
  SSLCertificateFile "${bp}/etc/httpd/server.crt"
  SSLCertificateKeyFile "${bp}/etc/httpd/server.key"
  <Directory "${PA_WWW}">
    Options FollowSymLinks
    AllowOverride All
    Require all granted
  </Directory>
  DirectoryIndex index.html index.php
  <FilesMatch \.php$>
    SetHandler "proxy:fcgi://127.0.0.1:9074"
  </FilesMatch>
  ErrorLog "${PA_LOG_DIR}/httpd-ssl-error.log"
  CustomLog "${PA_LOG_DIR}/httpd-ssl-access.log" common
</VirtualHost>
EOF

  if [ -f "$httpd_conf" ] && ! grep -q 'pa-converter.conf' "$httpd_conf" 2>/dev/null; then
    echo "Include $vhost" >> "$httpd_conf"
  fi

  # Self-signed cert for Homebrew httpd
  if [ ! -f "$bp/etc/httpd/server.crt" ]; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
      -keyout "$bp/etc/httpd/server.key" \
      -out "$bp/etc/httpd/server.crt" \
      -subj "/CN=localhost" 2>/dev/null || true
  fi

  # PHP-FPM 7.4 on 9074
  local php_ini_dir
  php_ini_dir="$(brew_prefix)/etc/php/7.4"
  if [ -d "$php_ini_dir" ]; then
    mkdir -p "$php_ini_dir/conf.d"
    cat > "$php_ini_dir/conf.d/99-pa-converter.ini" <<'EOF'
upload_max_filesize = 200M
post_max_size = 200M
memory_limit = 1G
max_execution_time = 10000
EOF
  fi
  local fpm_conf="$php_ini_dir/php-fpm.d/pa-converter.conf"
  if [ -d "$php_ini_dir/php-fpm.d" ]; then
    cat > "$fpm_conf" <<EOF
[pa-converter]
listen = 127.0.0.1:9074
user = $(whoami)
group = staff
pm = dynamic
pm.max_children = 10
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
EOF
  fi

  # Start MariaDB briefly to seed
  brew services start mariadb || true
  sleep 3
  SEED_MARKER="$PA_DATA_ROOT/db-seeded"
  if [ ! -f "$SEED_MARKER" ]; then
    pa_log "Seeding databases…"
    mysql -uroot <<SQL || true
CREATE DATABASE IF NOT EXISTS pandb CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE DATABASE IF NOT EXISTS pandbRBAC CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE DATABASE IF NOT EXISTS BestPractices CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE DATABASE IF NOT EXISTS RealTimeUpdates CHARACTER SET utf8 COLLATE utf8_general_ci;
ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';
CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION;
FLUSH PRIVILEGES;
SQL
    SQL_DIR="$PA_CONVERTER_ROOT/databases"
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 pandb < "${SQL_DIR}/pandb.sql"
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 pandbRBAC < "${SQL_DIR}/pandbRBAC.sql"
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 BestPractices < "${SQL_DIR}/BestPractices.sql"
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 RealTimeUpdates < "${SQL_DIR}/RealTimeUpdates.sql"
    touch "$SEED_MARKER"
  fi

  touch "$PA_MARKER"
  pa_log "macOS native install complete under $PREFIX"
  pa_log "Note: Apple Silicon may need Rosetta for Spark 2.4 / some PHP 7.4 bits."
}

write_user_defs() {
  pa_ensure_dirs
  pa_detect_java
  export JAVA_HOME SPARK_HOME
  export DB_HOST=127.0.0.1 RABBITMQ_HOST=127.0.0.1

  cat > "$PA_USERSPACE/userDefinitions.php" <<EOF
<?php
define('DBServer', '127.0.0.1');
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

  CPUS=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
  SUGG=$(( CPUS * 80 / 100 ))
  [ "$SUGG" -lt 1 ] && SUGG=1
  MEM_MB=$(sysctl -n hw.memsize 2>/dev/null | awk '{print int($1/1024/1024)}' || echo 8192)
  SUGG_RAM_MB=$(( MEM_MB * 40 / 100 ))
  [ "$SUGG_RAM_MB" -lt 1024 ] && SUGG_RAM_MB=1024
  [ "$SUGG_RAM_MB" -gt 4096 ] && SUGG_RAM_MB=4096

  cat > "$PA_USERSPACE/environmentParameters.php" <<EOF
<?php
define('NumCPUs', ${SUGG});
define('TotalCPUs', ${CPUS});
define('SparkRAM', '${SUGG_RAM_MB}m');
EOF
}

do_start() {
  if [ ! -f "$PA_MARKER" ]; then
    do_install
  fi
  need_brew
  write_user_defs

  brew services start mariadb || true
  brew services start rabbitmq || true

  # PHP-FPM
  if [ -x "$(brew_prefix)/opt/php@7.4/sbin/php-fpm" ]; then
    pkill -f 'php-fpm.*7.4' 2>/dev/null || true
    "$(brew_prefix)/opt/php@7.4/sbin/php-fpm" --nodaemonize >>"$PA_LOG_DIR/php-fpm.log" 2>&1 &
    echo $! > "$PA_DATA_ROOT/php-fpm.pid"
  fi

  # httpd
  if [ -x "$(brew_prefix)/bin/httpd" ]; then
    "$(brew_prefix)/bin/httpd" -k restart 2>/dev/null || "$(brew_prefix)/bin/httpd" -k start || true
  else
    brew services start httpd || true
  fi

  # panReadOrders
  if [ -f "$PA_WWW/console/messaging/readOrders.php" ]; then
    pkill -f 'php .*readOrders.php' 2>/dev/null || true
    (
      export RABBITMQ_HOST=127.0.0.1 JAVA_HOME SPARK_HOME PATH
      if [ -x "$(brew_prefix)/opt/php@7.4/bin/php" ]; then
        exec "$(brew_prefix)/opt/php@7.4/bin/php" "$PA_WWW/console/messaging/readOrders.php"
      else
        exec php "$PA_WWW/console/messaging/readOrders.php"
      fi
    ) >>"$PA_USERSPACE/panReadOrders.log" 2>&1 &
    echo $! > "$PA_DATA_ROOT/panReadOrders.pid"
  fi

  pa_log "Started. HTTPS https://localhost:${EXPEDITION_PORT}  (admin / paloalto)"
}

do_stop() {
  if [ -f "$PA_DATA_ROOT/panReadOrders.pid" ]; then
    kill "$(cat "$PA_DATA_ROOT/panReadOrders.pid")" 2>/dev/null || true
    rm -f "$PA_DATA_ROOT/panReadOrders.pid"
  fi
  pkill -f 'php .*readOrders.php' 2>/dev/null || true
  if [ -f "$PA_DATA_ROOT/php-fpm.pid" ]; then
    kill "$(cat "$PA_DATA_ROOT/php-fpm.pid")" 2>/dev/null || true
    rm -f "$PA_DATA_ROOT/php-fpm.pid"
  fi
  if [ -x "$(brew_prefix)/bin/httpd" ]; then
    "$(brew_prefix)/bin/httpd" -k stop 2>/dev/null || true
  fi
  brew services stop rabbitmq 2>/dev/null || true
  brew services stop mariadb 2>/dev/null || true
  pa_log "Stopped."
}

do_status() {
  echo "PA-Converter macOS status"
  echo "  prefix: $PREFIX"
  echo "  installed: $([ -f "$PA_MARKER" ] && echo yes || echo no)"
  mysqladmin ping -h127.0.0.1 -u"${DB_USER}" -p"${DB_PASS}" --silent 2>/dev/null && echo "  mariadb     UP" || echo "  mariadb     DOWN"
  brew services info rabbitmq 2>/dev/null | head -3 || true
  pgrep -f httpd >/dev/null && echo "  httpd       UP" || echo "  httpd       DOWN"
  pgrep -f 'php .*readOrders.php' >/dev/null && echo "  panReadOrders UP" || echo "  panReadOrders DOWN"
  echo "  UI: https://localhost:${EXPEDITION_PORT}"
}

do_logs() {
  FOLLOW=0
  for a in "$@"; do
    case "$a" in -f|--follow) FOLLOW=1 ;; esac
  done
  FILES=()
  for f in "$PA_LOG_DIR"/*.log "$PA_USERSPACE/panReadOrders.log"; do
    [ -f "$f" ] && FILES+=("$f")
  done
  if [ ${#FILES[@]} -eq 0 ]; then
    pa_log "No logs yet."
    exit 0
  fi
  if [ "$FOLLOW" -eq 1 ]; then
    tail -n 200 -F "${FILES[@]}"
  else
    tail -n 200 "${FILES[@]}"
  fi
}

case "$ACTION" in
  install) do_install ;;
  start) do_start ;;
  stop) do_stop ;;
  status) do_status ;;
  logs) do_logs "$@" ;;
  *)
    echo "Usage: $0 {install|start|stop|status|logs}" >&2
    exit 1
    ;;
esac
