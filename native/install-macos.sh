#!/usr/bin/env bash
# Native PA-Converter on macOS via Homebrew (no containers).
# Usage: install-macos.sh [install|start|stop|status|logs]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

ACTION="${1:-install}"
shift || true

# Prefer the real user home when invoked via `sudo npx` (do NOT install into /var/root).
_PA_REAL_HOME="$HOME"
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  _PA_REAL_HOME="$(eval echo "~${SUDO_USER}")"
  pa_log "Running as root — using ${SUDO_USER} home: ${_PA_REAL_HOME}"
fi

# Force macOS paths (common.sh may already have set Linux FHS defaults).
# Note: macOS seals /home — cannot symlink /home/userSpace; we rewrite PHP instead.
PREFIX="${PA_MAC_PREFIX:-$_PA_REAL_HOME/Library/Application Support/PA-Converter}"
export PA_DATA_ROOT="$PREFIX/var"
export PA_WWW="$PREFIX/www"
export PA_USERSPACE="$PREFIX/userSpace"
export PA_DATA="$PREFIX/data"
export PA_PALOGS="$PREFIX/PALogs"
export PA_LOG_DIR="$PA_DATA_ROOT/logs"
export PA_MARKER="$PA_DATA_ROOT/installed"
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

# Best-effort root symlinks for /data and /PALogs (never /home — sealed on macOS).
# Use sudo -n so we never block on a password prompt (PHP paths are rewritten anyway).
pa_link_classic_paths() {
  pa_ensure_dirs
  if [ ! -e /data ] && command -v sudo >/dev/null 2>&1; then
    sudo -n ln -sfn "$PA_DATA" /data 2>/dev/null || true
  fi
  if [ ! -e /PALogs ] && command -v sudo >/dev/null 2>&1; then
    sudo -n ln -sfn "$PA_PALOGS" /PALogs 2>/dev/null || true
  fi
}

# Rewrite hardcoded Linux paths inside the served app copy (not the package source).
pa_rewrite_php_paths() {
  [ -d "$PA_WWW" ] || return 0
  pa_log "Rewriting Expedition paths in $PA_WWW for macOS…"
  export PA_USERSPACE PA_DATA PA_PALOGS
  find "$PA_WWW" -type f \( -name '*.php' -o -name '*.inc' \) -print0 2>/dev/null \
    | xargs -0 perl -pi -e '
      s{/var/www/html}{$ENV{PA_WWW}}g;
      s{/home/userSpace}{$ENV{PA_USERSPACE}}g;
      s{/PALogs}{$ENV{PA_PALOGS}}g;
      s{(["'\''])/data\1}{$1.$ENV{PA_DATA}.$1}ge;
      s{(["'\''])/data/}{$1.$ENV{PA_DATA}."/"}ge;
    ' 2>/dev/null || true
}

brew_prefix() {
  brew --prefix 2>/dev/null || echo /usr/local
}

# Expedition health check greps `pip3.7 list` for uppercase "BPA".
pa_ensure_pip37_wrapper() {
  local dest="${1:-/usr/local/bin/pip3.7}"
  local py
  py="$(command -v python3 || true)"
  [ -n "$py" ] || return 0
  mkdir -p "$(dirname "$dest")"
  # Call python3 -m pip (never rewrite system pip3).
  cat > "$dest" <<EOF
#!/bin/bash
if [ "\$1" = "list" ]; then
  "${py}" -m pip "\$@" | sed 's/^bpa /BPA /'
else
  exec "${py}" -m pip "\$@"
fi
EOF
  chmod +x "$dest"
  ln -sf "$py" "$(dirname "$dest")/python3.7" 2>/dev/null || true
}

pa_install_bpa_macos() {
  local zip="$PA_CONVERTER_ROOT/app/OS/BPA/best_practice_assessment_ngfw_pano-master.zip"
  [ -f "$zip" ] || zip="$PA_WWW/OS/BPA/best_practice_assessment_ngfw_pano-master.zip"
  if command -v bpa-legacy-cli >/dev/null 2>&1; then
    pa_ensure_pip37_wrapper "$PREFIX/bin/pip3.7"
    export PATH="$PREFIX/bin:$PATH"
    return 0
  fi
  [ -f "$zip" ] || { pa_log "WARN: BPA zip missing - BPA reports unavailable"; return 0; }
  pa_log "Installing Best Practice Assessment (BPA)..."
  # Prefer brew packages when available; fall back to pip for the rest.
  brew install --quiet numpy || true
  pip3 install --user --no-cache-dir \
    'pandas<2' 'pendulum==2.1.2' lxml Pillow reportlab matplotlib seaborn \
    Jinja2 SQLAlchemy xlrd XlsxWriter PyMySQL six requests unidecode chardet \
    python-dateutil pytz iptools 'svglib<=0.9.0' cssselect2 tinycss2 webencodings \
    >/dev/null 2>&1 || true
  if pip3 install --user --no-cache-dir --no-deps "$zip" >/dev/null 2>&1; then
    pa_log "BPA installed."
  else
    pa_log "WARN: BPA install failed - BPA reports will not work"
  fi
  mkdir -p "$PREFIX/bin"
  pa_ensure_pip37_wrapper "$PREFIX/bin/pip3.7"
  # Ensure user-local scripts are on PATH for httpd / agent children
  local py_bin
  py_bin="$(python3 -m site --user-base 2>/dev/null)/bin"
  if [ -d "$py_bin" ]; then
    ln -sf "$py_bin"/bpa-legacy-cli "$PREFIX/bin/bpa-legacy-cli" 2>/dev/null || true
    ln -sf "$py_bin"/bpa-cli "$PREFIX/bin/bpa-cli" 2>/dev/null || true
  fi
  export PATH="$PREFIX/bin:$PATH"
}

do_install() {
  need_brew
  pa_ensure_dirs
  pa_link_classic_paths
  mkdir -p "$PREFIX/opt" "$PA_LOG_DIR"

  # Never prompt in brew (npx / CI)
  export NONINTERACTIVE=1
  export HOMEBREW_NO_AUTO_UPDATE=1
  export HOMEBREW_NO_ENV_HINTS=1
  export HOMEBREW_NO_INSTALL_CLEANUP=1

  pa_log "Installing Homebrew packages (MariaDB, RabbitMQ, OpenJDK 11, httpd)…"
  brew update || true
  brew install --quiet mariadb rabbitmq openjdk@11 httpd curl || true

  # PHP 7.4 via shivammathur/php (EOL but required by Expedition)
  if ! brew list php@7.4 >/dev/null 2>&1 && [ ! -x "$(brew_prefix)/opt/php@7.4/bin/php" ]; then
    pa_log "Tapping shivammathur/php for PHP 7.4…"
    brew tap shivammathur/php || true
    brew install --quiet shivammathur/php/php@7.4 || brew install --quiet php@7.4 || true
  else
    pa_log "PHP 7.4 already installed."
  fi

  # Prefer php@7.4 binaries without unlinking system php
  if [ -x "$(brew_prefix)/opt/php@7.4/bin/php" ]; then
    export PATH="$(brew_prefix)/opt/php@7.4/bin:$(brew_prefix)/opt/php@7.4/sbin:$PATH"
  fi

  if ! "$(brew_prefix)/opt/php@7.4/bin/php" -v 2>/dev/null | grep -qE 'PHP 7\.4'; then
    pa_log "WARN: PHP 7.4 binary missing at $(brew_prefix)/opt/php@7.4/bin/php"
  fi

  # Spark via GitHub CDN (fast) — Apache archive is last resort only
  pa_install_spark "$PREFIX" || true
  export SPARK_HOME="${SPARK_HOME:-$PREFIX/opt/Spark/spark}"

  pa_detect_java
  if [ -z "${JAVA_HOME:-}" ]; then
    if [ -d "$(brew_prefix)/opt/openjdk@11/libexec/openjdk.jdk/Contents/Home" ]; then
      export JAVA_HOME="$(brew_prefix)/opt/openjdk@11/libexec/openjdk.jdk/Contents/Home"
    fi
  fi

  # Best Practice Assessment (`bpa-legacy-cli`). Same approach as Linux: install
  # heavy deps from Homebrew / pip, then BPA itself with --no-deps.
  pa_install_bpa_macos

  # Sync app
  pa_log "Syncing app → $PA_WWW"
  mkdir -p "$PA_WWW"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "$PA_CONVERTER_ROOT/app/" "$PA_WWW/"
  else
    rm -rf "$PA_WWW"/* 2>/dev/null || true
    cp -a "$PA_CONVERTER_ROOT/app/." "$PA_WWW/"
  fi
  pa_rewrite_php_paths

  pa_write_httpd_vhost

  # Self-signed cert for Homebrew httpd
  local bp
  bp="$(brew_prefix)"
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
mysqli.reconnect = On
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

  # Homebrew MariaDB: OS user gets socket auth; `mysql -uroot` → ERROR 1698.
  # Bootstrap as current user, then create root@127.0.0.1 with password for Expedition.
  SEED_MARKER="$PA_DATA_ROOT/db-seeded"
  if [ ! -f "$SEED_MARKER" ]; then
    pa_log "Seeding databases (Homebrew MariaDB)…"
    mysql <<SQL
CREATE DATABASE IF NOT EXISTS pandb CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE DATABASE IF NOT EXISTS pandbRBAC CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE DATABASE IF NOT EXISTS BestPractices CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE DATABASE IF NOT EXISTS RealTimeUpdates CHARACTER SET utf8 COLLATE utf8_general_ci;
CREATE OR REPLACE USER 'root'@'127.0.0.1' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';
CREATE OR REPLACE USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
SQL
    SQL_DIR="$PA_CONVERTER_ROOT/databases"
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 pandb < "${SQL_DIR}/pandb.sql"
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 pandbRBAC < "${SQL_DIR}/pandbRBAC.sql"
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 BestPractices < "${SQL_DIR}/BestPractices.sql"
    mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 RealTimeUpdates < "${SQL_DIR}/RealTimeUpdates.sql"
    touch "$SEED_MARKER"
    pa_log "Databases seeded."
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
  # Match Expedition checkCPUs.sh: 80% of host RAM
  SUGG_RAM_MB=$(( MEM_MB * 80 / 100 ))
  [ "$SUGG_RAM_MB" -lt 1024 ] && SUGG_RAM_MB=1024

  cat > "$PA_USERSPACE/environmentParameters.php" <<EOF
<?php
define('NumCPUs', ${SUGG});
define('TotalCPUs', ${CPUS});
define('SparkRAM', '${SUGG_RAM_MB}m');
EOF
}

# Homebrew httpd vhost. Listen on 443 as well: checkAlive curls https://<ML IP>/
# (no port), and Spark uses <ML IP>:3306, so the ML address must be a bare IP.
# On macOS, binding *:443 works without root (127.0.0.1:443 does not).
pa_write_httpd_vhost() {
  local bp httpd_conf vhost
  bp="$(brew_prefix)"
  httpd_conf="$bp/etc/httpd/httpd.conf"
  vhost="$bp/etc/httpd/extra/pa-converter.conf"
  mkdir -p "$bp/etc/httpd/extra" "$PA_LOG_DIR"
  cat > "$vhost" <<EOF
Listen ${EXPEDITION_HTTP_PORT}
Listen ${EXPEDITION_PORT}
Listen 443
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

<VirtualHost *:${EXPEDITION_PORT} *:443>
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
}

# Post-install tuning: ML paths/IP, RabbitMQ 4.x compat, PHP/MariaDB knobs.
pa_tune_macos_runtime() {
  local bp ml_ip conf mycnf php_ini
  bp="$(brew_prefix)"
  ml_ip="$(ipconfig getifaddr en0 2>/dev/null || true)"
  [ -z "$ml_ip" ] && ml_ip="$(ipconfig getifaddr en1 2>/dev/null || true)"
  [ -z "$ml_ip" ] && ml_ip="$(route get 1.1.1.1 2>/dev/null | awk '/interface:/{iface=$2} END{print iface}')"
  if [ -n "$ml_ip" ] && [ "$ml_ip" != "en0" ] && [ "$ml_ip" != "en1" ]; then
    :
  else
    ml_ip="$(ifconfig en0 2>/dev/null | awk '/inet /{print $2; exit}')"
  fi
  [ -z "$ml_ip" ] && ml_ip="127.0.0.1"

  # RabbitMQ 4.x blocks Expedition's old php-amqplib queues unless permitted
  conf="$bp/etc/rabbitmq/rabbitmq.conf"
  mkdir -p "$(dirname "$conf")"
  if [ -f "$conf" ] && ! grep -q 'transient_nonexcl_queues' "$conf" 2>/dev/null; then
    cat >> "$conf" <<'EOF'

# Expedition / old php-amqplib compatibility (RabbitMQ 4.x)
deprecated_features.permit.transient_nonexcl_queues = true
EOF
  elif [ ! -f "$conf" ]; then
    cat > "$conf" <<'EOF'
# Expedition / old php-amqplib compatibility (RabbitMQ 4.x)
deprecated_features.permit.transient_nonexcl_queues = true
EOF
  fi

  # Spark jobs connect to <ML IP>:3306, so MariaDB must listen beyond loopback.
  mycnf="$bp/etc/my.cnf"
  mkdir -p "$(dirname "$mycnf")"
  if [ -f "$mycnf" ] && grep -qE '^\s*bind-address\s*=' "$mycnf" 2>/dev/null; then
    perl -pi -e 's/^\s*bind-address\s*=.*/bind-address = 0.0.0.0/' "$mycnf"
  else
    cat >> "$mycnf" <<'EOF'

[mysqld]
bind-address = 0.0.0.0
EOF
  fi
  # Apply bind-address change if MariaDB is already running.
  brew services restart mariadb >/dev/null 2>&1 || true

  # PHP mysqli reconnect (must be in main php.ini — PHP_INI_SYSTEM)
  php_ini="$bp/etc/php/7.4/php.ini"
  if [ -f "$php_ini" ]; then
    if grep -qE '^;?mysqli\.reconnect' "$php_ini"; then
      perl -pi -e 's/^;?mysqli\.reconnect\s*=.*/mysqli.reconnect = On/' "$php_ini"
    else
      echo 'mysqli.reconnect = On' >> "$php_ini"
    fi
  fi
  mkdir -p "$bp/etc/php/7.4/conf.d"
  cat > "$bp/etc/php/7.4/conf.d/99-pa-converter.ini" <<'EOF'
upload_max_filesize = 200M
post_max_size = 200M
memory_limit = 1G
max_execution_time = 10000
mysqli.reconnect = On
EOF

  # ML settings: checkAlive curls https://$server/API/... (port 443, no custom port
  # allowed - Spark also concatenates :3306 onto the same value). Store a bare IP;
  # httpd also listens on *:443 (see vhost above). Reject bare 127.0.0.1 in the UI.
  mkdir -p "$PA_DATA"
  chmod u+rwx "$PA_DATA" "$PA_USERSPACE" "$PA_PALOGS" 2>/dev/null || true
  local ml_server="$ml_ip"
  mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -h127.0.0.1 pandbRBAC -e "
INSERT INTO ml_settings (id, server, parquetPath, tempDataPath)
VALUES (1, '${ml_server}', '${PA_DATA}', '${PA_DATA}')
ON DUPLICATE KEY UPDATE server='${ml_server}', parquetPath='${PA_DATA}', tempDataPath='${PA_DATA}';
" 2>/dev/null || true
  pa_log "ML server=${ml_server} parquet=${PA_DATA}"
}

do_start() {
  if [ "$(id -u)" -eq 0 ] && [ -z "${PA_ALLOW_ROOT:-}" ]; then
    pa_log "Do not use sudo with npx — run as your user (Homebrew refuses root)."
    pa_log "Retry:  npx --yes github:TufaylAhmed/PA-Converter#v5.46.24 start"
    exit 1
  fi
  if [ ! -f "$PA_MARKER" ]; then
    do_install
  else
    pa_ensure_dirs
    pa_link_classic_paths
    # Package updates / fresh sync can restore Docker paths — always rewrite.
    pa_rewrite_php_paths
    pa_write_httpd_vhost
    pa_install_bpa_macos
  fi
  need_brew
  export PATH="$PREFIX/bin:$PATH"
  write_user_defs
  pa_tune_macos_runtime

  brew services start mariadb || true
  brew services restart rabbitmq 2>/dev/null || brew services start rabbitmq || true
  sleep 2

  # PHP-FPM 7.4 (explicit path — do not use shadowed brew php)
  if [ -x "$(brew_prefix)/opt/php@7.4/sbin/php-fpm" ]; then
    pkill -f 'php-fpm.*7.4' 2>/dev/null || true
    "$(brew_prefix)/opt/php@7.4/sbin/php-fpm" --nodaemonize >>"$PA_LOG_DIR/php-fpm.log" 2>&1 &
    echo $! > "$PA_DATA_ROOT/php-fpm.pid"
  fi

  # httpd — prefer brew services so it stays up across sessions
  if [ -x "$(brew_prefix)/bin/httpd" ]; then
    # Ensure ServerName to silence FQDN warning
    local httpd_conf
    httpd_conf="$(brew_prefix)/etc/httpd/httpd.conf"
    if [ -f "$httpd_conf" ] && ! grep -qE '^ServerName ' "$httpd_conf" 2>/dev/null; then
      echo 'ServerName localhost' >> "$httpd_conf"
    fi
    brew services start httpd 2>/dev/null || true
    "$(brew_prefix)/bin/httpd" -k restart 2>/dev/null || "$(brew_prefix)/bin/httpd" -k start || true
  else
    brew services start httpd || true
  fi
  # Wait briefly for listeners
  for _i in 1 2 3 4 5; do
    lsof -nP -iTCP:"${EXPEDITION_PORT}" -sTCP:LISTEN >/dev/null 2>&1 && break
    sleep 1
  done
  if ! lsof -nP -iTCP:"${EXPEDITION_PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
    pa_log "WARN: HTTPS port ${EXPEDITION_PORT} not listening — check $PA_LOG_DIR/httpd-ssl-error.log"
  fi

  # panReadOrders (after RabbitMQ permit is applied)
  if [ -f "$PA_WWW/console/messaging/readOrders.php" ]; then
    pkill -f 'readOrders.php' 2>/dev/null || true
    : > "$PA_USERSPACE/panReadOrders.log"
    (
      export RABBITMQ_HOST=127.0.0.1
      pa_detect_java || true
      export JAVA_HOME SPARK_HOME
      export PATH="$(brew_prefix)/opt/php@7.4/bin:${PATH}"
      exec "$(brew_prefix)/opt/php@7.4/bin/php" "$PA_WWW/console/messaging/readOrders.php"
    ) >>"$PA_USERSPACE/panReadOrders.log" 2>&1 &
    echo $! > "$PA_DATA_ROOT/panReadOrders.pid"
    sleep 1
    if pgrep -f 'readOrders.php' >/dev/null 2>&1; then
      pa_log "PanOrders agent running."
    else
      pa_log "WARN: PanOrders failed — see $PA_USERSPACE/panReadOrders.log"
    fi
  fi

  pa_log "Started. HTTPS https://localhost:${EXPEDITION_PORT}  (admin / paloalto)"
  pa_log "Data: $PREFIX"
  pa_log "Note: Ubuntu-only packages (expedition-beta / BPA apt) are N/A on macOS — some health checks will still fail."
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
