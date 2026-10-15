#!/usr/bin/env bash
# Shared paths/env for native PA-Converter runtime (no containers).
set -euo pipefail

NATIVE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Package / appliance root (app/, databases/, native/)
export PA_CONVERTER_ROOT="${PA_CONVERTER_ROOT:-$(cd "$NATIVE_DIR/.." && pwd)}"

# Platform defaults: Linux/WSL uses FHS paths; macOS uses a user-writable prefix.
if [ -z "${PA_DATA_ROOT:-}" ] || [ -z "${PA_WWW:-}" ]; then
  if [ "$(uname -s)" = "Darwin" ]; then
    _PA_PREFIX="${PA_MAC_PREFIX:-$HOME/Library/Application Support/PA-Converter}"
    : "${PA_DATA_ROOT:=$_PA_PREFIX/var}"
    : "${PA_WWW:=$_PA_PREFIX/www}"
    : "${PA_USERSPACE:=$_PA_PREFIX/userSpace}"
    : "${PA_DATA:=$_PA_PREFIX/data}"
    : "${PA_PALOGS:=$_PA_PREFIX/PALogs}"
    : "${SPARK_HOME:=$_PA_PREFIX/opt/Spark/spark}"
  else
    : "${PA_DATA_ROOT:=/var/lib/pa-converter}"
    : "${PA_WWW:=/var/www/pa-converter}"
    : "${PA_USERSPACE:=/home/userSpace}"
    : "${PA_DATA:=/data}"
    : "${PA_PALOGS:=/PALogs}"
    : "${SPARK_HOME:=/opt/Spark/spark}"
  fi
fi

export PA_DATA_ROOT="${PA_DATA_ROOT:-/var/lib/pa-converter}"
export PA_WWW="${PA_WWW:-/var/www/pa-converter}"
export PA_USERSPACE="${PA_USERSPACE:-/home/userSpace}"
export PA_DATA="${PA_DATA:-/data}"
export PA_PALOGS="${PA_PALOGS:-/PALogs}"
export PA_LOG_DIR="${PA_LOG_DIR:-$PA_DATA_ROOT/logs}"
export PA_MARKER="${PA_MARKER:-$PA_DATA_ROOT/installed}"

export DB_HOST="${DB_HOST:-127.0.0.1}"
export DB_USER="${DB_USER:-root}"
export DB_PASS="${DB_PASS:-paloalto}"
export MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-$DB_PASS}"
export RABBITMQ_HOST="${RABBITMQ_HOST:-127.0.0.1}"
export EXPEDITION_PORT="${EXPEDITION_PORT:-18443}"
export EXPEDITION_HTTP_PORT="${EXPEDITION_HTTP_PORT:-18080}"

export SPARK_HOME="${SPARK_HOME:-/opt/Spark/spark}"
export JAVA_HOME="${JAVA_HOME:-}"

pa_log() { echo "[pa-converter] $*"; }

# Emit install progress for Windows SETUP (Write-Progress) and console bar.
# Usage: pa_progress <0-100> <phase_id> <human message...>
pa_progress() {
  local pct="${1:-0}"
  local phase="${2:-work}"
  shift 2 || true
  local msg="${*:-working}"
  case "$pct" in
    ''|*[!0-9]*) pct=0 ;;
  esac
  if [ "$pct" -gt 100 ]; then pct=100; fi
  if [ "$pct" -lt 0 ]; then pct=0; fi
  local filled=$((pct / 5))
  local empty=$((20 - filled))
  local bar
  bar="$(printf '%*s' "$filled" '' | tr ' ' '#')"
  bar="${bar}$(printf '%*s' "$empty" '' | tr ' ' '-')"
  # Machine-readable for PowerShell / piped SETUP (skip on interactive TTY)
  if [ ! -t 1 ] || [ -n "${PA_PROGRESS_MACHINE:-}" ]; then
    printf 'PA_PROGRESS|%s|%s|%s\n' "$pct" "$phase" "$msg"
  fi
  printf '[pa-converter] [%s] %3d%%  %s\n' "$bar" "$pct" "$msg"
}

pa_ensure_dirs() {
  mkdir -p "$PA_DATA_ROOT" "$PA_LOG_DIR" "$PA_USERSPACE" "$PA_DATA" "$PA_PALOGS" "$PA_WWW"
}

pa_detect_java() {
  if [ -n "${JAVA_HOME}" ] && [ -x "${JAVA_HOME}/bin/java" ]; then
    return 0
  fi
  local arch
  arch="$(dpkg --print-architecture 2>/dev/null || uname -m)"
  case "$arch" in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
  esac
  for cand in \
    "/usr/lib/jvm/java-11-openjdk-${arch}" \
    /usr/lib/jvm/java-11-openjdk-amd64 \
    /usr/lib/jvm/java-11-openjdk-arm64 \
    /opt/homebrew/opt/openjdk@11/libexec/openjdk.jdk/Contents/Home \
    /usr/local/opt/openjdk@11/libexec/openjdk.jdk/Contents/Home
  do
    if [ -x "${cand}/bin/java" ]; then
      export JAVA_HOME="$cand"
      return 0
    fi
  done
  if command -v /usr/libexec/java_home >/dev/null 2>&1; then
    export JAVA_HOME="$(/usr/libexec/java_home -v 11 2>/dev/null || true)"
  fi
}

pa_is_wsl() {
  grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null
}

pa_service() {
  # usage: pa_service start|stop|status name
  local action="$1" name="$2"
  # WSL often has a systemctl stub that is not actually running — prefer SysV `service`.
  if pa_is_wsl && command -v service >/dev/null 2>&1; then
    service "$name" "$action" 2>/dev/null || true
    return 0
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
    systemctl "$action" "$name" 2>/dev/null || systemctl "$action" "${name}.service" 2>/dev/null || true
  elif command -v service >/dev/null 2>&1; then
    service "$name" "$action" 2>/dev/null || true
  elif command -v brew >/dev/null 2>&1; then
    case "$action" in
      start) brew services start "$name" 2>/dev/null || true ;;
      stop) brew services stop "$name" 2>/dev/null || true ;;
      status) brew services info "$name" 2>/dev/null || true ;;
    esac
  fi
}

# Rewrite site + ports.conf (idempotent). Fixes older installs that put Listen in the vhost file.
pa_ensure_apache_site() {
  local http_port="${EXPEDITION_HTTP_PORT:-18080}"
  local https_port="${EXPEDITION_PORT:-18443}"
  local log_dir="${APACHE_LOG_DIR:-/var/log/apache2}"
  local site_src="${PA_CONVERTER_ROOT}/native/apache/pa-converter.conf"
  local site_dst=/etc/apache2/sites-available/pa-converter.conf
  local ports=/etc/apache2/ports.conf

  mkdir -p "$log_dir" /etc/apache2/sites-available /etc/apache2/sites-enabled

  if [ ! -f "$site_src" ]; then
    pa_log "WARN: missing $site_src"
    return 1
  fi

  sed -e "s/\${EXPEDITION_HTTP_PORT}/${http_port}/g" \
      -e "s/\${EXPEDITION_PORT}/${https_port}/g" \
      -e "s|\${APACHE_LOG_DIR}|${log_dir}|g" \
      "$site_src" > "$site_dst"

  # Strip any Listen lines accidentally left in the vhost (breaks Apache with duplicates)
  if grep -qE '^\s*Listen\s+' "$site_dst" 2>/dev/null; then
    pa_log "Removing Listen directives from vhost (must live in ports.conf only)"
    grep -vE '^\s*Listen\s+' "$site_dst" > "${site_dst}.tmp" && mv "${site_dst}.tmp" "$site_dst"
  fi

  touch "$ports"
  if ! grep -qE "^Listen ${http_port}(\\s|\$)" "$ports" 2>/dev/null; then
    echo "Listen ${http_port}" >> "$ports"
  fi
  if ! grep -qE "^Listen ${https_port}(\\s|\$)" "$ports" 2>/dev/null; then
    echo "Listen ${https_port}" >> "$ports"
  fi

  # Snakeoil certs for HTTPS
  if [ ! -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]; then
    apt-get install -y --no-install-recommends ssl-cert >/dev/null 2>&1 || true
    make-ssl-cert generate-default-snakeoil >/dev/null 2>&1 || true
  fi

  a2enmod rewrite ssl headers 2>/dev/null || true
  a2dissite 000-default default-ssl 2>/dev/null || true
  a2ensite pa-converter 2>/dev/null || true
  return 0
}

# Start Apache reliably on WSL (apache2ctl often shells out to broken systemctl).
pa_start_apache() {
  pa_ensure_apache_site || true

  # Stop any half-started instance so a clean start can bind ports
  if pgrep -x apache2 >/dev/null 2>&1; then
    pa_log "Stopping existing Apache before clean start"
    apache2ctl -k stop 2>/dev/null || service apache2 stop 2>/dev/null || pkill apache2 2>/dev/null || true
    sleep 1
  fi

  # Always set runtime dirs BEFORE sourcing envvars / starting apache2.
  # (If envvars is not sourced, apache2.conf expands ${APACHE_RUN_DIR} to empty and dies.)
  export APACHE_RUN_DIR="${APACHE_RUN_DIR:-/var/run/apache2}"
  export APACHE_LOCK_DIR="${APACHE_LOCK_DIR:-/var/lock/apache2}"
  export APACHE_PID_DIR="${APACHE_PID_DIR:-/var/run/apache2}"
  export APACHE_LOG_DIR="${APACHE_LOG_DIR:-/var/log/apache2}"
  export APACHE_PID_FILE="${APACHE_PID_FILE:-/var/run/apache2/apache2.pid}"
  export APACHE_RUN_USER="${APACHE_RUN_USER:-www-data}"
  export APACHE_RUN_GROUP="${APACHE_RUN_GROUP:-www-data}"
  # shellcheck source=/dev/null
  if [ -f /etc/apache2/envvars ]; then
    # shellcheck disable=SC1091
    . /etc/apache2/envvars
  fi
  # Re-assert after envvars (some installs leave them empty)
  export APACHE_RUN_DIR="${APACHE_RUN_DIR:-/var/run/apache2}"
  export APACHE_LOCK_DIR="${APACHE_LOCK_DIR:-/var/lock/apache2}"
  export APACHE_PID_FILE="${APACHE_PID_FILE:-/var/run/apache2/apache2.pid}"
  export APACHE_LOG_DIR="${APACHE_LOG_DIR:-/var/log/apache2}"
  export APACHE_RUN_USER="${APACHE_RUN_USER:-www-data}"
  export APACHE_RUN_GROUP="${APACHE_RUN_GROUP:-www-data}"
  mkdir -p "$APACHE_RUN_DIR" "$APACHE_LOCK_DIR" "$APACHE_LOG_DIR" 2>/dev/null || true

  local ct
  ct="$(apache2ctl configtest 2>&1 || true)"
  if echo "$ct" | grep -qi 'Syntax error\|AH00526\|Cannot load\|SSLCertificate'; then
    pa_log "Apache configtest FAILED:"
    echo "$ct" | while IFS= read -r line; do pa_log "  $line"; done
  else
    pa_log "Apache configtest: $(echo "$ct" | tail -n 1)"
  fi

  # 1) SysV service (best on WSL without systemd)
  if pa_is_wsl && command -v service >/dev/null 2>&1; then
    service apache2 start 2>&1 | while IFS= read -r line; do pa_log "service: $line"; done || true
  fi

  # 2) Direct binary -k start (does not go through systemctl)
  if ! pgrep -x apache2 >/dev/null 2>&1 && [ -x /usr/sbin/apache2 ]; then
    pa_log "Starting /usr/sbin/apache2 -k start"
    /usr/sbin/apache2 -k start 2>&1 | while IFS= read -r line; do pa_log "apache2: $line"; done || true
  fi

  # 3) apache2ctl -k (still better than plain apache2ctl start on WSL)
  if ! pgrep -x apache2 >/dev/null 2>&1 && command -v apache2ctl >/dev/null 2>&1; then
    apache2ctl -k start 2>&1 | while IFS= read -r line; do pa_log "apache2ctl: $line"; done || true
  fi

  if pgrep -x apache2 >/dev/null 2>&1 || pgrep -x httpd >/dev/null 2>&1; then
    pa_log "Apache process is up (pids: $(pgrep -x apache2 | tr '\n' ' '))"
    return 0
  fi

  pa_log "WARN: Apache process not detected. Last error log:"
  tail -n 30 /var/log/apache2/error.log 2>/dev/null | while IFS= read -r line; do pa_log "  $line"; done || true
  tail -n 30 /var/log/apache2/pa-converter-ssl-error.log 2>/dev/null | while IFS= read -r line; do pa_log "  $line"; done || true
  return 1
}

pa_wait_port() {
  local port="$1" tries="${2:-30}"
  local i
  for i in $(seq 1 "$tries"); do
    if command -v ss >/dev/null 2>&1; then
      if ss -ltn 2>/dev/null | grep -qE ":${port}\\s"; then return 0; fi
    elif command -v netstat >/dev/null 2>&1; then
      if netstat -ltn 2>/dev/null | grep -qE ":${port}\\s"; then return 0; fi
    else
      # bash /dev/tcp fallback
      if (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1; then return 0; fi
    fi
    sleep 1
  done
  return 1
}

# Install Spark 2.4.3 under $1 (macOS: $PREFIX, Linux: /).
# Prefers local bundle + GitHub release CDN; Apache archive is last resort (slow/stall-prone).
pa_install_spark() {
  local root="${1:-/}"
  local spark_home_link="${root%/}/opt/Spark/spark"
  local spark_dir="${root%/}/opt/Spark"
  mkdir -p "$spark_dir"

  if [ -x "${spark_home_link}/bin/spark-submit" ]; then
    export SPARK_HOME="$spark_home_link"
    return 0
  fi
  if [ "${PA_SKIP_SPARK:-}" = "1" ]; then
    pa_log "Skipping Spark (PA_SKIP_SPARK=1)."
    return 0
  fi

  local cache="${PA_DATA_ROOT:-/tmp}/spark-download"
  mkdir -p "$cache"
  local bundle="$PA_CONVERTER_ROOT/docker/spark/opt-Spark.tar.gz"
  local asset_tag="${PA_SPARK_RELEASE:-v5.46.22}"
  local gh_asset="https://github.com/TufaylAhmed/PA-Converter/releases/download/${asset_tag}/opt-Spark.tar.gz"
  local gh_latest="https://github.com/TufaylAhmed/PA-Converter/releases/latest/download/opt-Spark.tar.gz"
  local apache="https://archive.apache.org/dist/spark/spark-2.4.3/spark-2.4.3-bin-hadoop2.7.tgz"
  local tgz=""

  if [ -f "$bundle" ] && [ "$(wc -c < "$bundle" | tr -d ' ')" -gt 1000000 ]; then
    pa_progress 84 spark "Using local Spark bundle"
    pa_log "Using local Spark bundle ($bundle)"
    tgz="$bundle"
  else
    local dest="$cache/opt-Spark.tar.gz"
    for url in "$gh_asset" "$gh_latest"; do
      pa_progress 85 spark "Downloading Spark from GitHub (~230MB)..."
      pa_log "Downloading Spark from GitHub CDN..."
      pa_log "  $url"
      # -sS: no progress bar (progress bar on stderr races with Windows SETUP log stream)
      if curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 \
          -C - -o "$dest" "$url"
      then
        tgz="$dest"
        break
      fi
      rm -f "$dest"
    done
    if [ -z "$tgz" ]; then
      dest="$cache/spark-2.4.3-bin-hadoop2.7.tgz"
      pa_progress 86 spark "Downloading Spark from Apache archive (slow)..."
      pa_log "GitHub asset missing - falling back to Apache archive (often slow)..."
      pa_log "  $apache"
      if curl -fsSL --retry 5 --retry-delay 5 --connect-timeout 30 \
          -C - -o "$dest" "$apache"
      then
        tgz="$dest"
      fi
    fi
  fi

  if [ -z "$tgz" ] || [ ! -f "$tgz" ]; then
    pa_log "WARN: Spark install failed - UI can run; ML jobs need Spark."
    return 1
  fi
  local sz
  sz="$(wc -c < "$tgz" | tr -d ' ')"
  if [ "${sz:-0}" -lt 1000000 ]; then
    pa_log "WARN: Spark archive too small (${sz} bytes) - deleting and skipping"
    rm -f "$tgz"
    return 1
  fi

  pa_progress 90 spark "Extracting Spark..."
  pa_log "Extracting Spark..."
  # Probe archive layout without pipefail SIGPIPE from tar|grep -m1
  local layout="apache"
  set +o pipefail
  if tar -tzf "$tgz" 2>/dev/null | grep -m1 -q '^opt/Spark/'; then
    layout="bundle"
  fi
  set -o pipefail
  if [ "$layout" = "bundle" ]; then
    tar -xzf "$tgz" -C "${root%/}" || {
      pa_log "WARN: Spark bundle extract failed"
      return 1
    }
  else
    tar -xzf "$tgz" -C "$spark_dir" || {
      pa_log "WARN: Spark Apache-tarball extract failed"
      return 1
    }
    if [ -d "$spark_dir/spark-2.4.3-bin-hadoop2.7" ]; then
      ln -sfn "$spark_dir/spark-2.4.3-bin-hadoop2.7" "$spark_home_link"
    fi
  fi
  if [ ! -e "$spark_home_link" ] && [ -d "$spark_dir/spark-2.4.3-bin-hadoop2.7" ]; then
    ln -sfn "$spark_dir/spark-2.4.3-bin-hadoop2.7" "$spark_home_link"
  fi
  if [ ! -e "$spark_home_link" ] && [ -d "$spark_dir/spark" ]; then
    ln -sfn "$spark_dir/spark" "$spark_home_link"
  fi
  # Bundled archive already includes opt/Spark/spark symlink
  if [ -x "$spark_home_link/bin/spark-submit" ] || [ -x "$spark_dir/spark/bin/spark-submit" ]; then
    export SPARK_HOME="$spark_home_link"
    [ -x "$spark_dir/spark/bin/spark-submit" ] && export SPARK_HOME="$spark_dir/spark"
    pa_log "Spark ready at $SPARK_HOME"
    return 0
  fi
  pa_log "WARN: Spark extract incomplete (layout=$layout). UI can still run."
  return 1
}
