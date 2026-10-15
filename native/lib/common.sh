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
    : "${PA_WWW:=/var/www/html}"
    : "${PA_USERSPACE:=/home/userSpace}"
    : "${PA_DATA:=/data}"
    : "${PA_PALOGS:=/PALogs}"
    : "${SPARK_HOME:=/opt/Spark/spark}"
  fi
fi

export PA_DATA_ROOT="${PA_DATA_ROOT:-/var/lib/pa-converter}"
export PA_WWW="${PA_WWW:-/var/www/html}"
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
  [ "${PA_FORCE_WSL:-}" = "1" ] || grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null
}

pa_service() {
  # usage: pa_service start|stop|status name
  local action="$1" name="$2"
  # WSL often has a systemctl stub that is not actually running — prefer SysV `service`.
  # Returns the real exit status so `pa_service start a || pa_service start b` falls back.
  if pa_is_wsl && command -v service >/dev/null 2>&1; then
    service "$name" "$action" 2>/dev/null
    return
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
    systemctl "$action" "$name" 2>/dev/null || systemctl "$action" "${name}.service" 2>/dev/null
  elif command -v service >/dev/null 2>&1; then
    service "$name" "$action" 2>/dev/null
  elif command -v brew >/dev/null 2>&1; then
    case "$action" in
      start) brew services start "$name" 2>/dev/null ;;
      stop) brew services stop "$name" 2>/dev/null ;;
      status) brew services info "$name" 2>/dev/null ;;
    esac
  else
    return 1
  fi
}

# Ubuntu 20.04 names the MariaDB init script `mysql`; newer releases use `mariadb`.
pa_start_mariadb() {
  # Spark jobs connect to <ML IP>:3306, so MariaDB must not be loopback-only.
  local cnf=/etc/mysql/mariadb.conf.d/99-pa-converter.cnf
  if [ -d /etc/mysql/mariadb.conf.d ] && [ ! -f "$cnf" ]; then
    printf '[mysqld]\nbind-address = 0.0.0.0\n' > "$cnf"
    if mysqladmin --protocol=tcp -h127.0.0.1 ping >/dev/null 2>&1; then
      pa_log "Restarting MariaDB to listen beyond loopback"
      pa_service restart mariadb || pa_service restart mysql || true
    fi
  fi
  if ! mysqladmin --protocol=tcp -h127.0.0.1 ping >/dev/null 2>&1; then
    pa_service start mariadb || pa_service start mysql || true
  fi
  local i
  for i in $(seq 1 30); do
    if mysqladmin --protocol=tcp -h127.0.0.1 ping >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  pa_log "ERROR: MariaDB is not answering on 127.0.0.1:3306"
  tail -n 20 /var/log/mysql/error.log 2>/dev/null | pa_log_lines || true
  return 1
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

  # Own ports.conf entirely: Ubuntu's default Listen 80/443 have no SSL vhost behind them.
  # Expedition calls its ML API at https://<ML IP>/ (port 443, no port allowed because
  # Spark also uses <ML IP>:3306), so serve 443 on that IP only - binding it on all
  # addresses would make WSL forward Windows' port 443.
  local ml_ip
  ml_ip="$(pa_ml_ip)"
  {
    echo "# Managed by PA-Converter"
    echo "Listen ${http_port}"
    echo "Listen ${https_port}"
    if [ -n "$ml_ip" ] && [ "$ml_ip" != "127.0.0.1" ]; then
      echo "Listen ${ml_ip}:443"
    fi
  } > "$ports"

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

# Non-loopback address Expedition stores as its ML server (checkAlive treats 127.0.0.1 as unset).
pa_ml_ip() {
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [ -z "$ip" ] || [ "$ip" = "127.0.0.1" ]; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  fi
  echo "${ip:-127.0.0.1}"
}

pa_log_lines() {
  local line
  while IFS= read -r line; do pa_log "  $line"; done
}

# Start (or reload) Apache without systemd.
# Never source /etc/apache2/envvars here: it reads unset vars and kills `set -u` scripts.
# `apache2ctl -k <action>` sources envvars in its own process and calls the binary
# directly, unlike `apache2ctl start` which defers to systemctl (a no-op on WSL).
pa_start_apache() {
  pa_ensure_apache_site || true
  mkdir -p /var/run/apache2 /var/lock/apache2 /var/log/apache2

  local out
  if ! out="$(apache2ctl configtest 2>&1)"; then
    pa_log "ERROR: Apache configtest failed:"
    printf '%s\n' "$out" | pa_log_lines
    return 1
  fi

  # Full stop/start, not graceful: a graceful reload cannot rebind changed Listen
  # addresses (EADDRINUSE) and leaves Apache dead.
  if pgrep -x apache2 >/dev/null 2>&1; then
    pa_log "Restarting Apache to apply config"
    apache2ctl -k stop >/dev/null 2>&1 || true
    local i
    for i in $(seq 1 15); do
      pgrep -x apache2 >/dev/null 2>&1 || break
      sleep 1
    done
    pkill -9 -x apache2 2>/dev/null || true
  fi
  out="$(apache2ctl -k start 2>&1)" || true
  [ -n "$out" ] && printf '%s\n' "$out" | pa_log_lines
  sleep 1

  if pgrep -x apache2 >/dev/null 2>&1; then
    return 0
  fi
  pa_log "ERROR: Apache did not start. Recent error log:"
  tail -n 20 /var/log/apache2/error.log 2>/dev/null | pa_log_lines || true
  return 1
}

# Print whatever is holding a port (helps diagnose leftovers such as old Docker proxies).
pa_port_owner() {
  ss -ltnp 2>/dev/null | grep -E ":$1\\s" || true
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

  # Older installs extracted the bare Apache tarball (no Expedition defaults/packages);
  # only treat Spark as installed when the full bundle layout is present.
  if [ -x "${spark_home_link}/bin/spark-submit" ] && [ -d "${spark_dir}/packages" ] \
     && [ -f "${spark_dir}/spark-defaults.conf" ]; then
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
  # Pin to releases that actually ship opt-Spark.tar.gz. Do NOT use /latest/
  # (new MSI-only releases 404 and then curl hangs on Apache archive).
  local asset_tag="${PA_SPARK_RELEASE:-v5.46.22}"
  local gh_urls=(
    "https://github.com/TufaylAhmed/PA-Converter/releases/download/${asset_tag}/opt-Spark.tar.gz"
    "https://github.com/TufaylAhmed/PA-Converter/releases/download/v5.46.39/opt-Spark.tar.gz"
    "https://github.com/TufaylAhmed/PA-Converter/releases/download/v5.46.22/opt-Spark.tar.gz"
  )
  local apache="https://archive.apache.org/dist/spark/spark-2.4.3/spark-2.4.3-bin-hadoop2.7.tgz"
  local tgz=""

  if [ -f "$bundle" ] && [ "$(wc -c < "$bundle" | tr -d ' ')" -gt 1000000 ]; then
    pa_progress 84 spark "Using local Spark bundle"
    pa_log "Using local Spark bundle ($bundle)"
    tgz="$bundle"
  else
    local dest="$cache/opt-Spark.tar.gz"
    local url
    for url in "${gh_urls[@]}"; do
      pa_progress 85 spark "Downloading Spark from GitHub (~230MB)..."
      pa_log "Downloading Spark from GitHub CDN..."
      pa_log "  $url"
      # Drop corrupt/partial leftovers (HTML 404 pages break -C resume)
      rm -f "$dest"
      # max-time 15m; no -C (resume of a bad partial causes silent hangs)
      if curl -fsSL --retry 2 --retry-delay 2 --connect-timeout 20 --max-time 900 \
          -o "$dest" "$url"
      then
        local got
        got="$(wc -c < "$dest" | tr -d ' ')"
        if [ "${got:-0}" -gt 1000000 ]; then
          tgz="$dest"
          pa_log "Spark download OK (${got} bytes)"
          break
        fi
        pa_log "WARN: download too small (${got} bytes) - trying next URL"
      else
        pa_log "WARN: download failed for $url"
      fi
      rm -f "$dest"
    done
    # Apache archive often stalls for hours — only if explicitly enabled
    if [ -z "$tgz" ] && [ "${PA_SPARK_APACHE:-0}" = "1" ]; then
      dest="$cache/spark-2.4.3-bin-hadoop2.7.tgz"
      pa_progress 86 spark "Downloading Spark from Apache archive (slow)..."
      pa_log "GitHub asset missing - Apache fallback (PA_SPARK_APACHE=1)..."
      pa_log "  $apache"
      rm -f "$dest"
      if curl -fsSL --retry 2 --retry-delay 5 --connect-timeout 30 --max-time 900 \
          -o "$dest" "$apache"
      then
        tgz="$dest"
      fi
    elif [ -z "$tgz" ]; then
      pa_log "WARN: Spark GitHub download failed. Skipping Apache archive (set PA_SPARK_APACHE=1 to try)."
      pa_log "WARN: UI will still start; ML jobs need Spark."
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
    tar -xzf "$tgz" -C "${root%/}/" || {
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
