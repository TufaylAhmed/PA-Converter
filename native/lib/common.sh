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

pa_service() {
  # usage: pa_service start|stop|status name
  local action="$1" name="$2"
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
