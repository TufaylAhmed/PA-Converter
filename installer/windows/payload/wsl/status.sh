#!/usr/bin/env bash
set -euo pipefail
INSTALL_ROOT="${PA_CONVERTER_ROOT:-/opt/pa-converter}"
export PA_CONVERTER_ROOT="$INSTALL_ROOT"
bash "$INSTALL_ROOT/native/status.sh"
