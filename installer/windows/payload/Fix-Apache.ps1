<#
.SYNOPSIS
  Repair Apache inside the PA-Converter / Ubuntu WSL distro and open the UI.
  Avoids fragile nested quoting (writes a .sh then runs it via wsl).
#>
[CmdletBinding()]
param(
  [string]$Distro = ""
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$mod = Join-Path $here "lib\PAConverter.psm1"
if (Test-Path $mod) {
  Import-Module $mod -Force
  if (-not $Distro) { $Distro = Get-PADistroName }
} elseif (-not $Distro) {
  $Distro = "Ubuntu-20.04"
}

$shDir = Join-Path $env:ProgramData "PA-Converter\logs"
New-Item -ItemType Directory -Force -Path $shDir | Out-Null
$shWin = Join-Path $shDir "fix-apache-inline.sh"

$bash = @'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export EXPEDITION_PORT=18443
export EXPEDITION_HTTP_PORT=18080

echo "=== FIX SITE / PORTS ==="
SITE=/etc/apache2/sites-available/pa-converter.conf
PORTS=/etc/apache2/ports.conf
if [ -f "$SITE" ]; then
  sed -i '/^[[:space:]]*Listen[[:space:]]/d' "$SITE"
  echo "vhost Listen lines removed (if any)"
fi
touch "$PORTS"
grep -qE '^Listen 18080([[:space:]]|$)' "$PORTS" || echo 'Listen 18080' >> "$PORTS"
grep -qE '^Listen 18443([[:space:]]|$)' "$PORTS" || echo 'Listen 18443' >> "$PORTS"
grep -n '^Listen' "$PORTS" || true

a2enmod ssl rewrite headers >/dev/null 2>&1 || true
a2dissite 000-default default-ssl >/dev/null 2>&1 || true
a2ensite pa-converter >/dev/null 2>&1 || true

if [ ! -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]; then
  apt-get install -y --no-install-recommends ssl-cert
  make-ssl-cert generate-default-snakeoil || true
fi

mkdir -p /var/run/apache2 /var/lock/apache2 /var/log/apache2

echo "=== CONFIGTEST ==="
apache2ctl configtest

echo "=== RESTART ==="
apache2ctl -k stop 2>/dev/null || true
pkill -x apache2 2>/dev/null || true
sleep 1
apache2ctl -k start
sleep 1

echo "=== RESULT ==="
pgrep -a apache2 || { echo "FAIL: apache2 not running"; tail -n 40 /var/log/apache2/error.log; exit 1; }
ss -ltn | grep -E ':18443|:18080' || { echo "FAIL: ports not listening"; tail -n 40 /var/log/apache2/error.log; exit 1; }
echo "OK - open https://localhost:18443 from Windows"
'@

# Write Unix LF script (no BOM) for bash
$utf8 = New-Object System.Text.UTF8Encoding $false
[IO.File]::WriteAllText($shWin, ($bash -replace "`r`n", "`n"), $utf8)

$shWsl = "/mnt/c/ProgramData/PA-Converter/logs/fix-apache-inline.sh"
Write-Host "Running repair in WSL distro '$Distro' ..." -ForegroundColor Cyan
& wsl.exe -d $Distro -u root -- bash "$shWsl"
$code = $LASTEXITCODE
if ($code -ne 0) {
  Write-Host "Repair failed (exit $code)." -ForegroundColor Red
  exit $code
}

Start-Process "https://localhost:18443/"
Write-Host "Opened https://localhost:18443  (admin / paloalto)" -ForegroundColor Green
exit 0
