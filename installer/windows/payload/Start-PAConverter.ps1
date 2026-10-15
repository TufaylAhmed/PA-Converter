[CmdletBinding()]
param(
  # Logon-task mode: no browser, no setup UI, and stay running to keep WSL alive.
  [switch]$Background
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here "lib\PAConverter.psm1") -Force
$root = Get-PAInstallRoot
$env:PA_CONVERTER_HOME = $root

$state = Get-PAState
if ($state.Phase -ne "ready" -or -not (Test-PADistroExists)) {
  if ($Background) { exit 0 }
  Write-Host "First-time setup is required..." -ForegroundColor Yellow
  & (Join-Path $here "Bootstrap-PAConverter.ps1")
  exit $LASTEXITCODE
}

Write-Host "Starting PA-Converter..." -ForegroundColor Cyan
$code = Invoke-PAWsl -ScriptName "start.sh"
if ($code -ne 0) { exit $code }

if ($Background) {
  if (Get-PAKeepAliveProcess) { exit 0 }
  & wsl.exe -d (Get-PADistroName) -u root -e sh -c "exec sleep infinity" pa-converter-keepalive
  exit 0
}

Start-PAKeepAlive
Start-Process "https://localhost:18443"
Write-Host "Opened https://localhost:18443  (admin / paloalto)"
Start-Sleep -Seconds 3
