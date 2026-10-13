$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here "lib\PAConverter.psm1") -Force
$root = Get-PAInstallRoot
$env:PA_CONVERTER_HOME = $root

$state = Get-PAState
if ($state.Phase -ne "ready") {
  Write-Host "First-time setup is required…" -ForegroundColor Yellow
  & (Join-Path $here "Bootstrap-PAConverter.ps1")
  exit $LASTEXITCODE
}

if (-not (Test-PADistroExists)) {
  Write-Host "WSL distro missing — running setup…" -ForegroundColor Yellow
  & (Join-Path $here "Bootstrap-PAConverter.ps1")
  exit $LASTEXITCODE
}

Write-Host "Starting PA-Converter…" -ForegroundColor Cyan
$code = Invoke-PAWsl -ScriptName "start.sh"
if ($code -ne 0) { exit $code }
Start-Process "https://localhost:18443"
Write-Host "Opened https://localhost:18443  (admin / paloalto)"
Start-Sleep -Seconds 3
