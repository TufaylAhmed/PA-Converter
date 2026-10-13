<#
.SYNOPSIS
  One-click appliance setup: enable WSL2, import Ubuntu, install Docker Engine,
  sync Expedition, and start the stack. No Docker Desktop / Node / GitHub PAT.
#>
[CmdletBinding()]
param(
  [string]$InstallRoot = $env:PA_CONVERTER_HOME,
  [switch]$SkipStart,
  [switch]$AfterReboot
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here "lib\PAConverter.psm1") -Force

if (-not $InstallRoot) { $InstallRoot = Get-PAInstallRoot }
$env:PA_CONVERTER_HOME = $InstallRoot
New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null

Write-Host ""
Write-Host "  PA-Converter setup" -ForegroundColor Cyan
Write-Host "  Install: $InstallRoot" -ForegroundColor DarkGray
Write-Host ""

if (-not (Test-IsAdmin)) {
  Write-PALog "Re-launching elevated…" "WARN"
  $args = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
  if ($SkipStart) { $args += " -SkipStart" }
  if ($AfterReboot) { $args += " -AfterReboot" }
  Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $args -Wait
  exit $LASTEXITCODE
}

# Expand engine.zip if present and engine\ missing
$zip = Join-Path $InstallRoot "engine.zip"
$engine = Join-Path $InstallRoot "engine"
if ((Test-Path $zip) -and -not (Test-Path (Join-Path $engine "docker\docker-compose.yml"))) {
  Write-PALog "Extracting engine.zip…"
  if (Test-Path $engine) { Remove-Item $engine -Recurse -Force }
  Expand-Archive -Path $zip -DestinationPath $engine -Force
}

if (-not (Test-Path (Join-Path $engine "docker\docker-compose.yml"))) {
  throw "Missing engine payload. Reinstall PA-Converter.msi."
}

$state = Get-PAState

# --- Phase: Windows features ---
if ($state.Phase -eq "init" -or -not $AfterReboot) {
  $needReboot = Enable-PAWindowsFeatures
  Install-PAWslKernel
  if ($needReboot) {
    $state.Phase = "post-reboot"
    $state.RebootPending = $true
    Set-PAState $state
    $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $InstallRoot 'Bootstrap-PAConverter.ps1')`" -AfterReboot"
    Register-PARunOnce -Command $cmd
    Write-Host ""
    Write-Host "A one-time reboot is required to finish enabling WSL." -ForegroundColor Yellow
    Write-Host "After reboot, setup continues automatically, then Start Menu → Start PA-Converter." -ForegroundColor Yellow
    Write-Host ""
    $ans = Read-Host "Reboot now? [Y/n]"
    if ($ans -notmatch '^[nN]') {
      Restart-Computer -Force
    }
    exit 0
  }
}

$state.Phase = "distro"
$state.RebootPending = $false
Set-PAState $state

# Ensure wsl.exe exists
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
  throw "wsl.exe not found. Install 'Windows Subsystem for Linux' from Optional Features, reboot, and run Configure again."
}

Install-PADistro -InstallRoot $InstallRoot
Sync-PAEngineIntoWsl -InstallRoot $InstallRoot

# Restart distro so systemd/wsl.conf applies
Write-PALog "Restarting WSL distro…"
& wsl.exe -t PA-Converter 2>$null
Start-Sleep -Seconds 2

$state.Phase = "provision"
Set-PAState $state

Write-PALog "Provisioning Docker + Expedition inside WSL (first run downloads packages/images)…"
$code = Invoke-PAWsl -ScriptName "provision.sh"
if ($code -ne 0) {
  throw "Provisioning failed (exit $code). See logs under $InstallRoot\logs and WSL /var/log."
}

$state.Phase = "ready"
Set-PAState $state
Write-PALog "Setup complete."

if (-not $SkipStart) {
  Start-Process "https://localhost:18443"
  Write-Host ""
  Write-Host "UI: https://localhost:18443" -ForegroundColor Green
  Write-Host "Login: admin / paloalto" -ForegroundColor Green
  Write-Host ""
}

Read-Host "Press Enter to close"
