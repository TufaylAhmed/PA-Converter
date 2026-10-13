<#
.SYNOPSIS
  One-click appliance setup: enable WSL2, import Ubuntu, install Docker Engine,
  sync Expedition, and start the stack.
#>
[CmdletBinding()]
param(
  [string]$InstallRoot = $env:PA_CONVERTER_HOME,
  [switch]$SkipStart,
  [switch]$AfterReboot
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

try {
  Import-Module (Join-Path $here "lib\PAConverter.psm1") -Force

  if (-not $InstallRoot) { $InstallRoot = Get-PAInstallRoot }
  $env:PA_CONVERTER_HOME = $InstallRoot
  New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null

  $transcript = Join-Path $InstallRoot "logs\transcript.txt"
  New-Item -ItemType Directory -Force -Path (Split-Path $transcript) | Out-Null
  Start-Transcript -Path $transcript -Append | Out-Null

  Write-Host ""
  Write-Host "  PA-Converter setup" -ForegroundColor Cyan
  Write-Host "  Install: $InstallRoot" -ForegroundColor DarkGray
  Write-Host "  Log:     $(Get-PALogPath)" -ForegroundColor DarkGray
  Write-Host ""

  if (-not (Test-IsAdmin)) {
    Write-PALog "Re-launching elevated..." "WARN"
    $argList = @(
      "-NoProfile", "-ExecutionPolicy", "Bypass",
      "-File", "`"$($MyInvocation.MyCommand.Path)`""
    )
    if ($SkipStart) { $argList += "-SkipStart" }
    if ($AfterReboot) { $argList += "-AfterReboot" }
    $p = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList -Wait -PassThru
    exit $p.ExitCode
  }

  Expand-PAEngine -InstallRoot $InstallRoot

  $state = Get-PAState

  if ($state.Phase -eq "init" -or $state.Phase -eq "post-reboot" -or -not $AfterReboot) {
    $needReboot = Enable-PAWindowsFeatures
    Install-PAWslKernel
    if ($needReboot -and -not $AfterReboot) {
      $state.Phase = "post-reboot"
      $state.RebootPending = $true
      Set-PAState $state
      $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $InstallRoot 'Bootstrap-PAConverter.ps1')`" -AfterReboot"
      Register-PARunOnce -Command $cmd
      Write-Host ""
      Write-Host "A one-time reboot is required to finish enabling WSL." -ForegroundColor Yellow
      Write-Host "After reboot, setup continues automatically." -ForegroundColor Yellow
      Write-Host ""
      Add-Type -AssemblyName System.Windows.Forms
      $r = [System.Windows.Forms.MessageBox]::Show(
        "WSL needs a reboot to finish enabling.`r`n`r`nReboot now? Setup will continue automatically after login.",
        "PA-Converter",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
      )
      if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
        Stop-Transcript | Out-Null
        Restart-Computer -Force
      }
      exit 0
    }
  }

  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "wsl.exe not found after enabling features. Reboot Windows, then run SETUP.bat again."
  }

  $state.Phase = "distro"
  $state.RebootPending = $false
  Set-PAState $state

  Install-PADistro -InstallRoot $InstallRoot
  Sync-PAEngineIntoWsl -InstallRoot $InstallRoot

  Write-PALog "Restarting WSL distro..."
  $distro = Get-PADistroName
  & wsl.exe -t $distro 2>$null
  Start-Sleep -Seconds 3

  $state.Phase = "provision"
  Set-PAState $state

  Write-PALog "Provisioning Docker + Expedition inside WSL (first run downloads packages/images)..."
  $code = Invoke-PAWsl -ScriptName "provision.sh"
  if ($code -ne 0) {
    throw "Provisioning failed (exit $code). See $(Get-PALogPath) and transcript $transcript"
  }

  $state.Phase = "ready"
  Set-PAState $state
  Write-PALog "Setup complete."

  if (-not $SkipStart) {
    Start-Process "https://localhost:18443/"
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(
      "PA-Converter is running.`r`n`r`nOpen: https://localhost:18443`r`nLogin: admin / paloalto",
      "PA-Converter",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
  }

  Stop-Transcript | Out-Null
  exit 0
}
catch {
  try { Stop-Transcript | Out-Null } catch {}
  $msg = $_.Exception.Message
  if (Get-Command Show-PAError -ErrorAction SilentlyContinue) {
    Show-PAError $msg
  } else {
    Write-Host "SETUP FAILED: $msg" -ForegroundColor Red
    Read-Host "Press Enter to close"
  }
  exit 1
}
