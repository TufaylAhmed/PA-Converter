<#
.SYNOPSIS
  One-click appliance setup: enable WSL2, import Ubuntu, install native stack
  (Apache/PHP/MariaDB/RabbitMQ/Spark — no Docker), and start the stack.
#>
[CmdletBinding()]
param(
  [string]$InstallRoot = $env:PA_CONVERTER_HOME,
  [switch]$SkipStart,
  [switch]$AfterReboot
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# Breadcrumb before Import-Module (PS 5.1 can die on UTF-8-no-BOM Unicode with no setup.log)
try {
  $bootLogDir = Join-Path $env:ProgramData "PA-Converter\logs"
  New-Item -ItemType Directory -Force -Path $bootLogDir | Out-Null
  $bootLog = Join-Path $bootLogDir "setup-boot.log"
  Add-Content -Path $bootLog -Value ("{0:u} boot start here={1} ps={2}" -f (Get-Date), $here, $PSVersionTable.PSVersion) -Encoding utf8
} catch {}

try {
  Import-Module (Join-Path $here "lib\PAConverter.psm1") -Force
  try { Add-Content -Path $bootLog -Value ("{0:u} module imported OK" -f (Get-Date)) -Encoding utf8 } catch {}

  # Portable ZIP: scripts sit next to engine.zip; runtime home is ProgramData.
  function Get-PAFullPath([string]$p) {
    return ([IO.Path]::GetFullPath($p)).TrimEnd('\', '/').ToLowerInvariant()
  }
  function Copy-PAIfDifferent([string]$Src, [string]$Dst) {
    if (-not (Test-Path $Src)) { return }
    $dstDir = Split-Path $Dst -Parent
    if ($dstDir) { New-Item -ItemType Directory -Force -Path $dstDir | Out-Null }
    if ((Get-PAFullPath $Src) -eq (Get-PAFullPath $Dst)) { return } # never copy onto itself
    Copy-Item -LiteralPath $Src -Destination $Dst -Force
  }

  $programDataRoot = Join-Path $env:ProgramData "PA-Converter"
  $localEngineZip = Join-Path $here "engine.zip"
  $hereKey = Get-PAFullPath $here
  $pdKey = Get-PAFullPath $programDataRoot

  if (-not $InstallRoot) {
    if (Test-Path $localEngineZip) {
      if ($hereKey -ne $pdKey) {
        Write-Host "Staging installer files to $programDataRoot ..."
        New-Item -ItemType Directory -Force -Path $programDataRoot | Out-Null
        New-Item -ItemType Directory -Force -Path (Join-Path $programDataRoot "lib") | Out-Null
        New-Item -ItemType Directory -Force -Path (Join-Path $programDataRoot "logs") | Out-Null

        Copy-PAIfDifferent $localEngineZip (Join-Path $programDataRoot "engine.zip")
        foreach ($name in @(
            "Bootstrap-PAConverter.ps1", "SETUP.bat", "Install.cmd",
            "Start-PAConverter.ps1", "Stop-PAConverter.ps1", "Status-PAConverter.ps1",
            "Start-PAConverter.cmd", "Stop-PAConverter.cmd", "Status-PAConverter.cmd",
            "Configure-PAConverter.cmd", "README.txt", "ENABLE-VIRTUALIZATION.txt"
          )) {
          Copy-PAIfDifferent (Join-Path $here $name) (Join-Path $programDataRoot $name)
        }
        Copy-PAIfDifferent (Join-Path $here "lib\PAConverter.psm1") (Join-Path $programDataRoot "lib\PAConverter.psm1")

        try {
          New-Item -Path "HKLM:\Software\PA-Converter" -Force | Out-Null
          Set-ItemProperty -Path "HKLM:\Software\PA-Converter" -Name "InstallDir" -Value $programDataRoot
        } catch {}

        # Re-launch from ProgramData so paths stay consistent after elevation
        $argList = @(
          "-NoProfile", "-ExecutionPolicy", "Bypass",
          "-File", "`"$(Join-Path $programDataRoot 'Bootstrap-PAConverter.ps1')`""
        )
        if ($SkipStart) { $argList += "-SkipStart" }
        if ($AfterReboot) { $argList += "-AfterReboot" }
        if (-not (Test-IsAdmin)) {
          $p = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList -Wait -PassThru
          exit $p.ExitCode
        }
        $p = Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Wait -PassThru -WorkingDirectory $programDataRoot
        exit $p.ExitCode
      }
      # Already running from ProgramData — continue in place
      $InstallRoot = $programDataRoot
    } else {
      $InstallRoot = Get-PAInstallRoot
    }
  }

  $env:PA_CONVERTER_HOME = $InstallRoot
  New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null

  # Re-import module from InstallRoot (after staging)
  $modPath = Join-Path $InstallRoot "lib\PAConverter.psm1"
  if (Test-Path $modPath) { Import-Module $modPath -Force }

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
      "-File", "`"$(Join-Path $InstallRoot 'Bootstrap-PAConverter.ps1')`""
    )
    if ($SkipStart) { $argList += "-SkipStart" }
    if ($AfterReboot) { $argList += "-AfterReboot" }
    $p = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList -Wait -PassThru
    exit $p.ExitCode
  }

  $engineZip = Join-Path $InstallRoot "engine.zip"
  if (-not (Test-Path $engineZip)) {
    throw "engine.zip missing at $engineZip`r`nExtract the portable ZIP fully, then run SETUP.bat from the extracted folder (not from inside the .zip)."
  }

  # Prevent overlapping SETUP runs (they terminate WSL / corrupt engine copy)
  $lockPath = Join-Path $InstallRoot "logs\setup.lock"
  New-Item -ItemType Directory -Force -Path (Split-Path $lockPath) | Out-Null
  try {
    $script:PASetupLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  } catch {
    throw "Another PA-Converter setup is already running. Wait for it to finish (or reboot), then retry SETUP.bat."
  }

  Expand-PAEngine -InstallRoot $InstallRoot

  # Tell the user about BIOS virtualization BEFORE long downloads
  if (-not $AfterReboot) {
    Show-PAPrerequisitesDialog
  }

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
      Add-Type -AssemblyName System.Windows.Forms
      $r = [System.Windows.Forms.MessageBox]::Show(
        "Windows needs a reboot to finish enabling WSL / Virtual Machine Platform.`r`n`r`n" +
        "AFTER reboot, if setup fails, enable CPU Virtualization in BIOS (VT-x / AMD-V / SVM),`r`n" +
        "or Nested Virtualization if this Windows is a VM. See ENABLE-VIRTUALIZATION.txt.`r`n`r`n" +
        "Reboot now? Setup will continue automatically after login.",
        "PA-Converter - reboot required",
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

  # Hard stop with popup + notepad help + Microsoft docs if BIOS virt still off
  Assert-PAVirtualizationReady

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

  Write-PALog "Provisioning native Expedition inside WSL (apt packages + Spark; no Docker)..."
  Write-Host ""
  Write-Host "  Installing native stack in WSL (live progress below)." -ForegroundColor Cyan
  Write-Host "  First run often takes 10-20 minutes (apt + Spark download)." -ForegroundColor DarkGray
  Write-Host ""
  $code = Invoke-PAWsl -ScriptName "provision.sh" -StreamProgress
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
  try { if ($script:PASetupLock) { $script:PASetupLock.Close() } } catch {}
  exit 0
}
catch {
  try { Stop-Transcript | Out-Null } catch {}
  try { if ($script:PASetupLock) { $script:PASetupLock.Close() } } catch {}
  $msg = $_.Exception.Message
  try {
    $bootLogDir = Join-Path $env:ProgramData "PA-Converter\logs"
    New-Item -ItemType Directory -Force -Path $bootLogDir | Out-Null
    Add-Content -Path (Join-Path $bootLogDir "setup-boot.log") -Value ("{0:u} SETUP FAILED: {1}" -f (Get-Date), $msg) -Encoding utf8
    Add-Content -Path (Join-Path $bootLogDir "setup.log") -Value ("{0:u} [ERROR] {1}" -f (Get-Date), $msg) -Encoding utf8
  } catch {}
  if (Get-Command Show-PAError -ErrorAction SilentlyContinue) {
    Show-PAError $msg
  } else {
    Write-Host "SETUP FAILED: $msg" -ForegroundColor Red
    Write-Host "Log: $env:ProgramData\PA-Converter\logs\setup-boot.log" -ForegroundColor DarkGray
    try {
      Add-Type -AssemblyName System.Windows.Forms
      [System.Windows.Forms.MessageBox]::Show($msg, "PA-Converter setup failed") | Out-Null
    } catch {
      Read-Host "Press Enter to close"
    }
  }
  exit 1
}
