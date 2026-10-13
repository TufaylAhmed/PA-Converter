# Shared helpers for PA-Converter Windows appliance installer
$script:DistroName = "PA-Converter"
$script:DefaultInstallRoot = Join-Path $env:ProgramData "PA-Converter"

function Get-PAInstallRoot {
  if ($env:PA_CONVERTER_HOME -and (Test-Path $env:PA_CONVERTER_HOME)) {
    return $env:PA_CONVERTER_HOME
  }
  $reg = Get-ItemProperty -Path "HKLM:\Software\PA-Converter" -Name "InstallDir" -ErrorAction SilentlyContinue
  if ($reg -and $reg.InstallDir -and (Test-Path $reg.InstallDir)) {
    return $reg.InstallDir
  }
  return $script:DefaultInstallRoot
}

function Write-PALog {
  param([string]$Message, [string]$Level = "INFO")
  $root = Get-PAInstallRoot
  $logDir = Join-Path $root "logs"
  New-Item -ItemType Directory -Force -Path $logDir | Out-Null
  $line = "{0:u} [{1}] {2}" -f (Get-Date), $Level, $Message
  Add-Content -Path (Join-Path $logDir "setup.log") -Value $line
  if ($Level -eq "ERROR") { Write-Host $Message -ForegroundColor Red }
  elseif ($Level -eq "WARN") { Write-Host $Message -ForegroundColor Yellow }
  else { Write-Host $Message }
}

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PAState {
  $path = Join-Path (Get-PAInstallRoot) "state.json"
  if (-not (Test-Path $path)) {
    return [pscustomobject]@{ Phase = "init"; RebootPending = $false }
  }
  return Get-Content $path -Raw | ConvertFrom-Json
}

function Set-PAState {
  param($State)
  $root = Get-PAInstallRoot
  New-Item -ItemType Directory -Force -Path $root | Out-Null
  ($State | ConvertTo-Json -Depth 5) | Set-Content (Join-Path $root "state.json") -Encoding utf8
}

function Enable-PAWindowsFeatures {
  Write-PALog "Enabling WSL / Virtual Machine Platform features…"
  $reboot = $false
  foreach ($name in @(
      "Microsoft-Windows-Subsystem-Linux",
      "VirtualMachinePlatform"
    )) {
    $f = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction SilentlyContinue
    if (-not $f) { continue }
    if ($f.State -ne "Enabled") {
      Write-PALog "Enabling feature $name"
      $r = Enable-WindowsOptionalFeature -Online -FeatureName $name -All -NoRestart
      if ($r.RestartNeeded) { $reboot = $true }
    }
  }
  return $reboot
}

function Install-PAWslKernel {
  # Best-effort WSL update (needs network)
  try {
    Write-PALog "Updating WSL kernel (wsl --update)…"
    & wsl.exe --update | Out-Host
  } catch {
    Write-PALog "wsl --update skipped: $_" "WARN"
  }
  try { & wsl.exe --set-default-version 2 | Out-Null } catch {}
}

function Test-PADistroExists {
  $list = & wsl.exe -l -q 2>$null
  if (-not $list) { return $false }
  foreach ($line in $list) {
    $n = ($line -replace "`0", "").Trim()
    if ($n -eq $script:DistroName) { return $true }
  }
  return $false
}

function Install-PADistro {
  param([string]$InstallRoot)

  if (Test-PADistroExists) {
    Write-PALog "WSL distro '$script:DistroName' already exists."
    return
  }

  $wslDir = Join-Path $InstallRoot "wsl-distro"
  New-Item -ItemType Directory -Force -Path $wslDir | Out-Null
  $tar = Join-Path $InstallRoot "cache\ubuntu-base.tar.gz"
  New-Item -ItemType Directory -Force -Path (Split-Path $tar) | Out-Null

  if (-not (Test-Path $tar)) {
    Write-PALog "Downloading Ubuntu 22.04 WSL rootfs (one-time)…"
    # Canonical cloud image rootfs used widely for wsl --import
    $url = "https://cloud-images.ubuntu.com/wsl/jammy/current/ubuntu-jammy-wsl-amd64-wsl.rootfs.tar.gz"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $tar -UseBasicParsing
  }

  Write-PALog "Importing WSL distro '$script:DistroName'…"
  & wsl.exe --import $script:DistroName $wslDir $tar --version 2
  if ($LASTEXITCODE -ne 0) {
    throw "wsl --import failed with exit $LASTEXITCODE"
  }
}

function Sync-PAEngineIntoWsl {
  param([string]$InstallRoot)
  $engine = Join-Path $InstallRoot "engine"
  if (-not (Test-Path $engine)) {
    throw "Engine payload missing at $engine. Reinstall the MSI."
  }

  Write-PALog "Syncing Expedition engine into WSL /opt/pa-converter…"
  # Create target and copy via tar over stdin for reliable permissions/symlinks
  & wsl.exe -d $script:DistroName -u root -- bash -lc "mkdir -p /opt/pa-converter && rm -rf /opt/pa-converter/*"
  $winPath = ($engine -replace '\\', '/')
  # Use /mnt/c style path
  if ($engine -match '^[A-Za-z]:\\') {
    $drive = $engine.Substring(0, 1).ToLower()
    $rest = $engine.Substring(2) -replace '\\', '/'
    $mnt = "/mnt/$drive/$rest"
  } else {
    throw "Unexpected install path: $engine"
  }

  & wsl.exe -d $script:DistroName -u root -- bash -lc "cp -a '$mnt'/. /opt/pa-converter/ && chmod +x /opt/pa-converter/wsl/*.sh && mkdir -p /data /home/userSpace"

  # Enable systemd when available (WSL2 recent)
  & wsl.exe -d $script:DistroName -u root -- bash -lc @'
set -e
mkdir -p /etc
cat > /etc/wsl.conf <<EOF
[boot]
systemd=true

[user]
default=root
EOF
'@
}

function Invoke-PAWsl {
  param([Parameter(Mandatory)][string]$ScriptName)
  $envLine = "export PA_CONVERTER_ROOT=/opt/pa-converter EXPEDITION_PORT=18443 EXPEDITION_HTTP_PORT=18080"
  & wsl.exe -d $script:DistroName -u root -- bash -lc "$envLine; bash /opt/pa-converter/wsl/$ScriptName"
  return $LASTEXITCODE
}

function Register-PARunOnce {
  param([string]$Command)
  $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
  Set-ItemProperty -Path $key -Name "PAConverterSetup" -Value $Command
  Write-PALog "Registered RunOnce to continue setup after reboot."
}

Export-ModuleMember -Function *
