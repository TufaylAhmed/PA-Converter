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

function Get-PALogPath {
  $logDir = Join-Path (Get-PAInstallRoot) "logs"
  New-Item -ItemType Directory -Force -Path $logDir | Out-Null
  return Join-Path $logDir "setup.log"
}

function Write-PALog {
  param([string]$Message, [string]$Level = "INFO")
  $line = "{0:u} [{1}] {2}" -f (Get-Date), $Level, $Message
  Add-Content -Path (Get-PALogPath) -Value $line -Encoding utf8
  switch ($Level) {
    "ERROR" { Write-Host $Message -ForegroundColor Red }
    "WARN"  { Write-Host $Message -ForegroundColor Yellow }
    default { Write-Host $Message }
  }
}

function Show-PAError {
  param([string]$Message)
  Write-PALog $Message "ERROR"
  $log = Get-PALogPath
  try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    [System.Windows.Forms.MessageBox]::Show(
      "$Message`r`n`r`nFull log:`r`n$log",
      "PA-Converter setup failed",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
  } catch {
    Write-Host "Full log: $log" -ForegroundColor Yellow
  }
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
  Write-PALog "Enabling WSL / Virtual Machine Platform features..."
  $reboot = $false
  foreach ($name in @(
      "Microsoft-Windows-Subsystem-Linux",
      "VirtualMachinePlatform"
    )) {
    try {
      $f = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop
      if ($f.State -ne "Enabled") {
        Write-PALog "Enabling feature $name"
        $r = Enable-WindowsOptionalFeature -Online -FeatureName $name -All -NoRestart
        if ($r.RestartNeeded) { $reboot = $true }
      } else {
        Write-PALog "Feature already enabled: $name"
      }
    } catch {
      Write-PALog "Could not toggle feature $name : $_" "WARN"
      # Fallback DISM
      $out = & dism.exe /online /enable-feature /featurename:$name /all /norestart 2>&1 | Out-String
      Write-PALog $out
      if ($out -match "restart|reboot") { $reboot = $true }
    }
  }
  return $reboot
}

function Install-PAWslKernel {
  try {
    Write-PALog "Updating WSL (wsl --update)..."
    & wsl.exe --update 2>&1 | ForEach-Object { Write-PALog "$_" }
  } catch {
    Write-PALog "wsl --update skipped: $_" "WARN"
  }
  try { & wsl.exe --set-default-version 2 2>&1 | Out-Null } catch {}
}

function Get-PAWslDistroNames {
  $names = @()
  $raw = & wsl.exe -l -q 2>$null
  if (-not $raw) { return $names }
  foreach ($line in @($raw)) {
    $n = (($line -replace "`0", "") -replace "[^\x20-\x7E]", "").Trim()
    if ($n) { $names += $n }
  }
  return $names
}

function Test-PADistroExists {
  return (Get-PAWslDistroNames) -contains $script:DistroName
}

function Get-PARootfsUrl {
  $arch = $env:PROCESSOR_ARCHITECTURE
  if ($arch -match "ARM") {
    return "https://cloud-images.ubuntu.com/wsl/releases/22.04/current/ubuntu-jammy-wsl-arm64-wsl.rootfs.tar.gz"
  }
  return "https://cloud-images.ubuntu.com/wsl/releases/22.04/current/ubuntu-jammy-wsl-amd64-wsl.rootfs.tar.gz"
}

function Save-PAWebFile {
  param([string]$Url, [string]$OutFile)
  Write-PALog "Downloading: $Url"
  Write-PALog "Saving to: $OutFile"
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $parent = Split-Path $OutFile -Parent
  New-Item -ItemType Directory -Force -Path $parent | Out-Null
  if (Test-Path $OutFile) { Remove-Item $OutFile -Force }

  # Prefer BITS for large files; fall back to Invoke-WebRequest
  try {
    Start-BitsTransfer -Source $Url -Destination $OutFile -ErrorAction Stop
  } catch {
    Write-PALog "BITS failed ($_); using Invoke-WebRequest..." "WARN"
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
  }

  if (-not (Test-Path $OutFile) -or ((Get-Item $OutFile).Length -lt 1MB)) {
    throw "Download failed or file too small: $OutFile"
  }
  Write-PALog ("Download OK ({0:N1} MB)" -f ((Get-Item $OutFile).Length / 1MB))
}

function Install-PADistro {
  param([string]$InstallRoot)

  if (Test-PADistroExists) {
    Write-PALog "WSL distro '$script:DistroName' already exists."
    return
  }

  # Prefer Microsoft's distro install when available (more reliable than rootfs import)
  $existing = Get-PAWslDistroNames
  Write-PALog ("Existing WSL distros: " + ($(if ($existing) { $existing -join ", " } else { "(none)" })))

  $wslDir = Join-Path $InstallRoot "wsl-distro"
  New-Item -ItemType Directory -Force -Path $wslDir | Out-Null
  $tar = Join-Path $InstallRoot "cache\ubuntu-jammy-wsl.rootfs.tar.gz"

  if (-not (Test-Path $tar) -or ((Get-Item $tar).Length -lt 1MB)) {
    Save-PAWebFile -Url (Get-PARootfsUrl) -OutFile $tar
  } else {
    Write-PALog "Using cached rootfs tar."
  }

  Write-PALog "Importing WSL distro '$script:DistroName'..."
  $out = & wsl.exe --import $script:DistroName $wslDir $tar --version 2 2>&1 | Out-String
  Write-PALog $out
  if ($LASTEXITCODE -ne 0) {
    Write-PALog "wsl --import failed; trying Ubuntu-22.04 from Microsoft..." "WARN"
    & wsl.exe --install -d Ubuntu-22.04 --no-launch 2>&1 | ForEach-Object { Write-PALog "$_" }
    Start-Sleep -Seconds 5
    # If Ubuntu-22.04 exists, export/import as PA-Converter OR just retarget DistroName
    $names = Get-PAWslDistroNames
    if ($names -contains "Ubuntu-22.04") {
      Write-PALog "Using distro Ubuntu-22.04 as runtime."
      $script:DistroName = "Ubuntu-22.04"
      Set-Content -Path (Join-Path $InstallRoot "distro-name.txt") -Value $script:DistroName -Encoding ascii
      return
    }
    throw "wsl --import failed and Ubuntu-22.04 install did not produce a distro. Exit=$LASTEXITCODE Output=$out"
  }
  Set-Content -Path (Join-Path $InstallRoot "distro-name.txt") -Value $script:DistroName -Encoding ascii
}

function Get-PADistroName {
  $root = Get-PAInstallRoot
  $f = Join-Path $root "distro-name.txt"
  if (Test-Path $f) {
    $n = (Get-Content $f -Raw).Trim()
    if ($n) { return $n }
  }
  return $script:DistroName
}

function Sync-PAEngineIntoWsl {
  param([string]$InstallRoot)
  $engine = Join-Path $InstallRoot "engine"
  if (-not (Test-Path (Join-Path $engine "docker\docker-compose.yml"))) {
    throw "Engine payload missing at $engine (docker-compose.yml not found)."
  }

  $distro = Get-PADistroName
  Write-PALog "Syncing Expedition engine into WSL distro '$distro' (/opt/pa-converter)..."

  if ($engine -notmatch '^[A-Za-z]:\\') {
    throw "Unexpected install path: $engine"
  }
  $drive = $engine.Substring(0, 1).ToLower()
  $rest = $engine.Substring(2) -replace '\\', '/'
  $mnt = "/mnt/$drive/$rest"

  & wsl.exe -d $distro -u root -- bash -lc "mkdir -p /opt/pa-converter /data /home/userSpace && rm -rf /opt/pa-converter/* && cp -a '$mnt'/. /opt/pa-converter/ && chmod +x /opt/pa-converter/wsl/*.sh"
  if ($LASTEXITCODE -ne 0) { throw "Failed to copy engine into WSL (exit $LASTEXITCODE). Mount path was $mnt" }

  & wsl.exe -d $distro -u root -- bash -lc "printf '%s\n' '[boot]' 'systemd=true' '' '[user]' 'default=root' > /etc/wsl.conf"
}

function Invoke-PAWsl {
  param([Parameter(Mandatory)][string]$ScriptName)
  $distro = Get-PADistroName
  $envLine = "export PA_CONVERTER_ROOT=/opt/pa-converter EXPEDITION_PORT=18443 EXPEDITION_HTTP_PORT=18080"
  Write-PALog "WSL[$distro] running $ScriptName ..."
  & wsl.exe -d $distro -u root -- bash -lc "$envLine; bash /opt/pa-converter/wsl/$ScriptName"
  return $LASTEXITCODE
}

function Register-PARunOnce {
  param([string]$Command)
  $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
  New-Item -Path $key -Force | Out-Null
  Set-ItemProperty -Path $key -Name "PAConverterSetup" -Value $Command
  Write-PALog "Registered RunOnce to continue setup after reboot."
}

function Expand-PAEngine {
  param([string]$InstallRoot)
  $zip = Join-Path $InstallRoot "engine.zip"
  $engine = Join-Path $InstallRoot "engine"
  $compose = Join-Path $engine "docker\docker-compose.yml"
  if (Test-Path $compose) {
    Write-PALog "Engine already extracted."
    return
  }
  if (-not (Test-Path $zip)) {
    throw "engine.zip missing at $zip"
  }
  Write-PALog "Extracting engine.zip (this can take a few minutes)..."
  if (Test-Path $engine) { Remove-Item $engine -Recurse -Force }
  New-Item -ItemType Directory -Force -Path $engine | Out-Null

  # Prefer tar.exe (Windows 10+) — handles large trees better than Expand-Archive
  if (Get-Command tar.exe -ErrorAction SilentlyContinue) {
    & tar.exe -xf $zip -C $engine
    if ($LASTEXITCODE -ne 0) { throw "tar extract failed ($LASTEXITCODE)" }
  } else {
    Expand-Archive -Path $zip -DestinationPath $engine -Force
  }

  if (-not (Test-Path $compose)) {
    # Sometimes zip has a single top-level folder
    $sub = Get-ChildItem $engine -Directory | Select-Object -First 1
    if ($sub -and (Test-Path (Join-Path $sub.FullName "docker\docker-compose.yml"))) {
      Write-PALog "Flattening nested engine folder $($sub.Name)"
      Get-ChildItem $sub.FullName | Move-Item -Destination $engine -Force
      Remove-Item $sub.FullName -Recurse -Force
    }
  }
  if (-not (Test-Path $compose)) {
    throw "After extract, docker-compose.yml still missing under $engine"
  }
  Write-PALog "Engine extract OK."
}

Export-ModuleMember -Function *
