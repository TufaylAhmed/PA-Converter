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

function ConvertFrom-PAWslText {
  param([object]$Raw)
  # wsl.exe writes UTF-16LE; PowerShell often turns it into null-padded ASCII ("U b u n t u")
  if ($null -eq $Raw) { return "" }
  $s = if ($Raw -is [Array]) { ($Raw | ForEach-Object { "$_" }) -join "`n" } else { [string]$Raw }
  $s = $s -replace "`0", ""
  # Collapse "U b u n t u" style spacing between letters
  if ($s -match '(\w ){3,}\w') {
    $s = [regex]::Replace($s, '(?<=\S) (?=\S)', '')
  }
  return $s
}

function Invoke-PAWslExe {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$WslArgs)
  $prev = [Console]::OutputEncoding
  try {
    [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
    $out = & wsl.exe @WslArgs 2>&1
    $code = $LASTEXITCODE
    $text = ConvertFrom-PAWslText $out
    return [pscustomobject]@{ ExitCode = $code; Text = $text; Raw = $out }
  } finally {
    [Console]::OutputEncoding = $prev
  }
}

function Get-PAWslDistroNames {
  $names = @()
  # --utf8 is available on recent WSL; also decode UTF-16 safely
  $r = Invoke-PAWslExe -WslArgs @("-l", "-q")
  $text = $r.Text
  if (-not $text) {
    # Fallback: read bytes via cmd redirection
    $tmp = Join-Path $env:TEMP "pa-wsl-list.txt"
    cmd.exe /c "wsl -l -q > `"$tmp`" 2>nul"
    if (Test-Path $tmp) {
      $bytes = [IO.File]::ReadAllBytes($tmp)
      if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $text = [Text.Encoding]::Unicode.GetString($bytes)
      } else {
        $text = [Text.Encoding]::UTF8.GetString($bytes)
      }
      $text = ConvertFrom-PAWslText $text
    }
  }
  foreach ($line in ($text -split "(`r`n|`n|`r)")) {
    $n = $line.Trim()
    if (-not $n) { continue }
    if ($n -match '^(Windows Subsystem|Subsistema|docker-desktop)') { continue }
    $names += $n
  }
  Write-PALog ("WSL distros detected: " + ($(if ($names.Count) { $names -join ", " } else { "(none)" })))
  return $names
}

function Test-PADistroExists {
  $names = Get-PAWslDistroNames
  return ($names -contains $script:DistroName)
}

function Set-PAActiveDistro {
  param([string]$InstallRoot, [string]$Name)
  $script:DistroName = $Name
  Set-Content -Path (Join-Path $InstallRoot "distro-name.txt") -Value $Name -Encoding ascii
  Write-PALog "Active WSL distro set to '$Name'"
}

function Find-PAUsableDistro {
  param([string]$InstallRoot)
  $names = Get-PAWslDistroNames
  foreach ($candidate in @("PA-Converter", "Ubuntu-22.04", "Ubuntu-24.04", "Ubuntu", "Ubuntu-20.04")) {
    if ($names -contains $candidate) {
      Set-PAActiveDistro -InstallRoot $InstallRoot -Name $candidate
      return $candidate
    }
  }
  # Any Ubuntu* distro
  $ubuntu = $names | Where-Object { $_ -like "Ubuntu*" } | Select-Object -First 1
  if ($ubuntu) {
    Set-PAActiveDistro -InstallRoot $InstallRoot -Name $ubuntu
    return $ubuntu
  }
  return $null
}

function Get-PARootfsUrl {
  $arch = $env:PROCESSOR_ARCHITECTURE
  if ($arch -match "ARM") {
    return "https://cloud-images.ubuntu.com/wsl/releases/22.04/current/ubuntu-jammy-wsl-arm64-wsl.rootfs.tar.gz"
  }
  return "https://cloud-images.ubuntu.com/wsl/releases/22.04/current/ubuntu-jammy-wsl-amd64-wsl.rootfs.tar.gz"
}

function Test-PAGzipFile {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return $false }
  $fs = [IO.File]::OpenRead($Path)
  try {
    $b0 = $fs.ReadByte(); $b1 = $fs.ReadByte()
    return ($b0 -eq 0x1F -and $b1 -eq 0x8B)
  } finally { $fs.Close() }
}

function Save-PAWebFile {
  param([string]$Url, [string]$OutFile)
  Write-PALog "Downloading: $Url"
  Write-PALog "Saving to: $OutFile"
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $parent = Split-Path $OutFile -Parent
  New-Item -ItemType Directory -Force -Path $parent | Out-Null
  if (Test-Path $OutFile) { Remove-Item $OutFile -Force }

  try {
    Start-BitsTransfer -Source $Url -Destination $OutFile -ErrorAction Stop
  } catch {
    Write-PALog "BITS failed ($_); using curl.exe / Invoke-WebRequest..." "WARN"
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
      & curl.exe -L --fail --retry 3 -o $OutFile $Url
      if ($LASTEXITCODE -ne 0) { throw "curl download failed ($LASTEXITCODE)" }
    } else {
      Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
    }
  }

  if (-not (Test-Path $OutFile) -or ((Get-Item $OutFile).Length -lt 10MB)) {
    throw "Download failed or file too small: $OutFile"
  }
  if (-not (Test-PAGzipFile $OutFile)) {
    throw "Downloaded file is not a gzip rootfs (got HTML/error page?). Delete cache and retry: $OutFile"
  }
  Write-PALog ("Download OK ({0:N1} MB, gzip verified)" -f ((Get-Item $OutFile).Length / 1MB))
}

function Install-PADistro {
  param([string]$InstallRoot)

  # Already have something usable?
  $existing = Find-PAUsableDistro -InstallRoot $InstallRoot
  if ($existing) {
    Write-PALog "Reusing existing WSL distro '$existing'."
    return
  }

  $wslDir = Join-Path $InstallRoot "wsl-distro"
  if (Test-Path $wslDir) {
    # Clean failed previous import VHDs
    Write-PALog "Cleaning previous wsl-distro folder..."
    try { & wsl.exe --unregister PA-Converter 2>$null } catch {}
    Remove-Item $wslDir -Recurse -Force -ErrorAction SilentlyContinue
  }
  New-Item -ItemType Directory -Force -Path $wslDir | Out-Null

  $tarGz = Join-Path $InstallRoot "cache\ubuntu-jammy-wsl.rootfs.tar.gz"
  $tar = Join-Path $InstallRoot "cache\ubuntu-jammy-wsl.rootfs.tar"

  if (-not (Test-PAGzipFile $tarGz)) {
    Save-PAWebFile -Url (Get-PARootfsUrl) -OutFile $tarGz
  } else {
    Write-PALog "Using cached rootfs tar.gz."
  }

  # Some WSL builds import .tar more reliably than .tar.gz — gunzip first
  if (-not (Test-Path $tar) -or ((Get-Item $tar).Length -lt 10MB)) {
    Write-PALog "Decompressing rootfs to .tar for import..."
    if (Test-Path $tar) { Remove-Item $tar -Force }
    $in = [IO.File]::OpenRead($tarGz)
    $gzip = New-Object IO.Compression.GzipStream($in, [IO.Compression.CompressionMode]::Decompress)
    $outFs = [IO.File]::Create($tar)
    try { $gzip.CopyTo($outFs) } finally { $outFs.Close(); $gzip.Close(); $in.Close() }
    Write-PALog ("Decompressed tar size: {0:N1} MB" -f ((Get-Item $tar).Length / 1MB))
  }

  Write-PALog "Importing WSL distro 'PA-Converter' from tar..."
  $import = Invoke-PAWslExe "--import", "PA-Converter", "$wslDir", "$tar", "--version", "2"
  Write-PALog ("wsl --import exit=$($import.ExitCode) output=$($import.Text)")

  if ($import.ExitCode -ne 0) {
    Write-PALog "Import with .tar failed; trying .tar.gz directly..." "WARN"
    $import = Invoke-PAWslExe "--import", "PA-Converter", "$wslDir", "$tarGz", "--version", "2"
    Write-PALog ("wsl --import (gz) exit=$($import.ExitCode) output=$($import.Text)")
  }

  if ((Find-PAUsableDistro -InstallRoot $InstallRoot) -eq "PA-Converter") {
    return
  }

  # Microsoft Store / wsl --install fallbacks (may need reboot after)
  foreach ($distroId in @("Ubuntu-22.04", "Ubuntu", "Ubuntu-24.04")) {
    Write-PALog "Trying: wsl --install -d $distroId --no-launch"
    $inst = Invoke-PAWslExe "--install", "-d", $distroId, "--no-launch"
    Write-PALog ("install $distroId exit=$($inst.ExitCode) output=$($inst.Text)")
    Start-Sleep -Seconds 8
    $found = Find-PAUsableDistro -InstallRoot $InstallRoot
    if ($found) { return }

    # Online install variant
    $inst2 = Invoke-PAWslExe "--install", "-d", $distroId, "--no-launch", "--web-download"
    Write-PALog ("web-download $distroId exit=$($inst2.ExitCode) output=$($inst2.Text)")
    Start-Sleep -Seconds 8
    $found = Find-PAUsableDistro -InstallRoot $InstallRoot
    if ($found) { return }
  }

  $names = Get-PAWslDistroNames
  $hint = @"
Could not create a WSL Linux distro automatically.

Detected distros: $(if ($names.Count) { $names -join ', ' } else { '(none)' })
Import output: $($import.Text)

Try manually in an elevated PowerShell, then re-run SETUP.bat:

  wsl --install -d Ubuntu-22.04
  # reboot if asked, then:
  wsl -l -v

Also ensure virtualization is enabled in BIOS/UEFI.
"@
  throw $hint
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
