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
  # Normalize UTF-16 junk from wsl.exe ("W S L 2" / null pads) into readable text
  if ($null -eq $Message) { $Message = "" }
  $Message = [string]$Message
  $Message = $Message -replace "`0", ""
  if ($Message -match '(\w ){3,}\w') {
    $Message = [regex]::Replace($Message, '(?<=\S) (?=\S)', '')
  }
  $Message = $Message.Trim()
  if (-not $Message) { return }
  $line = "{0:u} [{1}] {2}" -f (Get-Date), $Level, $Message
  Add-Content -Path (Get-PALogPath) -Value $line -Encoding utf8
  switch ($Level) {
    "ERROR" { Write-Host $Message -ForegroundColor Red }
    "WARN"  { Write-Host $Message -ForegroundColor Yellow }
    default { Write-Host $Message }
  }
}

function Test-PAVirtualizationReady {
  <#
    Returns @{ Ok=bool; Detail=string }
    WSL2 requires a running hypervisor (BIOS virt + VirtualMachinePlatform).
  #>
  $details = New-Object System.Collections.Generic.List[string]

  try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $details.Add("HypervisorPresent=$($cs.HypervisorPresent)")
    if (-not $cs.HypervisorPresent) {
      return @{
        Ok = $false
        Detail = "Windows does not see a hypervisor. CPU virtualization is OFF in firmware (BIOS/UEFI), or you are inside a VM without nested virtualization.`n`n" +
                 "Fix:`n" +
                 "1) Reboot into BIOS/UEFI and enable: Virtualization / SVM / VT-x / Hyper-V`n" +
                 "2) If Windows is inside Parallels/VMware/Hyper-V: enable Nested Virtualization for this VM`n" +
                 "3) In elevated PowerShell run:  bcdedit /set hypervisorlaunchtype auto`n" +
                 "4) Reboot Windows, then run SETUP.bat again`n`n" +
                 "Docs: https://aka.ms/enablevirtualization`n`n" +
                 ($details -join "; ")
      }
    }
  } catch {
    $details.Add("Win32_ComputerSystem check failed: $_")
  }

  try {
    $feat = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -ErrorAction SilentlyContinue
    if ($feat -and $feat.State -ne "Enabled") {
      return @{
        Ok = $false
        Detail = "Windows feature 'VirtualMachinePlatform' is not enabled (state=$($feat.State)). Re-run SETUP.bat as Administrator, reboot when asked, then retry."
      }
    }
    if ($feat) { $details.Add("VirtualMachinePlatform=$($feat.State)") }
  } catch {
    $details.Add("Feature check failed: $_")
  }

  # Probe WSL status (decode UTF-16)
  $prev = [Console]::OutputEncoding
  try {
    [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
    $st = & wsl.exe --status 2>&1 | Out-String
  } finally {
    [Console]::OutputEncoding = $prev
  }
  $st = ($st -replace "`0", "")
  if ($st -match '(\w ){3,}\w') { $st = [regex]::Replace($st, '(?<=\S) (?=\S)', '') }
  $details.Add("wsl --status: $($st.Trim())")

  if ($st -match 'virtualization is not enabled|HYPERV_NOT_INSTALLED|HCS_E_HYPERV') {
    return @{
      Ok = $false
      Detail = "WSL reports virtualization is not enabled on this machine.`n`n" +
               "Enable CPU virtualization in BIOS/UEFI (or nested virt if this is a VM), reboot, then run SETUP.bat again.`n" +
               "https://aka.ms/enablevirtualization"
    }
  }

  return @{ Ok = $true; Detail = ($details -join "; ") }
}

function Show-PAVirtualizationHelp {
  param([string]$Detail = "")
  $root = Get-PAInstallRoot
  $help = Join-Path $root "ENABLE-VIRTUALIZATION.txt"
  if (-not (Test-Path $help)) {
    $help = Join-Path $PSScriptRoot "..\ENABLE-VIRTUALIZATION.txt"
  }

  $msg = @"
PA-Converter needs WSL2, and WSL2 needs CPU virtualization.

Your PC is not ready yet (hypervisor not running).

What to do:
1) Reboot into BIOS/UEFI and ENABLE Virtualization
   (names: VT-x, AMD-V, SVM, Hyper-V, Virtualization Technology)
2) If Windows is inside Parallels/VMware: enable Nested Virtualization
3) Boot Windows, open elevated PowerShell, run:
     bcdedit /set hypervisorlaunchtype auto
4) Reboot Windows again
5) Run SETUP.bat again

Verify with:
  (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
(must be True)

Opening help + Microsoft docs next...
"@
  if ($Detail) { $msg += "`r`n`r`nDetails:`r`n$Detail" }

  Write-PALog $msg "ERROR"
  try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    [System.Windows.Forms.MessageBox]::Show(
      $msg,
      "Action required: enable virtualization",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
  } catch {}

  if (Test-Path $help) {
    try { Start-Process notepad.exe $help } catch {}
  }
  try { Start-Process "https://aka.ms/enablevirtualization" } catch {}
}

function Assert-PAVirtualizationReady {
  $r = Test-PAVirtualizationReady
  Write-PALog $r.Detail
  if (-not $r.Ok) {
    Show-PAVirtualizationHelp -Detail $r.Detail
    throw $r.Detail
  }
}

function Show-PAPrerequisitesDialog {
  <#
    Shown at the start of setup so users know BIOS virt is required
    before we spend time downloading Ubuntu images.
  #>
  $r = Test-PAVirtualizationReady
  $status = if ($r.Ok) { "READY - hypervisor detected" } else { "NOT READY - enable virtualization first (see steps)" }

  $msg = @"
Before PA-Converter setup continues:

Required:
  - 64-bit Windows 10/11
  - Administrator approval (UAC)
  - Internet (first run only)
  - CPU virtualization ON in BIOS/UEFI
    (or Nested Virtualization if Windows is a VM)

Current virtualization status:
  $status

If status is NOT READY:
  1) Enable Virtualization in BIOS (VT-x / AMD-V / SVM)
  2) Or enable Nested Virtualization in Parallels/VMware
  3) Run:  bcdedit /set hypervisorlaunchtype auto
  4) Reboot, then run SETUP.bat again

Click OK to continue (Windows features will still be enabled).
Setup will stop with clear instructions if the hypervisor is still missing after reboot.
"@

  Write-PALog "Prerequisite check: $status"
  try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    [System.Windows.Forms.MessageBox]::Show(
      $msg,
      "PA-Converter prerequisites",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      $(if ($r.Ok) {
          [System.Windows.Forms.MessageBoxIcon]::Information
        } else {
          [System.Windows.Forms.MessageBoxIcon]::Warning
        })
    ) | Out-Null
  } catch {
    Write-Host $msg
  }

  if (-not $r.Ok) {
    $help = Join-Path (Get-PAInstallRoot) "ENABLE-VIRTUALIZATION.txt"
    if (-not (Test-Path $help)) {
      # During first run InstallRoot may not have the file yet — try script dir
      $alt = Join-Path $PSScriptRoot "..\ENABLE-VIRTUALIZATION.txt"
      if (Test-Path $alt) { $help = $alt }
    }
    if (Test-Path $help) { try { Start-Process notepad.exe $help } catch {} }
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
