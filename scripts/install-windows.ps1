<#
.SYNOPSIS
  Bootstrap PA-Converter on Windows via npx (WSL2 native runtime).

.DESCRIPTION
  Checks Node + WSL, installs @sequr3/pa-converter from npmjs, and optionally starts.
  Does not require Docker Desktop.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/install-windows.ps1

.EXAMPLE
  .\scripts\install-windows.ps1 -Start
#>
[CmdletBinding()]
param(
  [string]$Version = "5.46.45",
  [switch]$Start,
  [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$Package = "@sequr3/pa-converter@$Version"

Write-Host ""
Write-Host "  PA-Converter Windows installer (native / WSL)" -ForegroundColor Cyan
Write-Host "  Package: $Package" -ForegroundColor DarkGray
Write-Host ""

function Assert-Command($Name, $Hint) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    Write-Host "Missing: $Name" -ForegroundColor Red
    Write-Host $Hint
    exit 1
  }
}

Assert-Command node "Install Node.js 18+ LTS: https://nodejs.org/"
Assert-Command npm  "npm should ship with Node.js."
Assert-Command wsl  "Install WSL2: wsl --install -d Ubuntu  (then reboot if prompted)."

$nodeMajor = [int]((node -v) -replace '^v','' -split '\.')[0]
if ($nodeMajor -lt 18) {
  Write-Host "Node.js 18+ required (found $(node -v))." -ForegroundColor Red
  exit 1
}

$distros = & wsl.exe -l -q 2>$null
if (-not $distros) {
  Write-Host "No WSL distro found. Run: wsl --install -d Ubuntu" -ForegroundColor Red
  exit 1
}

# Remove legacy GitHub Packages remap that forces auth for installs
$npmrc = Join-Path $HOME ".npmrc"
if (Test-Path $npmrc) {
  $lines = Get-Content $npmrc | Where-Object {
    $_ -notmatch '^@tufaylahmed:registry=' -and
    $_ -notmatch '^@sequr3:registry=https://npm\.pkg\.github\.com' -and
    $_ -notmatch '^//npm\.pkg\.github\.com/:_authToken='
  }
  Set-Content -Path $npmrc -Value $lines
}

if (-not $SkipInstall) {
  Write-Host "Installing $Package globally…" -ForegroundColor Cyan
  npm install -g $Package
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

if ($Start) {
  Write-Host "Starting PA-Converter (first run may take several minutes)…" -ForegroundColor Cyan
  pa-converter start
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  Start-Process "https://localhost:18443"
}

Write-Host "Done. UI: https://localhost:18443  (admin / paloalto)" -ForegroundColor Green
