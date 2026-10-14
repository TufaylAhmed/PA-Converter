<#
.SYNOPSIS
  Bootstrap PA-Converter on Windows (Node + Docker Desktop + public npm).

.DESCRIPTION
  Checks prerequisites, installs @sequr3/pa-converter globally from npmjs
  (no GitHub token), and optionally starts the stack.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/install-windows.ps1

.EXAMPLE
  .\scripts\install-windows.ps1 -Start
#>
[CmdletBinding()]
param(
  [string]$Version = "5.46.16",
  [switch]$Start,
  [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$Package = "@sequr3/pa-converter@$Version"

Write-Host ""
Write-Host "  PA-Converter Windows installer" -ForegroundColor Cyan
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
Assert-Command docker "Install Docker Desktop for Windows: https://docs.docker.com/desktop/setup/install/windows-install/`nEnable WSL2 backend, then start Docker Desktop."

$nodeMajor = [int]((node -v) -replace '^v','' -split '\.')[0]
if ($nodeMajor -lt 18) {
  Write-Host "Node.js 18+ required (found $(node -v))." -ForegroundColor Red
  exit 1
}

docker info 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
  Write-Host "Docker is installed but not running. Start Docker Desktop and retry." -ForegroundColor Red
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
  Set-Content -Path $npmrc -Value $lines -Encoding utf8
}

if (-not $SkipInstall) {
  Write-Host "Installing $Package from public npm …" -ForegroundColor Cyan
  npm install -g $Package --registry=https://registry.npmjs.org
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host ""
Write-Host "Installed. Run: pa-converter start" -ForegroundColor Green
if ($Start) {
  pa-converter start
}
