<#
.SYNOPSIS
  Bootstrap PA-Converter on Windows (Node + Docker Desktop + GitHub Packages).

.DESCRIPTION
  Checks prerequisites, configures ~/.npmrc for @tufaylahmed GitHub Packages,
  installs @tufaylahmed/pa-converter globally, and optionally starts the stack.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/install-windows.ps1

.EXAMPLE
  .\scripts\install-windows.ps1 -Token ghp_xxx -Start
#>
[CmdletBinding()]
param(
  [string]$Token = $env:GITHUB_TOKEN,
  [string]$Version = "5.45.6",
  [switch]$Start,
  [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$Package = "@tufaylahmed/pa-converter@$Version"

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

if (-not $Token) {
  Write-Host "GitHub Packages needs a Personal Access Token (classic) with:" -ForegroundColor Yellow
  Write-Host "  read:packages   (and repo if the linked repo is private)"
  Write-Host "Create one: https://github.com/settings/tokens"
  Write-Host ""
  $secure = Read-Host "Paste GitHub PAT" -AsSecureString
  $Token = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  )
}

if (-not $Token) {
  Write-Host "No token provided." -ForegroundColor Red
  exit 1
}

$npmrc = Join-Path $HOME ".npmrc"
$lines = @()
if (Test-Path $npmrc) {
  $lines = Get-Content $npmrc | Where-Object {
    $_ -notmatch '^@tufaylahmed:registry=' -and
    $_ -notmatch '^//npm\.pkg\.github\.com/:_authToken='
  }
}
$lines += "@tufaylahmed:registry=https://npm.pkg.github.com"
$lines += "//npm.pkg.github.com/:_authToken=$Token"
Set-Content -Path $npmrc -Value $lines -Encoding utf8
Write-Host "Wrote GitHub Packages auth to $npmrc" -ForegroundColor Green

if (-not $SkipInstall) {
  Write-Host "Installing $Package …" -ForegroundColor Cyan
  npm install -g $Package --registry=https://npm.pkg.github.com
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host ""
Write-Host "Installed. Commands:" -ForegroundColor Green
Write-Host "  pa-converter start"
Write-Host "  pa-converter status"
Write-Host "  pa-converter stop"
Write-Host "  npx $Package start"
Write-Host ""
Write-Host "UI: https://localhost:18443   login admin / paloalto" -ForegroundColor DarkGray
Write-Host ""

if ($Start) {
  pa-converter start
}
