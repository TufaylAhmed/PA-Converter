<#
.SYNOPSIS
  Post-MSI setup: GitHub Packages auth + global npm install of PA-Converter.
#>
[CmdletBinding()]
param(
  [string]$Token = $env:GITHUB_TOKEN,
  [string]$Version = "5.45.6",
  [switch]$Start
)

$ErrorActionPreference = "Stop"
$Package = "@tufaylahmed/pa-converter@$Version"

function Assert-Command($Name, $Hint) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    Write-Host "Missing: $Name" -ForegroundColor Red
    Write-Host $Hint
    Read-Host "Press Enter to exit"
    exit 1
  }
}

Write-Host ""
Write-Host "  PA-Converter — first-time configuration" -ForegroundColor Cyan
Write-Host "  Package: $Package" -ForegroundColor DarkGray
Write-Host ""

Assert-Command node "Install Node.js 18+ LTS from https://nodejs.org/ then re-run this shortcut."
Assert-Command npm  "npm should ship with Node.js."
Assert-Command docker @"
Install Docker Desktop for Windows (WSL2 backend):
https://docs.docker.com/desktop/setup/install/windows-install/
Start Docker Desktop, then re-run this shortcut.
"@

$nodeMajor = [int]((node -v) -replace '^v','' -split '\.')[0]
if ($nodeMajor -lt 18) {
  Write-Host "Node.js 18+ required (found $(node -v))." -ForegroundColor Red
  Read-Host "Press Enter to exit"
  exit 1
}

docker info 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
  Write-Host "Docker is installed but not running. Start Docker Desktop and retry." -ForegroundColor Red
  Read-Host "Press Enter to exit"
  exit 1
}

if (-not $Token) {
  Write-Host "A GitHub Personal Access Token is required (classic) with:" -ForegroundColor Yellow
  Write-Host "  read:packages"
  Write-Host "Create one: https://github.com/settings/tokens"
  Write-Host ""
  $secure = Read-Host "Paste GitHub PAT" -AsSecureString
  $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  $Token = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

if (-not $Token) {
  Write-Host "No token provided." -ForegroundColor Red
  Read-Host "Press Enter to exit"
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

Write-Host "Installing $Package globally…" -ForegroundColor Cyan
npm install -g $Package --registry=https://npm.pkg.github.com
if ($LASTEXITCODE -ne 0) {
  Read-Host "Install failed. Press Enter to exit"
  exit $LASTEXITCODE
}

$installDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pathEntry = $installDir
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$pathEntry*") {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$pathEntry", "User")
  Write-Host "Added to user PATH: $pathEntry" -ForegroundColor Green
}

Write-Host ""
Write-Host "Configuration complete." -ForegroundColor Green
Write-Host "  Start:  Start Menu → PA-Converter → Start PA-Converter"
Write-Host "  Or:     pa-converter start"
Write-Host "  UI:     https://localhost:18443  (admin / paloalto)"
Write-Host ""

if ($Start) {
  & (Join-Path $installDir "pa-converter.cmd") start
}

Read-Host "Press Enter to close"
