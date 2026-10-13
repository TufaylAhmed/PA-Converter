<#
.SYNOPSIS
  Stage engine.zip and build the self-contained PA-Converter.msi (Windows + WiX v4).
#>
[CmdletBinding()]
param(
  [string]$Version = "5.46.0",
  [string]$OutDir = (Join-Path $PSScriptRoot "dist")
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Building self-contained PA-Converter $Version MSI…" -ForegroundColor Cyan

# Stage Expedition engine into payload\engine.zip
& (Join-Path $PSScriptRoot "stage-payload.ps1")
if (-not (Test-Path (Join-Path $PSScriptRoot "payload\engine.zip"))) {
  throw "engine.zip was not created"
}

# Sync version strings
$wxs = Join-Path $PSScriptRoot "Package.wxs"
$w = Get-Content $wxs -Raw
$w = $w -replace 'ProductVersion = "[\d.]+"', "ProductVersion = `"$Version`""
Set-Content -Path $wxs -Value $w -Encoding utf8

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
  Write-Host "Installing WiX CLI…" -ForegroundColor Yellow
  dotnet tool update --global wix --version 4.0.5
  $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
              [Environment]::GetEnvironmentVariable("Path", "User")
}

Write-Host "Ensuring WiX UI extension…" -ForegroundColor DarkGray
& wix extension add "WixToolset.UI.wixext/4.0.5"
if ($LASTEXITCODE -ne 0) {
  Write-Host "Extension add returned $LASTEXITCODE — continuing" -ForegroundColor Yellow
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$msi = Join-Path $OutDir "PA-Converter-$Version.msi"

& wix build .\Package.wxs `
  -ext WixToolset.UI.wixext `
  -arch x64 `
  -out $msi

if (-not (Test-Path $msi)) {
  throw "MSI was not produced at $msi"
}

Write-Host ""
Write-Host "Built: $msi" -ForegroundColor Green
Get-Item $msi | Format-List Name, Length, LastWriteTime
