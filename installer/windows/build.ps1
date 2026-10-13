<#
.SYNOPSIS
  Build PA-Converter.msi with WiX Toolset v4 (must run on Windows).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\build.ps1
#>
[CmdletBinding()]
param(
  [string]$Version = "5.45.6",
  [string]$OutDir = (Join-Path $PSScriptRoot "dist")
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Building PA-Converter $Version MSI…" -ForegroundColor Cyan

# Keep payload script version in sync
$configure = Join-Path $PSScriptRoot "payload\Configure-PAConverter.ps1"
if (Test-Path $configure) {
  (Get-Content $configure -Raw) -replace 'Version = "[\d.]+"', "Version = `"$Version`"" |
    Set-Content $configure -Encoding utf8 -NoNewline
}

# Patch Package.wxs version define
$wxs = Join-Path $PSScriptRoot "Package.wxs"
(Get-Content $wxs -Raw) -replace 'ProductVersion = "[\d.]+"', "ProductVersion = `"$Version`"" |
  Set-Content $wxs -Encoding utf8 -NoNewline

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
  Write-Host "Installing WiX CLI (dotnet tool)…" -ForegroundColor Yellow
  dotnet tool update --global wix --version 4.0.5
  $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
              [Environment]::GetEnvironmentVariable("Path", "User")
}

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
  throw "WiX CLI not found. Install .NET SDK, then: dotnet tool install --global wix"
}

# UI extension
$extDir = Join-Path $PSScriptRoot ".wixext"
New-Item -ItemType Directory -Force -Path $extDir | Out-Null
Push-Location $PSScriptRoot
try {
  wix extension add WixToolset.UI.wixext/4.0.5 --quiet 2>$null
} catch { }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$msi = Join-Path $OutDir "PA-Converter-$Version.msi"

wix build .\Package.wxs `
  -ext WixToolset.UI.wixext `
  -arch x64 `
  -out $msi

if (-not (Test-Path $msi)) {
  throw "MSI was not produced."
}

Write-Host ""
Write-Host "Built: $msi" -ForegroundColor Green
Write-Host "Install: msiexec /i `"$msi`"" -ForegroundColor DarkGray
Get-Item $msi | Format-List Name, Length, LastWriteTime
