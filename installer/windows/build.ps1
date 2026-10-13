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
  $c = Get-Content $configure -Raw
  $c = $c -replace 'Version = "[\d.]+"', "Version = `"$Version`""
  Set-Content -Path $configure -Value $c -Encoding utf8
}

# Patch Package.wxs version define
$wxs = Join-Path $PSScriptRoot "Package.wxs"
$w = Get-Content $wxs -Raw
$w = $w -replace 'ProductVersion = "[\d.]+"', "ProductVersion = `"$Version`""
Set-Content -Path $wxs -Value $w -Encoding utf8

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
  Write-Host "Installing WiX CLI (dotnet tool)…" -ForegroundColor Yellow
  dotnet tool update --global wix --version 4.0.5
  $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
              [Environment]::GetEnvironmentVariable("Path", "User")
}

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
  throw "WiX CLI not found. Install .NET SDK, then: dotnet tool install --global wix"
}

Write-Host "Ensuring WiX UI extension…" -ForegroundColor DarkGray
# Cache extensions under the installer folder so CI is reproducible
$env:WIX_EXTENSIONS_CACHE = Join-Path $PSScriptRoot ".wixext"
New-Item -ItemType Directory -Force -Path $env:WIX_EXTENSIONS_CACHE | Out-Null

# wix extension add downloads to the user cache; -ext name resolves from there
& wix extension add "WixToolset.UI.wixext/4.0.5"
if ($LASTEXITCODE -ne 0) {
  Write-Host "Extension add returned $LASTEXITCODE (may already be installed) — continuing" -ForegroundColor Yellow
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$msi = Join-Path $OutDir "PA-Converter-$Version.msi"

Write-Host "Running wix build…" -ForegroundColor DarkGray
& wix build .\Package.wxs `
  -ext WixToolset.UI.wixext `
  -arch x64 `
  -out $msi

if (-not (Test-Path $msi)) {
  throw "MSI was not produced at $msi"
}

Write-Host ""
Write-Host "Built: $msi" -ForegroundColor Green
Write-Host "Install: msiexec /i `"$msi`"" -ForegroundColor DarkGray
Get-Item $msi | Format-List Name, Length, LastWriteTime
