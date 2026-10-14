<#
.SYNOPSIS
  Stage engine.zip and build PA-Converter.msi + portable ZIP (Windows + WiX v4).
#>
[CmdletBinding()]
param(
  [string]$Version = "5.46.17",
  [string]$OutDir = (Join-Path $PSScriptRoot "dist")
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Building self-contained PA-Converter $Version…" -ForegroundColor Cyan

& (Join-Path $PSScriptRoot "stage-payload.ps1")
$engineZip = Join-Path $PSScriptRoot "payload\engine.zip"
if (-not (Test-Path $engineZip)) {
  throw "engine.zip was not created"
}

$wxs = Join-Path $PSScriptRoot "Package.wxs"
$w = Get-Content $wxs -Raw
$w = $w -replace 'ProductVersion = "[\d.]+"', "ProductVersion = `"$Version`""
# Force ASCII-safe description (no em-dash / smart punctuation)
$w = $w -replace 'Description="[^"]*"', 'Description="PA-Converter - self-contained Expedition appliance for Windows (WSL2)"'
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

# Validate MSI is a real OLE compound document (not HTML/error page)
$bytes = [System.IO.File]::ReadAllBytes($msi)[0..7]
$sig = ($bytes | ForEach-Object { $_.ToString("X2") }) -join ""
if (-not $sig.StartsWith("D0CF11E0A1B11AE1")) {
  throw "MSI magic header invalid ($sig) — refusing to publish corrupt package"
}

# Portable ZIP fallback (no Windows Installer engine required)
$zipStage = Join-Path $OutDir "_zip_stage"
if (Test-Path $zipStage) { Remove-Item $zipStage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $zipStage | Out-Null
$payload = Join-Path $PSScriptRoot "payload"
foreach ($name in @(
    "engine.zip",
    "SETUP.bat",
    "Install.cmd",
    "Bootstrap-PAConverter.ps1",
    "Start-PAConverter.ps1", "Stop-PAConverter.ps1", "Status-PAConverter.ps1",
    "Start-PAConverter.cmd", "Stop-PAConverter.cmd", "Status-PAConverter.cmd",
    "Configure-PAConverter.cmd", "README.txt", "ENABLE-VIRTUALIZATION.txt"
  )) {
  Copy-Item (Join-Path $payload $name) $zipStage -Force
}
New-Item -ItemType Directory -Force -Path (Join-Path $zipStage "lib") | Out-Null
Copy-Item (Join-Path $payload "lib\PAConverter.psm1") (Join-Path $zipStage "lib") -Force

$portable = Join-Path $OutDir "PA-Converter-$Version-portable.zip"
if (Test-Path $portable) { Remove-Item $portable -Force }
Compress-Archive -Path (Join-Path $zipStage "*") -DestinationPath $portable -CompressionLevel Optimal
Remove-Item $zipStage -Recurse -Force

Write-Host ""
Write-Host "Built:" -ForegroundColor Green
Get-Item $msi, $portable | Format-Table Name, Length, LastWriteTime -AutoSize
