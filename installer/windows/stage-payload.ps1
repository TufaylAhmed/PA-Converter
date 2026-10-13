<#
.SYNOPSIS
  Build engine.zip (Expedition app + Compose) for the self-contained MSI.
  Run from repo on Windows CI (or any OS with Compress-Archive / zip).
#>
[CmdletBinding()]
param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$OutZip = (Join-Path $PSScriptRoot "payload\engine.zip")
)

$ErrorActionPreference = "Stop"
$stage = Join-Path $PSScriptRoot "payload\_engine_stage"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

Write-Host "Staging engine from $RepoRoot"

$copyMap = @(
  @{ Src = "app"; Dst = "app" },
  @{ Src = "databases"; Dst = "databases" },
  @{ Src = "bin"; Dst = "bin" },
  @{ Src = "docker\docker-compose.yml"; Dst = "docker\docker-compose.yml" },
  @{ Src = "docker\initdb"; Dst = "docker\initdb" },
  @{ Src = "docker\web"; Dst = "docker\web" },
  @{ Src = "docker\spark\README.md"; Dst = "docker\spark\README.md" },
  @{ Src = "installer\windows\payload\wsl"; Dst = "wsl" }
)

foreach ($item in $copyMap) {
  $src = Join-Path $RepoRoot $item.Src
  $dst = Join-Path $stage $item.Dst
  if (-not (Test-Path $src)) { throw "Missing $($item.Src)" }
  $parent = Split-Path $dst -Parent
  New-Item -ItemType Directory -Force -Path $parent | Out-Null
  Copy-Item -Path $src -Destination $dst -Recurse -Force
}

# Do not ship the 235MB Spark tarball — Dockerfile downloads Apache Spark on build
$sparkTar = Join-Path $stage "docker\spark\opt-Spark.tar.gz"
if (Test-Path $sparkTar) { Remove-Item $sparkTar -Force }

if (Test-Path $OutZip) { Remove-Item $OutZip -Force }
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $OutZip -CompressionLevel Optimal
Remove-Item $stage -Recurse -Force

$len = (Get-Item $OutZip).Length
Write-Host ("Wrote {0} ({1:N1} MB)" -f $OutZip, ($len / 1MB))
