$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here "lib\PAConverter.psm1") -Force
Write-Host "Stopping PA-Converter…" -ForegroundColor Cyan
exit (Invoke-PAWsl -ScriptName "stop.sh")
