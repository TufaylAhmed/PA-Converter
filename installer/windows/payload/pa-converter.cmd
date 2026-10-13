@echo off
setlocal EnableExtensions
rem PA-Converter launcher (installed by MSI) — always delegates to npx
set "PKG=@tufaylahmed/pa-converter"

where node >nul 2>&1
if errorlevel 1 (
  echo [pa-converter] Node.js 18+ is required.
  echo Download: https://nodejs.org/
  exit /b 1
)

where docker >nul 2>&1
if errorlevel 1 (
  echo [pa-converter] Docker Desktop is required and must be on PATH.
  echo Download: https://docs.docker.com/desktop/setup/install/windows-install/
  exit /b 1
)

npx --yes %PKG% %*
exit /b %ERRORLEVEL%
