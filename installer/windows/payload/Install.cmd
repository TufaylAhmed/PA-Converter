@echo off
setlocal EnableExtensions
rem Portable installer (no MSI). Run as Administrator.
net session >nul 2>&1
if errorlevel 1 (
  echo Requesting Administrator…
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set "SRC=%~dp0"
set "DST=%ProgramData%\PA-Converter"
echo Installing PA-Converter to %DST% …

mkdir "%DST%" 2>nul
mkdir "%DST%\lib" 2>nul

copy /Y "%SRC%engine.zip" "%DST%\engine.zip" >nul
copy /Y "%SRC%Bootstrap-PAConverter.ps1" "%DST%\" >nul
copy /Y "%SRC%Start-PAConverter.ps1" "%DST%\" >nul
copy /Y "%SRC%Stop-PAConverter.ps1" "%DST%\" >nul
copy /Y "%SRC%Status-PAConverter.ps1" "%DST%\" >nul
copy /Y "%SRC%Start-PAConverter.cmd" "%DST%\" >nul
copy /Y "%SRC%Stop-PAConverter.cmd" "%DST%\" >nul
copy /Y "%SRC%Status-PAConverter.cmd" "%DST%\" >nul
copy /Y "%SRC%Configure-PAConverter.cmd" "%DST%\" >nul
copy /Y "%SRC%README.txt" "%DST%\" >nul
copy /Y "%SRC%lib\PAConverter.psm1" "%DST%\lib\" >nul

reg add "HKLM\Software\PA-Converter" /v InstallDir /t REG_SZ /d "%DST%" /f >nul

echo.
echo Files installed. Starting first-time setup…
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%DST%\Bootstrap-PAConverter.ps1"
exit /b %ERRORLEVEL%
