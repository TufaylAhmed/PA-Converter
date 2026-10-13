@echo off
title PA-Converter Setup
cd /d "%~dp0"

echo.
echo  PA-Converter Setup
echo  ------------------
echo  This window will request Administrator access.
echo.

REM Always launch PowerShell elevated with ExecutionPolicy Bypass
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0Bootstrap-PAConverter.ps1\"\"'"

if errorlevel 1 (
  echo.
  echo Setup reported an error.
  echo Log folder: %ProgramData%\PA-Converter\logs
  echo.
  notepad "%ProgramData%\PA-Converter\logs\setup.log" 2>nul
  pause
  exit /b 1
)

echo.
echo Setup finished.
pause
exit /b 0
