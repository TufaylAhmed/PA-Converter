@echo off
title PA-Converter Setup
cd /d "%~dp0"

echo.
echo  PA-Converter Setup
echo  ------------------
echo.

if not exist "%~dp0engine.zip" (
  echo ERROR: engine.zip not found next to SETUP.bat
  echo.
  echo Extract the portable ZIP to a folder first, then run SETUP.bat
  echo from that folder. Do not run from inside the .zip window.
  echo.
  echo Looking in: %~dp0
  pause
  exit /b 1
)

echo Found engine.zip - starting setup...
echo A Windows Administrator prompt will appear next.
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -WorkingDirectory '%~dp0' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0Bootstrap-PAConverter.ps1\"\"'"

if errorlevel 1 (
  echo.
  echo Setup reported an error.
  echo Log: %ProgramData%\PA-Converter\logs\setup.log
  echo.
  if exist "%ProgramData%\PA-Converter\logs\setup.log" notepad "%ProgramData%\PA-Converter\logs\setup.log"
  pause
  exit /b 1
)

echo.
echo Setup finished.
pause
exit /b 0
