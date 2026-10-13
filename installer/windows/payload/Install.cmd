@echo off
setlocal EnableExtensions
title PA-Converter Install
cd /d "%~dp0"

echo.
echo  Installing files to %ProgramData%\PA-Converter ...
echo.

net session >nul 2>&1
if errorlevel 1 (
  echo Requesting Administrator...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
  exit /b
)

set "SRC=%~dp0"
set "DST=%ProgramData%\PA-Converter"
mkdir "%DST%" 2>nul
mkdir "%DST%\lib" 2>nul
mkdir "%DST%\logs" 2>nul

copy /Y "%SRC%engine.zip" "%DST%\engine.zip" >nul || goto :fail
copy /Y "%SRC%Bootstrap-PAConverter.ps1" "%DST%\" >nul || goto :fail
copy /Y "%SRC%SETUP.bat" "%DST%\" >nul
copy /Y "%SRC%Start-PAConverter.ps1" "%DST%\" >nul
copy /Y "%SRC%Stop-PAConverter.ps1" "%DST%\" >nul
copy /Y "%SRC%Status-PAConverter.ps1" "%DST%\" >nul
copy /Y "%SRC%Start-PAConverter.cmd" "%DST%\" >nul
copy /Y "%SRC%Stop-PAConverter.cmd" "%DST%\" >nul
copy /Y "%SRC%Status-PAConverter.cmd" "%DST%\" >nul
copy /Y "%SRC%Configure-PAConverter.cmd" "%DST%\" >nul
copy /Y "%SRC%README.txt" "%DST%\" >nul
copy /Y "%SRC%lib\PAConverter.psm1" "%DST%\lib\" >nul || goto :fail

reg add "HKLM\Software\PA-Converter" /v InstallDir /t REG_SZ /d "%DST%" /f >nul

echo Files copied. Starting setup...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%DST%\Bootstrap-PAConverter.ps1"
set ERR=%ERRORLEVEL%
if not "%ERR%"=="0" (
  echo.
  echo Setup failed. Opening log...
  notepad "%DST%\logs\setup.log"
  pause
  exit /b %ERR%
)
exit /b 0

:fail
echo FAILED to copy installer files from:
echo   %SRC%
echo Make sure you extracted the ZIP fully and run Install.cmd from inside the extracted folder.
pause
exit /b 1
