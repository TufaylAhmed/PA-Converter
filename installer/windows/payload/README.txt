PA-Converter for Windows
========================

IMPORTANT: Extract the ZIP first. Do not run files from inside the .zip window.

1. Right-click SETUP.bat  ->  Run as administrator
   (or double-click Install.cmd)

2. Allow UAC. Wait for setup.
   - May reboot once to enable WSL
   - First run needs internet (Ubuntu image + Docker packages)

3. Browser: https://localhost:18443
   Login:   admin / paloalto

If something fails, open:
  %ProgramData%\PA-Converter\logs\setup.log
  %ProgramData%\PA-Converter\logs\transcript.txt

Requirements: 64-bit Windows 10/11, virtualization ON in BIOS, internet on first setup.
No Docker Desktop / Node / GitHub token needed.
