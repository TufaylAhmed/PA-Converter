PA-Converter for Windows
========================

IMPORTANT: Extract the ZIP first. Do not run files from inside the .zip window.

Before you start
----------------
1. 64-bit Windows 10/11
2. Administrator rights
3. Internet (first run downloads Ubuntu + packages)
4. CPU VIRTUALIZATION must be ON
     - Physical PC: enable VT-x / AMD-V / SVM in BIOS/UEFI
     - Windows inside Parallels/VMware: enable Nested Virtualization
   See ENABLE-VIRTUALIZATION.txt and https://aka.ms/enablevirtualization

Install
-------
1. Right-click SETUP.bat  ->  Run as administrator
2. Read the prerequisites popup (shows READY / NOT READY)
3. Allow UAC. Setup may reboot once for WSL.
4. After reboot, setup continues. If it stops on virtualization,
   follow the popup + ENABLE-VIRTUALIZATION.txt, then run SETUP.bat again.
5. Browser: https://localhost:18443
   Login:   admin / paloalto

Logs
----
  %ProgramData%\PA-Converter\logs\setup.log
  %ProgramData%\PA-Converter\logs\transcript.txt

No Docker Desktop / Node / GitHub token needed.
