PA-Converter for Windows (self-contained)
========================================

Install the MSI, then use Start Menu → PA-Converter:

  1. Configure / Finish setup   (first run only — enables WSL, downloads Ubuntu
                                 rootfs + Docker packages, builds Expedition)
  2. Start PA-Converter
  3. Browser: https://localhost:18443
     Login:   admin / paloalto

You do NOT need to install Docker Desktop, Node.js, or a GitHub token.

Requirements
------------
- Windows 10 version 2004+ or Windows 11 (64-bit)
- Virtualization enabled in BIOS/UEFI
- Administrator approval (UAC) on first setup
- Internet on first setup (Ubuntu rootfs + Docker packages + image build)
- One reboot may be required the first time WSL is enabled

Stop / Status shortcuts are in the same Start Menu folder.

Logs: %ProgramData%\PA-Converter\logs\setup.log
