# Windows self-contained MSI

End users install **`PA-Converter-<version>.msi`** only.

No Docker Desktop, no Node.js, no GitHub Personal Access Token.

## What the MSI does

1. Copies launchers + `engine.zip` (Expedition app + Compose) to  
   `%ProgramData%\PA-Converter\`
2. On Finish / **Finish setup**, elevated Bootstrap:
   - Enables **WSL2** + Virtual Machine Platform (may reboot once)
   - Imports a private Ubuntu distro named `PA-Converter`
   - Installs **Docker Engine** (open source) *inside* that distro
   - Builds and starts the Expedition stack
3. Start Menu → **Start PA-Converter** opens https://localhost:18443  
   (`admin` / `paloalto`)

## Build (CI / Windows)

```powershell
cd installer\windows
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Version 5.46.0
```

Produces `dist\PA-Converter-5.46.0.msi`.

## User prerequisites (automatic where possible)

| Need | Handled by installer? |
|------|------------------------|
| WSL2 features | Yes (may ask for one reboot) |
| Ubuntu rootfs | Yes (downloaded on first setup) |
| Docker Engine | Yes (apt inside WSL) |
| Expedition app | Yes (embedded `engine.zip`) |
| BIOS virtualization | Must be enabled by IT/user once |
| Internet (first setup) | Required for rootfs/packages/build |

## Uninstall

Remove the product from **Apps & features**, then optionally:

```powershell
wsl --unregister PA-Converter
Remove-Item -Recurse -Force "$env:ProgramData\PA-Converter"
```
