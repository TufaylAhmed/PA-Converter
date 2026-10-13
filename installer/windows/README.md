# Windows MSI installer

Builds **`PA-Converter-<version>.msi`** with [WiX Toolset v4](https://wixtoolset.org/).

The MSI installs launchers + Start Menu shortcuts under `Program Files\PA-Converter`.  
It does **not** embed Expedition itself (that still comes from the private npm package via Docker). After install, users run **Configure PA-Converter** once (GitHub PAT → `npm install -g`).

## Requirements to *build* the MSI

- Windows (or GitHub Actions `windows-latest`)
- [.NET 8 SDK](https://dotnet.microsoft.com/download)
- WiX CLI: `dotnet tool install --global wix --version 4.0.5`

## Build locally

```powershell
cd installer\windows
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Version 5.45.6
```

Output: `installer\windows\dist\PA-Converter-5.45.6.msi`

## Install on a PC

1. Install [Node.js 18+](https://nodejs.org/) and [Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/) (WSL2).
2. Double-click the MSI (or `msiexec /i PA-Converter-5.45.6.msi`).
3. Leave **Configure GitHub auth…** checked on the finish page (or use Start Menu → **1. Configure PA-Converter**).
4. Start Menu → **2. Start PA-Converter**.
5. Open https://localhost:18443 → `admin` / `paloalto`.

## CI

Workflow: `.github/workflows/build-windows-msi.yml`  
Produces an artifact (and attaches to a GitHub Release on tags `v*`).
