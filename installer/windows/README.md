# PA-Converter Windows installer

Self-contained **MSI** + portable ZIP. First run enables WSL2, imports Ubuntu, installs the **native** stack (Apache / PHP 7.4 / MariaDB / RabbitMQ / Spark) inside WSL, and starts Expedition.

**No Docker Desktop, no Docker Engine, no Node.js, no GitHub Personal Access Token.**

## What setup does

1. Enables WSL / Virtual Machine Platform (may reboot once)
2. Imports a private `PA-Converter` Ubuntu distro
3. Syncs `engine.zip` → `/opt/pa-converter` in WSL
4. Runs `wsl/provision.sh` → `native/install.sh` + `native/start.sh`
5. Opens https://localhost:18443 (`admin` / `paloalto`)

| Component | How |
|-----------|-----|
| WSL2 Ubuntu | Yes (imported rootfs) |
| Native apt packages | Apache, PHP 7.4, MariaDB, RabbitMQ, OpenJDK 11 |
| Spark 2.4.3 | Downloaded into `/opt/Spark` |
| Docker Engine | **No** |

## Build (Windows)

```powershell
cd installer\windows
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Version 5.46.45
```

Outputs under `dist\`:

- `PA-Converter-5.46.18.msi`
- `PA-Converter-5.46.45-portable.zip`
