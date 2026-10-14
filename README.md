<div align="center">

# PA-Converter

### Palo Alto Expedition · Firewall Config Converter (native)

[![Version](https://img.shields.io/badge/Expedition-5.46.18-orange?style=for-the-badge)](https://github.com/TufaylAhmed/PA-Converter)
[![npm](https://img.shields.io/badge/npm-@sequr3/pa--converter-CB3837?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@sequr3/pa-converter)
[![GitHub](https://img.shields.io/badge/GitHub-public-181717?style=for-the-badge&logo=github)](https://github.com/TufaylAhmed/PA-Converter)
[![Platform](https://img.shields.io/badge/macOS%20%7C%20Windows%20WSL%20%7C%20Linux-ready-success?style=for-the-badge)](https://github.com/TufaylAhmed/PA-Converter)
[![Node](https://img.shields.io/badge/Node.js-18%2B-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)

**Convert · Import · Optimize · ML-assist** firewall configurations with Expedition — **no Docker Desktop**.

```
╔══════════════════════════════════════════════════════════════╗
║   Vendor configs  ──►  PA-Converter  ──►  PAN-OS XML         ║
║       Fortinet · Cisco · Checkpoint · Palo Alto · more       ║
╚══════════════════════════════════════════════════════════════╝
```

[Quick Start](#quick-start) · [Architecture](#architecture) · [CLI](#cli-commands)

</div>

---

## Overview

**PA-Converter** packages **Palo Alto Networks Expedition 5.45.4** for **macOS, Windows (WSL2), and Linux** using a **native** runtime: Apache + PHP 7.4, MariaDB, RabbitMQ, OpenJDK 11, and Spark 2.4.3. No containers required.

| Capability | Status |
|:-----------|:------:|
| Expedition web UI (HTTPS) | ✅ |
| Seed login (`admin` / `paloalto`) | ✅ |
| Palo Alto `running-config.xml` import | ✅ |
| Fortinet config import | ✅ |
| Background jobs (RabbitMQ + PanOrders) | ✅ |
| Machine Learning / Spark 2.4 | ✅ |
| Windows WSL2 (no Docker Engine) | ✅ |
| macOS Homebrew + PHP 7.4 tap | ✅ |

> For engineering / lab use. Expedition itself remains Palo Alto Networks software.

---

## Quick Start

### Prerequisites

| Platform | Requirement |
|----------|-------------|
| **All (npx)** | Node.js 18+ |
| **Windows** | WSL2 Ubuntu (or the MSI, which imports a distro) — **not** Docker Desktop |
| **macOS** | [Homebrew](https://brew.sh) (installs MariaDB, RabbitMQ, httpd, OpenJDK 11, PHP 7.4) |
| **Linux** | Ubuntu 20.04/22.04 recommended; `sudo` for apt |

**No login, token, or `.npmrc` required** for end users.

| Path | Who | Command / download |
|------|-----|-------------------|
| **npm / npx** | macOS / Linux / Windows+WSL | `npx @sequr3/pa-converter start` |
| **MSI / portable ZIP** | Windows | [GitHub Releases](https://github.com/TufaylAhmed/PA-Converter/releases) |
| **git clone** | contributors | clone this repo, then `npm start` |

> If an old `~/.npmrc` still has `@tufaylahmed:registry=https://npm.pkg.github.com`, **delete that line** or installs may ask for a GitHub PAT.

---

### macOS / Linux / Windows (npx)

```bash
npx @sequr3/pa-converter@5.46.18 start

npx @sequr3/pa-converter status
npx @sequr3/pa-converter logs -f
npx @sequr3/pa-converter stop
```

If npm is still validating a new version, run from GitHub (same native CLI):

```bash
npx --yes github:TufaylAhmed/PA-Converter#v5.46.18 start
```

First `start` installs packages and Spark (several minutes). Then open **https://localhost:18443** (accept the self-signed cert) → `admin` / `paloalto`.

On Windows, the CLI runs install/start **inside WSL** (`wsl.exe`). Install WSL first if needed: `wsl --install -d Ubuntu`.

Optional legacy Docker path: `PA_CONVERTER_RUNTIME=docker npx @sequr3/pa-converter start`.

---

### Windows — self-contained `.msi` (recommended)

**End users only need the MSI** — no Docker Desktop, Node.js, or npm account.

1. Download **`PA-Converter-5.46.18.msi`** (or the portable ZIP) from [Releases](https://github.com/TufaylAhmed/PA-Converter/releases).
2. Run the MSI (allow UAC). Leave **Finish setup** checked.
3. If Windows asks to reboot to enable WSL, reboot once — setup continues automatically.
4. Wait for first-time provisioning (apt packages + Spark inside WSL — **no Docker Engine**).
5. Open **https://localhost:18443** → `admin` / `paloalto`.

Later: Start Menu → **PA-Converter** → **Start / Stop / Status**.

> Needs 64-bit Windows 10/11, BIOS virtualization, and internet on **first** setup only.

Build the MSI (CI/Windows):

```powershell
cd installer\windows
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Version 5.46.18
```

---

### Run from git clone

```bash
git clone https://github.com/TufaylAhmed/PA-Converter.git
cd PA-Converter
npm start
```

| Protocol | URL |
|:---------|:----|
| HTTPS | **https://localhost:18443** |
| HTTP  | http://localhost:18080 |

```
admin / paloalto
```

### Ports

| Environment variable | Default | Role |
|:---------------------|:-------:|:-----|
| `EXPEDITION_PORT` | `18443` | HTTPS |
| `EXPEDITION_HTTP_PORT` | `18080` | HTTP |

---

## Architecture

```mermaid
flowchart LR
  npx[npx pa-converter start] --> mgr[Native runtime manager]
  mgr --> http[Apache PHP 7.4]
  mgr --> db[MariaDB]
  mgr --> mq[RabbitMQ]
  mgr --> spark[Java11 Spark 2.4]
  http --> db
  http --> mq
  http --> spark
```

| Component | Role |
|:----------|:-----|
| Apache + PHP 7.4 | Expedition UI + APIs |
| MariaDB | Seed schemas (`databases/`) |
| RabbitMQ | Job queue for PanOrders |
| OpenJDK 11 + Spark 2.4.3 | ML jobs |

---

## CLI Commands

```bash
pa-converter start      # Install (if needed) and start native services
pa-converter stop       # Stop Apache / MariaDB / RabbitMQ / agent
pa-converter status     # Service status
pa-converter logs [-f]  # Apache + agent logs
pa-converter url        # Print UI URL
```

```bash
export EXPEDITION_PORT=18443
export EXPEDITION_HTTP_PORT=18080
# Optional: PA_CONVERTER_RUNTIME=docker
```

---

## Repository layout

```
PA-Converter/
├── README.md
├── package.json
├── bin/expedition.js         # CLI (native primary; Docker opt-in)
├── app/                      # Expedition web root
├── databases/                # Seed SQL
├── native/                   # install / start / stop (Linux+WSL, macOS)
├── docker/                   # Legacy Compose (PA_CONVERTER_RUNTIME=docker)
└── installer/windows/        # MSI + WSL provision (native)
```

---

## Publish (maintainers)

```bash
npm login   # account sequr3
npm publish --access public
```

Windows MSI: `installer\windows\build.ps1 -Version 5.46.18`

---

## Notes

- First `start` may take several minutes (apt/brew + Spark download).
- PHP 7.4 is EOL — pinned via ondrej PPA (Linux) or `shivammathur/php` (macOS).
- Apple Silicon: Spark 2.4 / PHP 7.4 may need Rosetta for some bits.
- Engineering / lab packaging of Expedition only.

---

## Maintainer

**Tufail Ahmed Sheikh** ([@TufaylAhmed](https://github.com/TufaylAhmed)) · npm **[@sequr3](https://www.npmjs.com/~sequr3)**

---

<div align="center">

**PA-Converter** · Expedition 5.45.4 · [`@sequr3/pa-converter`](https://www.npmjs.com/package/@sequr3/pa-converter) · [GitHub](https://github.com/TufaylAhmed/PA-Converter)

</div>
