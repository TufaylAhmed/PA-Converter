# PA-Converter Wave 2 UI

Apple-inspired glass shell for PA-Converter: **left navigation**, **light / dark mode**, frosted materials.

## Run

```bash
cd wave2
npm install
npm run dev
```

Open the Vite URL (usually http://127.0.0.1:5173).

Classic Expedition (Docker stack) defaults:

| Surface | URL |
| --- | --- |
| HTTPS UI | https://localhost:18443 |
| HTTP probe | http://localhost:18080 |

Change these under **Settings** (persisted in `localStorage`).

## QA / Playwright

```bash
npm install
npm run test:e2e:install
npm run test:e2e
```

Tests cover navigation, brand/favicon graphics, Expedition URL wiring, settings persistence, theme toggle, and mobile layout.

## Stack

- Vite + React + TypeScript
- CSS variables + `data-theme` for light/dark
- System / SF Pro font stack (no Inter)
- Playwright for e2e QA
