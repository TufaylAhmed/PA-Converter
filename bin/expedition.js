#!/usr/bin/env node
'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const COMPOSE_FILE = path.join(ROOT, 'docker', 'docker-compose.yml');
const DEFAULT_PORT = process.env.EXPEDITION_PORT || '18443';
const DEFAULT_HTTP_PORT = process.env.EXPEDITION_HTTP_PORT || '18080';
const IS_WIN = process.platform === 'win32';

function die(msg, code = 1) {
  console.error(`pa-converter: ${msg}`);
  process.exit(code);
}

function which(cmd) {
  const finder = IS_WIN ? 'where' : 'which';
  const r = spawnSync(finder, [cmd], {
    encoding: 'utf8',
    shell: IS_WIN,
    windowsHide: true,
  });
  return r.status === 0;
}

function dockerCmd() {
  return IS_WIN ? 'docker.exe' : 'docker';
}

function runDocker(args, opts = {}) {
  const r = spawnSync(dockerCmd(), args, {
    stdio: opts.capture ? 'pipe' : 'inherit',
    env: opts.env || process.env,
    encoding: opts.capture ? 'utf8' : undefined,
    cwd: opts.cwd || ROOT,
    shell: IS_WIN,
    windowsHide: true,
  });
  return r;
}

function ensureDocker() {
  const dockerHelp = IS_WIN
    ? 'https://docs.docker.com/desktop/setup/install/windows-install/'
    : 'https://docs.docker.com/desktop/';
  if (!which('docker')) {
    die(`Docker is required. Install Docker Desktop: ${dockerHelp}`);
  }
  const info = runDocker(['info'], { capture: true });
  if (info.status !== 0) {
    die('Docker is installed but not running. Start Docker Desktop and retry.');
  }
  const compose = runDocker(['compose', 'version'], { capture: true });
  if (compose.status !== 0) {
    die('Docker Compose v2 is required (`docker compose`). Update Docker Desktop.');
  }
}

function projectName() {
  return process.env.EXPEDITION_PROJECT || 'panw-expedition';
}

function composeEnv() {
  return {
    ...process.env,
    EXPEDITION_PORT: DEFAULT_PORT,
    EXPEDITION_HTTP_PORT: DEFAULT_HTTP_PORT,
    EXPEDITION_IMAGE: process.env.EXPEDITION_IMAGE || '',
    COMPOSE_PROJECT_NAME: projectName(),
    // Avoid CRLF surprises when Compose reads bind-mounted shell scripts on Windows
    COMPOSE_CONVERT_WINDOWS_PATHS: '1',
  };
}

function compose(args, opts = {}) {
  // Forward compose file as a forward-slash path — Docker Engine accepts this on Windows
  const composeFile = COMPOSE_FILE.split(path.sep).join('/');
  const full = ['compose', '-f', composeFile, ...args];
  const r = runDocker(full, {
    capture: opts.capture,
    env: composeEnv(),
    cwd: ROOT,
  });
  if (opts.allowFail) return r;
  if (r.status !== 0) {
    process.exit(r.status || 1);
  }
  return r;
}

function printBanner() {
  console.log(`
  PA-Converter (Expedition 5.45.4) — macOS / Windows / Linux via Docker
  UI:   https://localhost:${DEFAULT_PORT}
  HTTP: http://localhost:${DEFAULT_HTTP_PORT}
  Login (seed): admin / paloalto

  Commands: start | stop | restart | status | logs | build | url
`);
}

function cmdStart() {
  ensureDocker();
  if (!fs.existsSync(path.join(ROOT, 'app', 'index.html'))) {
    die(`App tree missing at ${path.join(ROOT, 'app')}. Reinstall the package.`);
  }
  if (IS_WIN) {
    console.log('Windows tip: first build can take several minutes; keep Docker Desktop running.');
  }
  console.log(`Starting Expedition on https://localhost:${DEFAULT_PORT} …`);
  compose(['up', '-d', '--build']);
  console.log(`
Expedition is starting.
  Open:  https://localhost:${DEFAULT_PORT}
  Login: admin / paloalto
  Logs:  npx @sas3/pa-converter logs
  Stop:  npx @sas3/pa-converter stop

Note: accept the self-signed TLS warning in your browser.
`);
}

function cmdStop() {
  ensureDocker();
  compose(['down']);
}

function cmdRestart() {
  ensureDocker();
  compose(['down']);
  compose(['up', '-d', '--build']);
}

function cmdStatus() {
  ensureDocker();
  compose(['ps']);
}

function cmdLogs() {
  ensureDocker();
  const follow = process.argv.includes('-f') || process.argv.includes('--follow');
  compose(follow ? ['logs', '-f', '--tail', '200'] : ['logs', '--tail', '200']);
}

function cmdBuild() {
  ensureDocker();
  compose(['build']);
}

function cmdUrl() {
  console.log(`https://localhost:${DEFAULT_PORT}`);
}

function cmdHelp() {
  printBanner();
  console.log(`Usage: pa-converter <command>   (alias: expedition)

  start      Build (if needed) and start the stack
  stop       Stop and remove containers (keeps DB volume)
  restart    Stop then start
  status     Show container status
  logs [-f]  Show logs
  build      Build images only
  url        Print UI URL
  publish-help  How to publish to a private registry

Env:
  EXPEDITION_PORT       HTTPS host port (default 18443)
  EXPEDITION_HTTP_PORT  HTTP host port (default 18080)
  EXPEDITION_IMAGE      Optional prebuilt web image
  EXPEDITION_PROJECT    Compose project name (default panw-expedition)

Host: ${os.platform()} ${os.arch()} | package root: ${ROOT}
`);
}

function cmdPublishHelp() {
  console.log(`
Public npm (@sas3):
  npm publish --access public

Install / run (no auth):
  npx @sas3/pa-converter@5.46.13 start

Windows MSI:
  installer\\windows\\build.ps1   →  dist\\PA-Converter-5.46.13.msi

Host: ${os.platform()} ${os.arch()} | package root: ${ROOT}
`);
}

const cmd = process.argv[2] || 'help';
const map = {
  start: cmdStart,
  stop: cmdStop,
  restart: cmdRestart,
  status: cmdStatus,
  logs: cmdLogs,
  build: cmdBuild,
  url: cmdUrl,
  help: cmdHelp,
  '-h': cmdHelp,
  '--help': cmdHelp,
  'publish-help': cmdPublishHelp,
};

if (!map[cmd]) {
  die(`unknown command '${cmd}'. Try: pa-converter help`);
}
map[cmd]();
