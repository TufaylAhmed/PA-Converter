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

function die(msg, code = 1) {
  console.error(`expedition: ${msg}`);
  process.exit(code);
}

function which(cmd) {
  const r = spawnSync(process.platform === 'win32' ? 'where' : 'which', [cmd], {
    encoding: 'utf8',
  });
  return r.status === 0;
}

function ensureDocker() {
  if (!which('docker')) {
    die('Docker is required. Install Docker Desktop for macOS: https://docs.docker.com/desktop/');
  }
  const info = spawnSync('docker', ['info'], { encoding: 'utf8' });
  if (info.status !== 0) {
    die('Docker is installed but not running. Start Docker Desktop and retry.');
  }
  const compose = spawnSync('docker', ['compose', 'version'], { encoding: 'utf8' });
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
  };
}

function compose(args, opts = {}) {
  const full = ['compose', '-f', COMPOSE_FILE, ...args];
  const r = spawnSync('docker', full, {
    stdio: opts.capture ? 'pipe' : 'inherit',
    env: composeEnv(),
    encoding: opts.capture ? 'utf8' : undefined,
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
  Expedition (private package) — macOS/Linux via Docker
  UI:   https://localhost:${DEFAULT_PORT}
  HTTP: http://localhost:${DEFAULT_HTTP_PORT}
  Login (seed): admin / paloalto

  Commands: start | stop | restart | status | logs | build | url
`);
}

function cmdStart() {
  ensureDocker();
  if (!fs.existsSync(path.join(ROOT, 'app', 'index.html'))) {
    die(`App tree missing at ${path.join(ROOT, 'app')}. Re-extract or rebuild the package.`);
  }
  console.log(`Starting Expedition on https://localhost:${DEFAULT_PORT} …`);
  compose(['up', '-d', '--build']);
  console.log(`
Expedition is starting.
  Open:  https://localhost:${DEFAULT_PORT}
  Login: admin / paloalto
  Logs:  expedition logs
  Stop:  expedition stop

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
  console.log(`Usage: expedition <command>

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
  EXPEDITION_IMAGE      Optional prebuilt web image (skips local Dockerfile build context app/)
  EXPEDITION_PROJECT    Compose project name (default panw-expedition)
`);
}

function cmdPublishHelp() {
  console.log(`
Private publish (do NOT use public npmjs.org)

1) Container image (recommended — app is large):
   docker build -t <your-private-registry>/expedition-web:5.45.4 -f docker/web/Dockerfile .
   docker push <your-private-registry>/expedition-web:5.45.4

   Consumers:
   EXPEDITION_IMAGE=<your-private-registry>/expedition-web:5.45.4 expedition start

2) npm package (GitHub Packages / Artifactory / Verdaccio):
   # package.json already has "private": true and publishConfig for GitHub Packages
   npm login --registry=https://npm.pkg.github.com
   npm publish --registry=https://npm.pkg.github.com

   Or point publishConfig.registry at your Artifactory npm repo.

3) Install internally:
   npm install -g @panw/expedition --registry=https://npm.pkg.github.com
   expedition start

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
  die(`unknown command '${cmd}'. Try: expedition help`);
}
map[cmd]();
