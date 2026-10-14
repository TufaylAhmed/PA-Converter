#!/usr/bin/env node
'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const NATIVE = path.join(ROOT, 'native');
const COMPOSE_FILE = path.join(ROOT, 'docker', 'docker-compose.yml');
const DEFAULT_PORT = process.env.EXPEDITION_PORT || '18443';
const DEFAULT_HTTP_PORT = process.env.EXPEDITION_HTTP_PORT || '18080';
const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';
const IS_LINUX = process.platform === 'linux';
const USE_DOCKER = String(process.env.PA_CONVERTER_RUNTIME || '').toLowerCase() === 'docker';

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

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, {
    stdio: opts.capture ? 'pipe' : 'inherit',
    env: opts.env || process.env,
    encoding: opts.capture ? 'utf8' : undefined,
    cwd: opts.cwd || ROOT,
    shell: opts.shell != null ? opts.shell : IS_WIN,
    windowsHide: true,
  });
  return r;
}

function printBanner() {
  console.log(`
  PA-Converter (Expedition 5.45.4) — native runtime (no containers)
  UI:   https://localhost:${DEFAULT_PORT}
  HTTP: http://localhost:${DEFAULT_HTTP_PORT}
  Login (seed): admin / paloalto

  Commands: start | stop | restart | status | logs | url
`);
}

function ensureAppTree() {
  if (!fs.existsSync(path.join(ROOT, 'app', 'index.html'))) {
    die(`App tree missing at ${path.join(ROOT, 'app')}. Reinstall the package.`);
  }
  if (!fs.existsSync(path.join(NATIVE, 'start.sh'))) {
    die(`Native runtime missing at ${NATIVE}. Reinstall the package.`);
  }
}

function winToWslPath(winPath) {
  const resolved = path.resolve(winPath);
  const m = /^([A-Za-z]):[\\/](.*)$/.exec(resolved);
  if (!m) return resolved.replace(/\\/g, '/');
  const drive = m[1].toLowerCase();
  const rest = m[2].replace(/\\/g, '/');
  return `/mnt/${drive}/${rest}`;
}

function listWslDistros() {
  const r = spawnSync('wsl.exe', ['-l', '-q'], {
    encoding: 'utf8',
    windowsHide: true,
    shell: false,
  });
  let text = r.stdout || '';
  // Strip UTF-16 null pads if present
  if (text.includes('\u0000')) {
    text = Buffer.from(text, 'utf8').toString('utf16le');
  }
  return text
    .split(/\r?\n/)
    .map((s) => s.replace(/\0/g, '').trim())
    .filter(Boolean);
}

function pickWslDistro() {
  const names = listWslDistros();
  if (!names.length) {
    die(
      'No WSL distro found. Install WSL2 Ubuntu (wsl --install -d Ubuntu) or run the PA-Converter MSI first.'
    );
  }
  if (names.includes('PA-Converter')) return 'PA-Converter';
  const ubuntu = names.find((n) => /^Ubuntu/i.test(n));
  return ubuntu || names[0];
}

function wslBash(scriptBody, opts = {}) {
  const distro = opts.distro || pickWslDistro();
  const rootWsl = winToWslPath(ROOT);
  const env =
    `export PA_CONVERTER_ROOT='${rootWsl}' ` +
    `EXPEDITION_PORT='${DEFAULT_PORT}' EXPEDITION_HTTP_PORT='${DEFAULT_HTTP_PORT}' ` +
    `DB_HOST=127.0.0.1 RABBITMQ_HOST=127.0.0.1; ` +
    `cd '${rootWsl}'`;
  const full = `${env}; ${scriptBody}`;
  console.log(`pa-converter: WSL[${distro}] …`);
  const r = spawnSync(
    'wsl.exe',
    ['-d', distro, '-u', 'root', '--', 'bash', '-lc', full],
    {
      stdio: opts.capture ? 'pipe' : 'inherit',
      encoding: opts.capture ? 'utf8' : undefined,
      windowsHide: true,
      shell: false,
    }
  );
  return r;
}

function sudoBash(scriptPath, extraArgs = []) {
  const args = ['bash', scriptPath, ...extraArgs];
  if (process.getuid && process.getuid() === 0) {
    return run('bash', [scriptPath, ...extraArgs], { shell: false });
  }
  if (!which('sudo')) {
    die('sudo is required to install/start native services.');
  }
  return run('sudo', ['-E', 'env', `PA_CONVERTER_ROOT=${ROOT}`, ...args], {
    shell: false,
    env: {
      ...process.env,
      PA_CONVERTER_ROOT: ROOT,
      EXPEDITION_PORT: DEFAULT_PORT,
      EXPEDITION_HTTP_PORT: DEFAULT_HTTP_PORT,
    },
  });
}

/* ---------- Docker legacy (opt-in) ---------- */

function dockerCmd() {
  return IS_WIN ? 'docker.exe' : 'docker';
}

function runDocker(args, opts = {}) {
  return run(dockerCmd(), args, {
    capture: opts.capture,
    env: opts.env || process.env,
    cwd: opts.cwd || ROOT,
    shell: IS_WIN,
  });
}

function ensureDocker() {
  const dockerHelp = IS_WIN
    ? 'https://docs.docker.com/desktop/setup/install/windows-install/'
    : 'https://docs.docker.com/desktop/';
  if (!which('docker')) {
    die(`Docker is required when PA_CONVERTER_RUNTIME=docker. Install: ${dockerHelp}`);
  }
  const info = runDocker(['info'], { capture: true });
  if (info.status !== 0) {
    die('Docker is installed but not running. Start Docker Desktop and retry.');
  }
  const compose = runDocker(['compose', 'version'], { capture: true });
  if (compose.status !== 0) {
    die('Docker Compose v2 is required (`docker compose`).');
  }
}

function compose(args, opts = {}) {
  const composeFile = COMPOSE_FILE.split(path.sep).join('/');
  const full = ['compose', '-f', composeFile, ...args];
  const r = runDocker(full, {
    capture: opts.capture,
    env: {
      ...process.env,
      EXPEDITION_PORT: DEFAULT_PORT,
      EXPEDITION_HTTP_PORT: DEFAULT_HTTP_PORT,
      COMPOSE_PROJECT_NAME: process.env.EXPEDITION_PROJECT || 'panw-expedition',
      COMPOSE_CONVERT_WINDOWS_PATHS: '1',
    },
    cwd: ROOT,
  });
  if (opts.allowFail) return r;
  if (r.status !== 0) process.exit(r.status || 1);
  return r;
}

function cmdDockerStart() {
  ensureDocker();
  ensureAppTree();
  console.log(`Starting Expedition (Docker) on https://localhost:${DEFAULT_PORT} …`);
  compose(['up', '-d', '--build']);
  openUiHint();
}

function cmdDockerStop() {
  ensureDocker();
  compose(['down']);
}

function cmdDockerStatus() {
  ensureDocker();
  compose(['ps']);
}

function cmdDockerLogs() {
  ensureDocker();
  const follow = process.argv.includes('-f') || process.argv.includes('--follow');
  compose(follow ? ['logs', '-f', '--tail', '200'] : ['logs', '--tail', '200']);
}

/* ---------- Native ---------- */

function openUiHint() {
  console.log(`
Expedition is starting.
  Open:  https://localhost:${DEFAULT_PORT}
  Login: admin / paloalto
  Logs:  npx @sequr3/pa-converter logs
  Stop:  npx @sequr3/pa-converter stop

Note: accept the self-signed TLS warning in your browser.
`);
}

function cmdStartNative() {
  ensureAppTree();
  if (IS_WIN) {
    if (!which('wsl')) {
      die('WSL2 is required on Windows. Install with: wsl --install -d Ubuntu');
    }
    console.log(
      `Starting native stack in WSL (first run installs packages — several minutes)…`
    );
    const r = wslBash(
      `bash '${winToWslPath(path.join(NATIVE, 'start.sh'))}'`
    );
    if (r.status !== 0) process.exit(r.status || 1);
    openUiHint();
    return;
  }
  if (IS_MAC) {
    const installMac = path.join(NATIVE, 'install-macos.sh');
    if (!fs.existsSync(installMac)) {
      die('macOS installer missing (native/install-macos.sh).');
    }
    console.log('Starting native stack on macOS (Homebrew)…');
    const r = run('bash', [installMac, 'start'], {
      shell: false,
      env: {
        ...process.env,
        PA_CONVERTER_ROOT: ROOT,
        EXPEDITION_PORT: DEFAULT_PORT,
        EXPEDITION_HTTP_PORT: DEFAULT_HTTP_PORT,
      },
    });
    if (r.status !== 0) process.exit(r.status || 1);
    openUiHint();
    return;
  }
  if (IS_LINUX) {
    console.log('Starting native stack (apt)…');
    const r = sudoBash(path.join(NATIVE, 'start.sh'));
    if (r.status !== 0) process.exit(r.status || 1);
    openUiHint();
    return;
  }
  die(`Unsupported platform: ${process.platform}`);
}

function cmdStopNative() {
  if (IS_WIN) {
    const r = wslBash(`bash '${winToWslPath(path.join(NATIVE, 'stop.sh'))}'`);
    if (r.status !== 0) process.exit(r.status || 1);
    return;
  }
  if (IS_MAC) {
    const r = run('bash', [path.join(NATIVE, 'install-macos.sh'), 'stop'], {
      shell: false,
      env: { ...process.env, PA_CONVERTER_ROOT: ROOT },
    });
    if (r.status !== 0) process.exit(r.status || 1);
    return;
  }
  if (IS_LINUX) {
    const r = sudoBash(path.join(NATIVE, 'stop.sh'));
    if (r.status !== 0) process.exit(r.status || 1);
    return;
  }
  die(`Unsupported platform: ${process.platform}`);
}

function cmdStatusNative() {
  if (IS_WIN) {
    const r = wslBash(`bash '${winToWslPath(path.join(NATIVE, 'status.sh'))}'`);
    if (r.status !== 0) process.exit(r.status || 1);
    return;
  }
  if (IS_MAC) {
    const r = run('bash', [path.join(NATIVE, 'install-macos.sh'), 'status'], {
      shell: false,
      env: { ...process.env, PA_CONVERTER_ROOT: ROOT },
    });
    if (r.status !== 0) process.exit(r.status || 1);
    return;
  }
  if (IS_LINUX) {
    const r = run('bash', [path.join(NATIVE, 'status.sh')], {
      shell: false,
      env: { ...process.env, PA_CONVERTER_ROOT: ROOT },
    });
    if (r.status !== 0) process.exit(r.status || 1);
    return;
  }
  die(`Unsupported platform: ${process.platform}`);
}

function cmdLogsNative() {
  const follow = process.argv.includes('-f') || process.argv.includes('--follow');
  const followFlag = follow ? '-f' : '';
  if (IS_WIN) {
    const r = wslBash(
      `bash '${winToWslPath(path.join(NATIVE, 'logs.sh'))}' ${followFlag}`.trim()
    );
    if (r.status !== 0) process.exit(r.status || 1);
    return;
  }
  if (IS_MAC) {
    const r = run(
      'bash',
      [path.join(NATIVE, 'install-macos.sh'), 'logs', ...(follow ? ['-f'] : [])],
      { shell: false, env: { ...process.env, PA_CONVERTER_ROOT: ROOT } }
    );
    if (r.status !== 0) process.exit(r.status || 1);
    return;
  }
  const r = run(
    'bash',
    [path.join(NATIVE, 'logs.sh'), ...(follow ? ['-f'] : [])],
    { shell: false, env: { ...process.env, PA_CONVERTER_ROOT: ROOT } }
  );
  if (r.status !== 0) process.exit(r.status || 1);
}

function cmdStart() {
  if (USE_DOCKER) return cmdDockerStart();
  return cmdStartNative();
}
function cmdStop() {
  if (USE_DOCKER) return cmdDockerStop();
  return cmdStopNative();
}
function cmdRestart() {
  cmdStop();
  cmdStart();
}
function cmdStatus() {
  if (USE_DOCKER) return cmdDockerStatus();
  return cmdStatusNative();
}
function cmdLogs() {
  if (USE_DOCKER) return cmdDockerLogs();
  return cmdLogsNative();
}

function cmdBuild() {
  if (USE_DOCKER) {
    ensureDocker();
    compose(['build']);
    return;
  }
  console.log(
    'Native runtime has no image build. Run: pa-converter start (installs packages on first run).'
  );
  console.log('Optional Docker build: PA_CONVERTER_RUNTIME=docker pa-converter build');
}

function cmdUrl() {
  console.log(`https://localhost:${DEFAULT_PORT}`);
}

function cmdHelp() {
  printBanner();
  console.log(`Usage: pa-converter <command>   (alias: expedition)

  start      Install (if needed) and start native services
  stop       Stop Apache / MariaDB / RabbitMQ / agent
  restart    Stop then start
  status     Show service status
  logs [-f]  Show Apache + agent logs
  url        Print UI URL
  build      (Docker opt-in only) build images

Windows: requires WSL2 (Ubuntu or PA-Converter distro). No Docker Desktop.
macOS:   Homebrew + PHP 7.4 tap (shivammathur/php).
Linux:   apt packages (Ubuntu 20.04/22.04 recommended).

Env:
  EXPEDITION_PORT            HTTPS port (default 18443)
  EXPEDITION_HTTP_PORT       HTTP port (default 18080)
  PA_CONVERTER_RUNTIME=docker  Use legacy Docker Compose instead

Host: ${os.platform()} ${os.arch()} | package root: ${ROOT}
`);
}

function cmdPublishHelp() {
  console.log(`
Public npm (@sequr3):
  npm publish --access public

Install / run (no auth, no Docker):
  npx @sequr3/pa-converter@5.46.18 start

Windows MSI:
  installer\\windows\\build.ps1   →  dist\\PA-Converter-5.46.18.msi

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
