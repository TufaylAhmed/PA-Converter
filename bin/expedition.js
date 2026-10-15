#!/usr/bin/env node
'use strict';

/**
 * PA-Converter CLI
 *
 * Default runtimes:
 *   macOS / Linux → Podman (Compose) — fast, faithful Expedition stack
 *   Windows       → WSL native (MSI / apt) — no Docker Desktop
 *
 * Override with PA_CONVERTER_RUNTIME=podman|docker|native
 */

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

/** Resolve a binary: PATH first, then known install locations (Podman.app). */
function findBin(name, extraPaths = []) {
  const finder = IS_WIN ? 'where' : 'which';
  const r = spawnSync(finder, [name], {
    encoding: 'utf8',
    shell: IS_WIN,
    windowsHide: true,
  });
  if (r.status === 0) {
    const line = String(r.stdout || '')
      .split(/\r?\n/)
      .map((s) => s.trim())
      .find(Boolean);
    if (line && fs.existsSync(line)) return line;
  }
  for (const p of extraPaths) {
    if (p && fs.existsSync(p)) return p;
  }
  return null;
}

const PODMAN_BIN = findBin('podman', [
  '/opt/podman/bin/podman',
  '/usr/local/bin/podman',
  '/opt/homebrew/bin/podman',
  path.join(os.homedir(), '.local/bin/podman'),
]);

const WEB_IMAGE =
  process.env.EXPEDITION_IMAGE || 'panw/expedition-web:5.45.4';

function wantForceBuild() {
  return (
    process.argv.includes('--build') ||
    process.env.PA_CONVERTER_FORCE_BUILD === '1'
  );
}

function imageExists(engine, image) {
  if (engine === 'podman') {
    if (!PODMAN_BIN) return false;
    const r = run(PODMAN_BIN, ['image', 'exists', image], {
      capture: true,
      shell: false,
    });
    return r.status === 0;
  }
  const r = run(dockerCmd(), ['image', 'inspect', image], {
    capture: true,
    shell: IS_WIN,
  });
  return r.status === 0;
}

function run(cmd, args, opts = {}) {
  return spawnSync(cmd, args, {
    stdio: opts.capture ? 'pipe' : 'inherit',
    env: opts.env || process.env,
    encoding: opts.capture ? 'utf8' : undefined,
    cwd: opts.cwd || ROOT,
    shell: opts.shell != null ? opts.shell : IS_WIN,
    windowsHide: true,
  });
}

function ensureAppTree() {
  if (!fs.existsSync(path.join(ROOT, 'app', 'index.html'))) {
    die(`App tree missing at ${path.join(ROOT, 'app')}. Reinstall the package.`);
  }
  if (!fs.existsSync(COMPOSE_FILE)) {
    die(`Compose file missing at ${COMPOSE_FILE}. Reinstall the package.`);
  }
}

function openUiHint(runtime) {
  console.log(`
Expedition is starting (${runtime}).
  Open:  https://localhost:${DEFAULT_PORT}
  Login: admin / paloalto
  Logs:  npx @sequr3/pa-converter logs
  Stop:  npx @sequr3/pa-converter stop

Note: accept the self-signed TLS warning in your browser.
`);
}

function podmanComposeEnv() {
  // Avoid Docker Desktop's credsStore ("desktop") poisoning anonymous Hub pulls
  // when podman compose shells out to docker-compose.
  const emptyAuthDir = path.join(os.tmpdir(), 'pa-converter-podman-auth');
  try {
    fs.mkdirSync(emptyAuthDir, { recursive: true });
    const cfg = path.join(emptyAuthDir, 'config.json');
    if (!fs.existsSync(cfg)) {
      fs.writeFileSync(cfg, '{}\n', 'utf8');
    }
  } catch (_) {
    /* ignore */
  }
  return {
    ...process.env,
    EXPEDITION_PORT: DEFAULT_PORT,
    EXPEDITION_HTTP_PORT: DEFAULT_HTTP_PORT,
    COMPOSE_PROJECT_NAME: process.env.EXPEDITION_PROJECT || 'panw-expedition',
    COMPOSE_CONVERT_WINDOWS_PATHS: '1',
    DOCKER_CONFIG: emptyAuthDir,
    REGISTRY_AUTH_FILE: path.join(os.homedir(), '.config', 'containers', 'auth.json'),
  };
}

function composeEnv() {
  return {
    ...process.env,
    EXPEDITION_PORT: DEFAULT_PORT,
    EXPEDITION_HTTP_PORT: DEFAULT_HTTP_PORT,
    COMPOSE_PROJECT_NAME: process.env.EXPEDITION_PROJECT || 'panw-expedition',
    COMPOSE_CONVERT_WINDOWS_PATHS: '1',
  };
}

function composeFileArg() {
  return COMPOSE_FILE.split(path.sep).join('/');
}

/** Resolve runtime: env override, else platform default. */
function resolveRuntime() {
  const forced = String(process.env.PA_CONVERTER_RUNTIME || '')
    .toLowerCase()
    .trim();
  if (forced === 'podman' || forced === 'docker' || forced === 'native') {
    return forced;
  }
  // Windows MSI / npx path stays WSL-native (proven).
  if (IS_WIN) return 'native';
  // macOS + Linux: Podman first (incl. /opt/podman/bin — often missing from npx PATH).
  if (IS_MAC || IS_LINUX) {
    if (PODMAN_BIN) return 'podman';
    if (which('docker')) return 'docker';
    return 'podman'; // will print install instructions
  }
  return 'native';
}

/* ---------- Podman ---------- */

function podmanInfoOk() {
  if (!PODMAN_BIN) return false;
  const info = run(PODMAN_BIN, ['info'], { capture: true, shell: false });
  return info.status === 0;
}

function machineListText() {
  const list = run(
    PODMAN_BIN,
    ['machine', 'list', '--format', '{{.Name}}\t{{.Running}}'],
    { capture: true, shell: false }
  );
  return (list.stdout || '').trim();
}

function machineLooksRunning(listOut) {
  // Formats: "name\ttrue" or "name true" / "Currently running"
  return /\btrue\b/i.test(listOut) || /Currently running/i.test(listOut);
}

function startExitMeansAlreadyUp(status, combined) {
  if (status === 0) return true;
  const t = String(combined || '').toLowerCase();
  return (
    t.includes('already running') ||
    t.includes('is already running') ||
    t.includes('vm already running')
  );
}

function sleepMs(ms) {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  } catch (_) {
    spawnSync(process.execPath, ['-e', `setTimeout(()=>{},${ms})`], {
      stdio: 'ignore',
      windowsHide: true,
    });
  }
}

function waitForPodmanInfo(attempts = 15, delayMs = 1000) {
  for (let i = 0; i < attempts; i++) {
    if (podmanInfoOk()) return true;
    sleepMs(delayMs);
  }
  return podmanInfoOk();
}

/**
 * Machine can report Running=true while gvproxy/API socket is dead
 * (common after sleep / Docker Desktop fighting for sockets).
 * Recover: start if needed; if still unreachable, stop+start once.
 */
function ensurePodmanMachineReady() {
  let listOut = machineListText();
  if (!listOut) {
    console.log(
      'pa-converter: initializing Podman machine (one-time, a few minutes)…'
    );
    const init = run(
      PODMAN_BIN,
      ['machine', 'init', '--cpus', '4', '--memory', '4096', '--disk-size', '60'],
      { shell: false }
    );
    if (init.status !== 0) {
      die(
        'podman machine init failed. Run: podman machine init && podman machine start'
      );
    }
    listOut = machineListText();
  }

  if (!machineLooksRunning(listOut)) {
    console.log('pa-converter: starting Podman machine…');
    const st = run(PODMAN_BIN, ['machine', 'start'], { capture: true, shell: false });
    const combined = `${st.stdout || ''}\n${st.stderr || ''}`;
    if (!startExitMeansAlreadyUp(st.status, combined)) {
      // still try info — some versions return non-zero with recoverable noise
      if (!waitForPodmanInfo(8, 1500)) {
        die(
          `Could not start Podman machine.\n${combined.trim() || 'Run: podman machine start'}`
        );
      }
      return;
    }
  }

  if (waitForPodmanInfo(10, 1000)) return;

  // Stale "running" VM / dead API socket — bounce once
  console.log(
    'pa-converter: Podman machine looks up but API is unreachable; restarting machine…'
  );
  run(PODMAN_BIN, ['machine', 'stop'], { capture: true, shell: false });
  const st2 = run(PODMAN_BIN, ['machine', 'start'], { capture: true, shell: false });
  const combined2 = `${st2.stdout || ''}\n${st2.stderr || ''}`;
  if (!startExitMeansAlreadyUp(st2.status, combined2) && !waitForPodmanInfo(15, 1500)) {
    die(
      'Podman API still unreachable after machine restart.\n' +
        '  Try: podman machine stop && podman machine start\n' +
        '  Then: podman info\n' +
        (combined2.trim() ? `\n${combined2.trim()}` : '')
    );
  }
  if (!waitForPodmanInfo(15, 1500)) {
    die(
      'Podman API still unreachable. Try: podman machine stop && podman machine start'
    );
  }
}

function ensurePodman() {
  if (!PODMAN_BIN) {
    if (IS_MAC) {
      die(
        'Podman is required on macOS (not found in PATH or /opt/podman/bin).\n' +
          '  Install:  https://podman.io → Podman Desktop, or: brew install podman\n' +
          '  Then:     podman machine init && podman machine start\n' +
          '  PATH tip: export PATH="/opt/podman/bin:$PATH"\n' +
          '  Retry:    npx @sequr3/pa-converter start'
      );
    }
    die(
      'Podman is required. Install: https://podman.io/docs/installation\n' +
        'Or set PA_CONVERTER_RUNTIME=docker|native'
    );
  }

  // macOS / Windows Podman uses a VM — ensure one is up and the API socket works
  if (IS_MAC || IS_WIN) {
    if (!podmanInfoOk()) {
      ensurePodmanMachineReady();
    }
  } else if (!podmanInfoOk()) {
    die('Podman is installed but not usable.');
  }

  // Prefer `podman compose` (uses compose provider); fall back to podman-compose
  const cv = run(PODMAN_BIN, ['compose', 'version'], {
    capture: true,
    shell: false,
  });
  if (cv.status !== 0 && !which('podman-compose')) {
    die(
      'Podman Compose is required.\n' +
        '  macOS: brew install podman-compose   OR ensure docker-compose is on PATH\n' +
        '  See: man podman-compose'
    );
  }
}

function stopConflictingNativeMac() {
  if (!IS_MAC) return;
  // Free 18443/18080 if a previous Homebrew httpd is still bound
  const installMac = path.join(NATIVE, 'install-macos.sh');
  if (!fs.existsSync(installMac)) return;
  console.log('pa-converter: stopping previous native Homebrew stack (if any)…');
  run('bash', [installMac, 'stop'], {
    shell: false,
    capture: true,
    env: { ...process.env, PA_CONVERTER_ROOT: ROOT },
  });
}

function podmanCompose(args, opts = {}) {
  const composeFile = composeFileArg();
  const env = podmanComposeEnv();
  let r = run(PODMAN_BIN, ['compose', '-f', composeFile, ...args], {
    capture: opts.capture,
    env,
    cwd: ROOT,
    shell: false,
  });
  if (r.status !== 0 && which('podman-compose')) {
    r = run('podman-compose', ['-f', composeFile, ...args], {
      capture: opts.capture,
      env,
      cwd: ROOT,
      shell: false,
    });
  }
  if (opts.allowFail) return r;
  if (r.status !== 0) process.exit(r.status || 1);
  return r;
}

/** Align SparkRAM with Expedition health check (80% MemTotal), even on older images. */
function syncSparkRam(engine) {
  // Single-quoted-safe one-liner (no nested heredocs)
  const script =
    "MEM_KB=$(awk '/MemTotal/{print $2}' /proc/meminfo); " +
    'SUGG_RAM_MB=$((MEM_KB*80/100/1024)); [ "$SUGG_RAM_MB" -lt 1024 ] && SUGG_RAM_MB=1024; ' +
    'CPUS=$(nproc); SUGG=$((CPUS*80/100)); [ "$SUGG" -lt 1 ] && SUGG=1; ' +
    "printf '%s\\n' '<?php' \"define('NumCPUs', $SUGG);\" \"define('TotalCPUs', $CPUS);\" \"define('SparkRAM', '${SUGG_RAM_MB}m');\" " +
    '> /home/userSpace/environmentParameters.php; ' +
    "printf '%s\\n' '<?php' '$suggestedEnvironmentParameters = [' \" 'NumCPUs'=>$SUGG,\" \" 'TotalCPUs'=>$CPUS,\" \" 'SparkRAM'=>'${SUGG_RAM_MB}m',\" '];' " +
    '> /home/userSpace/tempEnvironmentParameters.php; ' +
    'chown www-data:www-data /home/userSpace/environmentParameters.php /home/userSpace/tempEnvironmentParameters.php 2>/dev/null || true; ' +
    'echo "SparkRAM=${SUGG_RAM_MB}m NumCPUs=$SUGG/$CPUS"';

  const execArgs = [
    'compose',
    '-f',
    composeFileArg(),
    'exec',
    '-T',
    'web',
    'bash',
    '-lc',
    script,
  ];

  sleepMs(2500);
  let r;
  if (engine === 'podman') {
    r = run(PODMAN_BIN, execArgs, {
      capture: true,
      shell: false,
      env: podmanComposeEnv(),
    });
    if (r.status !== 0 && which('podman-compose')) {
      r = run(
        'podman-compose',
        ['-f', composeFileArg(), 'exec', '-T', 'web', 'bash', '-lc', script],
        { capture: true, shell: false, env: podmanComposeEnv() }
      );
    }
  } else {
    r = run(dockerCmd(), execArgs, {
      capture: true,
      shell: IS_WIN,
      env: composeEnv(),
    });
  }
  const out = `${r.stdout || ''}${r.stderr || ''}`.trim();
  if (r.status === 0 && out) {
    console.log(`pa-converter: ${out.split('\n').pop()}`);
  }
}

function cmdPodmanStart() {
  ensureAppTree();
  ensurePodman();
  stopConflictingNativeMac();
  const force = wantForceBuild();
  const hasImg = imageExists('podman', WEB_IMAGE);
  console.log(
    `Starting Expedition via Podman on https://localhost:${DEFAULT_PORT} …`
  );
  if (!hasImg || force) {
    console.log(
      force
        ? '  [####----------------] build  forcing image rebuild (several minutes)…'
        : '  [####----------------] build  first run — building web image (several minutes)…'
    );
    podmanCompose(['up', '-d', '--build']);
    console.log('  [####################] build  image ready');
  } else {
    console.log(`  [####################] start  reusing ${WEB_IMAGE} (pass --build to rebuild)`);
    podmanCompose(['up', '-d']);
  }
  syncSparkRam('podman');
  openUiHint('Podman');
}

function cmdPodmanStop() {
  ensurePodman();
  podmanCompose(['down']);
}

function cmdPodmanStatus() {
  ensurePodman();
  podmanCompose(['ps']);
}

function cmdPodmanLogs() {
  ensurePodman();
  const follow = process.argv.includes('-f') || process.argv.includes('--follow');
  podmanCompose(follow ? ['logs', '-f', '--tail', '200'] : ['logs', '--tail', '200']);
}

function cmdPodmanBuild() {
  ensurePodman();
  podmanCompose(['build']);
}

/* ---------- Docker ---------- */

function dockerCmd() {
  return IS_WIN ? 'docker.exe' : 'docker';
}

function ensureDocker() {
  if (!which('docker')) {
    die('Docker not found. Install Docker Desktop or use Podman (default on macOS).');
  }
  const info = run(dockerCmd(), ['info'], { capture: true, shell: IS_WIN });
  if (info.status !== 0) {
    die('Docker is installed but not running. Start Docker Desktop and retry.');
  }
  const compose = run(dockerCmd(), ['compose', 'version'], {
    capture: true,
    shell: IS_WIN,
  });
  if (compose.status !== 0) {
    die('Docker Compose v2 is required (`docker compose`).');
  }
}

function dockerCompose(args, opts = {}) {
  const composeFile = composeFileArg();
  const r = run(dockerCmd(), ['compose', '-f', composeFile, ...args], {
    capture: opts.capture,
    env: composeEnv(),
    cwd: ROOT,
    shell: IS_WIN,
  });
  if (opts.allowFail) return r;
  if (r.status !== 0) process.exit(r.status || 1);
  return r;
}

function cmdDockerStart() {
  ensureAppTree();
  ensureDocker();
  const force = wantForceBuild();
  const hasImg = imageExists('docker', WEB_IMAGE);
  console.log(
    `Starting Expedition via Docker on https://localhost:${DEFAULT_PORT} …`
  );
  if (!hasImg || force) {
    console.log(
      '(building web image — Spark layer can take several minutes; prefer Podman on macOS)'
    );
    dockerCompose(['up', '-d', '--build']);
  } else {
    console.log(`(reusing image ${WEB_IMAGE} — pass --build to rebuild)`);
    dockerCompose(['up', '-d']);
  }
  syncSparkRam('docker');
  openUiHint('Docker');
}

/* ---------- Native (Windows WSL / opt-in) ---------- */

function winToWslPath(winPath) {
  const resolved = path.resolve(winPath);
  const m = /^([A-Za-z]):[\\/](.*)$/.exec(resolved);
  if (!m) return resolved.replace(/\\/g, '/');
  return `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, '/')}`;
}

function listWslDistros() {
  const r = spawnSync('wsl.exe', ['-l', '-q'], {
    encoding: 'utf8',
    windowsHide: true,
    shell: false,
  });
  let text = r.stdout || '';
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
    die('No WSL distro found. Install: wsl --install -d Ubuntu');
  }
  if (names.includes('PA-Converter')) return 'PA-Converter';
  return names.find((n) => /^Ubuntu/i.test(n)) || names[0];
}

function wslBash(scriptBody) {
  const distro = pickWslDistro();
  const rootWsl = winToWslPath(ROOT);
  const full =
    `export PA_CONVERTER_ROOT='${rootWsl}' EXPEDITION_PORT='${DEFAULT_PORT}' ` +
    `EXPEDITION_HTTP_PORT='${DEFAULT_HTTP_PORT}' DB_HOST=127.0.0.1 RABBITMQ_HOST=127.0.0.1; ` +
    `cd '${rootWsl}'; ${scriptBody}`;
  console.log(`pa-converter: WSL[${distro}] …`);
  return spawnSync(
    'wsl.exe',
    ['-d', distro, '-u', 'root', '--', 'bash', '-lc', full],
    { stdio: 'inherit', windowsHide: true, shell: false }
  );
}

function sudoBash(scriptPath) {
  if (process.getuid && process.getuid() === 0) {
    return run('bash', [scriptPath], { shell: false });
  }
  return run(
    'sudo',
    ['-E', 'env', `PA_CONVERTER_ROOT=${ROOT}`, 'bash', scriptPath],
    {
      shell: false,
      env: {
        ...process.env,
        PA_CONVERTER_ROOT: ROOT,
        EXPEDITION_PORT: DEFAULT_PORT,
        EXPEDITION_HTTP_PORT: DEFAULT_HTTP_PORT,
      },
    }
  );
}

function cmdStartNative() {
  if (!fs.existsSync(path.join(NATIVE, 'start.sh')) && !IS_MAC) {
    die('Native runtime missing. Use Podman/Docker or reinstall the package.');
  }
  if (IS_WIN) {
    if (!which('wsl')) die('WSL2 required. Install: wsl --install -d Ubuntu');
    console.log('Starting native stack in WSL…');
    const r = wslBash(`bash '${winToWslPath(path.join(NATIVE, 'start.sh'))}'`);
    if (r.status !== 0) process.exit(r.status || 1);
    openUiHint('native/WSL');
    return;
  }
  if (IS_MAC) {
    console.log('Starting native Homebrew stack (legacy)…');
    const r = run('bash', [path.join(NATIVE, 'install-macos.sh'), 'start'], {
      shell: false,
      env: {
        ...process.env,
        PA_CONVERTER_ROOT: ROOT,
        EXPEDITION_PORT: DEFAULT_PORT,
        EXPEDITION_HTTP_PORT: DEFAULT_HTTP_PORT,
      },
    });
    if (r.status !== 0) process.exit(r.status || 1);
    openUiHint('native/macOS');
    return;
  }
  if (IS_LINUX) {
    const r = sudoBash(path.join(NATIVE, 'start.sh'));
    if (r.status !== 0) process.exit(r.status || 1);
    openUiHint('native/Linux');
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
    run('bash', [path.join(NATIVE, 'install-macos.sh'), 'stop'], {
      shell: false,
      env: { ...process.env, PA_CONVERTER_ROOT: ROOT },
    });
    return;
  }
  sudoBash(path.join(NATIVE, 'stop.sh'));
}

function cmdStatusNative() {
  if (IS_WIN) {
    wslBash(`bash '${winToWslPath(path.join(NATIVE, 'status.sh'))}'`);
    return;
  }
  if (IS_MAC) {
    run('bash', [path.join(NATIVE, 'install-macos.sh'), 'status'], {
      shell: false,
      env: { ...process.env, PA_CONVERTER_ROOT: ROOT },
    });
    return;
  }
  run('bash', [path.join(NATIVE, 'status.sh')], {
    shell: false,
    env: { ...process.env, PA_CONVERTER_ROOT: ROOT },
  });
}

function cmdLogsNative() {
  const follow = process.argv.includes('-f') || process.argv.includes('--follow');
  if (IS_WIN) {
    wslBash(
      `bash '${winToWslPath(path.join(NATIVE, 'logs.sh'))}' ${follow ? '-f' : ''}`.trim()
    );
    return;
  }
  if (IS_MAC) {
    run(
      'bash',
      [path.join(NATIVE, 'install-macos.sh'), 'logs', ...(follow ? ['-f'] : [])],
      { shell: false, env: { ...process.env, PA_CONVERTER_ROOT: ROOT } }
    );
    return;
  }
  run('bash', [path.join(NATIVE, 'logs.sh'), ...(follow ? ['-f'] : [])], {
    shell: false,
    env: { ...process.env, PA_CONVERTER_ROOT: ROOT },
  });
}

/* ---------- Dispatch ---------- */

function withRuntime(handlers) {
  const rt = resolveRuntime();
  const fn = handlers[rt];
  if (!fn) die(`No handler for runtime '${rt}'`);
  return fn();
}

function cmdStart() {
  withRuntime({
    podman: cmdPodmanStart,
    docker: cmdDockerStart,
    native: cmdStartNative,
  });
}

function cmdStop() {
  withRuntime({
    podman: cmdPodmanStop,
    docker: () => {
      ensureDocker();
      dockerCompose(['down']);
    },
    native: cmdStopNative,
  });
}

function cmdRestart() {
  cmdStop();
  cmdStart();
}

function cmdStatus() {
  withRuntime({
    podman: cmdPodmanStatus,
    docker: () => {
      ensureDocker();
      dockerCompose(['ps']);
    },
    native: cmdStatusNative,
  });
}

function cmdLogs() {
  withRuntime({
    podman: cmdPodmanLogs,
    docker: () => {
      ensureDocker();
      const follow =
        process.argv.includes('-f') || process.argv.includes('--follow');
      dockerCompose(
        follow ? ['logs', '-f', '--tail', '200'] : ['logs', '--tail', '200']
      );
    },
    native: cmdLogsNative,
  });
}

function cmdBuild() {
  const rt = resolveRuntime();
  if (rt === 'podman') return cmdPodmanBuild();
  if (rt === 'docker') {
    ensureDocker();
    dockerCompose(['build']);
    return;
  }
  console.log('Native runtime has no image build. Use: PA_CONVERTER_RUNTIME=podman pa-converter build');
}

function cmdUrl() {
  console.log(`https://localhost:${DEFAULT_PORT}`);
}

function printBanner() {
  console.log(`
  PA-Converter (Expedition 5.45.4)
  Runtime default: ${resolveRuntime()}  (override: PA_CONVERTER_RUNTIME=podman|docker|native)
  UI:   https://localhost:${DEFAULT_PORT}
  Login: admin / paloalto
`);
}

function cmdHelp() {
  printBanner();
  console.log(`Usage: pa-converter <command>

  start [--build] | stop | restart | status | logs [-f] | build | url

macOS / Linux: Podman Compose (recommended) — no Docker Desktop
Windows:       WSL native (or MSI)

  # Podman Desktop installs to /opt/podman/bin (often missing from npx PATH)
  export PATH="/opt/podman/bin:$PATH"
  podman machine start
  npx @sequr3/pa-converter start          # reuses image if present
  npx @sequr3/pa-converter start --build  # force rebuild

Env:
  EXPEDITION_PORT / EXPEDITION_HTTP_PORT
  PA_CONVERTER_RUNTIME=podman|docker|native
  EXPEDITION_IMAGE   optional prebuilt web image

Host: ${os.platform()} ${os.arch()} | ${ROOT}
  Podman: ${PODMAN_BIN || 'not found'}
`);
}

function cmdPublishHelp() {
  console.log(`
npm:  npm publish --access public
GitHub: npx --yes github:TufaylAhmed/PA-Converter#v5.46.32 start
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

if (!map[cmd]) die(`unknown command '${cmd}'. Try: pa-converter help`);
map[cmd]();
