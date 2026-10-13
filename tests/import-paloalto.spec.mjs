import { chromium } from 'playwright';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(__dirname, 'artifacts');
fs.mkdirSync(outDir, { recursive: true });
const BASE = process.env.EXPEDITION_URL || 'https://localhost:18443';
const CONFIG = process.env.CONFIG_PATH || path.join(__dirname, '../../running-config.xml');
const PROJECT = process.env.PROJECT || 'Test';

const browser = await chromium.launch({ headless: true, args: ['--ignore-certificate-errors'] });
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 900 } });
const page = await context.newPage();
const net = [];
page.on('response', async (res) => {
  const u = res.url();
  if (/Auth\.php|uploader\.php|loader\.php|checkParseStatus/.test(u)) {
    let body = '';
    try { body = (await res.text()).slice(0, 500); } catch {}
    net.push({ url: u.replace(BASE, ''), status: res.status(), body });
  }
});

await page.goto(BASE + '/', { waitUntil: 'load', timeout: 90000 });
await page.waitForFunction(() => window.Ext && Ext.isReady && Ext.getCmp('user_name_login'), null, { timeout: 60000 });
await page.waitForTimeout(1000);

// Accept terms if present, then login via Auth API (same-origin cookies)
await page.evaluate(() => {
  const boxes = Ext.ComponentQuery.query('checkboxfield, checkbox');
  for (const c of boxes) {
    try {
      if ((c.boxLabel || c.getFieldLabel?.() || '').toString().toLowerCase().includes('term') ||
          (c.inputValue || '').toString().toLowerCase().includes('term')) {
        c.setValue(true);
      }
    } catch {}
  }
  // also tick any unchecked checkbox near the accept button
  Ext.ComponentQuery.query('checkbox').forEach((c) => { try { c.setValue(true); } catch {} });
});

const login = await page.evaluate(async () => {
  const body = new URLSearchParams({ action: 'get', type: 'login_users', user: 'admin', password: 'paloalto' });
  const r = await fetch('/bin/Auth.php', { method: 'POST', body, credentials: 'same-origin' });
  const text = await r.text();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch {}
  if (parsed?.success) {
    localStorage.setItem('MTLoggedIn', 'true');
    localStorage.setItem('username', 'admin');
    if (window.MySharedData) MySharedData.csrfToken = parsed.csrfToken;
  }
  return { status: r.status, text: text.slice(0, 300), success: !!parsed?.success, csrf: parsed?.csrfToken };
});
if (!login.success) {
  console.error('LOGIN_FAILED', login);
  fs.writeFileSync(path.join(outDir, 'import-result.json'), JSON.stringify({ login, net }, null, 2));
  await browser.close();
  process.exit(1);
}

// Open main UI if needed
await page.evaluate(() => {
  Ext.ComponentQuery.query('window').forEach((w) => { try { w.destroy(); } catch {} });
  if (!Ext.getCmp('mainviewport')) {
    try { Ext.create({ xtype: 'mainpanel' }); } catch {}
  }
  if (window.MySharedData) MySharedData.project = 'Test';
});
await page.waitForTimeout(2000);

// Re-upload config then kick loader (matches UI flow)
const upload = await page.evaluate(async ({ project, fileName, fileB64 }) => {
  const bin = Uint8Array.from(atob(fileB64), (c) => c.charCodeAt(0));
  const blob = new Blob([bin], { type: 'application/xml' });
  const fd = new FormData();
  fd.append('project', project);
  fd.append('vendor', 'PALOALTO');
  fd.append('paloaltoxml', blob, fileName);
  const r = await fetch('/bin/configurations/parsers/uploader.php', { method: 'POST', body: fd, credentials: 'same-origin' });
  const text = await r.text();
  return { status: r.status, text: text.slice(0, 500) };
}, {
  project: PROJECT,
  fileName: 'running-config.xml',
  fileB64: fs.readFileSync(CONFIG).toString('base64'),
});

const load = await page.evaluate(async (project) => {
  const r = await fetch('/bin/configurations/parsers/loader.php', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      project,
      vendor: 'PALOALTO',
      action: 'import',
      signatureid: '',
      username: '',
      password: '',
      afa_hostname: '',
      checkpoint_name: '',
      noDNAT: false,
      groupbydescription: false,
      asPanorama: false,
    }),
  });
  const text = await r.text();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch {}
  return { status: r.status, text: text.slice(0, 800), parsed };
}, PROJECT);

// Poll parse status if job started
let progress = [];
if (load.parsed?.success && load.parsed?.jobid) {
  for (let i = 0; i < 60; i++) {
    const st = await page.evaluate(async ({ project, jobid }) => {
      const u = `/bin/checkParseStatus.php?project=${encodeURIComponent(project)}&jobid=${encodeURIComponent(jobid)}`;
      const r = await fetch(u, { credentials: 'same-origin' });
      const text = await r.text();
      let parsed = null;
      try { parsed = JSON.parse(text); } catch {}
      return { status: r.status, text: text.slice(0, 500), parsed };
    }, { project: PROJECT, jobid: load.parsed.jobid });
    progress.push(st);
    const pct = Number(st.parsed?.percentage ?? st.parsed?.msg ?? NaN);
    const msg = (st.parsed?.message || st.parsed?.msg || st.text || '').toString();
    if (/100|completed|finished|done/i.test(msg) || pct >= 1 || /error|fail/i.test(msg)) break;
    await page.waitForTimeout(2000);
  }
}

// DB sanity: sources in project
const sources = await page.evaluate(async (project) => {
  const r = await fetch(`/bin/Configuration.php?project=${encodeURIComponent(project)}&action=get&type=sources&page=1&start=0&limit=50`, { credentials: 'same-origin' });
  return { status: r.status, text: (await r.text()).slice(0, 1000) };
}, PROJECT);

const result = { login, upload, load, progress: progress.slice(-5), sources, net: net.slice(-20) };
fs.writeFileSync(path.join(outDir, 'import-result.json'), JSON.stringify(result, null, 2));
console.log(JSON.stringify(result, null, 2));
await browser.close();

if (load.status !== 200 || !load.parsed?.success) process.exit(1);
