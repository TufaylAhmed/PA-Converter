import { chromium } from 'playwright';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(__dirname, 'artifacts');
fs.mkdirSync(outDir, { recursive: true });
const BASE = process.env.EXPEDITION_URL || 'https://localhost:18443';
const PROJECT = process.env.PROJECT || 'Test';

const browser = await chromium.launch({ headless: true, args: ['--ignore-certificate-errors'] });
const page = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();

await page.goto(BASE + '/', { waitUntil: 'load', timeout: 90000 });
await page.waitForFunction(() => window.Ext && Ext.isReady, null, { timeout: 60000 });

const login = await page.evaluate(async () => {
  const body = new URLSearchParams({ action: 'get', type: 'login_users', user: 'admin', password: 'paloalto' });
  const r = await fetch('/bin/Auth.php', { method: 'POST', body, credentials: 'same-origin' });
  const text = await r.text();
  const parsed = JSON.parse(text);
  if (parsed.success) {
    localStorage.setItem('MTLoggedIn', 'true');
    if (window.MySharedData) MySharedData.csrfToken = parsed.csrfToken;
  }
  return parsed;
});
if (!login.success) {
  console.error('LOGIN_FAILED', login);
  process.exit(1);
}

const load = await page.evaluate(async (project) => {
  const r = await fetch('/bin/configurations/parsers/loader.php', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      project,
      vendor: 'FORTINET',
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
  return { status: r.status, text: text.slice(0, 500), parsed };
}, PROJECT);

const progress = [];
if (load.parsed?.success && load.parsed?.jobid) {
  for (let i = 0; i < 90; i++) {
    const st = await page.evaluate(async ({ project, jobid }) => {
      const u = `/bin/checkParseStatus.php?project=${encodeURIComponent(project)}&jobid=${encodeURIComponent(jobid)}`;
      const r = await fetch(u, { credentials: 'same-origin' });
      const text = await r.text();
      let parsed = null;
      try { parsed = JSON.parse(text); } catch {}
      return { status: r.status, text: text.slice(0, 400), parsed };
    }, { project: PROJECT, jobid: load.parsed.jobid });
    progress.push(st);
    const pct = Number(st.parsed?.percentage ?? NaN);
    const msg = (st.parsed?.message || '').toString();
    if (pct >= 1 || /done\.?/i.test(msg) || /error|fail|fatal/i.test(msg)) break;
    await page.waitForTimeout(2000);
  }
}

const sources = await page.evaluate(async (project) => {
  const r = await fetch(`/bin/Configuration.php?project=${encodeURIComponent(project)}&action=get&type=sources&page=1&start=0&limit=50`, { credentials: 'same-origin' });
  return { status: r.status, text: (await r.text()).slice(0, 1500) };
}, PROJECT);

const result = { login: { success: login.success }, load, progress: progress.slice(-8), sources };
fs.writeFileSync(path.join(outDir, 'import-fortinet-result.json'), JSON.stringify(result, null, 2));
console.log(JSON.stringify(result, null, 2));
await browser.close();
if (load.status !== 200 || !load.parsed?.success) process.exit(1);
const last = progress[progress.length - 1];
if (!last || Number(last.parsed?.percentage) < 1) process.exit(2);
