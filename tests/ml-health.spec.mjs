import { chromium } from 'playwright';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(__dirname, 'artifacts');
fs.mkdirSync(outDir, { recursive: true });
const BASE = process.env.EXPEDITION_URL || 'https://localhost:18443';

const browser = await chromium.launch({ headless: true, args: ['--ignore-certificate-errors'] });
const page = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();
await page.goto(BASE + '/', { waitUntil: 'load', timeout: 90000 });
await page.waitForFunction(() => window.Ext && Ext.isReady, null, { timeout: 60000 });

await page.evaluate(async () => {
  const body = new URLSearchParams({ action: 'get', type: 'login_users', user: 'admin', password: 'paloalto' });
  const r = await fetch('/bin/Auth.php', { method: 'POST', body, credentials: 'same-origin' });
  const parsed = JSON.parse(await r.text());
  if (!parsed.success) throw new Error('login failed');
  localStorage.setItem('MTLoggedIn', 'true');
  if (window.MySharedData) MySharedData.csrfToken = parsed.csrfToken;
});

const health = await page.evaluate(async () => {
  const r = await fetch('/bin/MTSettings/healthcheck.php?_dc=' + Date.now(), { credentials: 'same-origin' });
  const text = await r.text();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch {}
  return { status: r.status, parsed };
});

const mlCpu = await page.evaluate(async () => {
  const r = await fetch('/bin/authentication/dashboard/cpu_status.php?scope=ml&_dc=' + Date.now(), { credentials: 'same-origin' });
  return { status: r.status, text: (await r.text()).slice(0, 1500) };
});

const mlSettings = await page.evaluate(async () => {
  const r = await fetch('/bin/authentication/ml_settings/ml_settings.php?action=get&_dc=' + Date.now(), { credentials: 'same-origin' });
  return { status: r.status, text: (await r.text()).slice(0, 1000) };
});

const checks = (health.parsed?.msg || []).map((c) => ({
  category: c.category,
  description: c.description,
  success: c.success,
  msg: (c.msg || '').toString().slice(0, 160),
}));
const failed = checks.filter((c) => c.success === false);
const mlRelated = checks.filter((c) =>
  /ml|spark|parquet|machine|bpa|expeditionml|pip|dependencies/i.test(`${c.category} ${c.description} ${c.msg}`)
);

const result = {
  healthOk: health.parsed?.code === true || health.parsed?.success === true,
  failedCount: health.parsed?.failed ?? failed.length,
  mlRelated,
  failed: failed.slice(0, 20),
  mlCpu,
  mlSettings,
};
fs.writeFileSync(path.join(outDir, 'ml-health-result.json'), JSON.stringify(result, null, 2));
console.log(JSON.stringify(result, null, 2));
await browser.close();
