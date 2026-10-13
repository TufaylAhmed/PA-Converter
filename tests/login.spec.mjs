import { chromium } from 'playwright';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(__dirname, 'artifacts');
fs.mkdirSync(outDir, { recursive: true });
const BASE = process.env.EXPEDITION_URL || 'https://localhost:18443';

const browser = await chromium.launch({ headless: true, args: ['--ignore-certificate-errors'] });
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 900 } });
const page = await context.newPage();

const network = [];
page.on('response', async (res) => {
  if (res.url().includes('/bin/Auth.php')) {
    let body = '';
    try { body = await res.text(); } catch {}
    network.push({ status: res.status(), body: body.slice(0, 400) });
  }
});

await page.goto(BASE + '/', { waitUntil: 'load', timeout: 90000 });
await page.waitForFunction(() => window.Ext && Ext.isReady && Ext.getCmp('user_name_login'), null, { timeout: 60000 });
await page.waitForTimeout(1500);
await page.screenshot({ path: path.join(outDir, '01-login.png'), fullPage: true });

await page.evaluate(() => {
  Ext.getCmp('user_name_login').setValue('admin');
  Ext.getCmp('user_password_login').setValue('paloalto');
});
await page.screenshot({ path: path.join(outDir, '02-filled.png'), fullPage: true });

const clicked = await page.evaluate(() => {
  const candidates = Ext.ComponentQuery.query('button').concat(Ext.ComponentQuery.query('button[text]'));
  for (const b of candidates) {
    const t = (b.getText && b.getText()) || (b.text) || '';
    if (/^login$/i.test(String(t).trim()) || /sign in/i.test(String(t))) {
      b.fireEvent('click', b);
      return t;
    }
  }
  // fallback: form submit handler used by Expedition
  const form = Ext.ComponentQuery.query('form')[0] || Ext.getCmp('login_form');
  if (form && form.getForm) {
    // try find login window button by itemId
  }
  const winBtns = Ext.ComponentQuery.query('window button');
  for (const b of winBtns) {
    const t = (b.getText && b.getText()) || '';
    if (/login/i.test(t)) { b.fireEvent('click', b); return 'win:' + t; }
  }
  return null;
});

// Also try pressing Enter in password field
if (!clicked) {
  await page.evaluate(() => {
    const p = Ext.getCmp('user_password_login');
    if (p) p.fireEvent('specialkey', p, { getKey: () => Ext.EventObject.ENTER, ENTER: Ext.EventObject.ENTER });
  });
}

await page.waitForTimeout(6000);
await page.screenshot({ path: path.join(outDir, '03-after-login.png'), fullPage: true });

// If still not logged in, call Auth.php directly from page context (same-origin cookies) then reload flow
if ((await page.evaluate(() => localStorage.getItem('MTLoggedIn'))) !== 'true') {
  const api = await page.evaluate(async () => {
    const body = new URLSearchParams({ action: 'get', type: 'login_users', user: 'admin', password: 'paloalto' });
    const r = await fetch('/bin/Auth.php', { method: 'POST', body, credentials: 'same-origin' });
    const text = await r.text();
    return { status: r.status, text };
  });
  network.push({ via: 'fetch', ...api });
  try {
    const parsed = JSON.parse(api.text);
    if (parsed.success) {
      await page.evaluate((token) => {
        localStorage.setItem('MTLoggedIn', 'true');
        localStorage.setItem('username', 'admin');
        if (window.MySharedData) MySharedData.csrfToken = token;
      }, parsed.csrfToken);
      await page.evaluate(() => {
        if (Ext.getCmp('mainviewport')) return;
        // destroy login window and create main panel like app does
        Ext.ComponentQuery.query('window').forEach(w => { try { w.destroy(); } catch(e){} });
        if (Ext.ClassManager.get('MT3.view.main.MainPanel') || Ext.ClassManager.isCreated('mainpanel')) {
          Ext.create({ xtype: 'mainpanel' });
        }
      });
      await page.waitForTimeout(3000);
      await page.screenshot({ path: path.join(outDir, '04-after-api-login.png'), fullPage: true });
    }
  } catch {}
}

const loggedIn = await page.evaluate(() => localStorage.getItem('MTLoggedIn'));
const domText = await page.evaluate(() => document.body.innerText.slice(0, 1500));
const result = { clicked, loggedIn, network, title: await page.title(), domText };
fs.writeFileSync(path.join(outDir, 'result.json'), JSON.stringify(result, null, 2));
console.log(JSON.stringify(result, null, 2));
await browser.close();
if (!network.some(n => (n.body || n.text || '').includes('"success":true')) && loggedIn !== 'true') process.exit(1);
