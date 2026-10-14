/**
 * Full UI audit: login (dark black) → main menus → project menus.
 * Writes screenshots + JSON report under tests/artifacts/ui-audit/
 */
import { chromium } from 'playwright'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const outDir = path.join(__dirname, 'artifacts', 'ui-audit')
fs.mkdirSync(outDir, { recursive: true })
const BASE = process.env.EXPEDITION_URL || 'https://localhost:18443'
const report = { ok: true, steps: [], issues: [] }

function note(step, data = {}) {
  report.steps.push({ step, ...data, t: Date.now() })
  console.log('✓', step, data.detail || '')
}
function issue(msg, data = {}) {
  report.ok = false
  report.issues.push({ msg, ...data })
  console.log('✗', msg, JSON.stringify(data))
}

const browser = await chromium.launch({
  headless: true,
  args: ['--ignore-certificate-errors'],
})
const context = await browser.newContext({
  ignoreHTTPSErrors: true,
  viewport: { width: 1440, height: 900 },
  colorScheme: 'dark',
})
const page = await context.newPage()

async function shot(name) {
  const p = path.join(outDir, `${name}.png`)
  await page.screenshot({ path: p, fullPage: false })
  return p
}

async function forceDark() {
  await page.evaluate(() => {
    try {
      localStorage.setItem('pa-converter-login-theme', 'dark')
    } catch {}
    document.documentElement.classList.remove('pa-login-theme-light', 'pa-theme-light')
    document.documentElement.classList.add('pa-login-theme-dark', 'pa-theme-dark', 'pa-converter-ui')
    document.documentElement.setAttribute('data-pa-theme', 'dark')
    if (window.paConverterToggleLoginTheme) {
      /* ensure applied */
    }
  })
}

async function clickTabByLabel(label) {
  return page.evaluate((want) => {
    const tabs = Array.from(document.querySelectorAll('.x-tab'))
    const norm = (s) => String(s || '').replace(/\s+/g, ' ').trim().toLowerCase()
    const target = norm(want)
    for (const t of tabs) {
      const text = norm(t.textContent)
      if (!text) continue
      if (text === target || text.includes(target) || target.includes(text)) {
        t.click()
        return text
      }
    }
    // Ext API fallback
    if (typeof Ext !== 'undefined' && Ext.ComponentQuery) {
      const comps = Ext.ComponentQuery.query('tab')
      for (const c of comps) {
        const text = norm((c.getText && c.getText()) || c.title || c.text)
        if (text === target || text.includes(target)) {
          const bar = c.up && c.up('tabbar')
          const panel = c.card || (c.ownerCt && c.ownerCt.getComponent && c.ownerCt.getComponent(c.card))
          try {
            if (c.tabBar) c.tabBar.setActiveTab(c)
            else if (c.fireEvent) c.fireEvent('click', c)
            else if (c.el) c.el.dom.click()
          } catch {}
          return text || target
        }
      }
    }
    return null
  }, label)
}

async function auditLogin() {
  await page.goto(`${BASE}/?_=${Date.now()}`, { waitUntil: 'domcontentloaded', timeout: 90000 })
  await page.waitForSelector('#login', { timeout: 60000 })
  await forceDark()
  await page.waitForTimeout(800)
  // Force theme via UI helper if present
  await page.evaluate(() => {
    document.documentElement.classList.add('pa-login-theme-dark', 'pa-theme-dark', 'pa-login-active')
    document.documentElement.classList.remove('pa-login-theme-light', 'pa-theme-light')
  })
  await page.waitForTimeout(400)
  await shot('00-login-dark')

  const colors = await page.evaluate(() => {
    const bodyBefore = getComputedStyle(document.body, '::before')
    // ::before may not resolve; sample html bg + login card
    const html = getComputedStyle(document.documentElement)
    const body = getComputedStyle(document.body)
    const card =
      document.querySelector('#login-body') ||
      document.querySelector('#login .x-window-body')
    const cardCs = card ? getComputedStyle(card) : null
    const input = document.querySelector('#user_name_login-inputEl')
    const inputCs = input ? getComputedStyle(input) : null
    return {
      htmlBg: html.backgroundColor,
      bodyBg: body.backgroundColor,
      cardBg: cardCs && cardCs.backgroundColor,
      inputBg: inputCs && inputCs.backgroundColor,
      classes: document.documentElement.className,
    }
  })
  note('login-colors', { detail: JSON.stringify(colors) })

  // Pure black expectation on card
  const isBlackish = (c) => {
    if (!c) return false
    const m = c.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/)
    if (!m) return /#000|#000000/i.test(c)
    return Number(m[1]) < 20 && Number(m[2]) < 20 && Number(m[3]) < 20
  }
  if (!isBlackish(colors.cardBg)) {
    issue('Login card is not pure black', { cardBg: colors.cardBg })
  }

  // Fill + login
  await page.locator('#user_name_login-inputEl').fill('admin')
  await page.locator('#user_password_login-inputEl').fill('paloalto')
  await shot('01-login-filled')
  await page.locator('#submit_login').click()
  try {
    await page.waitForSelector('#login', { state: 'hidden', timeout: 60000 })
    note('login-success')
  } catch (e) {
    issue('Login did not dismiss #login', { err: String(e) })
    // try Ext auth fallback
    await page.evaluate(async () => {
      const body = new URLSearchParams({
        action: 'get',
        type: 'login_users',
        user: 'admin',
        password: 'paloalto',
      })
      const r = await fetch('/bin/Auth.php', { method: 'POST', body, credentials: 'same-origin' })
      const text = await r.text()
      try {
        const j = JSON.parse(text)
        if (j.success) {
          localStorage.setItem('MTLoggedIn', 'true')
          localStorage.setItem('username', 'admin')
        }
      } catch {}
    })
    await page.reload({ waitUntil: 'domcontentloaded' })
    await forceDark()
    await page.waitForTimeout(2000)
  }
}

async function auditCharts() {
  await forceDark()
  await page.waitForTimeout(1500)
  // Ensure dashboard visible
  await clickTabByLabel('Dashboard')
  await page.waitForTimeout(2500)
  // Nudge chart restyle
  await page.evaluate(() => {
    try {
      if (typeof Ext !== 'undefined') {
        ;['appidchart', 'appidchart1', 'DashboardRadarChart'].forEach((id) => {
          const c = Ext.getCmp(id)
          if (c && c.redraw) c.redraw()
          if (c && c.getStore && c.getStore()) c.getStore().load()
        })
      }
    } catch {}
  })
  await page.waitForTimeout(2500)
  await shot('10-dashboard')

  // Nudge SVG / layout repair
  await page.evaluate(() => {
    try {
      if (window.paConverterRepairCharts) window.paConverterRepairCharts()
    } catch {}
  })
  await page.waitForTimeout(1500)

  const chartMeta = await page.evaluate(() => {
    function info(id) {
      const el = document.getElementById(id)
      if (!el) return { id, missing: true }
      const canvas = el.querySelector('canvas')
      const svg = el.querySelector('.pa-svg-pie svg, .pa-svg-radar svg, svg')
      const svgPaths = el.querySelectorAll(
        '.pa-svg-pie path, .pa-svg-pie polygon, .pa-svg-radar polygon, .pa-svg-radar line, svg path, svg polygon',
      )
      let pixels = 0
      if (canvas) {
        try {
          const ctx = canvas.getContext('2d')
          const w = Math.min(canvas.width, 80)
          const h = Math.min(canvas.height, 80)
          const data = ctx.getImageData(0, 0, w, h).data
          for (let i = 0; i < data.length; i += 16) {
            if (data[i + 3] > 10 && (data[i] > 20 || data[i + 1] > 20 || data[i + 2] > 20)) pixels++
          }
        } catch (e) {
          return { id, err: String(e), w: canvas.width, h: canvas.height }
        }
      }
      const r = el.getBoundingClientRect()
      return {
        id,
        hasCanvas: !!canvas,
        hasSvg: !!svg,
        svgPaths: svgPaths.length,
        w: canvas && canvas.width,
        h: canvas && canvas.height,
        hostW: Math.round(r.width),
        hostH: Math.round(r.height),
        paintedSamples: pixels,
        badge: !!(el.querySelector('.pa-pie-center-badge')),
      }
    }
    // Gauge white-island check (Ext theme default background:white)
    const gaugeWhite = []
    document.querySelectorAll('#DashboardCard canvas').forEach((c) => {
      const r = c.getBoundingClientRect()
      if (r.width < 40 || r.height < 40 || r.top > 420) return
      try {
        const ctx = c.getContext('2d')
        const p = ctx.getImageData(4, 4, 1, 1).data
        if (p[3] > 200 && p[0] > 240 && p[1] > 240 && p[2] > 240) {
          gaugeWhite.push({
            parent: (c.closest('[id]') || {}).id,
            corner: [p[0], p[1], p[2], p[3]],
          })
        }
      } catch {}
    })
    return {
      charts: [info('appidchart'), info('appidchart1'), info('DashboardRadarChart')],
      gaugeWhite,
    }
  })
  note('charts', { detail: JSON.stringify(chartMeta) })
  for (const c of chartMeta.charts) {
    if (c.missing) issue('Chart missing', c)
    else if (!c.hasCanvas && !(c.hasSvg && c.svgPaths >= 1)) {
      issue('Chart has no canvas or SVG', c)
    } else if (c.hasCanvas && !c.hasSvg && (c.paintedSamples || 0) < 5) {
      issue('Chart canvas looks empty', c)
    }
  }
  if (chartMeta.gaugeWhite && chartMeta.gaugeWhite.length) {
    issue('Gauge canvases still white', { n: chartMeta.gaugeWhite.length, sample: chartMeta.gaugeWhite[0] })
  }
}

async function auditMenus(labels, prefix) {
  for (const label of labels) {
    const clicked = await clickTabByLabel(label)
    await page.waitForTimeout(1200)
    const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, '-')
    await shot(`${prefix}-${slug}`)
    if (!clicked) issue(`Could not click menu: ${label}`)
    else note(`menu:${label}`, { detail: clicked })

    // Quick symmetry / overlap checks
    const layout = await page.evaluate(() => {
      const issues = []
      const tabs = document.querySelectorAll('.x-tab-bar-left .x-tab')
      tabs.forEach((t) => {
        const r = t.getBoundingClientRect()
        if (r.width > 0 && r.height > 0 && r.width < 40) issues.push('narrow-tab:' + (t.textContent || '').trim())
      })
      const toggle = document.getElementById('pa-login-theme-toggle')
      if (toggle) {
        const r = toggle.getBoundingClientRect()
        if (r.width > 40 || r.height > 40) issues.push('theme-toggle-too-large:' + r.width + 'x' + r.height)
      }
      const whites = []
      document.querySelectorAll('.x-panel-body, .x-grid-empty, .x-fieldset').forEach((el) => {
        const bg = getComputedStyle(el).backgroundColor
        const m = bg && bg.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/)
        if (m && Number(m[1]) > 240 && Number(m[2]) > 240 && Number(m[3]) > 240) {
          const r = el.getBoundingClientRect()
          if (r.width > 80 && r.height > 24) whites.push((el.id || el.className || '').toString().slice(0, 60))
        }
      })
      if (whites.length) issues.push('white-island:' + whites.slice(0, 5).join('|'))
      return issues
    })
    for (const i of layout) issue(`layout:${label}`, { i })
  }
}

try {
  await auditLogin()
  await forceDark()
  await page.waitForTimeout(1000)
  await shot('02-workspace')

  // Main left rail menus
  await auditMenus(
    ['Dashboard', 'Projects', 'Devices', 'Snippets', 'Settings', 'Logs'],
    '20-main',
  )

  // Open a project if available
  const opened = await page.evaluate(() => {
    try {
      if (typeof Ext === 'undefined') return false
      const grid = Ext.getCmp('ProjectsGridPanel')
      if (grid && grid.getStore && grid.getStore().getCount() > 0) {
        const rec = grid.getStore().getAt(0)
        grid.getSelectionModel().select(rec)
        grid.fireEvent('itemdblclick', grid.getView(), rec)
        return true
      }
      // try click first row
      const row = document.querySelector('#ProjectsGridPanel .x-grid-row')
      if (row) {
        row.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }))
        return true
      }
    } catch {}
    return false
  })
  note('open-project', { detail: String(opened) })
  await page.waitForTimeout(3000)
  await forceDark()
  await shot('30-project')

  await auditCharts()

  await auditMenus(
    [
      'Dashboard',
      'Import',
      'Plugins',
      'Best practices',
      'Machine learning',
      'Monitor',
      'Policies',
      'Objects',
      'Network',
      'Device',
      'Tools',
      'EXPORT',
    ],
    '40-proj',
  )

  await shot('99-final')
} catch (e) {
  issue('fatal', { err: String(e), stack: e.stack })
  await shot('zz-fatal')
}

fs.writeFileSync(path.join(outDir, 'report.json'), JSON.stringify(report, null, 2))
console.log('\nReport:', path.join(outDir, 'report.json'))
console.log('Issues:', report.issues.length)
await browser.close()
process.exit(report.issues.some((i) => i.msg === 'fatal') ? 1 : 0)
