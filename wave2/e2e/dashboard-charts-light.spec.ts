import { expect, test } from '@playwright/test'
import path from 'node:path'
import fs from 'node:fs'

const EXPEDITION = process.env.EXPEDITION_URL || 'https://localhost:18443'
const shots = path.join('test-results', 'theme-shots', 'charts')

test.describe('Dashboard charts light mode', () => {
  test.describe.configure({ timeout: 180_000 })
  test.use({ ignoreHTTPSErrors: true, baseURL: EXPEDITION })

  test('charts are not black plates in light mode', async ({ page }) => {
    fs.mkdirSync(shots, { recursive: true })
    await page.addInitScript(() => {
      try {
        localStorage.setItem('pa-converter-theme', 'light')
        localStorage.setItem('pa-converter-login-theme', 'light')
      } catch {}
    })
    await page.goto(`${EXPEDITION}/?_=${Date.now()}`, { waitUntil: 'domcontentloaded' })
    await expect(page.locator('#login')).toBeVisible({ timeout: 60_000 })
    await page.locator('#user_name_login-inputEl').fill('admin')
    await page.locator('#user_password_login-inputEl').fill('paloalto')
    await page.locator('#submit_login').click()
    await expect(page.locator('#mainpaneltabs')).toBeVisible({ timeout: 60_000 })
    await page.waitForTimeout(1500)
    await page.evaluate(() => {
      document.documentElement.classList.remove('pa-theme-dark', 'pa-login-theme-dark')
      document.documentElement.classList.add('pa-theme-light', 'pa-login-theme-light')
      document.documentElement.setAttribute('data-pa-theme', 'light')
      const fn = (window as any).paConverterApplyTheme || (window as any).paConverterToggleLoginTheme
      // force light restyle if available
      try {
        localStorage.setItem('pa-converter-theme', 'light')
      } catch {}
    })
    await page.locator('#mainpaneltabs .x-tab-bar-left .x-tab').filter({ hasText: 'Projects' }).click()
    await page.waitForTimeout(1200)
    const row = page.locator('#ProjectsGridPanel .x-grid-row').first()
    await expect(row).toBeVisible({ timeout: 30_000 })
    await row.dblclick()
    await page.waitForTimeout(3500)
    // ensure Dashboard tab
    const dashTab = page.locator('#projectOptions .x-tab-bar-left .x-tab, .pa-project-nav .x-tab').filter({ hasText: /^Dashboard$/i })
    if (await dashTab.count()) {
      await dashTab.first().click()
      await page.waitForTimeout(2000)
    }
    await page.screenshot({ path: path.join(shots, 'light-dashboard.png'), fullPage: true })

    const info = await page.evaluate(() => {
      function sampleCanvas(canvas: HTMLCanvasElement | null) {
        if (!canvas || canvas.width < 10 || canvas.height < 10) return null
        try {
          const ctx = canvas.getContext('2d')
          if (!ctx) return null
          const pts = [
            [0.5, 0.5],
            [0.3, 0.3],
            [0.7, 0.4],
            [0.4, 0.7],
          ]
          const samples = []
          for (const [fx, fy] of pts) {
            const d = ctx.getImageData(Math.floor(canvas.width * fx), Math.floor(canvas.height * fy), 1, 1).data
            samples.push([d[0], d[1], d[2], d[3]])
          }
          return samples
        } catch (e) {
          return String(e)
        }
      }
      function isNearBlack(rgb: number[]) {
        return rgb[3] > 200 && rgb[0] < 40 && rgb[1] < 40 && rgb[2] < 40
      }
      return ['appidchart', 'appidchart1', 'DashboardRadarChart'].map((id) => {
        const el = document.getElementById(id)
        if (!el) return { id, missing: true }
        const cs = getComputedStyle(el)
        const canvas = el.querySelector('canvas') as HTMLCanvasElement | null
        const svgPaths = [...el.querySelectorAll('.pa-svg-pie path, svg path')]
          .slice(0, 6)
          .map((p) => p.getAttribute('fill'))
        const samples = sampleCanvas(canvas)
        const blackSamples = Array.isArray(samples)
          ? samples.filter((s) => Array.isArray(s) && isNearBlack(s as number[])).length
          : 0
        const card = el.closest('.x-panel, .myborder') as HTMLElement | null
        const cardBg = card ? getComputedStyle(card).backgroundColor : ''
        return {
          id,
          hostBg: cs.backgroundColor,
          cardBg,
          scrub: el.getAttribute('data-pa-dark-scrub'),
          pathFills: svgPaths,
          samples,
          blackSamples,
          hasSvg: !!el.querySelector('.pa-svg-pie'),
          theme: document.documentElement.getAttribute('data-pa-theme'),
        }
      })
    })
    console.log('CHART_INFO', JSON.stringify(info, null, 2))
    for (const c of info) {
      if (c.missing) continue
      expect(c.theme).toBe('light')
      // host/card must not be solid black
      expect(c.hostBg || '').not.toMatch(/rgb\(\s*0,\s*0,\s*0\s*\)/)
      expect(c.cardBg || '').not.toMatch(/rgb\(\s*0,\s*0,\s*0\s*\)/)
      // SVG path fills should not be black/#000 or dark-mode slate leftovers
      for (const fill of c.pathFills || []) {
        if (!fill) continue
        const f = fill.toLowerCase()
        expect(f).not.toMatch(/^#000|^black$|^#0{3,6}$|^#1f2937$|^#334155$|^#2a3344$/)
      }
      // canvas should not be majority near-black samples
      if (typeof c.blackSamples === 'number') {
        expect(c.blackSamples, `${c.id} canvas looks black`).toBeLessThan(3)
      }
    }

    // Dark → light must repaint overlays (regression: black donuts after toggle)
    await page.evaluate(() => {
      const fn = (window as unknown as { paConverterToggleLoginTheme?: () => string })
        .paConverterToggleLoginTheme
      if (fn) fn()
    })
    await page.waitForTimeout(800)
    await page.evaluate(() => {
      const fn = (window as unknown as { paConverterToggleLoginTheme?: () => string })
        .paConverterToggleLoginTheme
      if (fn) fn()
      const repair = (window as unknown as { paConverterRepairCharts?: () => void })
        .paConverterRepairCharts
      if (repair) repair()
    })
    await page.waitForTimeout(1200)
    await page.screenshot({ path: path.join(shots, 'light-after-toggle.png'), fullPage: true })

    const after = await page.evaluate(() => {
      const dark = document.documentElement.getAttribute('data-pa-theme')
      const fills = [...document.querySelectorAll('#appidchart .pa-svg-pie path, #appidchart1 .pa-svg-pie path')]
        .map((p) => (p.getAttribute('fill') || '').toLowerCase())
      return { dark, fills }
    })
    expect(after.dark).toBe('light')
    expect(after.fills.length).toBeGreaterThan(0)
    for (const f of after.fills) {
      expect(f).not.toMatch(/^#000|^#1f2937$|^#334155$|^#2a3344$/)
    }
  })
})
