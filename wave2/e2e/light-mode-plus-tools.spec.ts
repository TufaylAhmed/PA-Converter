import { expect, test, type Page } from '@playwright/test'
import path from 'node:path'
import fs from 'node:fs'

const EXPEDITION = process.env.EXPEDITION_URL || 'https://localhost:18443'
const shots = path.join('test-results', 'theme-shots', 'plus-tools')

async function login(page: Page) {
  await page.addInitScript(() => {
    try {
      localStorage.setItem('pa-converter-theme', 'light')
      localStorage.setItem('pa-converter-login-theme', 'light')
    } catch {
      /* ignore */
    }
  })
  await page.goto(`${EXPEDITION}/?_=${Date.now()}`, { waitUntil: 'domcontentloaded' })
  await expect(page.locator('#login')).toBeVisible({ timeout: 60_000 })
  await page.locator('#user_name_login-inputEl').fill('admin')
  await page.locator('#user_password_login-inputEl').fill('paloalto')
  await page.locator('#submit_login').click()
  await expect(page.locator('#login')).toBeHidden({ timeout: 60_000 })
  await expect(page.locator('#mainpaneltabs')).toBeVisible({ timeout: 60_000 })
  await page.waitForTimeout(1500)
  // Force light workspace theme
  await page.evaluate(() => {
    document.documentElement.classList.remove('pa-theme-dark', 'pa-login-theme-dark')
    document.documentElement.classList.add('pa-theme-light', 'pa-login-theme-light')
    document.documentElement.setAttribute('data-pa-theme', 'light')
    try {
      localStorage.setItem('pa-converter-theme', 'light')
    } catch {
      /* ignore */
    }
  })
}

async function openProject(page: Page) {
  await page.locator('#mainpaneltabs .x-tab-bar-left .x-tab').filter({ hasText: 'Projects' }).click()
  await page.waitForTimeout(1200)
  const row = page.locator('#ProjectsGridPanel .x-grid-row').first()
  await expect(row).toBeVisible({ timeout: 30_000 })
  await row.dblclick()
  await expect
    .poll(async () => page.evaluate(() => !!Ext.getCmp('projectOptions')), { timeout: 60_000 })
    .toBeTruthy()
  await page.waitForTimeout(2000)
}

type ToolInfo = {
  tip: string
  display: string
  visibility: string
  opacity: string
  color: string
  bg: string
  w: number
  h: number
  contrastHint: string
}

async function collectPlusTools(page: Page): Promise<ToolInfo[]> {
  return page.evaluate(() => {
    function parseRgba(c: string): [number, number, number, number] | null {
      const m = c.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([0-9.]+))?/)
      return m
        ? [Number(m[1]), Number(m[2]), Number(m[3]), m[4] === undefined ? 1 : Number(m[4])]
        : null
    }
    function lum(r: number, g: number, b: number) {
      const a = [r, g, b].map((v) => {
        v /= 255
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4)
      })
      return 0.2126 * a[0] + 0.7152 * a[1] + 0.0722 * a[2]
    }
    const tools = [...document.querySelectorAll('.x-tool-plus')]
    const seen = new Set<Element>()
    const out: ToolInfo[] = []
    for (const el of tools) {
      const tool = (el.closest('.x-tool') as HTMLElement) || (el as HTMLElement)
      if (seen.has(tool)) continue
      seen.add(tool)
      // Library plus is intentionally replaced by "Add Project" — skip it
      if (tool.closest('#ProjectsGridPanel')) continue
      const img =
        (tool.querySelector('.x-tool-img, .x-tool-plus, .x-tool-tool-el') as HTMLElement) ||
        (el as HTMLElement)
      const cs = getComputedStyle(img)
      const tcs = getComputedStyle(tool)
      const r = tool.getBoundingClientRect()
      if (r.width < 1 || r.height < 1 || tcs.display === 'none' || tcs.visibility === 'hidden') {
        continue
      }
      const fg = parseRgba(cs.color)
      const bg = parseRgba(cs.backgroundColor)
      let contrastHint = 'unknown'
      if (fg) {
        const L1 = lum(fg[0], fg[1], fg[2])
        const bgTransparent = !bg || bg[3] < 0.15
        if (bgTransparent) {
          // On light wash, white/near-white glyphs disappear
          contrastHint = L1 > 0.72 ? 'likely-invisible-on-light' : 'ok-dark-glyph'
        } else {
          const L2 = lum(bg[0], bg[1], bg[2])
          const ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05)
          contrastHint = ratio < 1.5 ? 'poor' : ratio < 3 ? 'weak' : 'ok'
        }
      }
      out.push({
        tip: tool.getAttribute('data-qtip') || tool.getAttribute('title') || tool.id || '',
        display: tcs.display,
        visibility: tcs.visibility,
        opacity: cs.opacity,
        color: cs.color,
        bg: cs.backgroundColor,
        w: Math.round(r.width),
        h: Math.round(r.height),
        contrastHint,
      })
    }
    return out
  })
}

test.describe('Light mode panel + tools visible', () => {
  test.describe.configure({ timeout: 180_000 })
  test.use({ ignoreHTTPSErrors: true, baseURL: EXPEDITION })

  test.beforeAll(() => {
    fs.mkdirSync(shots, { recursive: true })
  })

  test('syslog and other header plus tools are visible in light mode', async ({ page }) => {
    await login(page)
    await openProject(page)

    // Objects → Server Profiles → Syslog (where the light-mode + bug was reported)
    for (const label of ['Objects', 'Device']) {
      const tab = page
        .locator('#projectOptions .x-tab-bar-left .x-tab, .pa-project-nav .x-tab')
        .filter({ hasText: new RegExp(`^\\s*${label}\\s*$`, 'i') })
      if ((await tab.count()) > 0) {
        await tab.first().click()
        await page.waitForTimeout(700)
        break
      }
    }
    const serverProfiles = page.locator('.x-tab, .x-btn').filter({ hasText: /Server Profiles/i })
    if ((await serverProfiles.count()) > 0) {
      await serverProfiles.first().click()
      await page.waitForTimeout(700)
    }
    const syslog = page.locator('.x-tab, .x-btn').filter({ hasText: /^Syslog$/i })
    if ((await syslog.count()) > 0) {
      await syslog.first().click()
      await page.waitForTimeout(900)
    }

    await page.screenshot({ path: path.join(shots, '01-syslog-context.png'), fullPage: true })

    // Bust CSS cache so the theme fix is applied
    await page.evaluate(async () => {
      const href = '/resources/css/pa-converter-theme.css'
      const links = [...document.querySelectorAll('link[rel="stylesheet"]')] as HTMLLinkElement[]
      for (const l of links) {
        if (l.href.includes('pa-converter-theme.css')) {
          l.href = `${href}?v=${Date.now()}`
        }
      }
      await new Promise((r) => setTimeout(r, 400))
    })
    await page.waitForTimeout(600)

    const tools = await collectPlusTools(page)
    console.log('PLUS_TOOLS', JSON.stringify(tools, null, 2))

    expect(tools.length, 'expected visible Ext plus tools in project UI').toBeGreaterThan(0)

    for (const t of tools) {
      expect(Number(t.opacity), `opacity for ${t.tip}`).toBeGreaterThan(0.2)
      expect(t.w, `width for ${t.tip}`).toBeGreaterThan(8)
      expect(t.h, `height for ${t.tip}`).toBeGreaterThan(8)
      expect(
        t.contrastHint,
        `contrast for ${t.tip} color=${t.color} bg=${t.bg}`,
      ).not.toMatch(/poor|likely-invisible/)
      // Accent blue or near-dark — never pure white on light glass
      expect(t.color, `glyph color for ${t.tip}`).not.toMatch(/rgb\(\s*255,\s*255,\s*255\s*\)/)
    }

    await page.screenshot({ path: path.join(shots, '02-plus-tools-light.png'), fullPage: true })
  })
})
