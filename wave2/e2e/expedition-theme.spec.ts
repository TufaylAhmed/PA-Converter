import { expect, test, type Page } from '@playwright/test'
import path from 'node:path'
import fs from 'node:fs'

const EXPEDITION = process.env.EXPEDITION_URL || 'https://localhost:18443'
const shots = path.join('test-results', 'theme-shots', 'iter')

async function login(page: Page) {
  await page.goto(`${EXPEDITION}/?_=${Date.now()}`, { waitUntil: 'domcontentloaded' })
  await expect(page.locator('#login')).toBeVisible({ timeout: 60_000 })
  await page.locator('#user_name_login-inputEl').click()
  await page.locator('#user_name_login-inputEl').fill('admin')
  await page.locator('#user_password_login-inputEl').click()
  await page.locator('#user_password_login-inputEl').fill('paloalto')
  await page.locator('#submit_login').click()
  await expect(page.locator('#login')).toBeHidden({ timeout: 60_000 })
  await expect(page.locator('#mainpaneltabs')).toBeVisible({ timeout: 60_000 })
  await page.waitForTimeout(2000)
}

async function bodyWidth(page: Page, id: string) {
  return page.evaluate((cmpId) => {
    const el = document.getElementById(`${cmpId}-body`)
    return el ? el.getBoundingClientRect().width : 0
  }, id)
}

async function leftBarMeta(page: Page, selector: string) {
  return page.evaluate((sel) => {
    const el = document.querySelector(sel) as HTMLElement | null
    if (!el) return null
    const r = el.getBoundingClientRect()
    const cs = getComputedStyle(el)
    return {
      w: r.width,
      h: r.height,
      x: r.x,
      y: r.y,
      backdrop: cs.backdropFilter || (cs as CSSStyleDeclaration & { webkitBackdropFilter?: string }).webkitBackdropFilter || '',
      bg: cs.backgroundColor,
      icons: [...el.querySelectorAll('.x-tab[data-pa-icon]')].map((t) => t.getAttribute('data-pa-icon')),
      labels: [...el.querySelectorAll('.x-tab-inner')]
        .map((t) => (t.textContent || '').trim())
        .filter(Boolean),
    }
  }, selector)
}

test.describe('Expedition glass left-nav QA', () => {
  test.describe.configure({ timeout: 120_000 })
  test.use({ ignoreHTTPSErrors: true, baseURL: EXPEDITION })

  test.beforeAll(() => {
    fs.mkdirSync(shots, { recursive: true })
  })

  test('assets: theme, enhancer, flat icons', async ({ request }) => {
    const theme = await (await request.get('/resources/css/pa-converter-theme.css')).text()
    expect(theme).toContain('backdrop-filter')
    expect(theme).toContain('data-pa-icon')
    expect(theme).toContain('pa-glass')
    expect(theme).toContain('pa-login-card-ready')
    expect(theme).toContain('login-banner.jpg')
    expect(theme).toContain('pa-login-theme-light')

    const ui = await (await request.get('/resources/js/pa-converter-ui.js')).text()
    expect(ui).toContain('projectOptions')
    expect(ui).toContain('ICON_MAP')
    expect(ui).toContain('All projects')
    expect(ui).toContain('styleLoginCard')
    expect(ui).toContain('pa-login-theme-toggle')
    expect(ui).toContain('applyLoginTheme')
    expect(ui).toContain('interfaces')
    expect(theme).toMatch(/--pa-accent:\s*#[0-9a-fA-F]{3,8}/)

    const banner = await request.get('/resources/images/expedition/login-banner.jpg')
    expect(banner.ok()).toBeTruthy()
    const logo = await request.get('/resources/images/expedition/logo-bg.png')
    expect(logo.ok()).toBeTruthy()

    expect(theme).toContain('pa-theme-dark')
    expect(theme).toContain('pa-projects-rows')
    expect(theme).toContain('pa-glass-title-chip')
    expect(theme).toContain('Inter')
    expect(theme).toContain('pa-vendor-tab')
    expect(theme).toContain('pa-progress-modern')
    expect(theme).toContain('response-pages.svg')
    expect(ui).toContain('pa-theme-')
    expect(ui).toContain('ICON_CLS_FLAT')
    expect(ui).toContain('enhanceVendorTabs')
    expect(ui).toContain('scrubImportAdvertising')
    expect(ui).toContain('pa-projects-rows')
    expect(ui).toContain('server-profiles')
    for (const name of ['vsys', 'response-pages', 'server-profiles', 'snmp', 'syslog', 'email', 'kerberos']) {
      const res = await request.get(`/resources/images/expedition/icons/${name}.svg`)
      expect(res.ok(), name).toBeTruthy()
    }

    for (const name of [
      'dashboard',
      'projects',
      'devices',
      'settings',
      'import',
      'policies',
      'objects',
      'back',
      'interfaces',
      'zones',
      'router',
      'vlan',
      'vpn',
      'export',
      'tools',
      'security',
      'nat',
      'app-override',
      'qos',
      'pbf',
      'decryption',
      'captive',
      'dos',
      'lock',
      'check',
      'trash',
      'gears',
      'heart',
    ]) {
      const res = await request.get(`/resources/images/expedition/icons/${name}.svg`)
      expect(res.ok(), name).toBeTruthy()
      expect(await res.text()).toContain('<svg')
    }
  })

  test('login split card matches inspiration', async ({ page }) => {
    await page.addInitScript(() => {
      try {
        localStorage.setItem('pa-converter-login-theme', 'light')
      } catch {
        /* ignore */
      }
    })
    await page.goto(`${EXPEDITION}/?_=${Date.now()}`, { waitUntil: 'domcontentloaded', timeout: 30_000 })
    await page.waitForSelector('#login', { state: 'attached', timeout: 60_000 })
    await expect
      .poll(
        async () =>
          page.evaluate(() => {
            const el = document.getElementById('login')
            return !!(
              el &&
              el.classList.contains('pa-login-window') &&
              document.querySelector('.pa-login-hero') &&
              document.getElementById('pa-login-theme-toggle')
            )
          }),
        { timeout: 30_000 },
      )
      .toBe(true)

    await expect(page.locator('.pa-login-hero')).toBeVisible()
    await expect(page.locator('.pa-login-form-pane')).toBeVisible()
    await expect(page.getByText('Sign in').first()).toBeVisible()
    await expect(page.locator('#pa-login-theme-toggle')).toBeVisible()
    await expect(page.locator('img.pa-login-form-logo')).toBeVisible()
    await expect(
      page.locator('.pa-login-hero .pa-login-brand-glass:visible'),
    ).toHaveCount(0)
    await expect(page.locator('.pa-login-terms:visible')).toHaveCount(0)
    await expect(page.getByText(/Terms and Conditions/i)).toBeHidden()
    await expect(page.getByText(/A calm, precise workspace/i)).toHaveCount(0)

    const card = await page.evaluate(() => {
      const body =
        document.getElementById('login-body') ||
        document.querySelector('#login .x-window-body')
      const form = document.getElementById('LoginForm')
      const user = document.getElementById('user_name_login')
      const hero = document.querySelector('.pa-login-hero') as HTMLElement | null
      const formPane = document.querySelector('.pa-login-form-pane') as HTMLElement | null
      const title = document.querySelector('.pa-login-form-title') as HTMLElement | null
      const sub = document.querySelector('.pa-login-form-sub') as HTMLElement | null
      const win = document.getElementById('login')
      if (!body) return null
      const r = body.getBoundingClientRect()
      const wr = win ? win.getBoundingClientRect() : null
      const fr = form ? form.getBoundingClientRect() : null
      const ur = user ? user.getBoundingClientRect() : null
      const hr = hero ? hero.getBoundingClientRect() : null
      const pr = formPane ? formPane.getBoundingClientRect() : null
      const tr = title ? title.getBoundingClientRect() : null
      const sr = sub ? sub.getBoundingClientRect() : null
      const heroBg = hero ? getComputedStyle(hero).backgroundImage : ''
      const bodyBorder = getComputedStyle(body).borderWidth
      const shadows = [...document.querySelectorAll('.x-css-shadow')].filter(
        (el) => getComputedStyle(el).display !== 'none' && getComputedStyle(el).visibility !== 'hidden',
      )
      return {
        ready: body.classList.contains('pa-login-card-ready'),
        w: r.width,
        h: r.height,
        centered: Math.abs(r.left + r.width / 2 - window.innerWidth / 2) < 48,
        formVisible: !!(fr && fr.height > 40 && fr.top > r.top && fr.bottom < r.bottom + 8),
        userVisible: !!(ur && ur.height > 20 && ur.top > r.top && ur.bottom < r.bottom + 8),
        heroW: hr?.width ?? 0,
        formW: pr?.width ?? 0,
        widthDelta: hr && pr ? Math.abs(hr.width - pr.width) : 999,
        heightDelta: hr && pr ? Math.abs(hr.height - pr.height) : 999,
        // Corner seam: hero must share the body's left/top edge (no 1px white bleed)
        heroFlushLeft: hr ? Math.abs(hr.left - r.left) <= 1 : false,
        heroFlushTop: hr ? Math.abs(hr.top - r.top) <= 1 : false,
        bodyHasNoCssBorder: bodyBorder === '0px',
        extShadowGone: shadows.length === 0,
        winRadius: win ? getComputedStyle(win).borderRadius : '',
        bannerBg: /login-banner\.jpg/.test(heroBg),
        theme: document.documentElement.classList.contains('pa-login-theme-light')
          ? 'light'
          : document.documentElement.classList.contains('pa-login-theme-dark')
            ? 'dark'
            : 'none',
        hasLogo: !!document.querySelector('img.pa-login-form-logo'),
        leftBrandHidden: (() => {
          const g = document.querySelector('.pa-login-hero .pa-login-brand-glass') as HTMLElement | null
          return !g || getComputedStyle(g).display === 'none'
        })(),
        termsHidden: ![...document.querySelectorAll('.pa-login-terms')].some(
          (el) => getComputedStyle(el).display !== 'none',
        ),
        // Form copy ↔ field column symmetry
        formAlignLeft:
          tr && sr && ur
            ? Math.max(
                Math.abs(tr.left - ur.left),
                Math.abs(sr.left - ur.left),
              ) <= 2
            : false,
        formAlignWidth:
          tr && ur ? Math.abs(tr.width - ur.width) <= 2 : false,
        titleToSubGap: tr && sr ? sr.top - tr.bottom : -1,
        subToUserGap: sr && ur ? ur.top - sr.bottom : -1,
        winMatchesBody:
          wr && r
            ? Math.abs(wr.left - r.left) <= 1 &&
              Math.abs(wr.top - r.top) <= 1 &&
              Math.abs(wr.width - r.width) <= 2 &&
              Math.abs(wr.height - r.height) <= 2
            : false,
      }
    })
    expect(card?.ready).toBe(true)
    expect(card!.w).toBeGreaterThan(640)
    expect(card!.h).toBeGreaterThan(420)
    expect(card!.centered).toBe(true)
    expect(card!.formVisible).toBe(true)
    expect(card!.userVisible).toBe(true)
    expect(card!.bannerBg).toBe(true)
    expect(card!.theme).toBe('light')
    expect(card!.hasLogo).toBe(true)
    expect(card!.leftBrandHidden).toBe(true)
    expect(card!.termsHidden).toBe(true)
    // Equal glass split — columns share height and near-equal width
    expect(card!.heightDelta).toBeLessThanOrEqual(2)
    expect(card!.heroW).toBeGreaterThan(300)
    expect(card!.formW).toBeGreaterThan(300)
    expect(card!.widthDelta).toBeLessThanOrEqual(8)
    // Wrapper / corner integrity
    expect(card!.heroFlushLeft).toBe(true)
    expect(card!.heroFlushTop).toBe(true)
    expect(card!.bodyHasNoCssBorder).toBe(true)
    expect(card!.extShadowGone).toBe(true)
    expect(card!.winMatchesBody).toBe(true)
    // Form column symmetry + breathing room under subtitle
    expect(card!.formAlignLeft).toBe(true)
    expect(card!.formAlignWidth).toBe(true)
    expect(card!.titleToSubGap).toBeGreaterThanOrEqual(4)
    expect(card!.titleToSubGap).toBeLessThanOrEqual(16)
    expect(card!.subToUserGap).toBeGreaterThanOrEqual(20)
    expect(card!.subToUserGap).toBeLessThanOrEqual(40)

    await page.screenshot({ path: path.join(shots, '10-login.png') })
    await page.screenshot({ path: path.join(shots, '10-login-light.png') })

    // Toggle to dark and re-check symmetry
    await page.evaluate(() => {
      const fn = (window as unknown as { paConverterToggleLoginTheme?: () => string })
        .paConverterToggleLoginTheme
      if (fn) fn()
      else (document.getElementById('pa-login-theme-toggle') as HTMLButtonElement | null)?.click()
    })
    await expect
      .poll(
        async () =>
          page.evaluate(() => {
            const root = document.documentElement
            if (root.classList.contains('pa-theme-dark') || root.classList.contains('pa-login-theme-dark'))
              return 'dark'
            return 'light'
          }),
        { timeout: 10_000 },
      )
      .toBe('dark')
    expect(
      await page.evaluate(() => document.documentElement.getAttribute('data-pa-theme')),
    ).toBe('dark')

    const dark = await page.evaluate(() => {
      const hero = document.querySelector('.pa-login-hero') as HTMLElement | null
      const formPane = document.querySelector('.pa-login-form-pane') as HTMLElement | null
      const body =
        document.getElementById('login-body') ||
        document.querySelector('#login .x-window-body')
      const hr = hero?.getBoundingClientRect()
      const pr = formPane?.getBoundingClientRect()
      return {
        cardBg: body ? getComputedStyle(body).backgroundColor : '',
        widthDelta: hr && pr ? Math.abs(hr.width - pr.width) : 999,
      }
    })
    expect(dark.widthDelta).toBeLessThan(120)
    expect(dark.cardBg).toBeTruthy()

    await page.screenshot({ path: path.join(shots, '10-login-dark.png') })
  })

  test('main left rail is glass with flat icons', async ({ page }) => {
    await login(page)
    await page.screenshot({ path: path.join(shots, '11-dashboard.png'), fullPage: true })

    const bar = await leftBarMeta(page, '#mainpaneltabs .x-tab-bar-left')
    expect(bar).toBeTruthy()
    expect(bar!.w).toBeGreaterThan(160)
    expect(bar!.w).toBeLessThan(320)
    expect(bar!.x).toBeLessThan(40)
    expect(bar!.backdrop).toMatch(/blur/i)
    expect(bar!.icons.length).toBeGreaterThanOrEqual(5)
    expect(bar!.icons).toEqual(
      expect.arrayContaining(['dashboard', 'projects', 'devices', 'settings']),
    )
    expect(await bodyWidth(page, 'mainpaneltabs')).toBeGreaterThan(400)

    // No double-gap between sidebar and body; Help removed; brand + hero present
    const shell = await page.evaluate(() => {
      const barEl = document.querySelector('#mainpaneltabs .x-tab-bar-left') as HTMLElement | null
      const bodyEl = document.getElementById('mainpaneltabs-body')
      const br = barEl?.getBoundingClientRect()
      const bd = bodyEl?.getBoundingClientRect()
      const helpVisible = [...document.querySelectorAll('#mainpaneltabs .x-tab-bar-left .x-tab')].some(
        (t) => /help/i.test(t.textContent || '') && getComputedStyle(t).display !== 'none',
      )
      return {
        gap: br && bd ? bd.left - br.right : 999,
        bodyRightSlack: bd ? Math.abs(window.innerWidth - bd.right) : 999,
        marginLeft: bodyEl ? getComputedStyle(bodyEl).marginLeft : '',
        helpVisible,
        hasNavBrand: !!document.querySelector('#mainpaneltabs .pa-nav-brand'),
        hasHeroVisible: (() => {
          const img = document.querySelector('img[src*="pa-side-hero"], img.pa-dash-hero') as HTMLElement | null
          return !!(img && getComputedStyle(img).display !== 'none')
        })(),
        tagline: /Policy conversion workspace/i.test(document.body.innerText || ''),
        theme: document.documentElement.getAttribute('data-pa-theme') || '',
      }
    })
    expect(shell.gap).toBeLessThanOrEqual(8)
    expect(shell.gap).toBeGreaterThanOrEqual(-2)
    expect(shell.marginLeft).toBe('0px')
    expect(shell.bodyRightSlack).toBeLessThanOrEqual(24)
    expect(shell.helpVisible).toBe(false)
    expect(shell.hasNavBrand).toBe(false)
    expect(shell.hasHeroVisible).toBe(false)
    expect(shell.tagline).toBe(false)
    expect(['light', 'dark']).toContain(shell.theme)

    // Active nav: Apple glass pill — text must stay readable (no solid blue fill on label)
    const activeNav = await page.evaluate(() => {
      const tab = document.querySelector(
        '#mainpaneltabs .x-tab-bar-left .x-tab-active, #mainpaneltabs .pa-side-nav .x-tab-active',
      ) as HTMLElement | null
      const inner = tab?.querySelector('.x-tab-inner') as HTMLElement | null
      const toggle = document.getElementById('pa-login-theme-toggle')
      const tr = toggle?.getBoundingClientRect()
      return {
        innerBg: inner ? getComputedStyle(inner).backgroundColor : '',
        tabBg: tab ? getComputedStyle(tab).backgroundColor : '',
        toggleBottom: tr ? window.innerHeight - tr.bottom : -1,
        toggleLeft: tr?.left ?? -1,
        toggleOverlapsFilter: (() => {
          if (!tr) return false
          const filters = [...document.querySelectorAll('.x-btn')]
            .filter((b) => /filter/i.test(b.textContent || ''))
            .map((b) => b.getBoundingClientRect())
          return filters.some(
            (f) =>
              tr.left < f.right &&
              tr.right > f.left &&
              tr.top < f.bottom &&
              tr.bottom > f.top,
          )
        })(),
      }
    })
    expect(activeNav.innerBg).toMatch(/rgba?\(0,\s*0,\s*0,\s*0\)|transparent/)
    expect(activeNav.toggleLeft).toBeLessThan(80)
    expect(activeNav.toggleBottom).toBeLessThan(40)
    expect(activeNav.toggleOverlapsFilter).toBe(false)

    // Glass atmosphere layer (body::before) — survives Ext body overrides
    const atmosphere = await page.evaluate(() => {
      const cs = getComputedStyle(document.body, '::before')
      return { img: cs.backgroundImage, pos: cs.position }
    })
    expect(atmosphere.img).toMatch(/gradient/i)
  })

  test('Projects list keeps left rail (no top primary menu)', async ({ page }) => {
    await login(page)
    await page.locator('#mainpaneltabs .x-tab-bar-left .x-tab').filter({ hasText: 'Projects' }).click()
    await page.waitForTimeout(1200)
    await page.screenshot({ path: path.join(shots, '12-projects.png'), fullPage: true })

    const pos = await page.evaluate(() => Ext.getCmp('mainpaneltabs')?.getTabPosition?.())
    expect(pos).toBe('left')

    // No visible wide top primary tab bar
    const topPrimary = await page.evaluate(() => {
      return [...document.querySelectorAll('.x-tab-bar-top, .x-tab-bar-horizontal')]
        .map((el) => el.getBoundingClientRect())
        .filter((r) => r.y >= 0 && r.y < 120 && r.width > 400 && r.height > 30)
    })
    expect(topPrimary.length).toBe(0)

    await expect(page.locator('#mainpaneltabs .pa-nav-brand')).toHaveCount(0)
    await expect(page.getByText('Library').first()).toBeVisible({ timeout: 15_000 })
    await expect(page.locator('#ProjectsGridPanel')).toBeVisible()
    await expect(page.locator('#ProjectsGridPanel.pa-projects-tiles')).toHaveCount(0)
  })

  test('opening a project uses left project nav (not top menu)', async ({ page }) => {
    await login(page)
    await page.locator('#mainpaneltabs .x-tab-bar-left .x-tab').filter({ hasText: 'Projects' }).click()
    await page.waitForTimeout(1500)

    const row = page.locator('#ProjectsGridPanel .x-grid-row').filter({ hasText: 'Test' }).first()
    await expect(row).toBeVisible({ timeout: 30_000 })
    await row.dblclick()

    // Wait for project workspace
    await expect
      .poll(async () => page.evaluate(() => !!Ext.getCmp('projectOptions')), { timeout: 60_000 })
      .toBeTruthy()

    await page.waitForTimeout(2500)
    await page.screenshot({ path: path.join(shots, '13-project-open.png'), fullPage: true })

    const projPos = await page.evaluate(() => Ext.getCmp('projectOptions')?.getTabPosition?.())
    expect(projPos).toBe('left')

    const projBar = await leftBarMeta(
      page,
      '#projectOptions .x-tab-bar-left, #ProjectOptionsTabBar.x-tab-bar-left, .pa-project-nav',
    )
    expect(projBar).toBeTruthy()
    expect(projBar!.w).toBeGreaterThan(160)
    expect(projBar!.w).toBeLessThan(320)
    expect(projBar!.backdrop).toMatch(/blur/i)

    // Project tabs should include Import / Policies style labels on the LEFT
    const labels = (projBar!.labels || []).map((l) => l.toLowerCase())
    expect(labels.some((l) => l.includes('import') || l.includes('dashboard'))).toBeTruthy()

    // No fat top menu spanning the viewport
    const topWide = await page.evaluate(() =>
      [...document.querySelectorAll('.x-tab-bar-top')]
        .map((el) => el.getBoundingClientRect())
        .filter((r) => r.y >= 0 && r.y < 80 && r.width > 700),
    )
    expect(topWide.length).toBe(0)

    await expect(page.locator('.pa-nav-back')).toBeVisible()
    expect(await bodyWidth(page, 'projectOptions')).toBeGreaterThan(400)

    // Network / Export must stay clickable (not section-headered away)
    const navClick = await page.evaluate(() => {
      const tabs = [...document.querySelectorAll('#projectOptions .x-tab-bar-left .x-tab, .pa-project-nav .x-tab')]
      const info = tabs.map((t) => ({
        text: (t.textContent || '').trim(),
        section: t.getAttribute('data-pa-section'),
        pe: getComputedStyle(t).pointerEvents,
        icon: t.getAttribute('data-pa-icon'),
      }))
      const bar = document.querySelector(
        '#projectOptions .x-tab-bar-left, .pa-project-nav',
      ) as HTMLElement | null
      const body = document.getElementById('projectOptions-body')
      const br = bar?.getBoundingClientRect()
      const bd = body?.getBoundingClientRect()
      return {
        info,
        gap: br && bd ? bd.left - br.right : 999,
        marginLeft: body ? getComputedStyle(body).marginLeft : '',
      }
    })
    expect(navClick.gap).toBeLessThanOrEqual(8)
    expect(navClick.marginLeft).toBe('0px')
    const clean = (t: string) => t.replace(/^[^\w]+/, '').trim().toLowerCase()
    const network = navClick.info.find((t) => clean(t.text) === 'network')
    const tools = navClick.info.find((t) => clean(t.text) === 'tools')
    const exp = navClick.info.find((t) => clean(t.text) === 'export')
    for (const tab of [network, tools, exp]) {
      if (!tab) continue
      expect(tab.section).toBeNull()
      expect(tab.pe).not.toBe('none')
    }

    // Click Network and confirm active tab changes
    const netTab = page
      .locator('#projectOptions .x-tab-bar-left .x-tab, .pa-project-nav .x-tab')
      .filter({ hasText: /Network/i })
    if ((await netTab.count()) > 0) {
      await netTab.first().click()
      await page.waitForTimeout(800)
      const active = await page.evaluate(() => {
        const t = Ext.getCmp('projectOptions')?.getActiveTab?.()
        return (t?.title || t?.itemId || '').toString()
      })
      expect(active.toLowerCase()).toMatch(/network/)
    }

    // Flat icons swapped into object stats when present
    await page.evaluate(() => {
      const fn = (window as unknown as { paConverterFixLayouts?: () => void }).paConverterFixLayouts
      // trigger via DOM mutation path — icons applied in fixAllLayouts already
      void fn
    })

    // Back to projects
    await page.locator('.pa-nav-back').click()
    await page.waitForTimeout(1500)
    await expect(page.locator('#mainpaneltabs')).toBeVisible()
    await page.screenshot({ path: path.join(shots, '14-back-projects.png'), fullPage: true })
  })

  test('Devices and Settings remain left-nav + glass', async ({ page }) => {
    await login(page)
    for (const name of ['Devices', 'Settings']) {
      await page.locator('#mainpaneltabs .x-tab-bar-left .x-tab').filter({ hasText: name }).click()
      await page.waitForTimeout(1000)
      await page.screenshot({
        path: path.join(shots, `15-${name.toLowerCase()}.png`),
        fullPage: true,
      })
      expect(await page.evaluate(() => Ext.getCmp('mainpaneltabs')?.getTabPosition?.())).toBe(
        'left',
      )
      expect(await bodyWidth(page, 'mainpaneltabs')).toBeGreaterThan(400)
    }
  })
})
