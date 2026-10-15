import { expect, test, type Page } from '@playwright/test'

const DEFAULT_UI = 'https://localhost:18443/'

async function resetStorage(page: Page) {
  await page.goto('/')
  await page.evaluate(() => {
    localStorage.removeItem('pa-converter-wave2-settings')
    localStorage.removeItem('pa-theme')
  })
  await page.reload()
}

/** Capture window.open targets without requiring Expedition to be running */
async function stubWindowOpen(page: Page) {
  await page.evaluate(() => {
    const w = window as Window & { __openedUrls?: string[] }
    w.__openedUrls = []
    window.open = ((url?: string | URL) => {
      w.__openedUrls!.push(String(url ?? ''))
      return null
    }) as typeof window.open
  })
}

async function openedUrls(page: Page) {
  return page.evaluate(() => {
    const w = window as Window & { __openedUrls?: string[] }
    return w.__openedUrls ?? []
  })
}

test.describe('PA-Converter Wave 2', () => {
  test.beforeEach(async ({ page }) => {
    await resetStorage(page)
  })

  test('shell renders brand, sidebar, and dashboard', async ({ page }) => {
    await expect(page.getByTestId('brand-name')).toHaveText('PA-Converter')
    await expect(page.getByTestId('sidebar')).toBeVisible()
    await expect(page.getByTestId('page-title')).toHaveText('Dashboard')
    await expect(page.getByTestId('page-dashboard')).toBeVisible()
    await expect(page.getByTestId('health-status')).toBeVisible()
    await expect(page.locator('.brand-mark-svg')).toBeVisible()
  })

  test('favicon is the PA mark (not Vite purple)', async ({ request, baseURL }) => {
    const res = await request.get(`${baseURL}/favicon.svg`)
    expect(res.ok()).toBeTruthy()
    const body = await res.text()
    expect(body).toContain('viewBox="0 0 64 64"')
    expect(body).not.toContain('#863bff')
    expect(body).toMatch(/#F5F5F7|#f5f5f7/)
  })

  test('pa.svg brand asset serves correctly', async ({ request, baseURL }) => {
    const res = await request.get(`${baseURL}/pa.svg`)
    expect(res.ok()).toBeTruthy()
    const body = await res.text()
    expect(body).toContain('linearGradient')
    expect(body).not.toContain('#863bff')
  })

  test('navigates all primary nav destinations', async ({ page }) => {
    const routes: Array<{ id: string; title: string }> = [
      { id: 'import', title: 'Import' },
      { id: 'projects', title: 'Projects' },
      { id: 'devices', title: 'Devices' },
      { id: 'ml', title: 'Machine learning' },
      { id: 'settings', title: 'Settings' },
      { id: 'dashboard', title: 'Dashboard' },
    ]
    for (const r of routes) {
      await page.getByTestId(`nav-${r.id}`).click()
      await expect(page.getByTestId('page-title')).toHaveText(r.title)
      await expect(page.getByTestId(`page-${r.id}`)).toBeVisible()
    }
  })

  test('dashboard CTAs use correct Expedition URL', async ({ page }) => {
    const link = page.getByTestId('dashboard-expedition-link')
    await expect(link).toHaveAttribute('href', DEFAULT_UI)
    await expect(link).toHaveText('https://localhost:18443')

    await stubWindowOpen(page)
    await page.getByTestId('cta-open-expedition').click()
    expect(await openedUrls(page)).toContain(DEFAULT_UI)
  })

  test('New import navigates to Import page', async ({ page }) => {
    await page.getByTestId('cta-new-import').click()
    await expect(page.getByTestId('page-title')).toHaveText('Import')
    await expect(page.getByTestId('import-expedition-link')).toHaveAttribute(
      'href',
      DEFAULT_UI,
    )
  })

  test('theme toggle switches light/dark', async ({ page }) => {
    const html = page.locator('html')
    const before = await html.getAttribute('data-theme')
    await page.getByTestId('theme-toggle').click()
    const after = await html.getAttribute('data-theme')
    expect(after).not.toBe(before)
    expect(after === 'light' || after === 'dark').toBeTruthy()
    await page.getByTestId('theme-toggle').click()
    await expect(html).toHaveAttribute('data-theme', before!)
  })

  test('settings persist base URL and update links', async ({ page }) => {
    await page.getByTestId('nav-settings').click()
    await page.getByTestId('settings-base-url').fill('https://127.0.0.1:18443')
    await page.getByTestId('settings-https-port').fill('18443')
    await page.getByTestId('settings-http-port').fill('18080')
    await page.getByTestId('cta-save-settings').click()
    await expect(page.getByTestId('settings-saved')).toBeVisible()
    await expect(page.getByTestId('settings-preview-link')).toHaveAttribute(
      'href',
      'https://127.0.0.1:18443/',
    )

    await page.getByTestId('nav-dashboard').click()
    await expect(page.getByTestId('dashboard-expedition-link')).toHaveAttribute(
      'href',
      'https://127.0.0.1:18443/',
    )
    await expect(page.getByTestId('health-status')).toContainText(
      'https://127.0.0.1:18443',
    )

    // Reload keeps persistence (do not clear storage here)
    await page.reload()
    await expect(page.getByTestId('dashboard-expedition-link')).toHaveAttribute(
      'href',
      'https://127.0.0.1:18443/',
    )
  })

  test('reset defaults restores Docker ports', async ({ page }) => {
    await page.getByTestId('nav-settings').click()
    await page.getByTestId('settings-base-url').fill('https://example.test:9999')
    await page.getByTestId('cta-save-settings').click()
    await page.getByTestId('cta-reset-settings').click()
    await expect(page.getByTestId('settings-base-url')).toHaveValue(
      'https://localhost:18443',
    )
    await expect(page.getByTestId('settings-https-port')).toHaveValue('18443')
    await expect(page.getByTestId('settings-http-port')).toHaveValue('18080')
  })

  test('sidebar classic UI opens Expedition', async ({ page }) => {
    await stubWindowOpen(page)
    await page.getByTestId('sidebar-open-classic').click()
    expect(await openedUrls(page)).toContain(DEFAULT_UI)
  })

  test('projects and devices link to Expedition', async ({ page }) => {
    await page.getByTestId('nav-projects').click()
    await expect(page.getByTestId('projects-expedition-link')).toHaveAttribute(
      'href',
      DEFAULT_UI,
    )

    await page.getByTestId('nav-devices').click()
    await expect(page.getByTestId('devices-expedition-link')).toHaveAttribute(
      'href',
      DEFAULT_UI,
    )

    await stubWindowOpen(page)
    await page.getByTestId('cta-add-device').click()
    expect(await openedUrls(page)).toContain(DEFAULT_UI)
  })

  test('ML page exposes probe + expedition link', async ({ page }) => {
    await page.getByTestId('nav-ml').click()
    await expect(page.getByTestId('ml-expedition-link')).toHaveAttribute(
      'href',
      DEFAULT_UI,
    )
    await expect(page.getByTestId('ml-agent-stat')).toBeVisible()
    await page.getByTestId('cta-refresh-ml').click()
    await expect(page.getByTestId('health-status')).toBeVisible()
  })

  test('mobile layout still shows brand and nav', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await expect(page.getByTestId('brand-name')).toBeVisible()
    await expect(page.getByTestId('nav-settings')).toBeVisible()
    await page.getByTestId('nav-settings').click()
    await expect(page.getByTestId('page-settings')).toBeVisible()
  })
})
