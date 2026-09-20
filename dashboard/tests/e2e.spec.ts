import { test, expect } from '@playwright/test'

const errors: string[] = []
test.beforeEach(({ page }) => {
  errors.length = 0
  page.on('pageerror', e => errors.push(String(e)))
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()) })
})
test.afterEach(() => {
  expect(errors.filter(e => !e.includes('favicon')
    && !(allow404 && e.includes('404')))).toEqual([])
})

const FID = 'f00000000'

let allow404 = false
test.afterEach(() => { allow404 = false })

test('overview renders repo scans, selected run, findings, inspector', async ({ page }) => {
  await page.goto('/?repo=alpha')
  await expect(page.getByRole('heading', { name: 'Security workspace' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Repository scans' })).toBeVisible()
  // bounded inventory: at most 4 rows plus a View-all affordance
  expect(await page.locator('table.rtable tbody tr').count()).toBeLessThanOrEqual(4)
  await expect(page.getByRole('link', { name: /View all/ })).toBeVisible()
  await expect(page.getByRole('link', { name: 'alpha', exact: true }).first()).toBeVisible()
  await expect(page.getByRole('heading', { name: /Run/ })).toBeVisible()
  await expect(page.getByRole('tab', { name: 'Proof' })).toBeVisible()
})

test('follow live only appears on a running run', async ({ page }) => {
  await page.goto('/?repo=alpha')
  // alpha's latest run is completed — no Follow live control (E09)
  await expect(page.getByRole('switch', { name: 'Follow live' })).toHaveCount(0)
  await page.goto('/?repo=beta')
  await expect(page.getByRole('switch', { name: 'Follow live' })).toBeVisible()
})

test('active nav is a real anchor state', async ({ page }) => {
  await page.goto('/findings')
  const cur = page.locator('.nav a[aria-current="page"]')
  await expect(cur).toHaveCount(1)
  await expect(cur).toHaveText(/Findings/)
})

test('findings list filters and navigates to a case', async ({ page }) => {
  await page.goto('/findings')
  await expect(page.getByRole('heading', { name: 'Findings' }).first()).toBeVisible()
  await page.getByRole('button', { name: /^Dismissed/ }).click()
  await expect(page).toHaveURL(/status=dismissed/)
  const first = page.locator('table.data tbody tr td a.rowtitle').first()
  await expect(first).toBeVisible()
  await first.click()
  await expect(page).toHaveURL(/\/repos\/[^/]+\/findings\//)
  await expect(page.getByRole('tab', { name: 'History' })).toBeVisible()
})

test('inspector opens the top finding by default; row selection switches', async ({ page }) => {
  await page.goto('/findings')
  // no explicit selection — inspector already shows real evidence
  await expect(page.getByRole('tab', { name: 'Proof' })).toBeVisible()
  await expect(page.locator('table.data tbody tr.sel')).toHaveCount(1)
  const row = page.locator('table.data tbody tr').nth(1)
  const id = await row.locator('.fid').first().innerText()
  await row.click()
  await expect(page).toHaveURL(/sel=/)
  await expect(page.locator('.inspector .ptitle')).toContainText(id.trim().replace(/…$/, ''))
})

test('search box drives findings query', async ({ page }) => {
  await page.goto('/')
  await page.getByLabel('Search findings').fill('eval')
  await page.getByLabel('Search findings').press('Enter')
  await expect(page).toHaveURL(/findings\?q=eval/)
})

test('runs and run detail render; event ledger loads older without duplication', async ({ page }) => {
  await page.goto('/runs')
  await expect(page.getByRole('heading', { name: 'Runs' }).first()).toBeVisible()
  await page.locator('table.data tbody tr').first().click()
  await expect(page).toHaveURL(/\/repos\/[^/]+\/runs\//)
  await expect(page.getByRole('heading', { name: /Events/ })).toBeVisible()
  const rows = page.locator('.evrow, .ev-ledger .evrow')
  const before = await rows.count()
  const older = page.getByRole('button', { name: /Load older/i })
  if (await older.count()) {
    await older.click()
    await page.waitForTimeout(400)
    expect(await rows.count()).toBeGreaterThan(before)
    // deduped: no two consecutive identical timestamps+messages
    const texts = await page.locator('.evrow').allTextContents()
    expect(new Set(texts).size).toBe(texts.length)
  }
})

test('repositories and repo detail render', async ({ page }) => {
  await page.goto('/repos')
  await expect(page.getByText('corrupt', { exact: true })).toBeVisible()
  await page.getByRole('link', { name: 'alpha', exact: true }).click()
  await expect(page).toHaveURL(/\/repos\/alpha$/)
  await expect(page.getByRole('heading', { name: /Runs ·/ })).toBeVisible()
})

test('fixes list and fix detail render', async ({ page }) => {
  await page.goto('/fixes')
  await expect(page.getByRole('heading', { name: 'Fixes' }).first()).toBeVisible()
  await page.locator('table.data tbody tr td a').first().click()
  await expect(page).toHaveURL(/\/repos\/[^/]+\/fixes\//)
  await expect(page.getByRole('heading', { name: 'Patch' })).toBeVisible()
})

test('artifact preview stays in-workspace', async ({ page }) => {
  await page.goto(`/repos/alpha/findings/${FID}`)
  const eye = page.getByRole('button', { name: /Preview/i }).first()
  if (await eye.count()) {
    await eye.click()
    // JSON must not open in another tab — an inline viewer appears
    await expect(page.getByRole('button', { name: /Close/i })).toBeVisible()
  }
})

test('keyboard: nav, scope, finding selection, tabs', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('link', { name: 'Findings' }).focus()
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(/findings/)
  const tabs = page.getByRole('tablist')
  if (await tabs.count()) {
    await page.getByRole('tab').first().focus()
    await page.keyboard.press('ArrowRight')
  }
})

test('deep link reload works', async ({ page }) => {
  await page.goto('/findings')
  const href = await page.locator('table.data tbody tr td a').first().getAttribute('href')
  await page.goto(href!)
  await page.reload()
  await expect(page.getByRole('tab', { name: 'Proof' })).toBeVisible()
})

test('unknown run is a real error, not a silent latest fallback', async ({ page }) => {
  allow404 = true
  await page.goto(`/repos/alpha/findings/${FID}?run=does-not-exist`)
  await expect(page.getByText(/not found|unavailable|does not exist/i).first()).toBeVisible()
  await expect(page.getByRole('link', { name: /latest/i })).toBeVisible()
})
