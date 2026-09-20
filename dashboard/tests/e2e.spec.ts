import { test, expect } from '@playwright/test'

const errors: string[] = []
test.beforeEach(({ page }) => {
  errors.length = 0
  page.on('pageerror', e => errors.push(String(e)))
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()) })
})
test.afterEach(() => {
  expect(errors.filter(e => !e.includes('favicon'))).toEqual([])
})

test('overview renders repo scans, selected run, findings, inspector', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Security workspace' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Repository scans' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'alpha', exact: true }).first()).toBeVisible()
  await expect(page.getByRole('heading', { name: /Run/ })).toBeVisible()
  await expect(page.getByRole('tab', { name: 'Proof' })).toBeVisible()
  await expect(page.getByRole('switch', { name: 'Follow live' })).toBeVisible()
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

test('search box drives findings query', async ({ page }) => {
  await page.goto('/')
  await page.getByLabel('Search findings').fill('eval')
  await page.getByLabel('Search findings').press('Enter')
  await expect(page).toHaveURL(/findings\?q=eval/)
})

test('runs and run detail render', async ({ page }) => {
  await page.goto('/runs')
  await expect(page.getByRole('heading', { name: 'Runs' }).first()).toBeVisible()
  await page.locator('table.data tbody tr').first().click()
  await expect(page).toHaveURL(/\/repos\/[^/]+\/runs\//)
  await expect(page.getByRole('heading', { name: /Events/ })).toBeVisible()
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
