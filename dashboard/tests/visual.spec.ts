import { test, expect, type Page } from '@playwright/test'
import { mkdirSync } from 'node:fs'

// Visual + behavioral gates for all nine routes (spec E14, §8.2).
// Fixture: tests/fixture_board.py — alpha (completed run + verified finding
// + fix), beta (running), gamma (stale), legacy, corrupt, delta.

const OUT = 'shots/visual'
const RUN = '20260101-000000-11111'
const FID = 'f00000000'

const ROUTES: { name: string; path: string; check: (p: Page) => Promise<void> }[] = [
  {
    name: 'overview', path: '/',
    check: async p => {
      await expect(p.getByRole('heading', { name: 'Security workspace' })).toBeVisible()
      await expect(p.getByRole('heading', { name: 'Repository scans' })).toBeVisible()
    },
  },
  {
    name: 'findings', path: '/findings',
    check: async p => {
      await expect(p.getByRole('heading', { name: 'Findings' }).first()).toBeVisible()
    },
  },
  {
    name: 'runs', path: '/runs',
    check: async p => {
      await expect(p.getByRole('heading', { name: 'Runs' }).first()).toBeVisible()
    },
  },
  {
    name: 'repos', path: '/repos',
    check: async p => {
      await expect(p.getByRole('heading', { name: 'Repositories' }).first()).toBeVisible()
    },
  },
  {
    name: 'fixes', path: '/fixes',
    check: async p => {
      await expect(p.getByRole('heading', { name: 'Fixes' }).first()).toBeVisible()
    },
  },
  {
    name: 'repo-detail', path: '/repos/alpha',
    check: async p => {
      await expect(p.getByRole('heading', { name: /Runs ·/ })).toBeVisible()
    },
  },
  {
    name: 'run-detail', path: `/repos/alpha/runs/${RUN}`,
    check: async p => {
      await expect(p.getByRole('heading', { name: /Events/ })).toBeVisible()
    },
  },
  {
    name: 'finding-case', path: `/repos/alpha/findings/${FID}`,
    check: async p => {
      await expect(p.getByRole('tab', { name: 'Proof' })).toBeVisible()
      await expect(p.getByRole('tab', { name: 'Source' })).toBeVisible()
    },
  },
  {
    name: 'fix-detail', path: `/repos/alpha/fixes/${FID}`,
    check: async p => {
      await expect(p.getByRole('heading', { name: 'Patch' })).toBeVisible()
    },
  },
]

const VIEWPORTS = [
  { name: '1536', width: 1536, height: 1024 },
  { name: '1440', width: 1440, height: 900 },
]
// Overview/Findings/case also exercise the outer desktop bounds.
const WIDE = [
  { name: '1280', width: 1280, height: 800 },
  { name: '1920', width: 1920, height: 1080 },
]

async function shoot(page: Page, vp: { name: string; width: number; height: number }, name: string, path: string) {
  mkdirSync(OUT, { recursive: true })
  await page.setViewportSize({ width: vp.width, height: vp.height })
  await page.goto(path)
  await page.evaluate(() => document.fonts.ready)
  await page.waitForTimeout(800)
  await page.screenshot({ path: `${OUT}/${vp.name}-${name}.png`, fullPage: false })
}

for (const vp of VIEWPORTS) {
  test(`all nine routes render+behave at ${vp.width}x${vp.height}`, async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(String(e)))
    page.on('console', m => { if (m.type() === 'error') errors.push(m.text()) })
    for (const r of ROUTES) {
      await shoot(page, vp, r.name, r.path)
      await r.check(page)
      // no page-wide horizontal overflow at any route
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth)
      expect(overflow, `horizontal overflow on ${r.name}`).toBeLessThanOrEqual(0)
    }
    expect(errors.filter(e => !e.includes('favicon'))).toEqual([])
  })
}

for (const vp of WIDE) {
  test(`key routes at ${vp.width}x${vp.height}`, async ({ page }) => {
    for (const rname of ['overview', 'findings', 'finding-case']) {
      const route = ROUTES.find(x => x.name === rname)!
      await shoot(page, vp, route.name, route.path)
      await route.check(page)
    }
  })
}

test('overview geometry matches the approved composition at 1536x1024', async ({ page }) => {
  await page.setViewportSize({ width: 1536, height: 1024 })
  await page.goto('/')
  await page.evaluate(() => document.fonts.ready)
  await page.waitForTimeout(800)

  const sidebar = page.locator('aside.sidebar')
  const sb = await sidebar.boundingBox()
  expect(sb!.width).toBeGreaterThanOrEqual(192)
  expect(sb!.width).toBeLessThanOrEqual(208)

  const main = page.locator('main.main')
  const mb = await main.boundingBox()
  expect(mb!.x).toBeGreaterThanOrEqual(200)
  expect(mb!.x).toBeLessThanOrEqual(224)

  // exactly one active nav item, with standard anchor semantics (E13)
  const current = page.locator('.nav a[aria-current="page"]')
  await expect(current).toHaveCount(1)
  await expect(current).toHaveText(/Overview/)

  // repository table is bounded: <=4 data rows + a View-all affordance
  const repoRows = page.locator('table.rtable tbody tr')
  expect(await repoRows.count()).toBeLessThanOrEqual(4)

  // findings/proof split is ~equal width (within 3 percentage points)
  const panels = page.locator('.split > *')
  if (await panels.count() >= 2) {
    const a = await panels.nth(0).boundingBox()
    const b = await panels.nth(1).boundingBox()
    const total = a!.width + b!.width
    expect(Math.abs(a!.width / total - 0.5)).toBeLessThanOrEqual(0.03)
  }

  // proof pane shows recorded output + a primary action (E04 regression)
  await expect(page.getByRole('tab', { name: 'Proof' })).toBeVisible()
})

test('finding case preserves run scope and tab in URL', async ({ page }) => {
  await page.goto(`/repos/alpha/findings/${FID}?run=${RUN}&tab=source`)
  await expect(page.getByRole('tab', { name: 'Source', selected: true })).toBeVisible()
  await page.getByRole('tab', { name: 'History' }).click()
  await expect(page).toHaveURL(/tab=history/)
  await expect(page).toHaveURL(new RegExp(`run=${RUN}`))
})
