import { test } from '@playwright/test'
import { mkdirSync } from 'node:fs'

const OUT = 'shots/visual'
const VIEWPORTS = [
  { name: 'desktop', width: 1536, height: 1024 },
  { name: 'laptop', width: 1280, height: 900 },
  { name: 'rail', width: 1100, height: 900 },
  { name: 'tablet', width: 820, height: 1100 },
  { name: 'phone', width: 390, height: 844 },
]
const ROUTES = ['/', '/findings', '/runs', '/repos', '/fixes']

for (const vp of VIEWPORTS) {
  test(`routes render at ${vp.name} ${vp.width}x${vp.height}`, async ({ page }) => {
    mkdirSync(OUT, { recursive: true })
    await page.setViewportSize({ width: vp.width, height: vp.height })
    for (const r of ROUTES) {
      await page.goto(r)
      await page.waitForTimeout(1200)
      await page.screenshot({
        path: `${OUT}/${vp.name}-${r === '/' ? 'overview' : r.slice(1)}.png`,
        fullPage: false,
      })
    }
  })
}
