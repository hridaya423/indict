import { describe, expect, it } from 'vitest'
import { ago, fmtBytes, fmtDur, fmtTime, shortRun, shortSha } from '../src/format'

describe('format', () => {
  it('fmtTime renders HH:MM:SS', () => {
    const t = fmtTime(1760000000)
    expect(t).toMatch(/^\d{2}:\d{2}:\d{2}$/)
  })
  it('ago never goes negative on future timestamps', () => {
    const future = Date.now() / 1000 + 3600
    expect(ago(future)).toBe('0s ago')
  })
  it('fmtDur handles missing ends and clamps negatives', () => {
    expect(fmtDur(null, 100)).toBe('—')
    expect(fmtDur(100, null)).toBe('—')
    expect(fmtDur(200, 100)).toBe('00:00')
    expect(fmtDur(100, 142)).toBe('00:42')
    expect(fmtDur(100, 160)).toBe('01:00')
    expect(fmtDur(100, 3760)).toBe('01:01:00')
  })
  it('fmtBytes', () => {
    expect(fmtBytes(null)).toBe('—')
    expect(fmtBytes(512)).toBe('512 B')
    expect(fmtBytes(2048)).toBe('2.0 KB')
  })
  it('shortSha/shortRun', () => {
    expect(shortSha('a1b2c3d4e5f6')).toBe('a1b2c3d4')
    expect(shortSha(null)).toBe('—')
    expect(shortRun('20260920-141434-40905')).toBe('40905')
    expect(shortRun('weird-id')).toBe('weird-id')
  })
})
