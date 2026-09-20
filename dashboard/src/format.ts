export const SEV_LABEL: Record<string, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info',
}
export const VER_LABEL: Record<string, string> = {
  reproduced: 'Reproduced',
  'recorded-verified': 'Recorded verified',
  awaiting: 'Awaiting test',
  candidate: 'Candidate',
  dismissed: 'Dismissed',
}
export const RUN_LABEL: Record<string, string> = {
  running: 'Running', completed: 'Completed', failed: 'Failed',
  pending: 'Pending', unknown: 'Unknown',
}
export const FIX_LABEL: Record<string, string> = {
  'fix-verified': 'Gate passed', 'fix-rejected': 'Rejected',
  'fix-unverifiable': 'Unverifiable',
}
export const CHECK_LABEL: Record<string, string> = {
  'patch-produced': 'Patch produced',
  'poc-contract': 'PoC replay contract',
  'poc-rerun-patched': 'PoC dead on patched code',
  'rescan-clean': 'Changed code rescans clean',
}
export const BASIS_LABEL: Record<string, string> = {
  signal: 'Recorded signal matched',
  sanitizer: 'Sanitizer fired',
  panic: 'Runtime panic observed',
  'probe-signal': 'Probe signal matched',
  'service-signal': 'Service probe matched',
}

export function fmtTime(ts: number | null | undefined): string {
  if (!ts) return '—'
  const d = new Date(ts * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

export function fmtFull(ts: number | null | undefined): string {
  if (!ts) return 'unrecorded'
  const d = new Date(ts * 1000)
  return d.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    timeZoneName: 'short',
  })
}

export function ago(ts: number | null | undefined, now?: number): string {
  if (!ts) return '—'
  const s = Math.max(0, (now ?? Date.now()) / 1000 - ts)
  if (s < 60) return `${Math.floor(s)}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

export function fmtDur(a: number | null | undefined, b?: number | null): string {
  if (a == null || b == null) return '—'
  return fmtDurSecs(Math.max(0, b - a))
}

export function fmtDurSecs(s: number | null | undefined): string {
  if (s == null) return '—'
  const sec = Math.floor(Math.max(0, s))
  if (sec < 60) return `00:${pad2(sec)}`
  const m = Math.floor(sec / 60)
  if (m < 60) return `${pad2(m)}:${pad2(sec % 60)}`
  return `${pad2(Math.floor(m / 60))}:${pad2(m % 60)}:${pad2(sec % 60)}`
}

const pad2 = (n: number) => String(n).padStart(2, '0')

export function fmtBytes(n: number | null | undefined): string {
  if (n == null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

export function shortSha(sha: string | null | undefined): string {
  return sha ? sha.slice(0, 8) : '—'
}

export function shortRun(id: string | null | undefined): string {
  if (!id) return '—'
  const m = id.match(/^\d{8}-\d{6}-(\d+)$/)
  return m ? m[1] : id
}

export function stageLabel(id: string): string {
  const labels: Record<string, string> = {
    poc: 'Verify', adjudicate: 'Adjudicate', sweep: 'Sweep', rank: 'Rank',
    ingest: 'Ingest', recon: 'Recon', consensus: 'Consensus', hunt: 'Hunt',
    report: 'Report', writeup: 'Writeup', learn: 'Learn', chain: 'Chain',
  }
  return labels[id] || id
}

export function heartbeatText(hb: { ts: number | null; live: boolean; done: boolean; stale: boolean } | null): { text: string; stale: boolean } {
  if (!hb || hb.ts == null) return { text: '—', stale: false }
  if (hb.done) return { text: 'Finished', stale: false }
  const t = ago(hb.ts)
  if (hb.live) return { text: t, stale: false }
  return { text: `${t} · stale`, stale: true }
}
