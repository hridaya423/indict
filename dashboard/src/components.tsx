import { useEffect, useRef, useState, type ReactNode } from 'react'
import { CheckCircle, XCircle, Warning, File, FileText, FileCode, DownloadSimple, Eye, ArrowClockwise } from '@phosphor-icons/react'
import type { ArtifactPreview, EventRow, Heartbeat, StageInterval, StagePending, EngineLane, ArtifactEntry, Progress } from './types'
import { fmtTime, fmtDur, fmtBytes, fmtEta, ago, RUN_LABEL } from './format'
import { Link, navigate } from './router'
import { ApiError, apiGet } from './api'

export function Badge({ kind, label }: { kind: string; label: string }) {
  return <span className={`badge ${kind}`}>{label}</span>
}

export function SeverityBadge({ sev }: { sev: string }) {
  const l = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }[sev] ?? sev
  return <Badge kind={sev} label={l} />
}

export function VerBadge({ v }: { v: string }) {
  const l: Record<string, string> = {
    reproduced: 'Reproduced', 'recorded-verified': 'Recorded verified',
    awaiting: 'Awaiting test', candidate: 'Candidate', dismissed: 'Dismissed',
  }
  return <Badge kind={v} label={l[v] ?? v} />
}

export function RunStateBadge({ state }: { state: string }) {
  return <Badge kind={state} label={RUN_LABEL[state] ?? state} />
}

export function HealthBadge({ h }: { h: string }) {
  const l = { complete: 'Complete', degraded: 'Degraded', unknown: 'Unknown' }[h] ?? h
  return <Badge kind={h} label={l} />
}

export function FixBadge({ verdict }: { verdict: string }) {
  const l: Record<string, string> = { 'fix-verified': 'Gate passed', 'fix-rejected': 'Rejected', 'fix-unverifiable': 'Unverifiable' }
  return <Badge kind={verdict} label={l[verdict] ?? verdict} />
}

export function CheckBadge({ outcome }: { outcome: string }) {
  const l = { pass: 'Pass', fail: 'Fail', skip: 'Skip' }[outcome] ?? outcome
  const k = outcome === 'pass' ? 'pass' : outcome === 'fail' ? 'failed' : 'not-run'
  return <Badge kind={k} label={l} />
}

export function WorkCell({ progress, state, etaSec, currentStageId }: {
  progress: Progress | null; state?: string; etaSec?: number | null
  currentStageId?: string
}) {
  if (state === 'completed') return <span className="txt muted">Complete</span>
  if (state === 'failed') return <span className="txt" style={{ color: 'var(--danger)' }}>Failed</span>
  const eta = state === 'running' && etaSec != null ? fmtEta(etaSec) : ''
  // progress belongs to the active stage only — a finished Hunt counter
  // must never read as Verify's progress
  if (!progress || progress.completed == null || progress.total == null
    || (currentStageId && progress.stage && progress.stage !== currentStageId))
    return <span className="txt muted">{eta ? `${eta} left` : '—'}</span>
  const pct = Math.min(100, Math.round((progress.completed / Math.max(1, progress.total)) * 100))
  return (
    <span className="work">
      <span className="pbar" role="progressbar" aria-valuenow={progress.completed} aria-valuemin={0} aria-valuemax={progress.total}
        aria-label={`${progress.completed} of ${progress.total} ${progress.unit}`}>
        <i style={{ width: `${pct}%` }} />
      </span>
      <span className="txt">{progress.completed} / {progress.total} {progress.unit}</span>
      {eta && <span className="txt muted">{eta} left</span>}
    </span>
  )
}

export function HeartbeatCell({ hb }: { hb: Heartbeat | null }) {
  if (!hb || hb.ts == null) return <span className="muted">—</span>
  if (hb.done) return <span className="muted">Finished</span>
  const t = ago(hb.ts)
  if (hb.live) return <span className="num">{t}</span>
  return <span className="warn-inline"><Warning size={14} weight="fill" />{t} · stale</span>
}

interface TLProps {
  stages: StageInterval[]
  pending: StagePending[]
  lanes?: EngineLane[]
  now: number
  compact?: boolean
  stale?: boolean
}

/** Shared elapsed axis, real start offsets. Stages without a recorded
    start are not drawn on the axis; unknown ends are gaps, not bars. */
export function Timeline({ stages, pending, lanes, now, compact, stale }: TLProps) {
  const recorded = stages.filter(s => s.startedAt != null)
  if (recorded.length === 0) {
    if (pending.length === 0) return <div className="dstate">No recorded stage timing for this run.</div>
    return <PendingList pending={pending} label="Recorded durations unavailable — stages observed:" />
  }
  const t0 = Math.min(...recorded.map(s => s.startedAt as number))
  const running = stages.some(s => s.state === 'running')
  const ends = recorded.map(s => s.endedAt ?? (s.state === 'running' ? now : null))
    .filter((x): x is number => x != null)
  let t1 = ends.length ? Math.max(...ends, running ? now : -Infinity) : t0 + 1
  if (t1 <= t0) t1 = t0 + 1
  const span = t1 - t0
  const pos = (t: number) => Math.max(0, Math.min(100, ((t - t0) / span) * 100))
  const markerT = running ? now : t1
  const markerLeft = pos(markerT)
  return (
    <div>
      <div className="tl-wrap" role="img" aria-label="Stage timeline">
        <div className="tl-axis">
          <div className="timeline tl-abs" style={{ flex: 1 }}>
            {recorded.map((s, i) => {
              const start = s.startedAt as number
              const end = s.endedAt ?? (s.state === 'running' ? now : null)
              const left = pos(start)
              const width = end == null ? 0 : Math.max(0.6, pos(end) - left)
              const cls = s.state === 'running' ? 'active' : s.state === 'failed' ? 'failed' : s.state === 'degraded' ? 'degraded' : ''
              const tiny = end != null && width < 3
              if (end == null) {
                return (
                  <div key={s.id + i} className="tl-seg tl-gap"
                    style={{ left: `${left}%`, width: `${Math.max(0.6, 100 - left)}%` }}
                    title={`${s.label} — end not recorded`}>
                    <span className="lbl">{s.label}</span>
                    <span className="dur">end unknown</span>
                  </div>
                )
              }
              return (
                <div key={s.id + i}
                  className={`tl-seg ${cls}${tiny ? ' tiny' : ''}`}
                  style={{ left: `${left}%`, width: `${width}%` }}
                  tabIndex={tiny ? 0 : undefined}
                  title={`${s.label} — ${fmtDur(s.startedAt, end)}${s.state === 'running' ? ' (running)' : ''}`}>
                  <span className="lbl">{s.label}</span>
                  {!tiny && <span className="dur">{s.state === 'running' ? `${fmtDur(start, now)} elapsed` : fmtDur(start, end)}</span>}
                </div>
              )
            })}
          </div>
          {pending.length > 0 && (
            <div className="tl-pending" style={{ flex: 'none' }}>
              {pending.map(p => (
                <div key={p.id} className="pend" title={`${p.label} — ${p.state}${p.reason ? `: ${p.reason}` : ''}`}>
                  <span className="lbl" style={{ fontWeight: 500 }}>{p.label}</span>
                  <span className="dur muted">{p.state === 'skipped' ? 'skipped' : 'pending'}</span>
                </div>
              ))}
            </div>
          )}
        </div>
        {(running || stale) && (
          <span className={`tl-now${stale ? ' stale-marker' : ''}`} style={{ left: `calc(${markerLeft}% - 2px)` }}>
            {!compact && (
              <span className="now-lbl">
                {stale && !running
                  ? <>Last observed<br />{fmtDur(t0, markerT)}</>
                  : <>Now<br />{fmtDur(t0, now)} elapsed</>}
              </span>
            )}
          </span>
        )}
      </div>
      {(lanes ?? []).length > 0 && (
        <div style={{ marginTop: compact ? 8 : 20 }}>
          {(lanes ?? []).map(l => {
            if (l.startedAt == null || l.endedAt == null) {
              return (
                <div key={l.id} className="tl-lane-row">
                  <span className="tl-unknown-chip">{l.label} — timing not recorded{l.outcome ? ` (${l.outcome})` : ''}</span>
                </div>
              )
            }
            const left = pos(Math.max(l.startedAt, t0))
            const w = Math.max(0.6, pos(Math.min(l.endedAt, t1)) - left)
            return (
              <div key={l.id} className="timeline tl-abs" style={{ height: 28, marginTop: 4 }}>
                <div className={`tl-seg ${l.outcome === 'completed' ? '' : 'degraded'}`}
                  style={{ left: `${left}%`, width: `${w}%`, flexDirection: 'row', alignItems: 'center', gap: 8 }}
                  title={`${l.label} — ${fmtDur(l.startedAt, l.endedAt)}`}>
                  <span className="lbl">{l.label}</span>
                  {w > 12 && <span className="dur">{l.outcome === 'completed' ? 'completed' : l.outcome ?? '—'}</span>}
                </div>
              </div>
            )
          })}
          {!compact && (
            <div className="note" style={{ marginTop: 6 }}>Engine lanes run concurrently within their parent stage.</div>
          )}
        </div>
      )}
    </div>
  )
}

function PendingList({ pending, label }: { pending: StagePending[]; label: string }) {
  return (
    <div>
      <div className="note" style={{ marginBottom: 8 }}>{label}</div>
      <div className="tl-pending" style={{ flexWrap: 'wrap' }}>
        {pending.map(p => <div key={p.id} className="pend"><span className="lbl">{p.label}</span><span className="dur muted">pending</span></div>)}
      </div>
    </div>
  )
}

export function EventList({ events, findingLink, showStage }: {
  events: EventRow[]
  findingLink?: (f: EventRow) => string | null
  showStage?: boolean
}) {
  if (events.length === 0) return <div className="dstate">No recorded events.</div>
  return (
    <div className="events">
      {events.map((e, i) => {
        const to = e.finding && findingLink ? findingLink(e) : null
        return (
          <div key={i} className={`evrow${e.level === 'kill' ? ' kill' : ''}`}>
            <span className="ts">{fmtTime(e.ts)}</span>
            <span className="msg">
              {showStage && e.stage && <span className="note" style={{ marginRight: 6 }}>[{e.stage}]</span>}
              {e.msg ?? e.kind ?? 'event'}
              {e.finding && (to
                ? <> · <Link className="flink" to={to}>{e.finding}</Link></>
                : <span className="flink muted"> · {e.finding}</span>)}
            </span>
          </div>
        )
      })}
    </div>
  )
}

export function Tabs({ tabs, active, onChange, ariaLabel }: {
  tabs: { id: string; label: string; count?: number }[]
  active: string; onChange: (id: string) => void; ariaLabel: string
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([])
  return (
    <div className="tabs" role="tablist" aria-label={ariaLabel}>
      {tabs.map((t, i) => (
        <button key={t.id} role="tab" aria-selected={active === t.id}
          tabIndex={active === t.id ? 0 : -1}
          ref={el => { refs.current[i] = el }}
          onClick={() => onChange(t.id)}
          onKeyDown={e => {
            let j = -1
            if (e.key === 'ArrowRight') j = (i + 1) % tabs.length
            else if (e.key === 'ArrowLeft') j = (i - 1 + tabs.length) % tabs.length
            else if (e.key === 'Home') j = 0
            else if (e.key === 'End') j = tabs.length - 1
            if (j >= 0) { e.preventDefault(); onChange(tabs[j].id); refs.current[j]?.focus() }
          }}>
          {t.label}{t.count != null ? ` ${t.count}` : ''}
        </button>
      ))}
    </div>
  )
}

export function DataState({ loading, error, stale, onRetry, empty, emptyTitle, emptyHint, children }: {
  loading?: boolean; error?: ApiError | null; stale?: boolean
  onRetry?: () => void; empty?: boolean
  emptyTitle?: string; emptyHint?: ReactNode; children: ReactNode
}) {
  if (loading) {
    return <div aria-busy="true"><div className="skel" style={{ width: '40%' }} /><div className="skel" style={{ width: '90%' }} /><div className="skel" style={{ width: '75%' }} /><div className="skel" style={{ width: '60%' }} /></div>
  }
  if (error && !stale) {
    return (
      <div className="dstate" role="alert">
        <div className="t">{error.message}</div>
        {error.retryable && onRetry && (
          <button className="btn secondary" style={{ marginTop: 8 }} onClick={onRetry}>
            <ArrowClockwise size={15} />Retry
          </button>
        )}
      </div>
    )
  }
  if (empty) {
    return <div className="dstate"><div className="t">{emptyTitle ?? 'Nothing here yet.'}</div>{emptyHint}</div>
  }
  return <>{children}</>
}

export function ArtifactIcon({ name }: { name: string }) {
  if (name.endsWith('.sh')) return <FileCode size={18} />
  if (name.endsWith('.py') || name.endsWith('.c') || name.endsWith('.ts')) return <FileCode size={18} />
  if (name.endsWith('.md') || name.endsWith('.txt') || name.endsWith('.json')) return <FileText size={18} />
  return <File size={18} />
}

export function ArtifactList({ artifacts, onPreview, limit }: {
  artifacts: ArtifactEntry[]; onPreview?: (a: ArtifactEntry) => void
  limit?: number
}) {
  if (artifacts.length === 0) return <div className="note">No recorded artifacts.</div>
  const shown = limit != null ? artifacts.slice(0, limit) : artifacts
  const hidden = artifacts.length - shown.length
  return (
    <div className="artifacts">
      {shown.map(a => (
        <div key={a.id} className="artrow">
          <span className="an">
            <ArtifactIcon name={a.name} />
            <span className="nm" title={`${a.name}${a.role ? ` — role: ${a.role}` : ''}`}>{a.name}</span>
            {a.role && a.role !== 'other' && <span className="note">{a.role}</span>}
            {a.producerTruncated && <span className="note" title="The producer truncated this file when recording">truncated at source</span>}
          </span>
          <span className="sz">{a.size != null ? fmtBytes(a.size) : 'size unavailable'}</span>
          <span className="tools">
            {a.previewable && (onPreview
              ? <button className="iconbtn" onClick={() => onPreview(a)} title="Preview" aria-label={`Preview ${a.name}`}><Eye size={16} /></button>
              : <a className="iconbtn" href={`/api/v1/artifacts/${a.id}?preview=1`} target="_blank" rel="noreferrer" title="Preview" aria-label={`Preview ${a.name}`}><Eye size={16} /></a>)}
            <a className="iconbtn" href={`/api/v1/artifacts/${a.id}`} title="Download" aria-label={`Download ${a.name}`}><DownloadSimple size={16} /></a>
          </span>
        </div>
      ))}
      {hidden > 0 && <div className="note" style={{ padding: '8px 0' }}>…and {hidden} more artifact{hidden === 1 ? '' : 's'}</div>}
    </div>
  )
}

/** In-workspace artifact viewer — never opens raw JSON in another tab. */
export function ArtifactPreviewPane({ artifact, onClose }: {
  artifact: ArtifactEntry; onClose: () => void
}) {
  const [p, setP] = useState<ArtifactPreview | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const ac = new AbortController()
    setP(null)
    setErr(null)
    apiGet<ArtifactPreview>(`/api/v1/artifacts/${artifact.id}?preview=1`, ac.signal)
      .then(b => setP(b))
      .catch(e => { if (!ac.signal.aborted) setErr(e instanceof Error ? e.message : 'Preview unavailable.') })
    ref.current?.focus()
    return () => ac.abort()
  }, [artifact.id])
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div className="preview-pane" ref={ref} tabIndex={-1} role="dialog" aria-label={`Preview of ${artifact.name}`}>
      <div className="preview-head">
        <span className="nm mono" style={{ fontSize: 12 }}>{artifact.name}</span>
        {artifact.role && <span className="note">{artifact.role}</span>}
        <span className="note">{artifact.size != null ? fmtBytes(artifact.size) : ''}</span>
        <span className="sp" style={{ flex: 1 }} />
        <button className="iconbtn" onClick={onClose} aria-label="Close preview">✕</button>
      </div>
      {err && <div className="dstate" role="alert"><div className="t">{err}</div></div>}
      {!err && !p && <div className="dstate">Loading…</div>}
      {!err && p && !p.previewable && (
        <div className="dstate"><div className="t">No text preview for this file type.</div>
          <a className="linkbtn" href={`/api/v1/artifacts/${artifact.id}`}>Download {artifact.name}</a></div>
      )}
      {!err && p && p.previewable && (
        <>
          {p.truncated && (
            <div className="note" style={{ margin: '4px 0 8px' }}>
              Showing {fmtBytes(p.shownBytes ?? null)} of {fmtBytes(p.totalBytes ?? null)} —{' '}
              <a className="linkbtn" href={`/api/v1/artifacts/${artifact.id}`}>download full file</a>
            </div>
          )}
          <pre className="output" tabIndex={0}>{p.text ?? ''}</pre>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button className="btn secondary" style={{ height: 30 }}
              onClick={() => navigator.clipboard?.writeText(p.text ?? '').then(() => {
                setCopied(true); setTimeout(() => setCopied(false), 2000)
              }).catch(() => setErr('Copy failed — select and copy manually.'))}>
              {p.truncated ? 'Copy displayed excerpt' : 'Copy'}
            </button>
            {copied && <span className="note" role="status">copied</span>}
            <a className="btn secondary" style={{ height: 30 }} href={`/api/v1/artifacts/${artifact.id}`}>Download</a>
          </div>
        </>
      )}
    </div>
  )
}

export function EvidenceCheck({ ok, text }: { ok: boolean | null; text: string }) {
  const icon = ok === true ? <CheckCircle size={16} weight="fill" />
    : ok === false ? <XCircle size={16} weight="fill" />
    : <Warning size={16} />
  return <span className={`evidence-row${ok === true ? ' ok' : ok === false ? ' bad' : ''}`}>{icon}{text}</span>
}

export function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <span className="switch-lbl">
      <button role="switch" aria-checked={checked} className="switch" aria-label={label}
        onClick={() => onChange(!checked)} />
      {label}
    </span>
  )
}

export function Pager({ page, pages, total, perPage, onPage }: {
  page: number; pages: number; total: number; perPage: number; onPage: (p: number) => void
}) {
  const from = total === 0 ? 0 : (page - 1) * perPage + 1
  const to = Math.min(total, page * perPage)
  return (
    <div className="pages">
      <span>Showing {from}–{to} of {total} findings · page {page} of {Math.max(1, pages)}</span>
      <span className="sp" />
      <button className="btn secondary" style={{ height: 30 }} disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
      <button className="btn secondary" style={{ height: 30 }} disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
    </div>
  )
}

export function RowLink({ to, children, className }: { to: string; children: ReactNode; className?: string }) {
  return <Link to={to} className={className ?? 'rowtitle'} onClick={e => e.stopPropagation()}>{children}</Link>
}

export function useRowNav() {
  return (to: string) => (e: React.MouseEvent) => {
    if (e.metaKey || e.ctrlKey) { window.open(to, '_blank'); return }
    navigate(to)
  }
}

export function Updated({ updatedAt, stale }: { updatedAt: number | null; stale?: boolean }) {
  const [, setT] = useState(0)
  useEffect(() => {
    const id = setInterval(() => setT(t => t + 1), 5000)
    return () => clearInterval(id)
  }, [])
  if (!updatedAt) return null
  const secs = Math.max(0, Math.floor((Date.now() - updatedAt) / 1000))
  return (
    <span className={`updated${stale ? ' stale' : ''}`} role="status">
      Updated {secs < 5 ? 'just now' : ago(updatedAt / 1000)}{stale ? ' · data may be stale' : ''}
    </span>
  )
}
