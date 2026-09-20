import { useEffect, useRef, useState, type ReactNode } from 'react'
import { CheckCircle, XCircle, Warning, File, FileText, FileCode, DownloadSimple, Eye, ArrowClockwise } from '@phosphor-icons/react'
import type { EventRow, Heartbeat, StageInterval, StagePending, EngineLane, ArtifactEntry, Progress } from './types'
import { fmtTime, fmtDur, fmtBytes, ago, RUN_LABEL } from './format'
import { Link, navigate } from './router'
import { ApiError } from './api'

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

export function WorkCell({ progress, state }: { progress: Progress | null; state?: string }) {
  if (state === 'completed') return <span className="txt muted">Complete</span>
  if (state === 'failed') return <span className="txt" style={{ color: 'var(--danger)' }}>Failed</span>
  if (!progress || progress.completed == null || progress.total == null)
    return <span className="txt muted">—</span>
  const pct = Math.min(100, Math.round((progress.completed / Math.max(1, progress.total)) * 100))
  return (
    <span className="work">
      <span className="pbar" role="progressbar" aria-valuenow={progress.completed} aria-valuemin={0} aria-valuemax={progress.total}
        aria-label={`${progress.completed} of ${progress.total} ${progress.unit}`}>
        <i style={{ width: `${pct}%` }} />
      </span>
      <span className="txt">{progress.completed} / {progress.total} {progress.unit}</span>
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
}

export function Timeline({ stages, pending, lanes, now, compact }: TLProps) {
  const recorded = stages.filter(s => s.startedAt != null)
  if (recorded.length === 0) {
    if (pending.length === 0) return <div className="dstate">No recorded stage timing for this run.</div>
    return <PendingList pending={pending} label="Recorded durations unavailable — stages observed:" />
  }
  const t0 = Math.min(...recorded.map(s => s.startedAt as number))
  const ends = recorded.map(s => s.endedAt ?? now)
  let t1 = Math.max(...ends)
  if (t1 <= t0) t1 = t0 + 1
  const span = t1 - t0
  const lanesEnded = (lanes ?? []).map(l => l.endedAt)
  const running = stages.some(s => s.state === 'running')
  const nextStart = (i: number): number | null => {
    for (let j = i + 1; j < stages.length; j++) {
      if (stages[j].startedAt != null) return stages[j].startedAt
    }
    return null
  }
  return (
    <div>
      <div className="tl-wrap" role="img" aria-label="Stage timeline">
        <div className="tl-axis">
          <div className="timeline" style={{ flex: 1 }}>
            {stages.map((s, i) => {
              if (s.startedAt == null) return null
              let end = s.endedAt ?? (running ? now : (nextStart(i) ?? t1))
              if (end <= s.startedAt) end = s.startedAt + Math.min(1, span * 0.005)
              const w = Math.max(1.5, ((end - s.startedAt) / span) * 100)
              const cls = s.state === 'running' ? 'active' : s.state === 'failed' ? 'failed' : s.state === 'degraded' ? 'degraded' : ''
              return (
                <div key={s.id + i} className={`tl-seg ${cls}`} style={{ width: `${w}%` }}
                  title={`${s.label} — ${fmtDur(s.startedAt, s.endedAt ?? now)}${s.state === 'running' ? ' (running)' : ''}`}>
                  <span className="lbl">{s.label}</span>
                  <span className="dur">{s.state === 'running' ? `${fmtDur(s.startedAt, now)} elapsed` : fmtDur(s.startedAt, end)}</span>
                </div>
              )
            })}
          </div>
          {pending.length > 0 && (
            <div className="tl-pending" style={{ flex: 'none' }}>
              {pending.map(p => (
                <div key={p.id} className="pend" title={`${p.label} — pending`}>
                  <span className="lbl" style={{ fontWeight: 500 }}>{p.label}</span>
                  <span className="dur muted">pending</span>
                </div>
              ))}
            </div>
          )}
        </div>
        {running && (
          <span className="tl-now" style={{ left: `calc(${(recordedWidth(stages, pending, t0, t1, now))}% - 2px)` }}>
            {!compact && <span className="now-lbl">Now<br />{fmtDur(t0, now)} elapsed</span>}
          </span>
        )}
      </div>
      {(lanes ?? []).length > 0 && (
        <div style={{ marginTop: compact ? 8 : 20 }}>
          {(lanes ?? []).map(l => {
            const w = Math.max(1.5, ((l.endedAt - t0) / span) * 100)
            return (
              <div key={l.id} className="timeline" style={{ height: 28, marginTop: 4 }}>
                <div className={`tl-seg ${l.outcome === 'completed' ? '' : 'degraded'}`} style={{ width: `${w}%`, flexDirection: 'row', alignItems: 'center', gap: 8 }}>
                  <span className="lbl">{l.label}</span>
                  <span className="dur">{l.outcome === 'completed' ? 'completed' : l.outcome ?? '—'}</span>
                </div>
              </div>
            )
          })}
          {!compact && lanesEnded.length > 0 && (
            <div className="note" style={{ marginTop: 6 }}>Engine lanes run concurrently within their parent stage.</div>
          )}
        </div>
      )}
    </div>
  )
}

function recordedWidth(stages: StageInterval[], pending: StagePending[], t0: number, t1: number, now: number): number {
  const recorded = stages.filter(s => s.startedAt != null)
  const lastEnd = Math.max(...recorded.map(s => s.endedAt ?? now))
  const rec = Math.max(0, lastEnd - t0)
  const span = t1 - t0
  if (pending.length === 0) return 100
  const recPct = Math.min(96, (rec / span) * 100)
  return recPct
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

export function EventList({ events, findingLink }: {
  events: EventRow[]
  findingLink?: (f: EventRow) => string | null
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

export function ArtifactList({ artifacts }: { artifacts: ArtifactEntry[] }) {
  if (artifacts.length === 0) return <div className="note">No recorded artifacts.</div>
  return (
    <div className="artifacts">
      {artifacts.map(a => (
        <div key={a.id} className="artrow">
          <span className="an"><ArtifactIcon name={a.name} /><span className="nm">{a.name}</span></span>
          <span className="sz">{a.size != null ? fmtBytes(a.size) : 'size unavailable'}</span>
          <span className="tools">
            {a.previewable && (
              <a className="iconbtn" href={`/api/v1/artifacts/${a.id}?preview=1`} target="_blank" rel="noreferrer" title="Preview" aria-label={`Preview ${a.name}`}><Eye size={16} /></a>
            )}
            <a className="iconbtn" href={`/api/v1/artifacts/${a.id}`} title="Download" aria-label={`Download ${a.name}`}><DownloadSimple size={16} /></a>
          </span>
        </div>
      ))}
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
