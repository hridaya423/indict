import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { apiGet, useResource, qs } from '../api'
import type { EventRow, EventsResp, FindingsResp, RunDetail } from '../types'
import { Link, navigate } from '../router'
import { Badge, DataState, EventList, HealthBadge, RunStateBadge, SeverityBadge, Switch, Timeline, VerBadge } from '../components'
import { fmtDurSecs, fmtFull, shortRun, shortSha } from '../format'

/** Event ledger over contiguous absolute offsets [lo, hi). The server
    owns cursors; pages never overlap, so duplication can't happen. */
function Ledger({ repo, run, total, tail, follow, onFollow }: {
  repo: string; run: string; total: number; tail: EventRow[]
  follow: boolean; onFollow: (v: boolean) => void
}) {
  const [items, setItems] = useState<EventRow[]>([])
  const [lo, setLo] = useState(0)
  const [hi, setHi] = useState(0)
  const [pendingNew, setPendingNew] = useState(0)
  const [err, setErr] = useState<string | null>(null)
  const box = useRef<HTMLDivElement>(null)
  const stageF = useRef<string>('')
  const levelF = useRef<string>('')
  const [filters, setFilters] = useState({ stage: '', level: '' })

  // seed from the run detail tail: it covers [total-len(tail), total)
  useEffect(() => {
    const start = Math.max(0, total - tail.length)
    setItems(tail)
    setLo(start)
    setHi(total)
    setPendingNew(0)
    setErr(null)
  }, [repo, run]) // eslint-disable-line react-hooks/exhaustive-deps

  // server total moved past our window -> unseen events exist
  useEffect(() => {
    setPendingNew(Math.max(0, total - hi))
    if (follow && total > hi) {
      apiGet<EventsResp>(`/api/v1/repos/${encodeURIComponent(repo)}/runs/${encodeURIComponent(run)}/events${qs({ after: `e:${hi}`, limit: 100 })}`)
        .then(p => { setItems(prev => [...prev, ...p.items]); setHi(total) })
        .catch(() => setErr('Could not load new events.'))
    }
  }, [total, hi, follow, repo, run])

  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight
  }, [items, follow])

  const loadOlder = () => {
    apiGet<EventsResp>(`/api/v1/repos/${encodeURIComponent(repo)}/runs/${encodeURIComponent(run)}/events${qs({ before: `e:${lo}`, limit: 100 })}`)
      .then(p => {
        setItems(prev => [...p.items, ...prev])
        setLo(prev => Math.max(0, prev - p.items.length))
        if (box.current) box.current.scrollTop += 40 * p.items.length
      })
      .catch(() => setErr('Could not load older events.'))
  }

  const stages = useMemo(() => [...new Set(items.map(e => e.stage).filter((s): s is string => !!s))], [items])
  const shown = items.filter(e =>
    (!filters.stage || e.stage === filters.stage) &&
    (!filters.level || e.level === filters.level))

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 8, alignItems: 'center' }}>
        <label className="field-label">Stage
          <select value={filters.stage}
            ref={el => { if (el) stageF.current = el.value }}
            onChange={e => setFilters(f => ({ ...f, stage: e.target.value }))}>
            <option value="">All stages</option>
            {stages.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label className="field-label">Level
          <select value={filters.level}
            ref={el => { if (el) levelF.current = el.value }}
            onChange={e => setFilters(f => ({ ...f, level: e.target.value }))}>
            <option value="">All levels</option>
            <option value="info">info</option>
            <option value="kill">kill</option>
          </select>
        </label>
        <span className="sp" style={{ flex: 1 }} />
        <Switch checked={follow} onChange={onFollow} label="Follow live" />
      </div>
      {lo > 0 && <button className="btn secondary" style={{ height: 30, marginBottom: 8 }} onClick={loadOlder}>Load older · {lo} earlier events</button>}
      {err && <div className="warn-inline" role="alert">{err}</div>}
      <div ref={box} style={{ maxHeight: 420, overflowY: 'auto' }}>
        {shown.length === 0
          ? <div className="dstate">
            {items.length === 0 ? 'No recorded events.' : 'No events match these filters.'}
          </div>
          : <EventList events={shown} showStage
            findingLink={e => `/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(e.finding ?? '')}?run=${encodeURIComponent(run)}`} />}
      </div>
      {!follow && pendingNew > 0 && (
        <button className="linkbtn" style={{ marginTop: 8 }} role="status"
          onClick={() => onFollow(true)}>{pendingNew} new event{pendingNew === 1 ? '' : 's'} — follow to view</button>
      )}
      <div className="note" style={{ marginTop: 8 }}>Showing {shown.length} of {total} recorded events.</div>
    </div>
  )
}

export function RunDetailPage({ repo, run }: { repo: string; run: string }) {
  const [now, setNow] = useState(Date.now() / 1000)
  const [follow, setFollow] = useState(true)
  const [fpage, setFpage] = useState(1)

  const load = useCallback(
    (signal: AbortSignal) => apiGet<RunDetail>(`/api/v1/repos/${encodeURIComponent(repo)}/runs/${encodeURIComponent(run)}`, signal),
    [repo, run],
  )
  const r = useResource<RunDetail>(`run:${repo}:${run}`, load, { interval: 4000 })
  const d = r.data
  const running = d?.state === 'running'
  const lastObserved = d?.eventsTail?.length
    ? d.eventsTail[d.eventsTail.length - 1].ts
    : d?.heartbeat?.ts ?? null

  useEffect(() => {
    if (!running) return
    const id = setInterval(() => setNow(Date.now() / 1000), 1000)
    return () => clearInterval(id)
  }, [running])

  const findings = useResource<FindingsResp>(
    `runf:${repo}:${run}:${fpage}`,
    useCallback((s: AbortSignal) => apiGet<FindingsResp>(
      `/api/v1/findings${qs({ repo, run, page: fpage, limit: 25 })}`, s), [repo, run, fpage]),
    { interval: 8000 })
  useEffect(() => { setFpage(1) }, [repo, run])

  return (
    <>
      <section className="panel" aria-labelledby="rund-h">
        <div className="panel-head" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 8 }}>
          <nav className="crumb" aria-label="Breadcrumb">
            <Link to="/runs">Runs</Link><span aria-hidden="true">/</span>
            <Link to={`/repos/${encodeURIComponent(repo)}`}>{repo}</Link><span aria-hidden="true">/</span>
            <span>{shortRun(run)}</span>
          </nav>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <h2 id="rund-h">Run {shortRun(run)}</h2>
            {d && <RunStateBadge state={d.state} />}
            {d && d.freshness === 'stale' && <Badge kind="stale" label="stale" />}
            {d && <HealthBadge h={d.engineHealth} />}
          </div>
          {d && (
            <div className="meta">
              Revision {shortSha(d.revision)} · Started {fmtFull(d.startedAt)}
              {d.endedAt ? ` · Ended ${fmtFull(d.endedAt)}` : ''}
              {' · '}Elapsed {fmtDurSecs(d.startedAt != null ? Math.max(0, (d.endedAt ?? (d.freshness === 'stale' ? lastObserved ?? now : now)) - d.startedAt) : null)}
              {d.freshness === 'stale' && lastObserved != null && (
                <span className="warn-inline" style={{ display: 'inline-flex' }}> · last observed {fmtFull(lastObserved)}</span>
              )}
              {d.error && <span style={{ color: 'var(--danger)' }}> · {d.error}</span>}
            </div>
          )}
          {d?.engines && d.engines.length > 0 && (
            <div className="meta">Engines: {d.engines.join(', ')}{d.models?.length ? ` · Models: ${d.models.join(', ')}` : ''}</div>
          )}
        </div>
        <div className="panel-body">
          <DataState loading={r.loading} error={r.error} stale={r.stale} onRetry={r.reload}>
            {d && <Timeline stages={d.stages} pending={d.pendingStages} lanes={d.lanes} now={now}
              stale={d.freshness === 'stale'} />}
            {d?.findingsSource === 'latest' && (
              <div className="note" style={{ marginTop: 8 }}>Legacy run — timing reconstructed from event order; per-stage durations approximate.</div>
            )}
            {d?.legacy && <div className="note" style={{ marginTop: 8 }}>Legacy record — no structured stage boundaries.</div>}
          </DataState>
        </div>
      </section>

      <div className="split">
        <section className="panel" aria-labelledby="runfinds-h">
          <div className="panel-head">
            <h2 id="runfinds-h">
              Findings · {findings.data?.total ?? d?.findingsTotal ?? 0}
            </h2>
            {d && findings.data && findings.data.total !== d.findingsTotal && (
              <span className="meta">showing {findings.data.total} of {d.findingsTotal} recorded</span>
            )}
          </div>
          <DataState loading={findings.loading} error={findings.error} stale={findings.stale} onRetry={findings.reload}
            empty={!!findings.data && findings.data.items.length === 0} emptyTitle="No findings recorded in this run.">
            {findings.data && (
              <>
                <table className="data fixed">
                  <colgroup><col style={{ width: '16%' }} /><col /><col style={{ width: '14%' }} /><col style={{ width: '22%' }} /></colgroup>
                  <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Verification</th></tr></thead>
                  <tbody>
                    {findings.data.items.map(f => (
                      <tr key={f.id} className="clickable" tabIndex={0}
                        onClick={() => navigate(`/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(f.id)}?run=${encodeURIComponent(run)}`)}
                        onKeyDown={e => { if (e.key === 'Enter') navigate(`/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(f.id)}?run=${encodeURIComponent(run)}`) }}>
                        <td><Link className="fid" title={f.id} to={`/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(f.id)}?run=${encodeURIComponent(run)}`}
                          onClick={e => e.stopPropagation()}>{f.id}</Link></td>
                        <td><Link className="rowtitle clamp2" to={`/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(f.id)}?run=${encodeURIComponent(run)}`}
                          onClick={e => e.stopPropagation()}>{f.title || f.vulnClass}</Link></td>
                        <td><SeverityBadge sev={f.severity} /></td>
                        <td><VerBadge v={f.verification} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {findings.data.pages > 1 && (
                  <div className="pages">
                    <span>Page {findings.data.page} of {findings.data.pages}</span>
                    <span className="sp" />
                    <button className="btn secondary" style={{ height: 30 }} disabled={fpage <= 1} onClick={() => setFpage(fpage - 1)}>Previous</button>
                    <button className="btn secondary" style={{ height: 30 }} disabled={fpage >= findings.data.pages} onClick={() => setFpage(fpage + 1)}>Next</button>
                  </div>
                )}
              </>
            )}
          </DataState>
        </section>

        <section className="panel" aria-labelledby="runev-h">
          <div className="panel-head">
            <h2 id="runev-h">Events · {(d?.eventsTotal ?? 0) + (d?.eventsMalformed ? ` (+${d.eventsMalformed} malformed)` : '')}</h2>
          </div>
          <div className="panel-body">
            <DataState loading={r.loading} empty={!!d && d.eventsTotal === 0} emptyTitle="No recorded events.">
              {d && <Ledger repo={repo} run={run} total={d.eventsTotal} tail={d.eventsTail}
                follow={follow} onFollow={setFollow} />}
            </DataState>
          </div>
        </section>
      </div>
    </>
  )
}
