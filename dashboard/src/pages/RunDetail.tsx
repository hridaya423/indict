import { useCallback, useEffect, useState } from 'react'
import { apiGet, useResource, qs } from '../api'
import type { EventsResp, FindingsResp, RunDetail } from '../types'
import { Link, navigate } from '../router'
import { Badge, DataState, EventList, HealthBadge, RunStateBadge, SeverityBadge, Timeline, VerBadge } from '../components'
import { fmtDurSecs, fmtFull, shortRun, shortSha } from '../format'

export function RunDetailPage({ repo, run }: { repo: string; run: string }) {
  const [now, setNow] = useState(Date.now() / 1000)
  const [cursor, setCursor] = useState<string | null>(null)
  const [extra, setExtra] = useState<import('../types').EventRow[]>([])

  const load = useCallback(
    (signal: AbortSignal) => apiGet<RunDetail>(`/api/v1/repos/${encodeURIComponent(repo)}/runs/${encodeURIComponent(run)}`, signal),
    [repo, run],
  )
  const r = useResource<RunDetail>(`run:${repo}:${run}`, load, { interval: 4000 })
  const d = r.data
  const running = d?.state === 'running'

  useEffect(() => {
    if (!running) return
    const id = setInterval(() => setNow(Date.now() / 1000), 1000)
    return () => clearInterval(id)
  }, [running])

  const findings = useResource<FindingsResp>(
    `runf:${repo}:${run}`,
    useCallback((s: AbortSignal) => apiGet<FindingsResp>(`/api/v1/findings${qs({ repo, run, limit: 100 })}`, s), [repo, run]),
    { interval: 8000 },
  )

  const loadMore = async () => {
    if (!cursor) return
    const page = await apiGet<EventsResp>(`/api/v1/repos/${encodeURIComponent(repo)}/runs/${encodeURIComponent(run)}/events${qs({ cursor, limit: 100 })}`)
    setExtra(prev => [...prev, ...page.items])
    setCursor(page.nextCursor)
  }

  useEffect(() => {
    if (d?.eventsTail) {
      const last = d.eventsTail[d.eventsTail.length - 1]
      setCursor(last ? `ts:${last.ts}` : null)
      setExtra([])
    }
  }, [d?.eventsTail])

  const events = [...(d?.eventsTail ?? []), ...extra]

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
              {' · '}Elapsed {fmtDurSecs(d.startedAt != null ? Math.max(0, (d.endedAt ?? now) - d.startedAt) : null)}
              {d.error && <span style={{ color: 'var(--danger)' }}> · {d.error}</span>}
            </div>
          )}
          {d?.engines && d.engines.length > 0 && (
            <div className="meta">Engines: {d.engines.join(', ')}{d.models?.length ? ` · Models: ${d.models.join(', ')}` : ''}</div>
          )}
        </div>
        <div className="panel-body">
          <DataState loading={r.loading} error={r.error} stale={r.stale} onRetry={r.reload}>
            {d && <Timeline stages={d.stages} pending={d.pendingStages} lanes={d.lanes} now={now} />}
            {d?.findingsSource === 'latest' && (
              <div className="note" style={{ marginTop: 8 }}>Legacy run — timing reconstructed from events; per-stage data is approximate.</div>
            )}
          </DataState>
        </div>
      </section>

      <div className="split">
        <section className="panel" aria-labelledby="runev-h">
          <div className="panel-head">
            <h2 id="runev-h">Events · {(d?.eventsTotal ?? 0) + (d?.eventsMalformed ? ` (+${d.eventsMalformed} malformed)` : '')}</h2>
          </div>
          <div className="panel-body">
            <DataState loading={r.loading} empty={events.length === 0} emptyTitle="No recorded events.">
              <EventList events={events} findingLink={e => `/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(e.finding ?? '')}?run=${encodeURIComponent(run)}`} />
              {cursor && <button className="btn secondary" style={{ marginTop: 12 }} onClick={loadMore}>Load more</button>}
            </DataState>
          </div>
        </section>

        <section className="panel" aria-labelledby="runfinds-h">
          <div className="panel-head"><h2 id="runfinds-h">Findings · {d?.findingsTotal ?? findings.data?.total ?? 0}</h2></div>
          <DataState loading={findings.loading} error={findings.error} stale={findings.stale} onRetry={findings.reload}
            empty={!!findings.data && findings.data.items.length === 0} emptyTitle="No findings recorded in this run.">
            {findings.data && (
              <table className="data fixed">
                <colgroup><col style={{ width: '12%' }} /><col /><col style={{ width: '12%' }} /><col style={{ width: '18%' }} /></colgroup>
                <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Verification</th></tr></thead>
                <tbody>
                  {findings.data.items.map(f => (
                    <tr key={f.id} className="clickable" tabIndex={0}
                      onClick={() => navigate(`/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(f.id)}?run=${encodeURIComponent(run)}`)}
                      onKeyDown={e => { if (e.key === 'Enter') navigate(`/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(f.id)}?run=${encodeURIComponent(run)}`) }}>
                      <td><Link className="mono nowrap" style={{ fontSize: 12 }} to={`/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(f.id)}?run=${encodeURIComponent(run)}`}>{f.id}</Link></td>
                      <td><Link className="rowtitle clamp2" to={`/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(f.id)}?run=${encodeURIComponent(run)}`}>{f.title || f.vulnClass}</Link></td>
                      <td><SeverityBadge sev={f.severity} /></td>
                      <td><VerBadge v={f.verification} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </DataState>
        </section>
      </div>
    </>
  )
}
