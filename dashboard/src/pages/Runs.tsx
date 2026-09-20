import { useCallback, useRef, useState } from 'react'
import { apiGet, useResource, qs } from '../api'
import type { ListResp, RunSummary } from '../types'
import { useRepoParam, useRoute, navigate } from '../router'
import { Badge, DataState, HealthBadge, RunStateBadge } from '../components'
import { fmtDur, fmtEta, fmtFull, shortRun, shortSha } from '../format'

const STATE_PILLS = [
  { id: '', label: 'All' }, { id: 'running', label: 'Active' },
  { id: 'stale', label: 'Stale' }, { id: 'completed', label: 'Completed' },
  { id: 'failed', label: 'Failed' }, { id: 'degraded', label: 'Degraded' },
  { id: 'unknown', label: 'Unknown' },
]

export function RunsPage() {
  const repo = useRepoParam()
  const route = useRoute()
  const state = route.query.get('state') ?? ''
  const [cursor, setCursor] = useState<string | null>(null)
  const cursorStack = useRef<(string | null)[]>([null])

  // 'degraded' is engine health, not a run state — the server filter is
  // skipped for it and rows filter client-side
  const serverState = state === 'degraded' ? '' : state
  const load = useCallback(
    (signal: AbortSignal) => apiGet<ListResp<RunSummary>>(`/api/v1/runs${qs({ repo, state: serverState, cursor, limit: 100 })}`, signal),
    [repo, serverState, cursor],
  )
  const r = useResource<ListResp<RunSummary>>(`runs:${repo}:${state}:${cursor ?? ''}`, load, { interval: 8000 })
  const data = r.data
  const items = (data?.items ?? []).filter(x => state !== 'degraded' || x.engineHealth === 'degraded')

  const setState = (v: string) => {
    const u = new URLSearchParams(route.query)
    if (v) u.set('state', v); else u.delete('state')
    navigate(`${route.path}${u.toString() ? '?' + u : ''}`, true)
    setCursor(null); cursorStack.current = [null]
  }

  return (
    <section className="panel" aria-labelledby="runs-h">
      <div className="panel-head">
        <h2 id="runs-h">Runs</h2>
        {repo && <span className="meta">scoped to {repo}</span>}
      </div>
      <div className="panel-body tight">
        <div className="pills" role="group" aria-label="Filter by run state">
          {STATE_PILLS.map(p => (
            <button key={p.id} className="pill" aria-pressed={state === p.id} onClick={() => setState(p.id)}>{p.label}</button>
          ))}
        </div>
      </div>
      <DataState loading={r.loading} error={r.error} stale={r.stale} onRetry={r.reload}
        empty={!!data && data.items.length === 0}
        emptyTitle="No recorded runs."
        emptyHint={<div>Run <span className="cmd">./indict --target &lt;git-url&gt;</span> to record a scan.</div>}>
        {data && (
          <>
            <table className="data rtable">
              <thead>
                <tr><th>Run</th><th>Repository</th><th>State</th><th>Freshness</th><th>Stage</th><th>Engines</th><th>Revision</th><th>Started</th><th className="num">Duration</th><th>Findings</th></tr>
              </thead>
              <tbody>
                {items.map(run => (
                  <tr key={`${run.repo}:${run.id}`} className="clickable"
                    onClick={() => navigate(`/repos/${encodeURIComponent(run.repo ?? '')}/runs/${encodeURIComponent(run.id)}`)}
                    onKeyDown={e => { if (e.key === 'Enter') navigate(`/repos/${encodeURIComponent(run.repo ?? '')}/runs/${encodeURIComponent(run.id)}`) }}
                    tabIndex={0}>
                    <td data-th="Run"><span className="mono" style={{ fontSize: 12 }}>{shortRun(run.id)}</span>{run.legacy && <span className="note"> · legacy</span>}</td>
                    <td data-th="Repository">{run.repo}</td>
                    <td data-th="State"><RunStateBadge state={run.state} /></td>
                    <td data-th="Freshness">{run.freshness === 'fresh' ? <Badge kind="ok" label="fresh" /> : run.freshness === 'stale' ? <Badge kind="stale" label="stale" /> : <span className="muted">—</span>}</td>
                    <td data-th="Stage">{run.state === 'running' && run.currentStage ? run.currentStage.label : <span className="muted">—</span>}</td>
                    <td data-th="Engines"><HealthBadge h={run.engineHealth} /></td>
                    <td data-th="Revision"><span className="mono" style={{ fontSize: 12 }}>{shortSha(run.revision)}</span></td>
                    <td data-th="Started" title={fmtFull(run.startedAt)}>{fmtFull(run.startedAt)}</td>
                    <td data-th="Duration" className="num">
                      {fmtDur(run.startedAt, run.endedAt)}
                      {run.state === 'running' && run.etaSec != null &&
                        <div className="note">{fmtEta(run.etaSec)} left</div>}
                    </td>
                    <td data-th="Findings">{run.outcome ? `${run.outcome.verified ?? 0} verified · ${run.outcome.dismissed ?? 0} dismissed` : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="pages">
              <button className="btn secondary" style={{ height: 30 }} disabled={cursorStack.current.length <= 1}
                onClick={() => { cursorStack.current.pop(); setCursor(cursorStack.current[cursorStack.current.length - 1] ?? null) }}>Previous</button>
              <button className="btn secondary" style={{ height: 30 }} disabled={!data.nextCursor}
                onClick={() => { cursorStack.current.push(data.nextCursor); setCursor(data.nextCursor) }}>Next</button>
              <span className="sp" />
              <span>{data.total} runs total</span>
            </div>
          </>
        )}
      </DataState>
    </section>
  )
}
