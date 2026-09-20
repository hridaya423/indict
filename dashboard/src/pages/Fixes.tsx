import { useCallback } from 'react'
import { apiGet, useResource, qs } from '../api'
import type { FixRow, ListResp } from '../types'
import { Link, useRepoParam, useRoute, navigate } from '../router'
import { CheckBadge, DataState, SeverityBadge } from '../components'
import { ago, fmtFull } from '../format'

const VERDICTS = [
  { id: '', label: 'All' },
  { id: 'fix-verified', label: 'Gate passed' },
  { id: 'fix-rejected', label: 'Rejected' },
  { id: 'fix-unverifiable', label: 'Unverifiable' },
]

export function FixesPage() {
  const repo = useRepoParam()
  const route = useRoute()
  const verdict = route.query.get('verdict') ?? ''
  const cursor = route.query.get('cursor') ?? null

  const setParam = (k: string, v: string | null) => {
    const u = new URLSearchParams(route.query)
    if (v) u.set(k, v); else u.delete(k)
    if (k !== 'cursor') u.delete('cursor')
    navigate(`${route.path}${u.toString() ? '?' + u : ''}`, true)
  }

  const load = useCallback(
    (signal: AbortSignal) => apiGet<ListResp<FixRow>>(`/api/v1/fixes${qs({ repo, verdict, cursor, limit: 50 })}`, signal),
    [repo, verdict, cursor],
  )
  const r = useResource<ListResp<FixRow>>(`fixes:${repo}:${verdict}:${cursor ?? ''}`, load, { interval: 8000 })
  const data = r.data

  return (
    <section className="panel" aria-labelledby="fixes-h">
      <div className="panel-head">
        <h2 id="fixes-h">Fixes</h2>
        <span className="meta">latest recorded attempt per finding{repo ? ` · scoped to ${repo}` : ''}</span>
      </div>
      <div className="panel-body tight">
        <div className="pills" role="group" aria-label="Filter by gate verdict">
          {VERDICTS.map(v => (
            <button key={v.id} className="pill" aria-pressed={verdict === v.id}
              onClick={() => setParam('verdict', v.id || null)}>{v.label}</button>
          ))}
        </div>
      </div>
      <DataState loading={r.loading} error={r.error} stale={r.stale} onRetry={r.reload}
        empty={!!data && data.items.length === 0}
        emptyTitle="No recorded fix attempts."
        emptyHint={<div>Run <span className="cmd">./indict --fix &lt;repo&gt; &lt;finding&gt;</span> to attempt one.</div>}>
        {data && (
          <>
            <table className="data rtable">
              <thead>
                <tr><th>Finding</th><th>Title</th><th>Severity</th><th>Repository</th><th>Verdict</th><th>Backend</th><th>Recorded</th></tr>
              </thead>
              <tbody>
                {data.items.map(fx => (
                  <tr key={`${fx.repo}:${fx.findingId}`}>
                    <td data-th="Finding"><Link className="fid" title={fx.findingId} to={`/repos/${encodeURIComponent(fx.repo)}/fixes/${encodeURIComponent(fx.findingId)}`}>{fx.findingId}</Link></td>
                    <td data-th="Title">
                      <Link className="rowtitle clamp2" to={`/repos/${encodeURIComponent(fx.repo)}/findings/${encodeURIComponent(fx.findingId)}`}>{fx.title || fx.findingId}</Link>
                    </td>
                    <td data-th="Severity"><SeverityBadge sev={fx.severity} /></td>
                    <td data-th="Repository"><Link to={`/repos/${encodeURIComponent(fx.repo)}`}>{fx.repo}</Link></td>
                    <td data-th="Verdict" title={fx.reason ?? ''}><CheckBadge outcome={fx.verdict === 'fix-verified' ? 'pass' : fx.verdict === 'fix-rejected' ? 'fail' : 'skip'} /></td>
                    <td data-th="Backend">{fx.backend ?? '—'}</td>
                    <td data-th="Recorded" title={fmtFull(fx.ts)}>{ago(fx.ts)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="pages">
              <button className="btn secondary" style={{ height: 30 }} disabled={!cursor}
                onClick={() => navigate('/fixes', true)}>Back to first page</button>
              <button className="btn secondary" style={{ height: 30 }} disabled={!data.nextCursor}
                onClick={() => setParam('cursor', data.nextCursor)}>Next</button>
              <span className="sp" />
              <span>{data.total} fix records{cursor ? ' (paged — first page via back)' : ''}</span>
            </div>
          </>
        )}
      </DataState>
    </section>
  )
}
