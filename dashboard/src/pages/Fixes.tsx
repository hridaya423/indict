import { useCallback, useRef, useState } from 'react'
import { apiGet, useResource, qs } from '../api'
import type { FixRow, ListResp } from '../types'
import { Link, useRepoParam } from '../router'
import { CheckBadge, DataState, SeverityBadge } from '../components'
import { ago, CHECK_LABEL } from '../format'

const VERDICTS = [
  { id: '', label: 'All' },
  { id: 'fix-verified', label: 'Gate passed' },
  { id: 'fix-rejected', label: 'Rejected' },
  { id: 'fix-unverifiable', label: 'Unverifiable' },
]

export function FixesPage() {
  const repo = useRepoParam()
  const [verdict, setVerdict] = useState('')
  const [cursor, setCursor] = useState<string | null>(null)
  const cursorStack = useRef<(string | null)[]>([null])

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
        {repo && <span className="meta">scoped to {repo}</span>}
      </div>
      <div className="panel-body tight">
        <div className="pills" role="group" aria-label="Filter by gate verdict">
          {VERDICTS.map(v => (
            <button key={v.id} className="pill" aria-pressed={verdict === v.id}
              onClick={() => { setVerdict(v.id); setCursor(null); cursorStack.current = [null] }}>{v.label}</button>
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
                <tr><th>Finding</th><th>Title</th><th>Severity</th><th>Repository</th><th>Gate</th><th>Backend</th><th>Recorded</th></tr>
              </thead>
              <tbody>
                {data.items.map(fx => (
                  <tr key={`${fx.repo}:${fx.findingId}`}>
                    <td data-th="Finding"><Link className="mono" style={{ fontSize: 12 }} to={`/repos/${encodeURIComponent(fx.repo)}/fixes/${encodeURIComponent(fx.findingId)}`}>{fx.findingId}</Link></td>
                    <td data-th="Title">
                      <Link className="rowtitle" to={`/repos/${encodeURIComponent(fx.repo)}/findings/${encodeURIComponent(fx.findingId)}`}>{fx.title || fx.findingId}</Link>
                      {fx.checks && <div className="rowsub">{fx.checks.map(ch => `${CHECK_LABEL[ch.id] ?? ch.id}: ${ch.outcome}`).join(' · ')}</div>}
                    </td>
                    <td data-th="Severity"><SeverityBadge sev={fx.severity} /></td>
                    <td data-th="Repository"><Link to={`/repos/${encodeURIComponent(fx.repo)}`}>{fx.repo}</Link></td>
                    <td data-th="Gate"><CheckBadge outcome={fx.verdict === 'fix-verified' ? 'pass' : fx.verdict === 'fix-rejected' ? 'fail' : 'skip'} /> <span className="note">{fx.reason ?? ''}</span></td>
                    <td data-th="Backend">{fx.backend ?? '—'}</td>
                    <td data-th="Recorded">{ago(fx.ts)}</td>
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
              <span>{data.total} fix records</span>
            </div>
          </>
        )}
      </DataState>
    </section>
  )
}
