import { useCallback } from 'react'
import { apiGet, useResource, qs } from '../api'
import type { FindingsResp } from '../types'
import { Link, useRepoParam, useRoute, navigate } from '../router'
import { DataState, FixBadge, Pager, SeverityBadge, VerBadge } from '../components'

const PILLS = [
  { id: 'all', label: 'All' },
  { id: 'verified', label: 'Reproduced' },
  { id: 'adjudicated', label: 'Awaiting test' },
  { id: 'dismissed', label: 'Dismissed' },
  { id: 'candidate', label: 'Candidate' },
]
const SEVS = ['', 'critical', 'high', 'medium', 'low', 'info']
const SORTS = [
  { id: 'severity', label: 'Severity' },
  { id: 'newest', label: 'Newest' },
  { id: 'file', label: 'File' },
]

export function FindingsPage() {
  const repo = useRepoParam()
  const route = useRoute()
  const q = route.query.get('q') ?? ''
  const status = route.query.get('status') ?? ''
  const severity = route.query.get('severity') ?? ''
  const sort = route.query.get('sort') ?? 'severity'
  const nofix = route.query.get('nofix') === '1'
  const page = Math.max(1, parseInt(route.query.get('page') ?? '1', 10) || 1)
  const limit = 50

  const setParam = (k: string, v: string) => {
    const u = new URLSearchParams(route.query)
    if (v) u.set(k, v); else u.delete(k)
    if (k !== 'page') u.delete('page')
    navigate(`${route.path}${u.toString() ? '?' + u : ''}`, true)
  }

  const load = useCallback(
    (signal: AbortSignal) => apiGet<FindingsResp>(`/api/v1/findings${qs({ repo, q, status, severity, sort, nofix: nofix ? '1' : '', page, limit })}`, signal),
    [repo, q, status, severity, sort, nofix, page],
  )
  const r = useResource<FindingsResp>(`findings:${repo}`, load, { interval: 8000 })
  const data = r.data

  const counts = data?.counts ?? {}
  const pillCount = (id: string) => {
    if (!id) return data?.total
    if (id === 'verified') return counts['verified']
    return counts[id]
  }

  return (
    <section className="panel" aria-labelledby="findings-h">
      <div className="panel-head">
        <h2 id="findings-h">Findings</h2>
        {q && <span className="meta">matching “{q}”</span>}
        <span className="end">
          <label className="field-label">Severity
            <select value={severity} onChange={e => setParam('severity', e.target.value)}>
              {SEVS.map(s => <option key={s} value={s}>{s || 'All severities'}</option>)}
            </select>
          </label>
          <label className="field-label">Sort
            <select value={sort} onChange={e => setParam('sort', e.target.value)}>
              {SORTS.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
            </select>
          </label>
          <label className="field-label">
            <input type="checkbox" checked={nofix} onChange={e => setParam('nofix', e.target.checked ? '1' : '')} />
            No fix attempt
          </label>
        </span>
      </div>
      <div className="panel-body tight">
        <div className="pills" role="group" aria-label="Filter by verification status">
          {PILLS.map(p => (
            <button key={p.id} className="pill" aria-pressed={status === p.id}
              onClick={() => setParam('status', p.id)}>
              {p.label}{pillCount(p.id) != null ? <span className="n"> {pillCount(p.id)}</span> : null}
            </button>
          ))}
        </div>
      </div>
      <DataState loading={r.loading} error={r.error} stale={r.stale} onRetry={r.reload}
        empty={!!data && data.items.length === 0}
        emptyTitle="No findings match."
        emptyHint={<div>{q ? <>No findings match “{q}”. </> : null}<button className="linkbtn" onClick={() => navigate('/findings')}>Clear filters</button></div>}>
        {data && (
          <>
            <table className="data fixed rtable">
              <caption className="sr">All recorded findings</caption>
              <colgroup>
                <col style={{ width: '12%' }} /><col style={{ width: '25%' }} /><col style={{ width: '10%' }} />
                <col style={{ width: '14%' }} /><col style={{ width: '12%' }} /><col style={{ width: '19%' }} /><col style={{ width: '8%' }} />
              </colgroup>
              {data.warnings.length > 0 && <div className="warn-inline" style={{ padding: '8px 16px' }}>{data.warnings[0]}</div>}
              <thead>
                <tr>
                  <th scope="col">ID</th><th scope="col">Title</th><th scope="col">Severity</th>
                  <th scope="col">Verification</th><th scope="col">Repository</th><th scope="col">File</th><th scope="col">Fix</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map(f => (
                  <tr key={`${f.repo}:${f.id}`}>
                    <td data-th="ID"><Link className="mono nowrap" style={{ fontSize: 12 }} to={`/repos/${encodeURIComponent(f.repo)}/findings/${encodeURIComponent(f.id)}`}>{f.id}</Link></td>
                    <td data-th="Title">
                      <Link className="rowtitle clamp2" to={`/repos/${encodeURIComponent(f.repo)}/findings/${encodeURIComponent(f.id)}`}>{f.title || f.vulnClass}</Link>
                      <div className="rowsub">{f.vulnClass}{f.engine ? ` · ${f.engine}` : ''}</div>
                    </td>
                    <td data-th="Severity"><SeverityBadge sev={f.severity} /></td>
                    <td data-th="Verification"><VerBadge v={f.verification} /></td>
                    <td data-th="Repository"><Link className="ell" title={f.repo} to={`/repos/${encodeURIComponent(f.repo)}`}>{f.repo}</Link></td>
                    <td data-th="File"><span className="mono ell" style={{ fontSize: 12 }} title={`${f.file}${f.line ? `:${f.line}` : ''}`}>{f.file}{f.line ? `:${f.line}` : ''}</span></td>
                    <td data-th="Fix">{f.fix ? <FixBadge verdict={f.fix.verdict} /> : <span className="muted">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pager page={data.page} pages={data.pages} total={data.total} perPage={limit}
              onPage={p => setParam('page', String(p))} />
          </>
        )}
      </DataState>
    </section>
  )
}
