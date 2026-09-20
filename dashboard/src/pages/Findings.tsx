import { useCallback } from 'react'
import { apiGet, useResource, qs } from '../api'
import type { FindingCase, FindingsResp } from '../types'
import { Link, useRepoParam, useRoute, navigate } from '../router'
import { DataState, FixBadge, Pager, SeverityBadge, VerBadge } from '../components'
import { ProofPanel } from '../proof'
import { shortRun } from '../format'

const PILLS = [
  { id: 'all', label: 'All' },
  { id: 'verified', label: 'Reproduced' },
  { id: 'adjudicated', label: 'Awaiting test' },
  { id: 'dismissed', label: 'Dismissed' },
  { id: 'candidate', label: 'Candidate' },
]
const SEVS = ['', 'critical', 'high', 'medium', 'low', 'info']
const SORTS = [
  { id: '', label: 'Verified first' },
  { id: 'severity', label: 'Severity' },
  { id: 'newest', label: 'Newest' },
  { id: 'file', label: 'File' },
]
const SIZES = [25, 50, 100]

export function FindingsPage() {
  const repo = useRepoParam()
  const route = useRoute()
  const q = route.query.get('q') ?? ''
  const status = route.query.get('status') ?? ''
  const severity = route.query.get('severity') ?? ''
  const vclass = route.query.get('class') ?? ''
  const engine = route.query.get('engine') ?? ''
  const sort = route.query.get('sort') ?? ''
  const nofix = route.query.get('nofix') === '1'
  const page = Math.max(1, parseInt(route.query.get('page') ?? '1', 10) || 1)
  const limit = SIZES.includes(parseInt(route.query.get('size') ?? '', 10))
    ? parseInt(route.query.get('size')!, 10) : 50
  const sel = route.query.get('sel') ?? ''

  const setParam = (k: string, v: string, push = false) => {
    const u = new URLSearchParams(route.query)
    if (v) u.set(k, v); else u.delete(k)
    if (k !== 'page') u.delete('page')
    navigate(`${route.path}${u.toString() ? '?' + u : ''}`, push)
  }

  const load = useCallback(
    (signal: AbortSignal) => apiGet<FindingsResp>(`/api/v1/findings${qs({ repo, q, status, severity, class: vclass, engine, sort, nofix: nofix ? '1' : '', page, limit })}`, signal),
    [repo, q, status, severity, vclass, engine, sort, nofix, page, limit],
  )
  const r = useResource<FindingsResp>(
    `findings:${repo}:${q}:${status}:${severity}:${vclass}:${engine}:${sort}:${nofix}:${page}:${limit}`,
    load, { interval: 8000 })
  const data = r.data

  // one bounded unfiltered-by-class/engine pass fills the filter selects
  const facets = useResource<FindingsResp>(
    `findings-facets:${repo}:${q}:${status}:${severity}:${sort}:${nofix}`,
    useCallback((s: AbortSignal) => apiGet<FindingsResp>(
      `/api/v1/findings${qs({ repo, q, status, severity, sort, nofix: nofix ? '1' : '', limit: 100 })}`, s),
      [repo, q, status, severity, sort, nofix]),
    { interval: 30000 })
  const classes = [...new Set((facets.data?.items ?? []).map(f => f.vulnClass).filter(Boolean))].sort()
  const engines = [...new Set((facets.data?.items ?? []).map(f => f.engine).filter(Boolean))].sort()

  // no explicit selection -> open the inspector on the top row of the
  // current view, so the pane never sits empty over real data
  const effSel = sel || (data?.items.length
    ? `${data.items[0].repo}:${data.items[0].id}` : '')
  const selKey = effSel.split(':')
  const caseRes = useResource<FindingCase | null>(
    `findcase:${effSel}`,
    useCallback((s: AbortSignal) => selKey.length === 2 && selKey[0] && selKey[1]
      ? apiGet<FindingCase>(`/api/v1/repos/${encodeURIComponent(selKey[0])}/findings/${encodeURIComponent(selKey[1])}`, s)
      : Promise.resolve(null), [effSel]),
    { interval: 8000 })

  const counts = data?.counts ?? {}
  const pillCount = (id: string) => {
    if (id === 'all') return Object.values(counts).reduce((a, b) => a + b, 0)
    return counts[id]
  }
  // a filter that hides an EXPLICIT selection closes the inspector, with a note
  const selHidden = !!sel && !!data && !data.items.some(f => `${f.repo}:${f.id}` === sel)

  return (
    <div className="findings-grid">
      <section className="panel" aria-labelledby="findings-h">
        <div className="panel-head">
          <h2 id="findings-h">Findings</h2>
          {q && <span className="meta">matching “{q}”</span>}
          <span className="end">
            <label className="field-label">Class
              <select value={vclass} onChange={e => setParam('class', e.target.value)}>
                <option value="">All classes</option>
                {classes.map(v => <option key={v} value={v}>{v}</option>)}
              </select>
            </label>
            <label className="field-label">Engine
              <select value={engine} onChange={e => setParam('engine', e.target.value)}>
                <option value="">All engines</option>
                {engines.map(v => <option key={v} value={v}>{v}</option>)}
              </select>
            </label>
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
            <label className="field-label" title="Includes findings with no fix attempt and with rejected or unverifiable attempts — only a passing gate excludes them">
              <input type="checkbox" checked={nofix} onChange={e => setParam('nofix', e.target.checked ? '1' : '')} />
              No passing fix recorded
            </label>
          </span>
        </div>
        <div className="panel-body tight">
          <div className="pills" role="group" aria-label="Filter by verification status">
            {PILLS.map(p => (
              <button key={p.id} className="pill" aria-pressed={status === p.id || (!status && p.id === '')}
                onClick={() => setParam('status', p.id === 'all' ? '' : p.id)}>
                {p.label}{pillCount(p.id) != null ? <span className="n"> {pillCount(p.id)}</span> : null}
              </button>
            ))}
          </div>
          {!status && <div className="note" style={{ marginTop: 8 }}>Dismissed hidden by default — select Dismissed to show them.</div>}
          {selHidden && (
            <div className="warn-inline" style={{ marginTop: 8 }}>
              Selection hidden by current filters.
              <button className="linkbtn" onClick={() => setParam('sel', '')}>Close inspector</button>
            </div>
          )}
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
                  <col style={{ width: '15%' }} /><col /><col style={{ width: '10%' }} />
                  <col style={{ width: '15%' }} /><col style={{ width: '12%' }} /><col style={{ width: '10%' }} /><col style={{ width: '8%' }} />
                </colgroup>
                {data.warnings.length > 0 && <div className="warn-inline" style={{ padding: '8px 16px' }}>{data.warnings[0]}</div>}
                <thead>
                  <tr>
                    <th scope="col">ID</th><th scope="col">Title</th><th scope="col">Severity</th>
                    <th scope="col">Verification</th>
                    <th scope="col" className="col-opt">Repository</th>
                    <th scope="col" className="col-opt">Latest run</th>
                    <th scope="col" className="col-opt">Fix</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map(f => (
                    <tr key={`${f.repo}:${f.id}`}
                      className={`clickable${`${f.repo}:${f.id}` === effSel ? ' sel' : ''}`}
                      tabIndex={0}
                      aria-current={`${f.repo}:${f.id}` === effSel ? 'true' : undefined}
                      onClick={() => setParam('sel', `${f.repo}:${f.id}`)}
                      onKeyDown={e => { if (e.key === 'Enter') setParam('sel', `${f.repo}:${f.id}`) }}>
                      <td data-th="ID"><span className="fid" title={f.id}>{f.id}</span></td>
                      <td data-th="Title">
                        <Link className="rowtitle clamp2"
                          to={`/repos/${encodeURIComponent(f.repo)}/findings/${encodeURIComponent(f.id)}${f.latestRun ? `?run=${encodeURIComponent(f.latestRun)}` : ''}`}
                          onClick={e => { e.stopPropagation(); sessionStorage.setItem(`indict:return:${f.repo}:${f.id}`, `${route.path}${route.query.toString() ? `?${route.query}` : ''}`) }}>
                          {f.title || f.vulnClass}
                        </Link>
                        <div className="rowsub">{f.repo} · {f.vulnClass}{f.engine ? ` · ${f.engine}` : ''}</div>
                        <div className="rowsub" title={`${f.file}${f.line ? `:${f.line}` : ''}`}>{f.file}{f.line ? `:${f.line}` : ''}</div>
                      </td>
                      <td data-th="Severity"><SeverityBadge sev={f.severity} /></td>
                      <td data-th="Verification"><VerBadge v={f.verification} /></td>
                      <td data-th="Repository" className="col-opt"><Link className="ell" title={f.repo} to={`/repos/${encodeURIComponent(f.repo)}`}
                        onClick={e => e.stopPropagation()}>{f.repo}</Link></td>
                      <td data-th="Latest run" className="col-opt">{f.latestRun
                        ? <Link className="mono" style={{ fontSize: 12 }} to={`/repos/${encodeURIComponent(f.repo)}/runs/${encodeURIComponent(f.latestRun)}`}
                          onClick={e => e.stopPropagation()}>{shortRun(f.latestRun)}</Link>
                        : <span className="muted">—</span>}</td>
                      <td data-th="Fix" className="col-opt">{f.fix ? <FixBadge verdict={f.fix.verdict} /> : <span className="muted">—</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '8px 16px 0' }}>
                <label className="field-label">Rows
                  <select value={String(limit)} onChange={e => setParam('size', e.target.value)}>
                    {SIZES.map(n => <option key={n} value={n}>{n}</option>)}
                  </select>
                </label>
              </div>
              <Pager page={data.page} pages={data.pages} total={data.total} perPage={limit}
                onPage={p => setParam('page', String(p), true)} />
            </>
          )}
        </DataState>
      </section>

      <aside className="panel inspector" aria-labelledby="insp-h" aria-live="polite">
        <div className="panel-body">
          <h2 id="insp-h" className="sr">Finding inspector</h2>
          {!effSel && <div className="dstate"><div className="t">Select a finding to inspect its evidence.</div></div>}
          {!!effSel && !selHidden && (
            <DataState loading={caseRes.loading && !caseRes.data} error={caseRes.error} stale={caseRes.stale} onRetry={caseRes.reload}>
              {caseRes.data?.finding
                ? <>
                  <ProofPanel c={caseRes.data} compact />
                  <div className="note" style={{ marginTop: 8 }}>
                    Reproduced requires a recorded successful execution; “Recorded verified” means the structured record is unavailable.
                  </div>
                </>
                : !caseRes.loading && !caseRes.error
                  ? <div className="dstate"><div className="t">Selection unavailable.</div></div>
                  : null}
            </DataState>
          )}
        </div>
      </aside>
    </div>
  )
}
