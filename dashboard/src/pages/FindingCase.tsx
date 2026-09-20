import { useCallback } from 'react'
import { ApiError, apiGet, useResource, qs } from '../api'
import type { FindingCase } from '../types'
import { Link, useRoute, navigate } from '../router'
import { DataState, SeverityBadge, VerBadge } from '../components'
import { ProofPanel, normalizeTab } from '../proof'
import { shortRun } from '../format'

function caseError(code: string, title: string, repo: string, id: string, latestRun?: string | null) {
  return (
    <div className="dstate" role="alert">
      <div className="t">{title}</div>
      <div>
        {code === 'unknown-run' && 'The requested run does not exist for this repository.'}
        {code === 'not-in-run' && 'This finding is absent from that run\u2019s snapshot — historical proof is not borrowed from later scans.'}
        {code === 'unknown-finding' && 'It may have been removed, or the id is wrong.'}
      </div>
      <div style={{ marginTop: 12, display: 'flex', gap: 12 }}>
        {latestRun && (
          <Link className="linkbtn" to={`/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(id)}?run=${encodeURIComponent(latestRun)}`}>
            Open latest-run case
          </Link>
        )}
        {code !== 'unknown-finding' && !latestRun && (
          <Link className="linkbtn" to={`/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(id)}`}>Open latest case</Link>
        )}
        {code === 'unknown-finding' && <Link className="linkbtn" to={`/findings?q=${encodeURIComponent(id)}`}>Search findings</Link>}
      </div>
    </div>
  )
}

export function FindingCasePage({ repo, id }: { repo: string; id: string }) {
  const route = useRoute()
  const run = route.query.get('run') ?? undefined
  const tabRaw = route.query.get('tab')
  const tab = normalizeTab(tabRaw)
  const load = useCallback(
    (signal: AbortSignal) => apiGet<FindingCase>(`/api/v1/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(id)}${qs({ run })}`, signal),
    [repo, id, run],
  )
  const r = useResource<FindingCase>(`case:${repo}:${id}:${run ?? ''}`, load, { interval: 8000 })
  const c = r.data
  const f = c?.finding
  const backTo = sessionStorage.getItem(`indict:return:${repo}:${id}`)

  const setTab = (t: string) => {
    const q = new URLSearchParams(route.query)
    q.set('tab', t)
    navigate(`${route.path}?${q.toString()}`, true)
  }

  if (!r.loading && r.error instanceof ApiError
    && ['unknown-run', 'not-in-run', 'unknown-finding'].includes(r.error.code)) {
    return (
      <section className="panel">
        <div className="panel-head">
          <nav className="crumb" aria-label="Breadcrumb">
            <Link to="/findings">Findings</Link><span aria-hidden="true">/</span>
            <Link to={`/repos/${encodeURIComponent(repo)}`}>{repo}</Link><span aria-hidden="true">/</span>
            <span>{id}</span>
          </nav>
        </div>
        <div className="panel-body">{caseError(r.error.code, 'Case unavailable.', repo, id,
          (r.error as unknown as { extra?: { latestRun?: string | null } }).extra?.latestRun)}</div>
      </section>
    )
  }

  return (
    <section className="panel" aria-labelledby="case-h">
      <div className="panel-head" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 8 }}>
        <nav className="crumb" aria-label="Breadcrumb">
          {backTo ? <Link to={backTo}>← Findings</Link> : <Link to="/findings">Findings</Link>}
          <span aria-hidden="true">/</span>
          <Link to={`/repos/${encodeURIComponent(repo)}`}>{repo}</Link><span aria-hidden="true">/</span>
          <span>{id}</span>
        </nav>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <h2 id="case-h" className="clamp2" style={{ flex: '1 1 100%', minWidth: 0, overflowWrap: 'anywhere' }}
            title={f?.title || f?.vulnClass || id}>{f ? (f.title || f.vulnClass) : id}</h2>
          {f && <SeverityBadge sev={f.severity} />}
          {c && <VerBadge v={c.proof?.reproduced ? 'reproduced' : c.proof?.recordedVerified ? 'recorded-verified' : f?.status === 'dismissed' ? 'dismissed' : 'awaiting'} />}
          {run && <Link className="meta linkbtn" to={`/repos/${encodeURIComponent(repo)}/runs/${encodeURIComponent(run)}`}>run {shortRun(run)}</Link>}
          {c?.snapshot && <span className="meta">· run snapshot</span>}
        </div>
      </div>
      <div className="panel-body">
        <DataState loading={r.loading} error={r.error} stale={r.stale} onRetry={r.reload}
          empty={!!c && !c.finding}
          emptyTitle="Finding not found."
          emptyHint={<div>It may have been removed, or the id is wrong. <Link to={`/findings?q=${encodeURIComponent(id)}`}>Search findings</Link>.</div>}>
          {c && c.finding && <ProofPanel c={c} tab={tab} onTab={setTab} />}
          {c && c.warnings.length > 0 && (
            <div style={{ marginTop: 16 }}>
              {c.warnings.map((w, i) => <div key={i} className="warn-inline">{w}</div>)}
            </div>
          )}
        </DataState>
      </div>
    </section>
  )
}
