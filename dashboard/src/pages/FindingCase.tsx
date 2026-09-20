import { useCallback } from 'react'
import { apiGet, useResource, qs } from '../api'
import type { FindingCase } from '../types'
import { Link, useRoute } from '../router'
import { DataState, SeverityBadge, VerBadge } from '../components'
import { ProofPanel } from '../proof'
import { shortRun } from '../format'

export function FindingCasePage({ repo, id }: { repo: string; id: string }) {
  const route = useRoute()
  const run = route.query.get('run') ?? undefined
  const load = useCallback(
    (signal: AbortSignal) => apiGet<FindingCase>(`/api/v1/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(id)}${qs({ run })}`, signal),
    [repo, id, run],
  )
  const r = useResource<FindingCase>(`case:${repo}:${id}:${run ?? ''}`, load, { interval: 8000 })
  const c = r.data
  const f = c?.finding

  return (
    <section className="panel" aria-labelledby="case-h">
      <div className="panel-head" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 8 }}>
        <nav className="crumb" aria-label="Breadcrumb">
          <Link to="/findings">Findings</Link><span aria-hidden="true">/</span>
          <Link to={`/repos/${encodeURIComponent(repo)}`}>{repo}</Link><span aria-hidden="true">/</span>
          <span>{id}</span>
        </nav>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <h2 id="case-h" className="clamp2" style={{ flex: '1 1 100%', minWidth: 0, overflowWrap: 'anywhere' }}
            title={f?.title || f?.vulnClass || id}>{f ? (f.title || f.vulnClass) : id}</h2>
          {f && <SeverityBadge sev={f.severity} />}
          {c && <VerBadge v={c.proof?.reproduced ? 'reproduced' : c.proof?.recordedVerified ? 'recorded-verified' : f?.status === 'dismissed' ? 'dismissed' : 'awaiting'} />}
          {run && <span className="meta">run {shortRun(run)}</span>}
          {c?.snapshot && <span className="meta">· run snapshot</span>}
        </div>
      </div>
      <div className="panel-body">
        <DataState loading={r.loading} error={r.error} stale={r.stale} onRetry={r.reload}
          empty={!!c && !c.finding}
          emptyTitle="Finding not found."
          emptyHint={<div>It may have been removed, or the id is wrong. <Link to={`/findings?q=${encodeURIComponent(id)}`}>Search findings</Link>.</div>}>
          {c && c.finding && <ProofPanel c={c} />}
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
