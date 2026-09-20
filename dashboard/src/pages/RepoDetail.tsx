import { useCallback } from 'react'
import { apiGet, useResource } from '../api'
import type { RepoDetail } from '../types'
import { Link } from '../router'
import { Badge, DataState, RunStateBadge } from '../components'
import { ago, fmtDur, fmtFull, shortRun, shortSha } from '../format'

export function RepoDetailPage({ repo }: { repo: string }) {
  const load = useCallback(
    (signal: AbortSignal) => apiGet<RepoDetail>(`/api/v1/repos/${encodeURIComponent(repo)}`, signal),
    [repo],
  )
  const r = useResource<RepoDetail>(`repo:${repo}`, load, { interval: 8000 })
  const d = r.data
  const c = d?.counts ?? {}

  return (
    <>
      <section className="panel" aria-labelledby="repod-h">
        <div className="panel-head" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 8 }}>
          <nav className="crumb" aria-label="Breadcrumb">
            <Link to="/repos">Repositories</Link><span aria-hidden="true">/</span><span>{repo}</span>
          </nav>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <h2 id="repod-h">{repo}</h2>
            {d?.state === 'corrupt' && <Badge kind="failed" label="unreadable" />}
            {d?.daemonAlive && <Badge kind="ok" label="daemon alive" />}
          </div>
          {d && (
            <div className="meta">
              {d.lastScan?.ts ? `Last scan ${ago(d.lastScan.ts)} · ${shortSha(d.lastScan.sha)}` : 'Never scanned'}
              {d.watch?.url ? ` · watch: ${d.watch.url}` : ''}
              {d.watch?.budget != null ? ` · watch budget $${d.watch.budget}` : ''}
            </div>
          )}
        </div>
        <div className="panel-body">
          <DataState loading={r.loading} error={r.error} stale={r.stale} onRetry={r.reload}>
            {d && (
              <div className="kv" style={{ gridTemplateColumns: 'repeat(4, max-content 1fr)' }}>
                <span className="k">Verified</span><span className="v">{c.verified ?? 0}</span>
                <span className="k">Awaiting test</span><span className="v">{c.adjudicated ?? 0}</span>
                <span className="k">Candidates</span><span className="v">{c.candidate ?? 0}</span>
                <span className="k">Dismissed</span><span className="v">{c.dismissed ?? 0}</span>
                <span className="k">Fixes</span><span className="v">{d.fixesTotal ? `${d.fixesPassed} / ${d.fixesTotal} gate-passed` : 'none'}</span>
              </div>
            )}
            {d && d.warnings.length > 0 && d.warnings.map((w, i) => <div key={i} className="warn-inline" style={{ marginTop: 8 }}>{w}</div>)}
          </DataState>
        </div>
      </section>

      <section className="panel" aria-labelledby="reporuns-h">
        <div className="panel-head"><h2 id="reporuns-h">Runs · {d?.runs.length ?? 0}</h2></div>
        <DataState loading={r.loading} empty={!!d && d.runs.length === 0}
          emptyTitle="No recorded runs for this repository."
          emptyHint={<div>Run <span className="cmd">./indict --target &lt;git-url&gt;</span> to record one.</div>}>
          {d && (
            <table className="data rtable">
              <thead><tr><th>Run</th><th>State</th><th>Freshness</th><th>Revision</th><th>Started</th><th className="num">Duration</th><th>Findings</th></tr></thead>
              <tbody>
                {d.runs.map(run => (
                  <tr key={run.id}>
                    <td data-th="Run"><Link className="mono" style={{ fontSize: 12 }} to={`/repos/${encodeURIComponent(repo)}/runs/${encodeURIComponent(run.id)}`}>{shortRun(run.id)}</Link>{run.legacy && <span className="note"> · legacy</span>}</td>
                    <td data-th="State"><RunStateBadge state={run.state} /></td>
                    <td data-th="Freshness">{run.freshness === 'fresh' ? <Badge kind="ok" label="fresh" /> : run.freshness === 'stale' ? <Badge kind="stale" label="stale" /> : <span className="muted">—</span>}</td>
                    <td data-th="Revision"><span className="mono" style={{ fontSize: 12 }}>{shortSha(run.revision)}</span></td>
                    <td data-th="Started">{fmtFull(run.startedAt)}</td>
                    <td data-th="Duration" className="num">{fmtDur(run.startedAt, run.endedAt)}</td>
                    <td data-th="Findings">{run.outcome ? `${run.outcome.verified ?? 0} verified · ${run.outcome.dismissed ?? 0} dismissed` : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </DataState>
      </section>
    </>
  )
}
