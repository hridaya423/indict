import { useCallback } from 'react'
import { apiGet, useResource } from '../api'
import type { ListResp, RepoSummary } from '../types'
import { Link } from '../router'
import { Badge, DataState, RunStateBadge } from '../components'
import { ago, shortSha } from '../format'

export function ReposPage() {
  const load = useCallback(
    (signal: AbortSignal) => apiGet<ListResp<RepoSummary>>('/api/v1/repos?limit=100', signal),
    [],
  )
  const r = useResource<ListResp<RepoSummary>>('repos-list', load, { interval: 10000 })
  const data = r.data

  return (
    <section className="panel" aria-labelledby="repos-h">
      <div className="panel-head"><h2 id="repos-h">Repositories</h2></div>
      <DataState loading={r.loading} error={r.error} stale={r.stale} onRetry={r.reload}
        empty={!!data && data.items.length === 0}
        emptyTitle="No repositories recorded."
        emptyHint={<div>Scan a target to record it here.</div>}>
        {data && (
          <table className="data rtable">
            <thead>
              <tr><th>Repository</th><th>Registered</th><th>Last scan</th><th>Latest run</th><th>Findings</th><th>Daemon</th></tr>
            </thead>
            <tbody>
              {data.items.map(repo => (
                <tr key={repo.name}>
                  <td data-th="Repository">
                    <Link className="rowtitle" to={`/repos/${encodeURIComponent(repo.name)}`}>{repo.name}</Link>
                    {repo.warnings.length > 0 && <div className="rowsub">{repo.warnings[0]}</div>}
                  </td>
                  <td data-th="Registered">{repo.registered === null ? <span className="muted">—</span> : repo.registered ? 'yes' : 'no'}</td>
                  <td data-th="Last scan">{repo.lastScan?.ts ? <span title={shortSha(repo.lastScan.sha)}>{ago(repo.lastScan.ts)}</span> : <span className="muted">never</span>}</td>
                  <td data-th="Latest run">
                    {repo.latestRun
                      ? <><RunStateBadge state={repo.latestRun.state} /> <Link className="mono" style={{ fontSize: 12 }} to={`/repos/${encodeURIComponent(repo.name)}/runs/${encodeURIComponent(repo.latestRun.id)}`}>{repo.latestRun.id}</Link></>
                      : <Badge kind="never-scanned" label={repo.state === 'never-scanned' ? 'never scanned' : 'no runs'} />}
                  </td>
                  <td data-th="Findings" className="num">
                    {(repo.counts.verified ?? 0) + (repo.counts.adjudicated ?? 0) + (repo.counts.candidate ?? 0) + (repo.counts.dismissed ?? 0)}
                  </td>
                  <td data-th="Daemon">{repo.daemonAlive ? <Badge kind="ok" label="alive" /> : <span className="muted">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </DataState>
    </section>
  )
}
