import { useCallback, useEffect, useState } from 'react'
import { apiGet, useResource, qs } from '../api'
import type { FindingRow, Overview } from '../types'
import { useRepoParam, useRoute, navigate } from '../router'
import { DataState, SeverityBadge, VerBadge } from '../components'
import { ProofPanel } from '../proof'
import { RepoScansTable, RepoScanCounts, SelectedRunPanel } from '../runview'

const PILLS = [
  { id: '', label: 'All' },
  { id: 'verified', label: 'Reproduced' },
  { id: 'adjudicated', label: 'Awaiting test' },
  { id: 'dismissed', label: 'Dismissed' },
]

export function OverviewPage() {
  const repo = useRepoParam()
  const route = useRoute()
  const [follow, setFollow] = useState(true)
  const [now, setNow] = useState(Date.now() / 1000)

  const selRunQ = route.query.get('run') ?? undefined
  const selFindingQ = route.query.get('finding') ?? undefined
  const load = useCallback(
    (signal: AbortSignal) => apiGet<Overview>(`/api/v1/overview${qs({ repo, run: selRunQ, finding: selFindingQ })}`, signal),
    [repo, selRunQ, selFindingQ],
  )
  const r = useResource<Overview>(`overview:${repo}`, load, { interval: 4000 })

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now() / 1000), 1000)
    return () => clearInterval(id)
  }, [])

  const data = r.data
  const selected = data?.selected ?? null
  const selRun = selected?.run ?? null
  const findings = selected?.findings
  const [pill, setPill] = useState('')
  const selFindingId = route.query.get('finding')
  const proof = selected?.proof

  const filtered: FindingRow[] = (findings?.items ?? []).filter(f => {
    if (!pill) return true
    if (pill === 'verified') return f.verification === 'reproduced' || f.verification === 'recorded-verified'
    if (pill === 'adjudicated') return f.status === 'adjudicated'
    if (pill === 'dismissed') return f.status === 'dismissed'
    return true
  })

  return (
    <>
      <section className="panel" aria-labelledby="reposcans-h">
        <div className="panel-head">
          <h2 id="reposcans-h">Repository scans</h2>
          {data && <RepoScanCounts repos={data.repos} />}
        </div>
        <DataState loading={r.loading} error={r.error} stale={r.stale} onRetry={r.reload}
          empty={!!data && data.repos.every(x => !x.latestRun)}
          emptyTitle="No scans yet."
          emptyHint={<div>Run <span className="cmd">./indict --target &lt;git-url&gt;</span> to record a scan.</div>}>
          {data && <RepoScansTable repos={data.repos} selected={selected?.repo} />}
        </DataState>
      </section>

      {data && !selRun && data.repos.length > 0 && (
        <section className="panel"><div className="dstate"><div className="t">No recorded runs yet.</div></div></section>
      )}
      {selRun && selected && (
        <SelectedRunPanel repo={selected.repo} run={selRun} follow={follow} onFollow={setFollow} now={now} />
      )}

      {selRun && selected && (
        <div className="split" style={{ marginTop: 0 }}>
          <section className="panel" aria-labelledby="runfind-h">
            <div className="panel-head">
              <h2 id="runfind-h">Findings in this run · {findings?.total ?? 0}</h2>
              {findings?.source === 'latest' && <span className="meta">latest records — run snapshot unavailable</span>}
            </div>
            <div className="panel-body tight">
              <div className="pills" role="group" aria-label="Filter findings by verification">
                {PILLS.map(p => (
                  <button key={p.id} className="pill" aria-pressed={pill === p.id}
                    onClick={() => setPill(p.id)}>{p.label}</button>
                ))}
              </div>
            </div>
            <DataState empty={filtered.length === 0} emptyTitle="No findings in this run."
              emptyHint={pill ? <div>No {PILLS.find(p => p.id === pill)?.label.toLowerCase()} findings recorded for this run.</div> : undefined}>
              <table className="data fixed">
                <colgroup>
                  <col style={{ width: '14%' }} /><col /><col style={{ width: '13%' }} /><col style={{ width: '19%' }} /><col style={{ width: '24%' }} />
                </colgroup>
                <thead>
                  <tr><th>ID</th><th>Title</th><th>Severity</th><th>Verification</th><th>File path</th></tr>
                </thead>
                <tbody>
                  {filtered.map(f => (
                    <tr key={f.id}
                      className={`clickable${selFindingId === f.id || (!selFindingId && proof?.finding?.id === f.id) ? ' sel' : ''}`}
                      onClick={() => {
                        const q = new URLSearchParams(route.query)
                        q.set('finding', f.id)
                        navigate(`${route.path}?${q.toString()}`, true)
                      }}
                      onKeyDown={e => {
                        if (e.key === 'Enter') {
                          const q = new URLSearchParams(route.query)
                          q.set('finding', f.id)
                          navigate(`${route.path}?${q.toString()}`, true)
                        }
                      }}
                      tabIndex={0}
                      aria-current={proof?.finding?.id === f.id ? 'true' : undefined}>
                      <td><span className="mono nowrap" style={{ fontSize: 12 }}>{f.id}</span></td>
                      <td><span className="rowtitle clamp2">{f.title || f.vulnClass}</span></td>
                      <td><SeverityBadge sev={f.severity} /></td>
                      <td><VerBadge v={f.verification} /></td>
                      <td><span className="mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>{f.file}{f.line ? `:${f.line}` : ''}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </DataState>
          </section>

          <aside className="panel inspector" aria-labelledby="insp-h" aria-live="polite">
            <div className="panel-body">
              <h2 id="insp-h" style={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)' }}>Finding inspector</h2>
              {proof
                ? <ProofPanel c={proof} compact />
                : <div className="dstate"><div className="t">Select a finding to inspect its evidence.</div></div>}
            </div>
          </aside>
        </div>
      )}
    </>
  )
}
