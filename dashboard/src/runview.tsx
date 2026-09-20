import { Link } from './router'
import type { RepoSummary, RunDetail, RunSummary } from './types'
import { fmtDurSecs, fmtEta, shortRun, shortSha } from './format'
import { Badge, EventList, HeartbeatCell, RunStateBadge, Switch, Timeline, WorkCell } from './components'

export function RepoScansTable({ repos, selected, maxRows, onSelect }: {
  repos: RepoSummary[]; selected?: string | null
  maxRows?: number; onSelect?: (name: string) => void
}) {
  const withRuns = repos.filter(r => r.latestRun)
  let shown = maxRows != null ? withRuns.slice(0, maxRows) : withRuns
  if (maxRows != null && selected != null) {
    const i = withRuns.findIndex(r => r.name === selected)
    if (i >= maxRows) shown = [withRuns[i], ...withRuns.slice(0, maxRows - 1)]
  }
  const hidden = withRuns.length - shown.length
  return (
    <table className="data rtable">
      <caption className="sr">Latest recorded run per repository. Repositories without runs are omitted.</caption>
      <thead>
        <tr>
          {onSelect && <th scope="col" style={{ width: 36 }}><span className="sr">Select</span></th>}
          <th scope="col">Repository</th>
          <th scope="col">Scanned revision</th>
          <th scope="col">Current stage</th>
          <th scope="col">Work completed</th>
          <th scope="col" style={{ textAlign: 'right' }}>Heartbeat</th>
        </tr>
      </thead>
      <tbody>
        {shown.map(r => {
          const run = r.latestRun as RunSummary
          const sel = selected === r.name || selected === run.id
          return (
            <tr key={r.name} className={sel ? 'sel' : ''}
              onClick={onSelect && !sel ? () => onSelect(r.name) : undefined}
              style={onSelect && !sel ? { cursor: 'pointer' } : undefined}>
              {onSelect && (
                <td>
                  <button className="selbtn" aria-pressed={sel}
                    title={`Show ${r.name} workspace`} aria-label={`Select ${r.name}`}
                    onClick={e => { e.stopPropagation(); onSelect(r.name) }} />
                </td>
              )}
              <td>
                <Link className="rowtitle" to={`/repos/${encodeURIComponent(r.name)}`}
                  title={`Open ${r.name} detail`}>{r.name}</Link>
                {r.warnings.length > 0 && <div className="rowsub">{r.warnings[0]}</div>}
              </td>
              <td><span className="mono" style={{ fontSize: 12 }} title={run.revision ?? ''}>{shortSha(run.revision)}</span></td>
              <td>
                {run.state === 'running' && run.currentStage
                  ? <span>{run.currentStage.label} <RunStateBadge state="running" /></span>
                  : run.state === 'completed'
                    ? <RunStateBadge state="completed" />
                    : run.state === 'failed'
                      ? <RunStateBadge state="failed" />
                      : <span className="muted">—</span>}
              </td>
              <td><WorkCell progress={run.progress} state={run.state} etaSec={run.etaSec} currentStageId={run.currentStage?.id} /></td>
              <td style={{ textAlign: 'right' }}>
                {run.state === 'completed'
                  ? <span className="muted">Finished</span>
                  : run.state === 'failed'
                    ? <span className="muted">—</span>
                    : <HeartbeatCell hb={run.heartbeat} />}
              </td>
            </tr>
          )
        })}
      </tbody>
      {hidden > 0 && (
        <tfoot>
          <tr>
            <td colSpan={onSelect ? 6 : 5} style={{ padding: '8px 12px' }}>
              <Link className="linkbtn" to="/repos">View all {repos.length} repositories</Link>
            </td>
          </tr>
        </tfoot>
      )}
    </table>
  )
}

export function RepoScanCounts({ repos }: { repos: RepoSummary[] }) {
  const runs = repos.map(r => r.latestRun).filter(Boolean) as RunSummary[]
  const active = runs.filter(r => r.state === 'running').length
  const stale = runs.filter(r => r.freshness === 'stale').length
  const complete = runs.filter(r => r.state === 'completed').length
  const parts = [
    active ? `${active} active` : null,
    stale ? `${stale} stale` : null,
    complete ? `${complete} complete` : null,
  ].filter(Boolean)
  return <span className="meta">{parts.length ? parts.join(' · ') : `${runs.length} recorded`}</span>
}

export function SelectedRunPanel({ repo, run, follow, onFollow, now, events }: {
  repo: string; run: RunDetail | RunSummary
  follow: boolean; onFollow: (v: boolean) => void
  now: number; events?: { items: import('./types').EventRow[]; total?: number }
}) {
  const detail = run as RunDetail
  const tail = events?.items ?? detail.eventsTail ?? []
  const elapsed = fmtDurSecs(run.startedAt != null ? Math.max(0, (run.endedAt ?? now) - run.startedAt) : null)
  return (
    <section className="panel" aria-labelledby="selrun-h">
      <div className="panel-head">
        <h2 id="selrun-h">
          <Link to={`/repos/${encodeURIComponent(repo)}`}>{repo}</Link>
          {' / '}Run {shortRun(run.id)}
        </h2>
        <span className="meta">
          Revision {shortSha(run.revision)} · Elapsed {elapsed}
          {run.state === 'running' && run.etaSec != null &&
            <> · <span title="estimated time remaining">{fmtEta(run.etaSec)} left</span></>}
          {run.state !== 'running' && <> · <RunStateBadge state={run.state} /></>}
        </span>
        <span className="end">
          <Link className="linkbtn" to={`/repos/${encodeURIComponent(repo)}/runs/${encodeURIComponent(run.id)}`}>View full run</Link>
          {run.state === 'running' && (
            <Switch checked={follow} onChange={onFollow} label="Follow live" />
          )}
        </span>
      </div>
      <div className="panel-body">
        <Timeline stages={run.stages} pending={run.pendingStages} lanes={run.lanes} now={now} compact
          stale={run.freshness === 'stale'} />
        {run.findingsSource === 'latest' && (
          <div className="note" style={{ marginTop: 8 }}>Legacy run — stage timing reconstructed from events.</div>
        )}
        <div style={{ marginTop: 16 }}>
          <EventList events={tail} findingLink={e => `/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(e.finding ?? '')}?run=${encodeURIComponent(run.id)}`} />
        </div>
      </div>
    </section>
  )
}

export function RunFindingsCell({ outcome }: { outcome?: Record<string, number | null> | null }) {
  if (!outcome) return <span className="muted">—</span>
  const v = outcome.verified ?? 0
  const d = outcome.dismissed ?? 0
  const t = outcome.total ?? v + d
  if (t === 0 && v === 0) return <span className="muted">none recorded</span>
  return (
    <span>
      <Badge kind="ok" label={`${v} verified`} />{' '}
      <Badge kind="dismissed" label={`${d} dismissed`} />
    </span>
  )
}
