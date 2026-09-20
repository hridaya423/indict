import { useCallback, useEffect, useState } from 'react'
import { apiGet, useResource } from '../api'
import type { ArtifactPreview, FixDetail } from '../types'
import { Link } from '../router'
import { ArtifactList, Badge, CheckBadge, DataState, SeverityBadge } from '../components'
import { fmtFull, shortSha, CHECK_LABEL, FIX_LABEL } from '../format'

export function FixDetailPage({ repo, id }: { repo: string; id: string }) {
  const load = useCallback(
    (signal: AbortSignal) => apiGet<FixDetail>(`/api/v1/repos/${encodeURIComponent(repo)}/fixes/${encodeURIComponent(id)}`, signal),
    [repo, id],
  )
  const r = useResource<FixDetail>(`fix:${repo}:${id}`, load, { interval: 10000 })
  const d = r.data
  const fix = d?.fix
  const f = d?.finding as Record<string, unknown> | null
  const diffArt = fix?.artifacts?.find(a => a.name === 'fix.diff' || a.name.endsWith('.diff'))

  return (
    <>
      <section className="panel" aria-labelledby="fixd-h">
        <div className="panel-head" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 8 }}>
          <nav className="crumb" aria-label="Breadcrumb">
            <Link to="/fixes">Fixes</Link><span aria-hidden="true">/</span>
            <Link to={`/repos/${encodeURIComponent(repo)}`}>{repo}</Link><span aria-hidden="true">/</span>
            <span>{id}</span>
          </nav>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <h2 id="fixd-h">{(f?.title as string) || `Fix for ${id}`}</h2>
            {typeof f?.severity === 'string' && <SeverityBadge sev={f.severity} />}
            {fix && <Badge kind={fix.verdict === 'fix-verified' ? 'ok' : fix.verdict === 'fix-rejected' ? 'failed' : 'unverifiable'} label={FIX_LABEL[fix.verdict] ?? fix.verdict} />}
            {fix && fix.latest === false && <Badge kind="not-run" label="superseded" />}
          </div>
          {fix && (
            <div className="meta">
              {fix.backend ? `Backend ${fix.backend} · ` : ''}
              {fix.ts ? `Recorded ${fmtFull(fix.ts)} · ` : ''}
              {fix.baseSha ? `Base ${shortSha(fix.baseSha)}` : ''}
              {fix.reason ? ` · ${fix.reason}` : ''}
            </div>
          )}
        </div>
        <div className="panel-body">
          <DataState loading={r.loading} error={r.error} stale={r.stale} onRetry={r.reload}
            empty={!!d && !fix}
            emptyTitle="No recorded fix attempt."
            emptyHint={<div>Run <span className="cmd">./indict --fix {repo} {id}</span> to attempt one.</div>}>
            {fix && (
              <>
                {f && (
                  <div className="kv" style={{ marginBottom: 16 }}>
                    <span className="k">Finding</span>
                    <span className="v"><Link to={`/repos/${encodeURIComponent(repo)}/findings/${encodeURIComponent(id)}`}>{id}</Link>{f.file ? ` — ${String(f.file)}${f.line ? `:${String(f.line)}` : ''}` : ''}</span>
                    {f.status ? <><span className="k">Status</span><span className="v">{String(f.status)}</span></> : null}
                  </div>
                )}
                <h3 style={{ marginBottom: 8 }}>Gate checks</h3>
                {fix.gate && fix.gate.length > 0 ? (
                  <table className="data">
                    <thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead>
                    <tbody>
                      {fix.gate.map((ch, i) => (
                        <tr key={i}>
                          <td>{CHECK_LABEL[ch.id] ?? ch.id}</td>
                          <td><CheckBadge outcome={ch.outcome} /></td>
                          <td className="muted">{ch.detail ?? '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : <div className="note">No structured gate checks recorded.</div>}
                {fix.rescanFindings && fix.rescanFindings.length > 0 && (
                  <>
                    <h3 style={{ margin: '20px 0 8px' }}>Rescan findings on patched code</h3>
                    <table className="data">
                      <thead><tr><th>ID</th><th>File</th><th>Severity</th></tr></thead>
                      <tbody>
                        {fix.rescanFindings.map((rf, i) => (
                          <tr key={i}>
                            <td className="mono" style={{ fontSize: 12 }}>{String(rf.id ?? '—')}</td>
                            <td className="mono" style={{ fontSize: 12 }}>{String(rf.file ?? '—')}</td>
                            <td>{typeof rf.severity === 'string' ? <SeverityBadge sev={rf.severity} /> : '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
                {fix.artifacts && fix.artifacts.length > 0 && (
                  <>
                    <h3 style={{ margin: '20px 0 4px' }}>Artifacts</h3>
                    <ArtifactList artifacts={fix.artifacts} />
                  </>
                )}
                {d && d.warnings.map((w, i) => <div key={i} className="warn-inline" style={{ marginTop: 12 }}>{w}</div>)}
              </>
            )}
          </DataState>
        </div>
      </section>
      {diffArt && <DiffPanel artifactId={diffArt.id} />}
    </>
  )
}

function DiffPanel({ artifactId }: { artifactId: string }) {
  const [p, setP] = useState<ArtifactPreview | null>(null)
  const [err, setErr] = useState(false)
  useEffect(() => {
    let on = true
    fetch(`/api/v1/artifacts/${artifactId}?preview=1`)
      .then(r => r.json())
      .then(b => { if (on) setP(b as ArtifactPreview) })
      .catch(() => { if (on) setErr(true) })
    return () => { on = false }
  }, [artifactId])
  return (
    <section className="panel" aria-labelledby="diff-h">
      <div className="panel-head">
        <h2 id="diff-h">Patch</h2>
        {p?.truncated && <span className="meta">preview truncated at {Math.round((p.shownBytes ?? 0) / 1024)} KB — download for full diff</span>}
      </div>
      <div className="panel-body">
        {err && <div className="dstate">Patch preview unavailable.</div>}
        {!err && !p && <div className="dstate">Loading…</div>}
        {p && (
          <pre className="output diff" style={{ maxHeight: 480, padding: 0 }} tabIndex={0}>
            {(p.text ?? '').split('\n').map((l, i) => {
              const cls = l.startsWith('+') && !l.startsWith('+++') ? 'add'
                : l.startsWith('-') && !l.startsWith('---') ? 'del'
                : l.startsWith('@@') || l.startsWith('diff') || l.startsWith('index') ? 'hd' : ''
              return <div key={i} className={`dl ${cls}`}><span className="ln">{i + 1}</span>{l}</div>
            })}
          </pre>
        )}
      </div>
    </section>
  )
}
