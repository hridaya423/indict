import { useCallback, useEffect, useState } from 'react'
import { apiGet, useResource } from '../api'
import type { ArtifactEntry, ArtifactPreview, FixDetail } from '../types'
import { Link } from '../router'
import { ArtifactList, ArtifactPreviewPane, Badge, CheckBadge, DataState, SeverityBadge } from '../components'
import { fmtFull, shortSha, CHECK_LABEL, FIX_LABEL } from '../format'

const VERDICT_NOTE: Record<string, string> = {
  'fix-verified': 'Gate passed means the recorded local gate passed — it does not establish that the patch is merged, deployed, or currently applied.',
  'fix-rejected': 'Rejected means the recorded local gate failed for this attempt.',
  'fix-unverifiable': 'Unverifiable means the gate could not produce a trustworthy verdict for this attempt.',
}

export function FixDetailPage({ repo, id }: { repo: string; id: string }) {
  const load = useCallback(
    (signal: AbortSignal) => apiGet<FixDetail>(`/api/v1/repos/${encodeURIComponent(repo)}/fixes/${encodeURIComponent(id)}`, signal),
    [repo, id],
  )
  const r = useResource<FixDetail>(`fix:${repo}:${id}`, load, { interval: 10000 })
  const d = r.data
  const fix = d?.fix
  const f = d?.finding as Record<string, unknown> | null
  const [preview, setPreview] = useState<ArtifactEntry | null>(null)
  const diffArt = fix?.artifacts?.find(a => a.role === 'patch')
    ?? fix?.artifacts?.find(a => a.name === 'fix.diff' || a.name.endsWith('.diff'))

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
          {fix && <div className="note" style={{ marginTop: 6 }}>{VERDICT_NOTE[fix.verdict] ?? ''}</div>}
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
                    <ArtifactList artifacts={fix.artifacts} onPreview={setPreview} />
                  </>
                )}
                {preview && <ArtifactPreviewPane artifact={preview} onClose={() => setPreview(null)} />}
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
  const [wrap, setWrap] = useState(false)
  useEffect(() => {
    let on = true
    fetch(`/api/v1/artifacts/${artifactId}?preview=1`)
      .then(r => r.json())
      .then(b => { if (on) setP(b as ArtifactPreview) })
      .catch(() => { if (on) setErr(true) })
    return () => { on = false }
  }, [artifactId])
  // real new-file line numbers from hunks — sequential preview numbering
  // would invent positions that don't exist in the patch
  const [copied, setCopied] = useState(false)
  return (
    <section className="panel" aria-labelledby="diff-h">
      <div className="panel-head">
        <h2 id="diff-h">Patch</h2>
        {p?.truncated && <span className="meta">preview shows the first {Math.round((p.shownBytes ?? 0) / 1024)} KB — download for the full diff</span>}
        <span className="end">
          <label className="field-label">
            <input type="checkbox" checked={wrap} onChange={e => setWrap(e.target.checked)} /> Wrap lines
          </label>
          <button className="btn secondary" style={{ height: 30 }} disabled={!p}
            onClick={() => navigator.clipboard?.writeText(p?.text ?? '')
              .then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000) })}>
            {copied ? 'Copied' : 'Copy patch'}
          </button>
          <a className="btn secondary" style={{ height: 30 }} href={`/api/v1/artifacts/${artifactId}`}>Download full diff</a>
        </span>
      </div>
      <div className="panel-body">
        {err && <div className="dstate">Patch preview unavailable.</div>}
        {!err && !p && <div className="dstate">Loading…</div>}
        {p && (
          <pre className="output diff" style={{ maxHeight: 480, padding: 0, whiteSpace: wrap ? 'pre-wrap' : 'pre' }} tabIndex={0}>
            {(() => {
              let newLn = 0
              return (p.text ?? '').split('\n').map((l, i) => {
                const cls = l.startsWith('+') && !l.startsWith('+++') ? 'add'
                  : l.startsWith('-') && !l.startsWith('---') ? 'del'
                  : l.startsWith('@@') || l.startsWith('diff') || l.startsWith('index') ? 'hd' : ''
                let num = ''
                if (l.startsWith('@@')) {
                  const m = l.match(/^@@ -\d+(?:,\d+)? \+(\d+)/)
                  newLn = m ? parseInt(m[1], 10) : newLn
                  num = '…'
                } else if (cls === 'del' || cls === 'hd' || l.startsWith('---') || l.startsWith('+++')) {
                  num = ''
                } else if (newLn > 0) {
                  if (cls === 'add') { num = String(newLn); newLn += 1 }
                  else if (cls === '' && !l.startsWith('\\')) { /* context/advance */ num = String(newLn); newLn += 1 }
                }
                return <div key={i} className={`dl ${cls}`}><span className="ln">{num}</span>{l}</div>
              })
            })()}
          </pre>
        )}
      </div>
    </section>
  )
}
