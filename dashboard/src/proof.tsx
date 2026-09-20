import { useEffect, useState } from 'react'
import { Copy, ArrowRight } from '@phosphor-icons/react'
import type { FindingCase, VerificationRecord } from './types'
import { fmtDurSecs, shortRun, shortSha, BASIS_LABEL, FIX_LABEL } from './format'
import { ArtifactList, ArtifactPreviewPane, Badge, CheckBadge, EventList, EvidenceCheck, SeverityBadge, Tabs, VerBadge } from './components'
import { Link } from './router'

const TABS = [
  { id: 'proof', label: 'Proof' },
  { id: 'source', label: 'Source' },
  { id: 'reproduction', label: 'Reproduction' },
  { id: 'fix', label: 'Fix' },
  { id: 'history', label: 'History' },
]

export function normalizeTab(t: string | null | undefined): string {
  if (!t) return 'proof'
  const n = t === 'repro' ? 'reproduction' : t
  return TABS.some(x => x.id === n) ? n : 'proof'
}

export function ProofPanel({ c, compact, tab, onTab }: {
  c: FindingCase; compact?: boolean
  tab?: string; onTab?: (t: string) => void
}) {
  const [intTab, setIntTab] = useState('proof')
  const active = tab != null ? normalizeTab(tab) : intTab
  const change = (t: string) => { setIntTab(t); onTab?.(t) }
  const [preview, setPreview] = useState<import('./types').ArtifactEntry | null>(null)
  const f = c.finding
  if (!f) return <div className="dstate"><div className="t">Finding record unavailable.</div></div>
  const proof = c.proof
  const basis = proof?.basis
  const ver = proof?.reproduced ? 'reproduced' : proof?.recordedVerified ? 'recorded-verified' : f.status === 'dismissed' ? 'dismissed' : 'awaiting'

  return (
    <div>
      {compact ? (
        <div className="ptitle">
          <span className="mono" style={{ fontSize: 13, color: 'var(--text-muted)' }}>{f.id}</span>
          <span>{f.title || f.vulnClass}</span>
          <SeverityBadge sev={f.severity} />
          <VerBadge v={ver} />
        </div>
      ) : (
        <div className="fmeta">
          <span className="mono">{f.id}</span>
          <span className="mono" title={`${f.file}${f.line ? `:${f.line}` : ''}`}>{f.file}{f.line ? `:${f.line}` : ''}</span>
          {f.engine && <span>{f.engine}</span>}
          {f.model && <span>{f.model}</span>}
          {f.confidence != null && <span>confidence {f.confidence.toFixed(2)}</span>}
        </div>
      )}
      <div style={{ marginTop: 12 }}>
        <Tabs tabs={TABS} active={active} onChange={change} ariaLabel={`Evidence for finding ${f.id}`} />
      </div>
      <div style={{ paddingTop: 16 }} role="tabpanel" aria-label={`${TABS.find(t => t.id === active)?.label} tab`}>
        {active === 'proof' && <ProofTab c={c} onPreview={setPreview} />}
        {active === 'source' && <SourceTab c={c} />}
        {active === 'reproduction' && <ReproTab c={c} />}
        {active === 'fix' && <FixTab c={c} />}
        {active === 'history' && <HistoryTab c={c} />}
      </div>
      {preview && <ArtifactPreviewPane artifact={preview} onClose={() => setPreview(null)} />}
      {compact && (
        <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
          <Link className="btn primary" to={`/repos/${encodeURIComponent(f.repo)}/findings/${encodeURIComponent(f.id)}${c.run?.id ? `?run=${encodeURIComponent(c.run.id)}&tab=${active}` : `?tab=${active}`}`}>
            Open full case<ArrowRight size={15} />
          </Link>
          {c.pack
            ? <a className="btn secondary" href={`/api/v1/artifacts/${c.pack.id}`}>Evidence pack</a>
            : <span className="btn secondary" aria-disabled="true" title="No evidence pack recorded" style={{ opacity: 0.55 }}>Evidence pack</span>}
        </div>
      )}
      {proof && !proof.basis && (proof.reproduced || proof.recordedVerified) && (
        <div className="note" style={{ marginTop: 12 }}>Detailed execution data unavailable for this scope — recorded before structured verification records, or not captured for this run.</div>
      )}
      {!basis && !proof?.recordedVerified && !proof?.reproduced && f.status !== 'dismissed' && (
        <div className="note" style={{ marginTop: 12 }}>No recorded execution output for this finding in this scope.</div>
      )}
    </div>
  )
}

function MetaLine({ c }: { c: FindingCase }) {
  const parts = [
    c.run?.revision ? `Revision ${shortSha(c.run.revision)}` : c.run ? 'Revision unrecorded' : null,
    c.run ? `Run ${shortRun(c.run.id)}` : null,
    c.proof?.basis?.mode ? `Mode: ${c.proof.basis.mode}` : null,
  ].filter(Boolean)
  if (parts.length === 0) return null
  return <div className="note">{parts.join(' · ')}</div>
}

function ProofTab({ c, onPreview }: {
  c: FindingCase; onPreview?: (a: import('./types').ArtifactEntry) => void
}) {
  const proof = c.proof
  const basis = proof?.basis
  // pick recorded output by artifact role + attempt identity, never by
  // guessing filenames — falls back to any stdout artifact
  const outs = (c.artifacts ?? []).filter(a => a.role === 'stdout')
  const outArt = outs.find(a => a.attempt != null && a.attempt === basis?.attempt)
    ?? outs.find(a => a.attempt == null) ?? outs[0]
  const later = proof?.laterFailures ?? []
  return (
    <div>
      {proof?.claim && <p className="claim">{proof.claim}</p>}
      <MetaLine c={c} />
      {basis && (
        <div className="kv" style={{ marginTop: 8 }}>
          {basis.script && <><span className="k">Command</span><span className="v mono">{basis.script}</span></>}
          {basis.returnCode != null && <><span className="k">Exit code</span><span className="v">{basis.returnCode}</span></>}
          {basis.mode && <><span className="k">Execution mode</span><span className="v">{basis.mode}</span></>}
        </div>
      )}
      {outArt && <OutputBlock artifactId={outArt.id} truncated={outArt.producerTruncated} />}
      {basis && !outArt && <div className="note" style={{ marginTop: 8 }}>Recorded output not available for this attempt.</div>}
      {later.length > 0 && (
        <div className="note" style={{ marginTop: 8 }}>
          Later attempt{later.length === 1 ? '' : 's'} did not reproduce ({later.map(a => a.outcome ?? 'failed').join(', ')}) — the successful observation above stands as recorded.
        </div>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 12 }}>
        {basis?.signal
          ? <EvidenceCheck ok={true} text={`${BASIS_LABEL[basis.basis ?? ''] ?? 'Recorded check'} — ${basis.signal}`} />
          : basis?.basis
            ? <EvidenceCheck ok={true} text={BASIS_LABEL[basis.basis] ?? basis.basis} />
            : <EvidenceCheck ok={null} text="No recorded signal check" />}
        {basis?.traced === true && <EvidenceCheck ok={true} text="Syscall trace confirmed" />}
        {basis?.traced === false && <EvidenceCheck ok={false} text="Trace did not confirm — outcome downgraded" />}
        {c.fix
          ? <EvidenceCheck ok={null} text={`Current remediation: ${FIX_LABEL[c.fix.verdict] ?? c.fix.verdict}${c.fix.ts ? ` (recorded separately)` : ''}`} />
          : <EvidenceCheck ok={null} text="Fix verification: not run" />}
      </div>
      <h3 style={{ margin: '20px 0 4px' }}>Artifacts</h3>
      {c.artifactsScope === 'run' && <div className="note" style={{ marginBottom: 4 }}>Evidence frozen with this run.</div>}
      {(c.artifactsScope === 'current' || c.artifactsScope === 'mixed') && (
        <div className="note" style={{ marginBottom: 4 }}>Latest recorded evidence{c.artifactsScope === 'mixed' ? ' + this run\u2019s frozen copies' : ''}.</div>
      )}
      {c.artifacts && c.artifacts.length > 0
        ? <ArtifactList artifacts={c.artifacts} onPreview={onPreview} />
        : <div className="note">No recorded artifacts for this finding in this scope.</div>}
    </div>
  )
}

function OutputBlock({ artifactId, truncated }: { artifactId: string; truncated?: boolean }) {
  const [text, setText] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [err, setErr] = useState(false)
  useEffect(() => {
    let on = true
    fetch(`/api/v1/artifacts/${artifactId}?preview=1`)
      .then(r => r.json())
      .then(b => { if (on) setText(typeof b.text === 'string' ? b.text : 'Preview unavailable.') })
      .catch(() => { if (on) setErr(true) })
    return () => { on = false }
  }, [artifactId])
  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
        <span className="note">Recorded output{truncated ? ' (truncated by producer)' : ''}</span>
        <button className="iconbtn" aria-label="Copy recorded output" title="Copy output"
          onClick={() => { if (text) navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000) }) }}>
          <Copy size={15} />{copied && <span className="note">copied</span>}
        </button>
      </div>
      <pre className="output" tabIndex={0}>{err ? 'Output preview unavailable.' : text ?? 'Loading…'}</pre>
    </div>
  )
}

function SourceTab({ c }: { c: FindingCase }) {
  const s = c.source
  if (!s || !s.available) {
    return <div className="dstate"><div className="t">Source excerpt unavailable.</div><div>{s?.reason ?? 'No recorded source for this finding.'}</div></div>
  }
  return (
    <div>
      <div className="kv">
        <span className="k">Path</span><span className="v mono">{s.path}:{s.line}</span>
        <span className="k">Revision</span><span className="v mono">{s.revision ? shortSha(s.revision) : 'unrecorded'}</span>
        {s.truncated && <><span className="k">Note</span><span className="v">Showing lines {s.from}–{s.to} (bounded excerpt)</span></>}
      </div>
      <pre className="output" style={{ marginTop: 12 }} tabIndex={0}>
        {(s.lines ?? []).map((l, i) => {
          const n = (s.from ?? 1) + i
          const mark = n === s.line
          return <div key={i} style={mark ? { background: 'var(--selected)', margin: '0 -12px', padding: '0 12px' } : undefined}>
            <span style={{ display: 'inline-block', width: '4ch', textAlign: 'right', marginRight: 12, color: 'var(--text-muted)', userSelect: 'none' }}>{n}</span>{l}
          </div>
        })}
      </pre>
    </div>
  )
}

function ReproTab({ c }: { c: FindingCase }) {
  const proof = c.proof
  if (!proof || proof.attempts.length === 0) {
    return (
      <div className="dstate">
        <div className="t">{c.finding?.status === 'verified' ? 'Verified before structured execution records existed.' : 'No recorded reproduction attempts.'}</div>
        <div>Detailed execution data is unavailable for this finding.</div>
      </div>
    )
  }
  const rc = proof.rerunContract
  return (
    <div>
      {rc && Object.keys(rc).length > 0 && (
        <>
          <h3 style={{ marginBottom: 8 }}>Rerun contract</h3>
          <pre className="output" tabIndex={0}>{Object.entries(rc).map(([k, v]) => `${k}: ${String(v)}`).join('\n')}</pre>
        </>
      )}
      <h3 style={{ margin: '16px 0 8px' }}>Recorded attempts</h3>
      <table className="data">
        <thead><tr><th>Attempt</th><th>Mode</th><th>Signal</th><th>Exit</th><th>Runtime</th><th>Outcome</th></tr></thead>
        <tbody>
          {proof.attempts.map((a: VerificationRecord, i) => (
            <tr key={i}>
              <td>{a.attempt ?? i + 1}</td>
              <td>{a.mode ?? '—'}</td>
              <td className="mono" style={{ fontSize: 12 }}>{a.signal ?? '—'}</td>
              <td className="num">{a.returnCode ?? '—'}</td>
              <td className="num">{fmtDurSecs(a.startedAt != null && a.endedAt != null ? a.endedAt - a.startedAt : null)}</td>
              <td>{a.outcome === 'verified' ? <Badge kind="ok" label="verified" /> : a.outcome ? <Badge kind="failed" label={a.outcome} /> : '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function FixTab({ c }: { c: FindingCase }) {
  const fix = c.fix
  if (!fix) {
    return <div className="dstate"><div className="t">No recorded fix attempt.</div><div>Run <code>./indict --fix {c.finding?.repo} {c.finding?.id}</code> to attempt a fix.</div></div>
  }
  const f = c.finding
  return (
    <div>
      <div className="kv">
        <span className="k">Verdict</span><span className="v"><CheckBadge outcome={fix.verdict === 'fix-verified' ? 'pass' : fix.verdict === 'fix-rejected' ? 'fail' : 'skip'} /> {FIX_LABEL[fix.verdict] ?? fix.verdict}</span>
        {fix.reason && <><span className="k">Reason</span><span className="v">{fix.reason}</span></>}
        {fix.backend && <><span className="k">Backend</span><span className="v">{fix.backend}</span></>}
        {fix.baseSha && <><span className="k">Base</span><span className="v mono">{shortSha(fix.baseSha)}</span></>}
      </div>
      {fix.checks && fix.checks.length > 0 && (
        <table className="data" style={{ marginTop: 12 }}>
          <thead><tr><th>Gate check</th><th>Result</th><th>Detail</th></tr></thead>
          <tbody>
            {fix.checks.map((ch, i) => (
              <tr key={i}><td>{ch.id}</td><td><CheckBadge outcome={ch.outcome} /></td><td className="muted">{ch.detail ?? '—'}</td></tr>
            ))}
          </tbody>
        </table>
      )}
      {fix.artifacts && fix.artifacts.length > 0 && (
        <>
          <h3 style={{ margin: '16px 0 4px' }}>Fix artifacts</h3>
          <ArtifactList artifacts={fix.artifacts} />
        </>
      )}
      {f && (
        <div style={{ marginTop: 12 }}>
          <Link className="linkbtn" to={`/repos/${encodeURIComponent(f.repo)}/fixes/${encodeURIComponent(f.id)}`}>Open fix detail<ArrowRight size={14} /></Link>
        </div>
      )}
    </div>
  )
}

function HistoryTab({ c }: { c: FindingCase }) {
  const f = c.finding
  const [allRuns, setAllRuns] = useState(false)
  const runEmpty = c.eventsScope === 'run-empty' && !allRuns
  const All = c.eventsAll ?? []
  const events = runEmpty ? [] : c.eventsScope === 'run' && !allRuns ? c.events ?? [] : All.length ? All : c.events ?? []
  return (
    <div>
      <div className="note" style={{ marginBottom: 8 }}>
        {runEmpty
          ? 'No recorded events for this finding in this run.'
          : c.eventsScope === 'run'
            ? (allRuns ? 'All-runs history (explicitly requested).' : `Recorded events for this finding in run ${c.run?.id ?? ''}.`)
            : 'Recorded events that mention this finding (all runs).'}
      </div>
      {c.eventsScope === 'run-empty' && (
        <button className="linkbtn" onClick={() => setAllRuns(true)}>Show all-runs history</button>
      )}
      {c.eventsScope === 'run' && All.length > 0 && !allRuns && (
        <button className="linkbtn" style={{ marginLeft: 12 }} onClick={() => setAllRuns(true)}>Show all runs</button>
      )}
      {(c.eventsScope === 'run' || c.eventsScope === 'run-empty') && allRuns && (
        <button className="linkbtn" style={{ marginLeft: 12 }} onClick={() => setAllRuns(false)}>Back to this run</button>
      )}
      {events.length === 0
        ? (runEmpty ? null : <div className="dstate">No recorded events for this finding.</div>)
        : <EventList events={events} />}
      {f?.poc && (
        <div className="note" style={{ marginTop: 12 }}>
          PoC directory: <code>{f.poc}</code>
        </div>
      )}
      {c.writeup && (
        <>
          <h3 style={{ margin: '16px 0 8px' }}>Writeup</h3>
          <pre className="output" style={{ maxHeight: 240 }} tabIndex={0}>{c.writeup}</pre>
        </>
      )}
      {c.related && c.related.length > 0 && (
        <>
          <h3 style={{ margin: '16px 0 8px' }}>Related records</h3>
          {c.related.map((r, i) => (
            <div key={i} className="note">{r.kind} · {r.id} {r.title ? `— ${r.title}` : ''}</div>
          ))}
        </>
      )}
      {f && <MetaTime f={f} />}
    </div>
  )
}

function MetaTime({ f }: { f: { tags?: string[]; engine?: string; model?: string } }) {
  const parts = [f.engine ? `Engine: ${f.engine}` : null, f.model ? `Model: ${f.model}` : null].filter(Boolean)
  if (parts.length === 0 && (!f.tags || f.tags.length === 0)) return null
  return (
    <div className="note" style={{ marginTop: 12 }}>
      {parts.join(' · ')}
      {f.tags && f.tags.length > 0 && <div style={{ marginTop: 4 }}>{f.tags.map(t => <Badge key={t} kind="candidate" label={t} />)}</div>}
    </div>
  )
}
