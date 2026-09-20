import { useEffect, useRef, useState } from 'react'
import {
  SquaresFour, ShieldCheck, Play, Folder, Wrench,
  MagnifyingGlass, GearSix, List,
} from '@phosphor-icons/react'
import { useRoute, Link, navigate, useRepoParam, setRepoParam } from './router'
import { apiGet, useResource } from './api'
import { subscribeUpdated, getUpdated } from './updated'
import { useSyncExternalStore } from 'react'
import type { RepoSummary } from './types'
import { Updated } from './components'
import { OverviewPage } from './pages/Overview'
import { FindingsPage } from './pages/Findings'
import { FindingCasePage } from './pages/FindingCase'
import { RunsPage } from './pages/Runs'
import { RunDetailPage } from './pages/RunDetail'
import { ReposPage } from './pages/Repos'
import { RepoDetailPage } from './pages/RepoDetail'
import { FixesPage } from './pages/Fixes'
import { FixDetailPage } from './pages/FixDetail'

const NAV = [
  { name: 'overview', to: '/', label: 'Overview', icon: SquaresFour },
  { name: 'findings', to: '/findings', label: 'Findings', icon: ShieldCheck },
  { name: 'runs', to: '/runs', label: 'Runs', icon: Play },
  { name: 'repos', to: '/repos', label: 'Repositories', icon: Folder },
  { name: 'fixes', to: '/fixes', label: 'Fixes', icon: Wrench },
]

const GROUPS: Record<string, string> = {
  overview: 'overview', findings: 'findings', finding: 'findings',
  runs: 'runs', run: 'runs', repos: 'repos', repo: 'repos',
  fixes: 'fixes', fix: 'fixes',
}

export function App() {
  const route = useRoute()
  const repo = useRepoParam()
  const [navOpen, setNavOpen] = useState(false)
  const [q, setQ] = useState(route.name === 'findings' ? (route.query.get('q') ?? '') : '')
  const repos = useResource<RepoSummary[]>('repos', loadRepos, { interval: 15000 })

  useEffect(() => { setNavOpen(false) }, [route.path])
  useEffect(() => {
    if (route.name === 'findings') setQ(route.query.get('q') ?? '')
  }, [route])

  const searchRef = useRef<HTMLInputElement>(null)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === '/' && !(e.target instanceof HTMLInputElement) && !(e.target instanceof HTMLTextAreaElement)) {
        e.preventDefault()
        searchRef.current?.focus()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const scopeable = ['overview', 'findings', 'runs', 'fixes'].includes(route.name)
  const submitSearch = () => {
    const t = q.trim()
    navigate(`/findings${t ? '?q=' + encodeURIComponent(t) : ''}`)
  }

  return (
    <div className="shell">
      <div className={`drawer-veil${navOpen ? ' show' : ''}`} onClick={() => setNavOpen(false)} />
      <aside className={`sidebar${navOpen ? ' open' : ''}`} aria-label="Primary">
        <Link to="/" className="wordmark">INDICT</Link>
        <nav className="nav">
          {NAV.map(n => (
            <Link key={n.name} to={n.to}
              aria-current={GROUPS[route.name] === n.name ? 'page' : undefined}>
              <n.icon size={18} weight={GROUPS[route.name] === n.name ? 'fill' : 'regular'} />
              <span className="lbl">{n.label}</span>
            </Link>
          ))}
        </nav>
        <span className="sp" />
        <div className="sidebar-foot">
          <span className="mode"><GearSix size={16} /><span className="lbl">Light mode</span></span>
          <span className="cap">Read-only workspace</span>
        </div>
      </aside>

      <main className="main">
        <div className="pagehead">
          <button className="iconbtn burger" aria-label="Open navigation" aria-expanded={navOpen}
            onClick={() => setNavOpen(v => !v)}><List size={22} /></button>
          <div className="titles">
            <RouteHeader />
          </div>
          <div className="headside">
            <div className="headrow">
              <form className="search" role="search" onSubmit={e => { e.preventDefault(); submitSearch() }}>
                <MagnifyingGlass size={16} />
                <input
                  ref={searchRef}
                  type="search"
                  placeholder="Search findings — id, title, file, engine"
                  aria-label="Search findings"
                  value={q}
                  onChange={e => setQ(e.target.value)}
                />
              </form>
              <UpdatedSlot />
            </div>
            {scopeable && (
              <div className="headrow" style={{ justifyContent: 'flex-end' }}>
                <label className="field-label">
                  Scope
                  <select value={repo} onChange={e => setRepoParam(e.target.value)} aria-label="Repository scope">
                    <option value="">All repositories</option>
                    {(repos.data ?? []).map(r => <option key={r.name} value={r.name}>{r.name}</option>)}
                  </select>
                </label>
              </div>
            )}
          </div>
        </div>

        <RouteSwitch />
      </main>
    </div>
  )
}

const loadRepos = (signal: AbortSignal) =>
  apiGet<{ items: RepoSummary[] }>('/api/v1/repos?limit=100', signal).then(r => r.items)

function UpdatedSlot() {
  const s = useSyncExternalStore(subscribeUpdated, getUpdated)
  return <Updated updatedAt={s.ts} stale={s.stale} />
}

function RouteHeader() {
  const route = useRoute()
  const sub: Record<string, string> = {
    overview: 'Live scans, findings, and evidence across registered repositories.',
    findings: 'Every recorded finding, with verification state and evidence.',
    runs: 'Recorded scan runs, their stages, and outcomes.',
    repos: 'Registered repositories and their scan history.',
    fixes: 'Recorded fix attempts and gate verdicts.',
  }
  const titles: Record<string, string> = {
    overview: 'Security workspace', findings: 'Findings', runs: 'Runs',
    repos: 'Repositories', fixes: 'Fixes',
    finding: `Finding ${route.params.id}`, run: `Run ${route.params.run}`,
    repo: route.params.repo ?? 'Repository', fix: `Fix ${route.params.id}`,
  }
  return (
    <>
      <h1>{titles[route.name] ?? 'INDICT'}</h1>
      {sub[route.name] && <div className="sub">{sub[route.name]}</div>}
    </>
  )
}

function RouteSwitch() {
  const route = useRoute()
  switch (route.name) {
    case 'overview': return <OverviewPage />
    case 'findings': return <FindingsPage />
    case 'finding': return <FindingCasePage repo={route.params.repo} id={route.params.id} />
    case 'runs': return <RunsPage />
    case 'run': return <RunDetailPage repo={route.params.repo} run={route.params.run} />
    case 'repos': return <ReposPage />
    case 'repo': return <RepoDetailPage repo={route.params.repo} />
    case 'fixes': return <FixesPage />
    case 'fix': return <FixDetailPage repo={route.params.repo} id={route.params.id} />
    default:
      return (
        <div className="panel"><div className="dstate">
          <div className="t">Page not found.</div>
          <Link to="/">Return to the overview.</Link>
        </div></div>
      )
  }
}
