import { createContext, useEffect, useSyncExternalStore, type ReactNode, type MouseEvent } from 'react'

export interface Route {
  name: string
  path: string
  params: Record<string, string>
  query: URLSearchParams
}

const routes: { name: string; re: RegExp; keys: string[] }[] = [
  { name: 'finding', re: /^\/repos\/([^/]+)\/findings\/([^/]+)$/, keys: ['repo', 'id'] },
  { name: 'run', re: /^\/repos\/([^/]+)\/runs\/([^/]+)$/, keys: ['repo', 'run'] },
  { name: 'repo', re: /^\/repos\/([^/]+)$/, keys: ['repo'] },
  { name: 'fix', re: /^\/repos\/([^/]+)\/fixes\/([^/]+)$/, keys: ['repo', 'id'] },
  { name: 'findings', re: /^\/findings$/, keys: [] },
  { name: 'runs', re: /^\/runs$/, keys: [] },
  { name: 'repos', re: /^\/repos$/, keys: [] },
  { name: 'fixes', re: /^\/fixes$/, keys: [] },
  { name: 'overview', re: /^\/$/, keys: [] },
]

function parse(pathname: string, search: string): Route {
  for (const r of routes) {
    const m = pathname.match(r.re)
    if (m) {
      const params: Record<string, string> = {}
      r.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]) })
      return { name: r.name, path: pathname, params, query: new URLSearchParams(search) }
    }
  }
  return { name: 'not-found', path: pathname, params: {}, query: new URLSearchParams(search) }
}

let current = parse(location.pathname, location.search)
const listeners = new Set<() => void>()
function emit() { for (const l of listeners) l() }

window.addEventListener('popstate', () => {
  current = parse(location.pathname, location.search)
  emit()
})

export function navigate(to: string, replace = false) {
  const url = new URL(to, location.href)
  const next = parse(url.pathname, url.search)
  if (next.path === current.path && next.query.toString() === current.query.toString()) return
  if (replace) history.replaceState(null, '', url)
  else history.pushState(null, '', url)
  current = next
  emit()
}

function subscribe(l: () => void) { listeners.add(l); return () => listeners.delete(l) }
export function useRoute(): Route {
  return useSyncExternalStore(subscribe, () => current)
}

export function useRepoParam(): string {
  const r = useRoute()
  return r.query.get('repo') ?? ''
}

export function setRepoParam(repo: string) {
  const q = new URLSearchParams(current.query)
  if (repo) q.set('repo', repo); else q.delete('repo')
  navigate(`${current.path}${q.toString() ? '?' + q.toString() : ''}`, true)
}

export function back(fallback: string) {
  if (history.length > 1) history.back()
  else navigate(fallback)
}

export function Link({ to, className, children, onClick, ...rest }: {
  to: string; className?: string; children?: ReactNode
  onClick?: (e: MouseEvent) => void
} & Record<string, unknown>) {
  return (
    <a {...rest} href={to} className={className} onClick={(e) => {
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
      e.preventDefault()
      onClick?.(e)
      navigate(to)
    }}>{children}</a>
  )
}

export const RouteCtx = createContext<Route>(current)
export function RouteProvider({ children }: { children: ReactNode }) {
  const r = useRoute()
  useEffect(() => { document.title = titleFor(r) }, [r])
  return <RouteCtx.Provider value={r}>{children}</RouteCtx.Provider>
}

function titleFor(r: Route): string {
  const names: Record<string, string> = {
    overview: 'Overview', findings: 'Findings', finding: `Finding ${r.params.id}`,
    runs: 'Runs', run: `Run ${r.params.run}`, repos: 'Repositories',
    repo: r.params.repo ?? 'Repository', fixes: 'Fixes', fix: `Fix ${r.params.id}`,
  }
  return `${names[r.name] ?? 'Not found'} — INDICT`
}
