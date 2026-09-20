import { useEffect, useRef, useState, useCallback } from 'react'
import { reportUpdated } from './updated'

export class ApiError extends Error {
  code: string
  retryable: boolean
  constructor(code: string, message: string, retryable = true) {
    super(message)
    this.code = code
    this.retryable = retryable
  }
}

export async function apiGet<T>(path: string, signal?: AbortSignal): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, { signal, headers: { Accept: 'application/json' } })
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e
    throw new ApiError('unavailable', 'Cannot reach the board', true)
  }
  let body: { error?: { code?: string; message?: string; retryable?: boolean } } | null = null
  try {
    body = await res.json()
  } catch {
    throw new ApiError('bad-response', `Non-JSON response (HTTP ${res.status})`, true)
  }
  if (!res.ok) {
    const err = body?.error
    throw new ApiError(err?.code ?? `http-${res.status}`, err?.message ?? `HTTP ${res.status}`, err?.retryable ?? res.status >= 500)
  }
  return body as T
}

export function qs(params: Record<string, string | number | undefined | null>): string {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') u.set(k, String(v))
  }
  const s = u.toString()
  return s ? `?${s}` : ''
}

export interface Resource<T> {
  data: T | null
  error: ApiError | null
  loading: boolean
  stale: boolean
  updatedAt: number | null
  reload: () => void
}

const BACKOFF = [2000, 5000, 15000]

export function useResource<T>(
  key: string,
  load: (signal: AbortSignal) => Promise<T>,
  opts: { interval?: number } = {},
): Resource<T> {
  const [state, setState] = useState<{ data: T | null; error: ApiError | null; loading: boolean; stale: boolean; updatedAt: number | null }>({
    data: null, error: null, loading: true, stale: false, updatedAt: null,
  })
  const [tick, setTick] = useState(0)
  const keyRef = useRef(key)
  const failRef = useRef(0)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const abortRef = useRef<AbortController | null>(null)

  const reload = useCallback(() => setTick(t => t + 1), [])

  useEffect(() => {
    if (keyRef.current !== key) {
      keyRef.current = key
      setState({ data: null, error: null, loading: true, stale: false, updatedAt: null })
    }
    let cancelled = false
    const run = async () => {
      abortRef.current?.abort()
      const ac = new AbortController()
      abortRef.current = ac
      try {
        const data = await load(ac.signal)
        if (cancelled || ac.signal.aborted) return
        failRef.current = 0
        setState(s => ({ ...s, data, error: null, loading: false, stale: false, updatedAt: Date.now() }))
        reportUpdated(Date.now(), false)
        schedule(opts.interval ?? 0)
      } catch (e) {
        if (cancelled || ac.signal.aborted) return
        const err = e instanceof ApiError ? e : new ApiError('unknown', String(e), true)
        setState(s => {
          reportUpdated(s.updatedAt, s.data != null)
          return { ...s, error: err, loading: false, stale: s.data != null }
        })
        const delay = err.retryable ? BACKOFF[Math.min(failRef.current++, BACKOFF.length - 1)] : 0
        schedule(delay)
      }
    }
    const schedule = (ms: number) => {
      if (timerRef.current) clearTimeout(timerRef.current)
      if (ms <= 0) return
      timerRef.current = setTimeout(() => { if (!cancelled) run() }, ms)
    }
    run()
    return () => {
      cancelled = true
      abortRef.current?.abort()
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [key, tick, load, opts.interval])

  return { ...state, reload }
}
