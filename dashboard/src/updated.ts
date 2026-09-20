type Listener = () => void
const listeners = new Set<Listener>()
let state = { ts: null as number | null, stale: false }

export function reportUpdated(ts: number | null, stale: boolean) {
  state = { ts, stale }
  listeners.forEach(l => l())
}
export function subscribeUpdated(l: Listener): () => void {
  listeners.add(l)
  return () => { listeners.delete(l) }
}
export function getUpdated() { return state }
