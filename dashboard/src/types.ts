export type RunState = 'pending' | 'running' | 'completed' | 'failed' | 'unknown'
export type Freshness = 'fresh' | 'stale' | 'unavailable'
export type FindingStatus = 'candidate' | 'adjudicated' | 'verified' | 'dismissed'
export type Verification = 'reproduced' | 'recorded-verified' | 'awaiting' | 'candidate' | 'dismissed'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface StageInterval {
  id: string; label: string
  startedAt: number | null; endedAt: number | null
  state: string; attempt: number; reason?: string | null; msg?: string
}
export interface StagePending { id: string; label: string; state: string; reason?: string | null }
export interface EngineLane {
  id: string; label: string; engine?: string; model?: string | null
  outcome?: string; reason?: string | null; added?: number | null
  startedAt: number | null; endedAt: number
  state: string
}
export interface Progress { completed: number | null; total: number | null; unit: string; stage?: string; msg?: string }
export interface Heartbeat {
  ts: number | null; live: boolean; done: boolean; daemon: boolean
  run?: string | null; stale: boolean; matchesRun: boolean
}
export interface RunSummary {
  id: string; state: RunState; freshness: Freshness
  startedAt: number | null; endedAt: number | null
  revision: string | null; target?: string | null
  engines?: string[] | null; models?: string[] | null
  scope?: Record<string, unknown> | null; error?: string | null
  outcome?: Record<string, number | null> | null
  currentStage: { id: string; label: string } | null
  progress: Progress | null
  stages: StageInterval[]; pendingStages: StagePending[]; lanes: EngineLane[]
  heartbeat: Heartbeat | null
  engineHealth: 'complete' | 'degraded' | 'unknown'
  findingsSource: 'snapshot' | 'latest' | 'events' | 'none'
  legacy: boolean; repo?: string
}
export interface RunDetail extends RunSummary {
  eventsTail: EventRow[]; eventsTotal: number; eventsMalformed?: number
  findingsTotal: number
}
export interface EventRow {
  ts: number; run?: string | null; stage?: string; msg?: string
  level?: string; finding?: string; kind?: string; schemaVersion?: number
  stageId?: string; outcome?: string; reason?: string
  completed?: number; total?: number; unit?: string
  engine?: string; model?: string | null; added?: number
}
export interface RepoSummary {
  name: string; registered: boolean | null; daemonAlive: boolean
  state: 'ok' | 'corrupt' | 'never-scanned'
  lastScan: { sha: string | null; ts: number | null } | null
  latestRun: RunSummary | null
  counts: Record<string, number>
  warnings: string[]
  watch?: { url?: string; models?: unknown; budget?: number } | null
}
export interface FindingRow {
  id: string; repo: string; title: string; file: string; line: number
  severity: Severity | string; status: FindingStatus; verification: Verification | string
  vulnClass: string; engine: string; model: string; confidence: number | null
  tags: string[]; verdict: string; detail?: string
  latestRun: string | null; runScope: string
  fix: { verdict: string; ts: number | null } | null
}
export interface Overview {
  generatedAt: number; warnings: string[]
  policy: { heartbeatTtlSeconds: number }
  counts: { repos: number; active: number; stale: number; complete: number; failed: number; unknown: number; neverScanned: number }
  repos: RepoSummary[]
  selected: {
    repo: string; run: RunDetail | null
    findings: { items: FindingRow[]; total: number; source: string }
    proof?: FindingCase
  } | null
}
export interface VerificationRecord {
  attempt?: number; mode?: string; script?: string; signal?: string
  lang?: string; startedAt?: number; endedAt?: number; returnCode?: number
  basis?: string | null; traced?: boolean | null; outcome?: string
  outputFile?: string; producerTruncated?: boolean
}
export interface SourceExcerpt {
  available: boolean; reason?: string; source?: string
  revision?: string | null; path?: string; line?: number
  from?: number; to?: number; lines?: string[]; truncated?: boolean
}
export interface ArtifactEntry {
  id: string; name: string; path: string; size: number | null
  type: string; previewable: boolean
}
export interface FixSummary {
  verdict: string; reason?: string; backend?: string; ts?: number | null
  checks?: GateCheck[] | null; baseSha?: string | null
  artifacts?: ArtifactEntry[]; issue?: string | null
}
export interface GateCheck { id: string; outcome: string; detail?: string }
export interface FindingCase {
  finding: (FindingRow & { poc?: string }) | null
  warnings: string[]
  writeup?: string
  run: { id: string; state: RunState; freshness: Freshness; revision: string | null } | null
  proof?: {
    claim: string | null; verdict: string; basis: VerificationRecord | null
    attempts: VerificationRecord[]; reproduced: boolean
    recordedVerified: boolean; rerunContract: Record<string, unknown> | null
  }
  events?: EventRow[]; eventsScope?: string
  artifacts?: ArtifactEntry[]
  pack?: ArtifactEntry | null
  fix?: FixSummary | null
  related?: { id: string; title: string | null; kind: string }[]
  source?: SourceExcerpt
  snapshot?: boolean
}
export interface ListResp<T> {
  items: T[]; total: number; nextCursor: string | null
  generatedAt: number; warnings: string[]
}
export interface FindingsResp extends ListResp<FindingRow> {
  page: number; pages: number
  counts: Record<string, number>
}
export interface EventsResp extends ListResp<EventRow> { legacy?: boolean }
export interface FixRow {
  findingId: string; repo: string; title: string; severity: string
  status: string; verdict: string; reason?: string; backend?: string
  ts: number | null; checks?: GateCheck[] | null
}
export interface FixDetail {
  fix: (FixSummary & {
    gate?: GateCheck[] | null; gateTs?: number | null
    rescanFindings?: Record<string, unknown>[]; latest?: boolean
  }) | null
  finding: Record<string, unknown> | null; warnings: string[]
}
export interface RepoDetail {
  repo: string; state: string; counts: Record<string, number>
  warnings: string[]; lastScan: { sha: string | null; ts: number | null } | null
  daemonAlive: boolean; latestRun: RunSummary | null
  runs: RunSummary[]
  watch: { url?: string; models?: unknown; budget?: number } | null
  fixesPassed: number; fixesTotal: number; generatedAt: number
}
export interface ArtifactPreview {
  name: string; size: number; previewable: boolean
  text?: string | null; shownBytes?: number; totalBytes?: number
  truncated?: boolean
}
