# Indict dashboard implementation specification

Status: ready for implementation planning. The user approved the combined light-mode image and requested a faithful multipage implementation specification. This task produces documentation only.

**Goal:** let an analyst move from repository scan progress to run history, findings, reproducible evidence, and fix results without losing context.

**Architecture:** serve a compiled React/TypeScript frontend from the existing localhost Python board. Keep filesystem evidence authoritative. Add structured scan records at the producers, and expose bounded read-only API projections from the board.

**Stack decision:** React, TypeScript, Vite, plain CSS semantic tokens, and a small client router. Use native tables, forms, and CSS for layout and progress. No Next.js server, UI dashboard template, database, websocket layer, graph library, or general state framework is required. Resolve supported package versions and official APIs when implementing, then pin the lockfile. No frontend packages currently exist in this repository.

## 1. Authority and scope

Visual authority, in descending order:

1. [Approved workspace image](../design/dashboard-concepts/04-approved-workspace.png).
2. [DESIGN.md](../../DESIGN.md), including explicit accessibility and data-correctness corrections to the image.
3. This spec's interaction and route contracts.
4. Earlier concept images, solely as secondary references for information organization.

The reference is 1536 × 1024. It is illustrative data, not a screenshot of a working product. Exact tokens in DESIGN.md are implementation decisions. Do not copy its sample repositories or shell output into production fallbacks.

The release includes Overview, Findings, full finding cases, Runs, run detail, Repositories, repository detail, Fixes, and fix detail. Evidence is part of a finding case, not a separate top-level library. Search is a persistent entry point to the Findings page with a query; do not build a second universal search product.

Preserve `./indict --board [PORT]`, default localhost port 8404, and `--out` support. Reading the board must not run scans, execute PoCs, create packs, edit findings, file issues, send alerts, start fixes, or mutate targets. Existing CLI workflows remain the execution surface. Download actions only serve existing artifacts. No fake action controls.

## 2. Current implementation and gaps

| Existing source | What can be reused | Required change |
| --- | --- | --- |
| `indictment/board.py` | localhost server, findings aggregation, path containment | static frontend assets, scoped APIs, bounded artifact access, per-repo errors |
| `indictment/board.html` | current behavior as compatibility reference | replace served UI after the new frontend passes gates |
| `indictment/events.py` | append-only run-tagged ledger and heartbeat | structured event fields and stage boundaries; retain old rows |
| `indictment/pipeline.py` | stage orchestration and run ID | record revision at start, stage execution, progress and run snapshots |
| `indictment/store.py` | Finding model, severity/status, identifiers | reuse; add run membership in separate snapshots rather than changing ID semantics |
| `indictment/state.py` | most recent finished SHA and scan time | do not use these as the active run's revision or historical snapshot |
| `indictment/poc.py`, `indictment/probes.py`, `indictment/service.py` | artifacts and reproduction mechanisms | inspect every verification path; persist structured observed results |
| `indictment/fix.py` | patch.diff, verdict.json, gate output | expose artifacts and record separate mechanical checks for new attempts |
| `indictment/pack.py` | existing pack creation via CLI | expose existing packs read-only; no GET-triggered generation |
| `indictment/watch.py` and watch registry | registered repositories and daemon activity | distinguish daemon heartbeat from run heartbeat; show registered repos without findings |
| `tests/test_board.py` | HTTP and missing/torn data coverage | extend at HTTP boundary; replace legacy HTML title assertion intentionally |

Observed traps to correct: existing state only lists directories containing findings.jsonl; events returned in state are capped at 300; PoC previews are only 200 characters; current UI labels poll time as scan time; the funnel double-counts verified records; narrative text is split into an apparent evidence chain. Preserve tolerant reads, but expose incomplete data instead of silently presenting it as complete.

`Finding.status=verified` does not by itself prove a particular signal matched: the current PoC implementation can accept sanitizer or panic output. Store the actual verification basis. The UI must never derive “signal matched” just from that status or the presence of rerun.json.

## 3. Navigation and context

| Route | Purpose | Primary interaction |
| --- | --- | --- |
| `/` | Overview | select repository, run, then finding |
| `/findings` | cross-repository triage | filter/sort findings and inspect selection |
| `/repos/:repo/findings/:id` | full case | inspect proof, source, reproduction, fix and history |
| `/runs` | current and historical scans | select run, inspect progress and exceptions |
| `/repos/:repo/runs/:run` | single run | inspect intervals, events and exact run findings |
| `/repos` | repository inventory | compare freshness, scan configuration and outcomes |
| `/repos/:repo` | repository detail | inspect latest run, scan history and findings |
| `/fixes` | recorded remediation attempts | compare mechanical verdicts |
| `/repos/:repo/fixes/:id` | latest recorded fix for a finding | inspect patch, output and gate results |

Use repository-scoped full IDs in URLs; short display IDs are presentation only. Never use ambiguous prefix matching to navigate or return evidence. Encode route segments.

Query state: `repo`, `run`, `finding`, `q`, `status`, `severity`, `sort`, `page`, and detail `tab` as applicable. Shareable URLs restore selection, filters and tab. Back/Forward restore route state and list position. A run-specific case URL carries `run`; its evidence must match that run or explicitly say unavailable.

Default Overview selection: newest active run by recorded start, otherwise newest finished run, otherwise first repository alphabetically. Within that run, select the highest-severity reproduced finding, then an awaiting-test finding, then candidate. Break ties by stable ID. Polling never overrides a user's selection. Repository change selects that repository's latest eligible run and resets incompatible finding selection.

## 4. Page contracts

### 4.1 Overview

Match the approved image's three horizontal regions and connected blue selection.

Repository panel: show four repositories at most, with repository, scanned revision, current stage, named work count and heartbeat. Prioritize selected, then active, then stale, then latest completed. A separate “View all N repositories” link prevents hidden rows from seeming absent. Aggregate active/stale/complete counts use the full current scope, with explicit “latest run per repository” semantics.

Selected-run panel: title, full-copyable revision, elapsed time, true stage timeline, three latest events, Follow live, and View full run. Follow live only controls automatic event-log scrolling; it never changes repository/run selection. New runs produce an “A newer run is available” link.

Lower section: run-scoped findings list and proof inspector. Counts derive from the selected run snapshot; show “Showing 5 of N” when limited. Selecting a row updates inspector without moving the page. Proof tab contains claim, provenance, actual recorded output, verification basis, fix state and artifacts. Source, Reproduction, Fix and History show compact real content; Open full case preserves tab and run. Missing content has a precise state, not a dummy paragraph.

Acceptance: selecting worker updates run title, revision, counts, events and finding scope together. No pane continues to show artifact-service evidence under a worker heading. Slow responses from an old selection cannot overwrite the current one.

### 4.2 Findings

Full-height working list and a persistent inspector, reusing the overview components at larger size. Header: Findings, scoped total, search, repository scope. Filters: verification status, severity, class, engine, and “No passing fix recorded”. Label that filter exactly; it is not proof that code remains exploitable today.

Columns: title with path underneath, repository, severity, verification, latest observed run. Optional class and engine appear via column controls only if needed after the core fits. Default sort: critical to info, then reproduced before adjudicated/candidate, then stable ID. Dismissed is excluded by default with visible filter state. Sorting never shuffles rows automatically while a user is inspecting one; offer Apply updates when order-changing data arrives.

Search case-insensitively across ID, title, path, repository and vulnerability class. Submit on Enter; preserve query in URL. Status counts share the repository/search scope but ignore the selected status filter. Paginate 50 rows by default; offer 25/50/100. No infinite-scroll dependency.

No bulk dismissal, assignment, or acknowledgements in this read-only release. Empty, filtered-empty, refresh-failed, partial data and missing selection states are mandatory.

### 4.3 Full finding case

Breadcrumb: Findings / repository / finding ID. Header: full title, severity, verification state, scanned revision, run link and source path. Main layout approximately 2:1 evidence/provenance at wide widths; stack below 1024px.

Tabs:

| Tab | Required content |
| --- | --- |
| Proof | claim separated from observed result; verification basis; attempts; output; artifact manifest; provenance |
| Source | read-only excerpt at recorded revision, numbered lines and highlighted finding line; full path; unavailable reason |
| Reproduction | recorded command and runtime, prerequisites, execution mode, recorded signal and output; copy; no browser execution |
| Fix | latest recorded fix verdict and link to complete fix page; separate PoC and rescan checks when available |
| History | finding events scoped to run, status transitions and optional older observations with explicit scope |

Proof records distinguish signal match, sanitizer result, panic result, traced location, and service probe. Show unknown for absent execution metadata. A model summary is labeled “Generated summary” and follows the recorded evidence. Failed attempts remain viewable. Output previews state how much is displayed and whether the producer itself truncated the file.

Artifacts: file name, byte size, type, preview/download controls. Text previews are escaped. Binary data offers download only. The evidence-pack action serves an existing pack; if absent, display “Pack not generated” and a copyable `./indict --pack <repo> <id>` command. The button must not silently generate it.

Related findings show explicit stored parent relationships when available. Legacy text references are labeled “Mentioned in narrative” and never drawn as verified exploit edges. A chain is reproduced only with the recorded chain result and parent check references.

### 4.4 Runs and run detail

Runs list: repository, run ID, revision, started time, elapsed, stage, within-stage progress, heartbeat, terminal outcome and engine health. Filters for repository, active, stale, completed, failed and degraded. A completed but degraded scan retains both labels.

Run detail: metadata header; interval timeline; named stage work counters; engine outcomes; paginated event ledger; exact run findings. Event columns are timestamp, stage, level, finding link, message. Include kill/dismissal events as ordinary inspectable records. Filter by stage, level and finding. Show log gaps or truncated history explicitly.

The actual pipeline includes ingestion, sweep, recon/hunt, consensus, adjudication, falsification, PoC verification, report and optional tail stages. Render executed stage records rather than hardcoding the five labels in the concept. Map `poc` to Verify for display while retaining the internal stage name in details. Disabled stages are Skipped with a reason, not Pending forever.

Elapsed stops at a terminal timestamp. A stale run shows elapsed to its last reliable observation with an “as of” label; never present an endlessly ticking timer as confirmed execution. No ETA without an independently validated model; none is in scope.

### 4.5 Repositories and repository detail

Inventory merges configured watch entries with discovered result directories. Resolve identity using existing watch resolution logic, not basename alone. If two targets collide under the current output naming scheme, show an identity warning rather than merging histories.

Columns: repository, watch state, latest scanned revision/time, latest run state, reproduced findings, awaiting validation and degraded/unknown checks. “Never scanned” is a first-class row. Do not infer clean from zero findings or from an unreadable directory. Configuration is read-only; show models/mode only when recorded, with unavailable values explicit.

Repository detail: latest scan summary, revision, watch information, scan history, findings and fix counts, stage/engine execution for selected run. “Compared with previous run” may show new/still-observed/not-evaluated findings only when complete compatible snapshots exist. A disappeared finding is “Not observed in this run”, not “Resolved”. Different mode, engine set or scope makes comparison partial and must be labeled.

No speculative coverage heatmap. Display file/test coverage only if the producer records a well-defined denominator and excluded scope. “Sweep-only” scans must not look equivalent to scans with model adjudication and PoC verification.

### 4.6 Fixes and fix detail

Queue columns: finding, repository, finding severity, fix verdict, backend, recorded timestamp. Tabs/filter: Gate passed, Rejected, Unverifiable, All. Detail shows original evidence reference, recorded patch, attempted revision/base if available, backend, time, gate checks, gate output, associated rescan findings and existing issue link.

Passing means the recorded local gate passed. It never means merged, deployed or currently safe. Separate checks: original exploit reproduction, patched PoC run outcome, signal absent/present, changed-code rescan result, overall gate verdict. Missing subchecks say “Not recorded”; do not reverse-engineer proof from a prose reason.

Reuse existing verdict names as wire values: `fix-verified`, `fix-rejected`, `fix-unverifiable`. Display labels are Gate passed, Rejected, Unverifiable. Preserve exact recorded reason. Current storage keeps one fix directory per finding; label it Latest recorded attempt and do not manufacture attempt history. Future attempt history requires append-only attempt identity before adding that UI.

Render a unified patch diff with line numbers and visible added/removed signs. Offer wrap and copy/download; large diffs are bounded with a full download. Link to an issue only when the recorded URL is valid. No Apply, Merge, Publish, Run fix or Send notification button.

## 5. State and trust model

Keep three axes independent: vulnerability severity, verification state, remediation verdict. Model confidence is provenance-only and never a primary sorting or trust indicator.

| Stored finding state | Display |
| --- | --- |
| candidate | Candidate |
| adjudicated | Awaiting test; explain model adjudication does not establish reproduction |
| verified with structured observed result | Reproduced, with actual basis visible |
| verified without structured observed result | Recorded verified; execution details unavailable |
| dismissed | Dismissed, with disproof/verdict |

Run state is pending, running, completed, failed or unknown. Freshness is fresh, stale or unavailable. Engine health is complete, degraded or unknown. These are separate fields: stale does not imply failed and daemon-alive does not imply scan-running. Use the existing 90-second run-heartbeat TTL as the initial backend policy; return it in metadata so UI and server do not disagree.

Never treat response `generatedAt` as scan time. Distinguish last UI refresh, last run heartbeat, run start/end and last completed scan. All wire timestamps are UTC epoch seconds; display local time with full date/time/timezone on focus or hover. Future timestamps surface clock skew and do not produce negative elapsed values.

## 6. Required records and data ownership

The scanner writes; the board reads. Keep everything under the configured findings root. Preserve existing golden state and append-only events. No migrations rewrite historical evidence.

Add structured fields compatibly to new event rows: `schemaVersion`, `kind`, `stageId`, `attempt`, `completed`, `total`, `unit`, `outcome`, and `reason` where appropriate. Existing `ts`, `run`, `stage`, `msg`, `level`, `finding` remain readable. Kinds include run-start, stage-start, stage-progress, stage-end, finding-observed, verification-result, run-end, engine-outcome. Missing fields remain absent, not zero.

Use stage attempt identity so retries and parallel workers do not overwrite each other. Completed/total must be nonnegative integers with completed <= total when a total is known. Units are explicit, such as files, candidates reviewed or candidates tested. Record totals when they become known; do not infer them from message strings. Final run outcome is authoritative only from a terminal record. Emit completion in the correct success/failure path; a best-effort telemetry write must not abort a scan.

Proposed persistent records:

| Path under each repository | Ownership and contents |
| --- | --- |
| `runs/<run>/run.json` | scanner; atomic start/terminal summary with revision captured at start, scope, engine configuration, timestamps and outcomes |
| `runs/<run>/findings.jsonl` | scanner; atomic snapshot for that run, including intermediate snapshot updates while active |
| `runs/<run>/evidence/<id>/` | scanner; preserved artifact copy for new run evidence, with manifest and verification records |
| `events.jsonl` | append-only structured and legacy events; run-scoped reads |
| existing `poc/<id>/` | existing latest evidence contract remains available for CLI compatibility |
| existing `fixes/<id>/` | existing patch/verdict evidence plus additive structured gate checks for new fixes |

Run snapshots and evidence prevent later scans from changing historical proof. Copy only files belonging to a finding attempt; do not hardlink mutable latest artifacts. A snapshot that predates historical capture remains unknown rather than borrowing the current artifact directory.

Each new verification record must contain: repo/run/finding identity, attempt, recorded revision or explicit unknown, execution mode, runtime, command arguments suitable for display, start/end, return code if available, observed basis, expected signal when relevant, actual check outcomes, output artifact IDs, trace result and producer truncation flags. Do not persist credentials in display commands; preserve placeholders and identify redactions.

Source excerpts are captured at scan time for new findings or obtained read-only from a configured local repository at the exact recorded commit. Never substitute HEAD. Do not clone or fetch to satisfy a dashboard GET. Artifact descriptors use opaque IDs, relative display names, size, type, download availability and truncation state.

## 7. Read-only API contract

Keep existing `/api/state` and `/api/finding` working during transition. New frontend uses `/api/v1/` resources; normalize legacy records server-side once. All list responses return `items`, `total`, `nextCursor`, `generatedAt`, and `warnings`. Null means unknown. Cap list limits at 100; default 50. Cursor ordering must be stable with a timestamp plus unique ID or append position, and refreshed separately from older pages.

| Endpoint | Contract |
| --- | --- |
| `GET /api/v1/overview?repo=` | bounded latest-run repository summary, aggregate scope/counts, freshness policy and warnings |
| `GET /api/v1/repos` | full registered/discovered inventory, paginated |
| `GET /api/v1/repos/:repo` | read-only configuration and latest scan metadata |
| `GET /api/v1/runs?repo=&state=&cursor=&limit=` | run summaries across repositories |
| `GET /api/v1/repos/:repo/runs/:run` | run metadata, stage intervals, progress, engine health and warnings |
| `GET /api/v1/repos/:repo/runs/:run/events?cursor=&limit=` | ordered run-scoped events, including legacy completeness marker |
| `GET /api/v1/findings?...` | filters/sort from Findings; optional exact run scope |
| `GET /api/v1/repos/:repo/findings/:id?run=` | full case, structured proof, manifests, provenance and related records |
| `GET /api/v1/fixes?repo=&verdict=&cursor=` | latest recorded fix per repository/finding |
| `GET /api/v1/repos/:repo/fixes/:id` | verdict, structured gate results and patch/output manifest |
| `GET /api/v1/artifacts/:artifactId?preview=1` | bounded escaped-text payload with metadata; default without preview downloads existing bytes |

API errors: 400 invalid scope/cursor, 404 unknown identity or unavailable artifact, 413 oversized preview request, 500 unexpected server failure. Error body has `code`, `message`, `retryable`; no local secrets or stack traces. A per-repository parse failure is a warning plus unavailable repository state, not disappearance or a global error. Skip torn JSONL tails, report malformed committed rows as incomplete data.

Security: bind localhost; allow only same-origin browser access, reject unsupported Host values and cross-origin mutations; no write routes. Resolve paths against the allowed root after symlink resolution, reject traversal and unknown artifact IDs, and revalidate opened file identity against replacement races. Serve attachments with safe filenames, correct MIME type and nosniff. Never inline executable HTML/SVG or render markdown with raw HTML. Content security policy permits bundled code/assets and same-origin API, not arbitrary script execution. Validate lengths and enums. Do not spawn a shell for preview, source or artifact resolution.

Text preview cap: 64 KiB per request, with explicit byte count and full-download link. Source cap: 200 lines centered around the finding, expandable by bounded requests if available. Event pages: 100 rows maximum. Downloads stream bytes; do not load entire packs into memory. API reads must not build packs or modify indexes on disk.

## 8. Frontend behavior and delivery

Use `dashboard/` for source; compile to `indictment/board_dist/`. The Python server serves these assets and returns index.html for recognized frontend routes; API/asset 404s never fall through to HTML. Include the compiled bundle in the chosen repository distribution so `./indict --board` works without Node at runtime. Build deterministically in verification and reject stale committed output. Preserve the CLI's read-only localhost contract.

Suggested files and ownership:

| Files | Responsibility |
| --- | --- |
| `dashboard/package.json`, lockfile, `vite.config.ts`, `tsconfig.json`, `index.html` | pinned frontend build and scripts |
| `dashboard/src/main.tsx`, `App.tsx` | router and persistent shell |
| `dashboard/src/styles/tokens.css`, `app.css` | DESIGN.md tokens and shared layout |
| `dashboard/src/api.ts`, `types.ts` | request/cancellation and explicit API contracts |
| `dashboard/src/pages/Overview.tsx`, `Findings.tsx`, `FindingCase.tsx`, `Runs.tsx`, `RunDetail.tsx`, `Repositories.tsx`, `RepositoryDetail.tsx`, `Fixes.tsx`, `FixDetail.tsx` | route composition |
| `dashboard/src/components/` | only demonstrated reuse: AppShell, FindingTable, ProofInspector, RunTimeline, StatusBadge, ArtifactList, DataState |
| `indictment/board.py`, proposed `indictment/board_data.py` | HTTP/static serving and read-only filesystem projections |
| `indictment/events.py`, `indictment/pipeline.py`, verification producers | telemetry and snapshots |
| `tests/test_board.py`, proposed `tests/test_board_records.py` | real HTTP/filesystem contract tests |
| `dashboard/tests/` | browser workflow, responsive and visual tests |

Use router state for shareable selection and filters, local state for transient UI, and one shared request owner for each live resource. No duplicate polling per panel. Poll overview/active run every 2 seconds while visible; finished history does not need continual polling. Do not overlap requests. On failure retain last good data, show staleness, and back off to 5 then 15 seconds; successful fetch resets cadence. Abort selection-dependent requests on navigation. Keep a stable DOM and focus during updates. Never replace the entire application markup on each tick.

Native table pagination is the initial performance strategy. Do not add virtualization until measurements on the defined fixture show it necessary. Timeline uses CSS grid/flex widths from recorded intervals; no charting package. A small accessible tab/menu primitive may be used if native behavior is insufficient, but do not import a visual theme that overrides the approved design.

## 9. Build sequence and checkpoints

Before each phase inspect current working changes; these files already contain unrelated local work. Load the repository's required coding/design skills. No comments in new implementation code. Keep a progress checkpoint in `docs/plans/dashboard-implementation-progress.md` with completed gates, evidence paths and next step.

1. **Fixture and shell.** Create deterministic sample records matching the reference, plus missing/stale/degraded variants. Implement tokens, fonts, shell and the Overview geometry against an isolated fixture root. Add scripts `build`, `typecheck`, `test`, `test:e2e` and `test:visual`. Render at 1536 × 1024; inspect before connecting real data. No production fallback to fixture data.
2. **Read contracts.** Add scoped projections and HTTP tests for existing/legacy data, malformed rows, unknown values, exact identity and path containment. Confirm old APIs still work. Build the new frontend request boundary.
3. **Structured producer records.** Instrument actual stage boundaries and all verification paths, capture start revision, record denominator changes and snapshots. Test with stubbed execution at existing seams in a scratch output root. Verify historical evidence survives a later scan. Don't run model hunts merely to produce UI data.
4. **Connected Overview and Findings.** Replace fixtures with real APIs, preserve query state, verify selection changes under slow responses, stable polling and keyboard interaction. Match reference screenshot with deterministic data.
5. **Cases and artifacts.** Implement each detail tab, exact-revision source, bounded previews, existing pack download and missing-record states. Verify executable content remains inert.
6. **Runs and Repositories.** Implement history, parallel/retry timelines, never-scanned inventory, degradation and watch/run freshness separation. Verify count and duration semantics.
7. **Fixes.** Implement queue, patch and independent gate results. Retain legacy missing-check states. Verify no route can execute a fix or transmit a message.
8. **Distribution and review.** Serve compiled routes through the Python board, verify `--out`, run full suite and visual matrix, review changes with code-deslop and the required structural review skill if the resulting diff is substantial. Ship only after all release gates below pass.

Do not commit unrelated working files or rewrite target clones. All scans and test-generated findings use `--out <scratch-dir>`. `findings/<repo>/` golden data is not a UI fixture workspace.

## 10. Quality bars and release gates

### Visual fidelity

Use the saved approved PNG as an immutable reference. Render deterministic fixture data at 1536 × 1024, DPR 1, browser zoom 100%, with fonts loaded and motion disabled. Save actual screenshot, 50% overlay and difference image. Inspect them yourself; automated comparison alone cannot approve generated reference text.

At reference size: sidebar width within 8px of target, main section edges within 8px, primary column split within 3 percentage points. Heading/font sizes follow DESIGN.md; do not shrink text to meet geometry. All three overview regions remain visible with the reference fixture. No overlap, clipping, accidental whitespace bands or inconsistent row padding. Within each shared component, repeated dimensions must match exactly.

The generated timeline's duration proportions are intentionally corrected. Small raster font/icon differences are acceptable; changes to hierarchy, panel order, density, blue selection treatment or light palette require explicit design review. Record every accepted deviation with screenshot evidence. Establish subsequent automated pixel baselines from the approved implemented render, not from an unreviewed first build.

Score composition, typography, spacing/alignment, color/states and cross-page consistency from 1–5 during review. Each must be at least 4, with zero blocking defects. Scores are a review aid, not a substitute for the geometry and behavior gates.

### Mandatory visual matrix

Capture Overview at 1536×1024, 1440×900, 1280×800, 1024×768, 768×1024 and 390×844. Capture all nine route types at 1440×900 and 390×844. Include loaded, initial-empty, filtered-empty, loading, refresh-failed, partial-data and stale states for their owning components. Include a long title, long path, 100-row page, large output, missing artifact and completed scan with skipped stages. At 200% browser zoom, all actions remain reachable and content reflows without page-wide horizontal clipping.

### Interaction and data correctness

- Cross-repository selection never leaks a previous repository's proof. Back/Forward, reload and direct deep links preserve context.
- Counts match scoped records; status buckets are mutually exclusive. Snapshot totals never borrow current findings for a historical run.
- Progress uses explicit units and known totals. Timeline duration sums respect concurrency, pauses and retries. Missing boundaries do not become fabricated time bars.
- Stale run, live watcher, failed run, degraded completed run and disconnected UI remain distinguishable.
- Copy copies the complete recorded value, not truncated preview text. Downloads return actual existing bytes and names.
- Every visible action works or shows an explicit unavailable reason. No dead tabs, fake search, silent placeholders or demo values in real mode.

### Accessibility

Measure rendered text contrast: at least 4.5:1 for normal text, 3:1 for large text; interactive boundaries and focus indicators at least 3:1 against adjacent backgrounds. Use a browser audit and manually verify contrast where image/status styling is involved. No unresolved serious/critical automated accessibility findings.

Keyboard path: open navigation, scope repository, select finding, change proof tab, copy output, open case, return to prior row. Focus remains visible and stable during polling. Semantic headings, table captions/headers, form labels and selected states are required. Announce important state changes politely, at most once every 5 seconds, without reading the whole event stream. Reduced motion removes movement. Status is never color-only.

### Performance and reliability

Use a documented local test machine and a synthetic scratch fixture with 50 repositories, 10,000 findings and 100,000 total events. Targets: overview API p95 <= 500ms after warm-up; filter/selection interaction p95 <= 100ms after data arrives; initial useful render <= 2 seconds on localhost; no polling work that blocks the main thread for more than 50ms. Initial JS budget <= 250 KiB gzip, excluding lazy-loaded detail/diff code and fonts. Report measured values, not estimates.

A bounded response is not enough if every request rescans all historical files. If measurements fail, add a small in-memory projection cache keyed by file metadata with invalidation for replacement/truncation; do not introduce a database or background daemon by default. No increasing request count, event duplication or memory growth across a 15-minute polling session. Slow and failed endpoints preserve usable last-known data.

### Security and regression

HTTP boundary tests cover encoded traversal, symlink escape, unknown IDs, artifact replacement, untrusted HTML/script content, oversized preview, missing/corrupt files, torn tails and exact run scope. Verify output root isolation and read-only GETs by comparing fixture file hashes before and after browser workflows. No target clone writes, shell execution from board input or remote calls from serving the dashboard.

Run existing verification with repository dependencies:

```sh
uv run python tests/test_board.py
uv run python tests/test_ops.py
uv run python tests/test_sie.py
uv run python tests/test_rank_semantic.py
uv run python tests/test_dedup_semantic.py
bash tests/verify.sh
```

Add new record tests to the suite. Frontend commands, once package scripts exist:

```sh
npm --prefix dashboard ci
npm --prefix dashboard run typecheck
npm --prefix dashboard run build
npm --prefix dashboard run test
npm --prefix dashboard run test:e2e
npm --prefix dashboard run test:visual
```

No unexplained failing required checks, console errors, missing assets or route reload failures. Report environment-dependent skipped checks and their effect; do not call them passed.

## 11. Completion evidence

Deliver the implementation with an evidence index containing build/test commands and results, reference/actual/overlay screenshots, responsive screenshots, measured contrast and performance, exercised keyboard paths, data migration/legacy behavior, and approved visual deviations. Review every page in the browser, not only Overview. A page with hardcoded production data, incomplete tabs, unreadable density or unverified evidence provenance blocks completion.

The frontend implementation is a separate next task. This specification does not claim that the dashboard, APIs, tokens, accessibility or performance targets are already implemented or verified.
