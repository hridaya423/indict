# INDICT dashboard refinement specification

Status: implementation-ready follow-up to the current dashboard audit. Desktop only for this release, as requested. No application changes are part of this document-writing task.

## 1. Outcome and authority

Deliver a polished internal security workspace that lets an analyst inspect repository progress, follow a scan, compare findings, examine recorded PoC evidence and review a fix without losing the selected repository or run.

Keep the approved [light-mode concept](../design/dashboard-concepts/04-approved-workspace.png) and the visual tokens in [DESIGN.md](../../DESIGN.md). Keep the current INDICT name and `./indict` CLI; the older CRS wordmark in the image is not a request to undo the rename. Retain React, TypeScript, Vite and the existing Python board. This is a targeted completion and refinement pass, not another framework migration.

This specification supersedes conflicting completion claims and acceptance criteria in the [original spec](2026-09-20-dashboard-spec.md). In particular, mobile layouts, mobile navigation and touch-specific testing are deferred. Do not remove existing responsive behavior, but do not spend this release redesigning it. Supported acceptance viewports are 1280×800, 1440×900, 1536×1024 and 1920×1080 CSS pixels. Keyboard access, readable text and browser zoom remain required on desktop.

Priority definitions:

- P0: evidence or scope can mislead an analyst. Block release until corrected.
- P1: essential workflow or fidelity requirement is incomplete. Required for this release.
- P2: final consistency and polish. Required after P0/P1; not a substitute for them.

“Finished” means every requirement below has observable acceptance evidence. It does not mean every route renders or every existing test passes.

## 2. Assessment of the current implementation

The implementation has a useful foundation: light surfaces, a restrained palette, a real multipage shell, filesystem-backed APIs, source excerpts, fix records and tolerant reads. Preserve those. The current result is not yet faithful to the approved working layout, and some evidence/history behavior is unsafe to interpret as presented.

The browser audit used isolated synthetic findings at localhost:8743. The reference viewport was confirmed as 1536×1024, DPR 1 for the final overview capture. Earlier exploratory captures used other desktop sizes; do not use them for pixel matching. Source files changed concurrently during the audit. [API evidence](../design/dashboard-audit/api-evidence.json) records the tested build's behavior, a Git revision and source hashes. Reproduce each issue on the implementation branch before fixing it; do not overwrite concurrent improvements.

### Confirmed findings and required disposition

| ID | Priority | Observed behavior and source anchor | Required disposition |
| --- | --- | --- | --- |
| E01 | P0 | `board_data.finding_case` reads latest `poc/<id>/verification.jsonl` for a historical case. Adding a failed record belonging to a newer run changed the old case's basis while `reproduced` stayed true. | Resolve proof by exact repository/run/finding/attempt identity. Never borrow current proof for historical scope. |
| E02 | P0 | An unknown requested run returned the latest run. A missing snapshot finding can fall back to the current finding. | Explicit unavailable/404 response; offer a separately labeled latest-case link. |
| E03 | P0 | `finding_case` can combine frozen artifacts with current artifacts, writeup and rerun contract; `_source_excerpt` can fall back to last-scan revision. | Separate historical observation from current remediation. Match all proof/source artifacts to the selected run or mark unavailable. |
| E04 | P1 | `ProofTab` looks only for `poc-output.txt`, while the fixture provides `output.txt`; proof output is absent despite an available output file. | Resolve output by artifact role recorded in the API. |
| E05 | P1 | Artifact Preview opens the JSON preview API in another tab. | Readable in-workspace preview with copy/download and truncation states. |
| E06 | P1 | `RunDetail` sends `ts:` cursors, while `run_events` consumes `e:` cursors. Load more appended all 43 events after the latest three, duplicating the tail. Polling also clears loaded events. | One server-owned cursor contract; stable chronological history without duplication or disappearing pages. |
| E07 | P1 | Timeline segments use widths without start offsets; engine lanes extend from zero to their end. Legacy events synthesize apparent completed durations. | Shared elapsed axis with actual starts/ends; unknown timing stays unknown. |
| E08 | P1 | Overview displayed Verify beside the completed Hunt counter “3 / 3 batches”. | Progress belongs to the active stage and attempt; absent progress is not inherited. |
| E09 | P1 | Follow live only changes switch state; no scrolling behavior consumes it. | Wire it to following the visible event tail or remove it where no scrolling tail exists. |
| E10 | P1 | `ProofPanel` full-case link drops run and tab. `?tab=source` still opens Proof. Filters commonly use replaceState or local state. | Preserve exact context in URLs, browser history and return links. |
| E11 | P1 | Findings is a full-width table without the specified inspector. No fix attempt differs from No passing fix recorded. | Restore triage list/inspector and precise filter semantics. |
| E12 | P1 | Overview repository links navigate away instead of selecting the connected workspace. Unbounded inventory and engine lanes push evidence below the fold. | Distinct select/detail actions and bounded overview content. |
| E13 | P1 | Sidebar active styling never appears because `Link` drops `aria-current`. Browser DOM contained zero current navigation links. | Preserve standard anchor attributes and show a single active section. |
| E14 | P1 | `visual.spec.ts` captures only five routes and makes no visual assertions. The completion checkpoint calls all gates green. | Replace screenshot-only passes with behavioral and visual gates covering all nine routes. |
| E15 | P2 | Detail pages repeat generic ID headings and title sections, while case content stretches across the page with little hierarchy. | One useful page title, compact provenance and purpose-specific detail layouts. |
| E16 | P2 | Repo detail spreads values over an eight-column key/value grid; Fixes shows Pass instead of the clearer Gate passed. | Consistent labeled summaries, exact units and distinct domain states. |

The audit's TypeScript check, five Vitest tests and `tests/test_board_records.py` passed. Those results do not invalidate the reproduced failures. No new full security audit, performance benchmark or cross-browser certification is claimed here.

### Measured overview gap

With the populated alpha fixture at 1536×1024, the repository panel began at y=112 and was about 297px tall. The run panel began at y=425 and was 324px tall. The findings/proof section began at y=765, compared with approximately y=586 in the approved concept. The proof panel extended beyond the viewport. These values vary with data; their purpose is to expose uncontrolled density, not impose fixed heights on arbitrary content.

See [current overview](../design/dashboard-audit/overview-desktop.png), [Findings](../design/dashboard-audit/findings-desktop.png), [run detail](../design/dashboard-audit/run-detail-desktop.png), [repository detail](../design/dashboard-audit/repository-detail-desktop.png) and [fix detail](../design/dashboard-audit/fix-detail-desktop.png).

## 3. Shared desktop experience

### 3.1 Shell and navigation

Keep a 200px sidebar at 1440px and above and a 176px sidebar at 1280px. Keep labels visible throughout the supported desktop range. Main gutters and section gaps are 16px. Use the established 30px page title, 18px section heading, 14px body and 12px technical metadata. Do not shrink text to fit more data.

Every route has one page title that identifies the work: Findings, Runs, repository name, finding title or fix title. Detail breadcrumbs precede the title. Full IDs, revisions and engine provenance sit below it. Remove duplicated page titles inside the first panel when they add no context.

The active navigation item has the reference's blue text/icon and pale blue fill. Detail routes activate their parent section. Native link behavior, modifier-click, accessible names, title and ARIA attributes survive the router component. Fix the existing Link boundary rather than painting active states separately in each page.

Search remains “Search findings” everywhere and preserves repository scope unless the analyst explicitly clears it. A scope control must mean the same thing across pages. If Overview keeps a global inventory while selecting a repository, label its control “Selected repository”, not “Scope”; label counts “All repositories”. Else apply scope to inventory and counts consistently. Adopt the first option for Overview, and actual filtering scope on list pages.

### 3.2 State in URLs

Use repository, run, finding and tab identity in every evidence link. Findings filters, sort, page size and page/cursor must survive refresh and Back. Runs/Fixes filters receive the same treatment. Use history push for deliberate context changes; replace only for normalization or transient text while typing. Submitting search creates a navigable history entry.

Opening a case from a list stores a return URL and restores filters, selected row and scroll when returning. Direct deep links work without prior navigation. Tabs use stable values `proof`, `source`, `reproduction`, `fix`, `history`. Normalize old `repro` links if already used. Invalid tab values select Proof without changing evidence scope.

Selection and loading state have the same resource key. While a new finding loads, clear the previous proof or retain it only under its previous visible identity with an explicit loading overlay. Never show old evidence below a new title. Abort obsolete requests and ignore late responses.

### 3.3 Refresh and failures

One request owner polls each live resource; panels reuse it. Pause polling when the document is hidden and refresh on return. Stop continuous polling for immutable finished-run details. Keep bounded backoff and last-good data, but show errors at the resource that failed. An unrelated successful repository-list request must not reset the current case's stale indicator.

Polling preserves focus, selection, loaded history and scroll. Order-changing results show “N updates available” while an analyst is inspecting the queue. Apply them on request. Provide visible last-successful-fetch time, separate from run heartbeat and scan timestamps.

Every panel covers initial loading, empty data, filtered empty, partial data, unavailable evidence and failed retrieval. Distinguish “No events recorded” from “Could not load events”. Unknown is never silently converted to zero, passed or completed.

## 4. Page specifications

### 4.1 Overview: connected operational workspace

Preserve the approved three-tier composition. With the reference fixture, repository panel y≈102–352, run panel y≈368–570, and findings/proof y≈586 onward; section-edge tolerance is 8px once fonts are loaded. Use actual content and documented row limits to meet these targets, not clipping.

Repository inventory shows up to four rows, selected row first when it would otherwise be hidden, with “View all N repositories”. Counts are mutually exclusive for their stated summary: fresh active, stale outcome unknown, completed, failed. A stale running record must not inflate both active and stale summary counts. An unavailable or never-scanned target remains discoverable in Repositories and in a compact overview exception link.

Clicking a row's selection control updates the run, finding list and proof together. A separate repository-name detail link opens its repository page. Keyboard users can perform both actions. Blue selection is visible and programmatic.

The run band contains name/ID, revision, freshness, elapsed, one compact stage timeline and three latest event rows. Engine lane detail belongs on the run page, behind an explicit disclosure on Overview if needed. Do not permanently add one overview row per engine. Completed runs have no meaningless Follow live control.

The lower region uses equal-width findings and proof panes at 1536px. Show at most five finding rows and a total-aware View all link. Place filter controls in one compact toolbar rather than spending another large header row. Selected finding title gets two lines at most here, with full title in the case page. Put long paths beneath titles at 1280px instead of wrapping narrow path columns into many lines.

Proof preview shows claim, provenance, 6–8 lines of actual recorded output when available, actual verification basis and fix state. Show at most three primary artifacts with View all. Open full case retains run/tab. Proof footer should remain visible with the approved fixture at 1536×1024. At 1280×800, normal document scrolling is acceptable; do not hide content to claim above-fold parity.

### 4.2 Findings: working triage queue

Use approximately 60% list and 40% inspector at wide desktop sizes; allow a user-resizable divider only if the fixed layout fails real content testing. Default fixed split is sufficient. At 1280px retain both with compact columns and wrapped titles.

Columns: finding title/path, repository, severity, verification. Full ID is available on selection/copy and may be a compact secondary field. Class, engine and latest observed run are filterable and visible in inspector provenance. Avoid redundant metadata columns that squeeze the title.

Filters: status, severity, repository, vulnerability class, engine and “No passing fix recorded”. That last filter includes no attempt, rejected and unverifiable attempts; it excludes only a matching passing gate. Keep a separate “No fix attempt” filter only if desired, with distinct semantics. Default excludes Dismissed and visibly says so. All status pills have clear selected state and correctly scoped counts. Reproduced must not imply that legacy recorded-verified evidence has structured proof; expose the distinction in the pill or its breakdown.

Search covers title, full ID, path, repository and class. Sort by severity, verification, then stable identity by default. Page sizes 25/50/100. Counts describe the active filter scope; pagination never leaves a blank page after scope change. Show latest observed run explicitly where available, not invented recency from file order.

Selecting a row opens the persistent ProofPanel. Opening a full case and returning restores the queue. The inspector supports all five case tabs in compact form. A filter that hides selection closes it with an explanation; it must not leave disconnected proof on screen.

### 4.3 Finding case: evidence-first investigation

Use one full finding title, severity and verification, then repository/revision/run/path. Wide layout: evidence approximately two thirds, provenance and artifacts one third. Keep source/output width useful. Tabs may switch the main evidence area while provenance remains visible.

Proof: explicit claim, actual observed result, successful attempt if one exists, failed attempts accessible, output, trace status and verification basis. Separate generated narrative and unverified model claims from mechanically recorded observations. Show sanitizer, panic, signal match or service-probe basis accurately. A recorded signal string alone is not a matched check.

Source: exact captured revision and path, numbered excerpt, highlighted relevant line, wrap toggle and copy. Missing source at that revision shows a precise unavailable state. Never fetch another revision as if it were the same observation.

Reproduction: recorded runtime, execution mode, command, prerequisites, attempt chronology, actual return outcome, signal/assertion and linked output. Copy preserves the full recorded command. Execution is not available in the browser. Host/service/sandbox modes must be explicit; do not apply a generic sandbox label.

Fix: latest matching fix summary, gate checks and link to fix detail. If it is newer than the selected historical observation, label “Current remediation” with its own revision/time rather than mixing it into historical proof.

History: status transitions and finding events for the selected run by default. All-runs is an explicit alternate scope. Keep run links and exact timestamps. Do not fall back to all-runs events invisibly when the requested run has none.

Related findings distinguish verified parent/chain relationships from narrative mentions. Only draw a chain when structured relationships and the chain result exist. Do not add a decorative attack graph.

### 4.4 Runs list

Make this an operating view: repository, run/revision, stage, within-stage work, freshness, elapsed, outcome and engine health. Keep full timestamps on demand and concise timestamps in rows. Labels distinguish run Completed from Engines complete; avoid two adjacent badges both reading Complete.

Filters: repository, fresh active, stale, completed, failed, degraded and unknown. State and freshness remain independently represented. Clicking a run opens run detail. A selected preview is optional only after the required columns and filters work; do not add another inspector for symmetry.

Expose skipped/degraded checks and the recorded scan mode. A sweep-only completion must not imply PoC verification ran. Do not display an ETA unless its measured basis is available and its uncertainty is named; no ETA is required by this release.

### 4.5 Run detail

Header shows run identity, recorded start revision, scope/mode, start/end, health and last reliable observation. Timeline uses run start as origin and terminal time or reliable observation as end. Unknown intervals remain gaps; missing boundaries produce an event list, not fabricated durations.

Stage positions: `left = (start - origin) / span`; widths: `(end - start) / span`. Concurrent workers occupy separate lanes using their actual starts. Tiny stages receive an accessible marker/tooltip without falsifying duration width. Skipped and pending stages are outside the elapsed axis and labeled distinctly. A stale run has a “Last observed” marker, not a ticking Now implying confirmed work.

Event ledger includes timestamp, stage, outcome/level, message and finding link. Filter by stage, level and finding. Server returns an opaque cursor and stable event identity/position. The client never manufactures a cursor. Older pages prepend or append according to a declared order, with deduplication and scroll anchoring. Follow live controls following new events only; new events while paused show a counter.

All recorded findings are reachable through pagination. Header totals and visible rows agree or state “Showing X of Y; Dismissed hidden”. The fixture's four findings must not silently appear as three under an unqualified total of four.

### 4.6 Repositories list

Inventory shows watch registration, last completed scan, scanned revision, current run state/freshness, reproduced/awaiting counts and unavailable/skipped checks. Avoid combining dismissed and reproduced into one unexplained Findings number. Unknown counts render an em dash with explanation, not zero.

Never-scanned targets remain explicit and can open detail. Distinguish no completed scan from no scan ever: a currently running first scan is not simply “never”. Identity collisions, unreadable data and missing watch resolution are warnings rather than silent merges.

Provide repository search, status filters and bounded pagination. Keep the selection model consistent with scope elsewhere. Read-only watch configuration is visible; no configuration editor is required.

### 4.7 Repository detail

One repository title and compact metadata. Present latest scan/run, recorded revision, watch mode, models and last reliable heartbeat. Show grouped finding counts as linked filters into Findings, plus fix gate summary. Use a small labeled grid with sensible column widths, not alternating labels/values stretched across the full page.

Below it, run history with complete pagination and current/historical context; a findings section scoped to the selected run; read-only watch information and engine outcomes. Clarify budget units from the producer: do not prefix a hunt duration with a currency symbol. Absent units are unavailable until resolved.

Comparison is permitted only for compatible snapshots. Use New, Still observed, Not observed and Not evaluated. Not observed is not Resolved. Different scope/mode/engine sets make the comparison partial. Do not build a global risk score or coverage heatmap without supporting records.

### 4.8 Fixes list

Queue labels use Gate passed, Rejected and Unverifiable. Pass/Fail belongs to individual checks. Columns: finding/title, repository, severity, overall verdict, backend, time. Move verbose individual-check explanations to detail so rows remain scannable.

Filters and pagination live in the URL. The default queue is latest recorded attempt per finding, clearly labeled. No invented attempt history. Show No attempts separately from No results for these filters. Links connect to both the finding observation and fix detail with correct scope.

### 4.9 Fix detail

Header: finding title, fix verdict, backend, timestamp, base/patched revisions where recorded. A short explanation states that a local gate passing does not establish merge or deployment.

Main view pairs the patch with gate evidence. Show independently recorded patch-produced, patched reproduction outcome, signal present/absent, environment validity and diff rescan checks. Missing details say Not recorded. An absent signal caused by broken execution is not a passing remediation result.

Patch uses actual old/new line numbers parsed from hunks, clear added/removed markers, wrap toggle, copy and full download. Current sequential preview row numbers are not source line numbers. Large patches remain bounded with a clear truncation notice. Link gate output, rescan findings, original proof and any recorded issue URL. Keep current fix identity separate from a historical finding's run.

## 5. Evidence contract and API corrections

Introduce one cohesive case-evidence resolver used by list verification labels, case detail, proof previews and artifact manifests. Its input is exact repository, run, finding and optional attempt; its result names provenance and completeness. This removes independent fallbacks scattered across `_ver_display`, `finding_case` and `_source_excerpt`.

For an explicit run:

1. Validate the run exists. Unknown run is 404, not latest.
2. Read its finding snapshot. A finding absent from that snapshot is absent in that run; current data can be offered through a separate link.
3. Read immutable verification/attempt/source/artifact records captured for that run.
4. If historical records are incomplete, return partial/unavailable with known facts retained. Do not infer missing proof from latest records.
5. Return current remediation separately, identified as current and with its own provenance.

A successful reproduction label requires a matching recorded successful verification result, not simply `verified` status plus a nonempty verification file. Preserve legacy status as Recorded verified when structured proof is unavailable. Later failed attempts must not erase an earlier successful observation; present the selected successful attempt and subsequent failures distinctly. A contradictory record is visible and never silently coerced to success.

Artifact metadata includes stable ID, display name, role (`stdout`, `stderr`, `script`, `verification`, `source`, `patch`, `pack`, `other`), attempt/run identity, size/type, producer-truncated flag and preview-truncated flag. The UI chooses output by role. Legacy role inference is a server-side compatibility mapping with explicit uncertainty, not filename guesses in JSX.

Keep existing immutable run evidence layout. Capture verification and rerun contracts with the run, not only source. Do not rewrite golden files to backfill missing history. Current records are allowed only when the request explicitly asks for latest and their relationship to that run is known.

Progress is keyed by run/stage/attempt and unit. The latest global stage-progress row is insufficient. Returning Verify with Hunt counts is invalid. Unknown denominator shows elapsed/stage label only. Reject negative counters and impossible totals; don't clamp malformed values into apparently valid success.

Preserve localhost binding, read-only GETs, output-root containment, escaped evidence and safe attachment downloads. Add regression coverage at these boundaries when changing the resolver. This pass does not authorize PoC execution, issue filing, alert transmission or repository mutation from the board.

## 6. Artifact viewing, accessibility and polish

Preview opens a right-side drawer or an inline viewer in the case, not raw JSON. Title shows filename, role, run and byte count. Text is escaped, selectable and monospaced; binary files offer download. Copy is explicitly “Copy displayed excerpt” when truncated, with a separate full-file action. Do not claim a clipped preview is the complete output.

Handle preview loading, 404, unreadable content, unsupported type and copy failure. Reset preview/error state on artifact change and cancel obsolete requests. Use the shared API error handling rather than ad hoc unchecked fetches. Keep primary actions visible and unavailable actions explained in normal text, not only inaccessible tooltips.

Desktop keyboard path: sidebar → scope/filter → selected row → tabs → preview → close → return to row. Tabs have associated tabpanels. Drawers/dialogs receive focus, trap it appropriately, close on Escape and restore focus. Selection does not add duplicate focus stops for a row and every nested link. Provide full values for truncated IDs and paths through focusable copy/details controls.

Measure normal text contrast >=4.5:1 and interactive/focus boundaries >=3:1. Status always has text. No pulsing dots, animated table insertion or motion during keyboard selection. Retain reduced-motion support. Live announcements are limited to important updates and do not reread the whole proof pane on each poll.

Polish pass: align titles and numeric columns, standardize row heights and badges, remove repeated headings, use exact domain labels and units, replace unexplained dashes with contextual unavailable states, and keep one filled action per working pane. No new decorative charts or animations are needed.

## 7. Implementation work packages

Preserve existing work. Source changed during the audit, so first rebase the checklist on the current implementation without resetting files. Work in these bounded packages, each with its own verification evidence:

| Package | Main files | Exit condition |
| --- | --- | --- |
| A. Evidence integrity | `indictment/board_data.py`, existing run/evidence producers, `tests/test_board_records.py` | E01–E03 reproduced before fix; exact-scope tests pass afterward |
| B. Context and request ownership | `dashboard/src/router.tsx`, `api.ts`, `updated.ts`, `App.tsx`, route links | Back/reload/deep-link preserve scope and tab; stale/late responses cannot mislabel proof |
| C. Progress and ledger | `components.tsx` Timeline, `runview.tsx`, `RunDetail.tsx`, API event/progress projections | actual time positions, stage-specific counts, stable cursor pages and functional Follow live |
| D. Proof and previews | `proof.tsx`, ArtifactList, API artifact descriptors | output visible; preview never opens JSON; role/attempt/provenance and truncation shown |
| E. Overview and triage fidelity | `Overview.tsx`, `Findings.tsx`, shared table/inspector, CSS | reference composition restored; inspector and bounded rows work |
| F. Remaining desktop pages | Runs, RunDetail, Repos, RepoDetail, Fixes, FixDetail | all page contracts and long-content states reviewed |
| G. Release evidence | frontend tests, fixtures, progress/evidence index | all acceptance gates below pass, with honest reported limits |

Keep modules organized around demonstrated responsibilities. `board_data.py` exceeded 1,000 lines during review and combines inventory, timeline inference, evidence resolution and artifact handling. Extract the exact-scope evidence resolver as a real invariant owner; separate artifact resolution only if it reduces duplicated trust checks. Do not distribute every helper into a new file. Likewise, extract a Timeline or ArtifactViewer component when it owns these behaviors, not to satisfy arbitrary file counts.

Keep native tables and CSS for timelines. No framework migration, generic state bus, websocket rewrite, new database or dashboard template is justified by these findings. A router/library replacement is optional only if fixing existing link/history semantics would otherwise require more complexity.

## 8. Acceptance tests and quality bars

### 8.1 Evidence and state tests

Required fixtures include two runs of the same finding with different revisions, outputs and outcomes; a missing historical snapshot; a failed latest attempt after a successful older one; a signal string without a matched check; sanitizer-based verification; unknown run; stale active run; skipped stage; parallel engines; zero/unknown totals; missing/binary/truncated artifacts; rejected and unverifiable fixes.

Required assertions:

- Requesting run A after run B writes new evidence still returns A's proof and artifacts, or explicit unavailable data.
- Unknown run returns 404. A finding absent from a snapshot does not appear through latest fallback.
- A failed record from run B cannot make run A appear reproduced or supply its basis.
- A Verify stage never shows Hunt progress. Pending, skipped and unknown remain distinct.
- Loading every event page yields exactly the recorded number of unique ordered events; polling does not erase earlier pages.
- A stale run stops its confirmed elapsed time at last observation and cannot appear fresh because the watch daemon is alive.
- Full-case links and tabs preserve run. Back restores list state. Old request completion cannot overwrite new selection.
- Filtering to No passing fix recorded includes rejected/unverifiable attempts and excludes only matching passing records.
- Artifact preview displays escaped content, actual filename and truncation; missing artifacts produce a useful error rather than an empty successful pane.

### 8.2 Visual fidelity tests

Create a reference fixture matching the approved image's content length and density: four repository rows, five findings, populated PoC output and three primary artifacts. Keep adversarial/legacy fixtures separate. Freeze time and isolate the watch registry so the user's local watch.yaml does not change screenshot inventory. The current fixture unexpectedly includes machine-local watch entries; eliminate that dependency in tests.

At 1536×1024/DPR 1/100% zoom, load bundled fonts before capture. Save reference, actual, overlay and diff. Required anchors: sidebar 200px ±8px, main left x=216 ±8px, 16px section gaps, lower split within 3 percentage points of equal. Match section positions within 8px using the reference fixture. Correct interval geometry and accessible text are permitted deviations, documented with rationale.

Human inspection must confirm the repository → run → finding → proof relationship is immediately visible; the evidence pane contains recorded output and reachable primary action; long titles do not overwhelm badges; selected navigation and rows are unmistakable. No clipped controls, unexpected whitespace bands, overlapping text or unreadably narrow metadata columns.

Establish regression baselines only after the first corrected render is visually approved. Screenshot generation alone is not a passing test. Add assertions for visible key content, counts, selection, absence of page-wide overflow and comparison against the approved implementation baseline. Mask only volatile timestamps, never entire broken panels.

Capture all nine routes at 1440×900 and 1536×1024. Exercise Overview, Findings and full case at 1280×800 and 1920×1080 too. Include long-path, long-title, empty, filtered-empty, stale, partial and failed-request states. Mobile screenshots are not a release gate.

### 8.3 Reliability, accessibility and performance

Run TypeScript, meaningful component/contract tests, browser journeys and the existing board/ops/semantic suites. Add assertions for active sidebar semantics and correct tabpanel relationships. No console errors, invalid DOM nesting or failed expected asset/API requests on tested paths. Manual keyboard walkthrough is mandatory.

Preserve the original performance targets and measure them on a documented fixture and machine: overview API p95 <=500ms after warm-up for 50 repositories/10,000 findings/100,000 events; selection response <=100ms after data arrival; no polling-induced main-thread task >50ms. Measure a 15-minute live session for duplicated requests, disappearing history and growing memory. Report actual values and any unmet target; don't reuse old measurements after relevant changes.

Tests must start a fresh known fixture server or verify the running server's fixture/build identity. Do not use unconditional `reuseExistingServer: true` to accept whichever service is on the port. Verify the compiled served bundle corresponds to reviewed source. Keep Node unnecessary for the user running `./indict --board`.

### 8.4 Release decision

All P0 and P1 findings must be closed with a reproduction test and evidence. P2 visual review must pass all desktop page contracts. Do not mark completion from route count or test count alone. The release evidence index contains:

1. Source revision, built asset identity and fixture identity.
2. Requirement IDs mapped to tests or inspected screenshots.
3. Reference overlays and all nine page captures.
4. Exact command results, keyboard audit, contrast and performance measurements.
5. Explicit remaining limitations and any approved visual deviations.

Update `dashboard-implementation-progress.md` only with verified outcomes. Supersede its earlier blanket completion claim once the new evidence is available. Historical audit screenshots remain evidence, not new design references.

## 9. Definition of done

An analyst can select a repository, understand its actual scan progress, open a finding with the correct run's PoC, preview/copy/download evidence, inspect its source and fix gate, then return to the same queue. The desktop workspace matches the approved light composition, all nine pages use the same visual system, and no success state rests on guessed or borrowed evidence.

Mobile refinement, write actions, dark mode, new charts, assignment workflows and a separate evidence-library product are outside this pass.
