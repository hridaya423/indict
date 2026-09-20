# Dashboard implementation progress

Executing `2026-09-20-dashboard-spec.md` + `DESIGN.md`, refined by
`2026-09-20-dashboard-refinement-spec.md` (this pass supersedes the earlier
blanket "complete" claim below). Reference:
`docs/design/dashboard-concepts/04-approved-workspace.png` (1536×1024).

Status: **refinement pass landed; P0/P1 evidence and workflow fixes verified
by tests. Remaining release items listed under "Open".**

## Refinement pass — verified evidence (2026-09-20)

| Audit finding | Fix | Evidence |
| --- | --- | --- |
| E01 proof borrowed across runs | `finding_case` resolves verification records by exact run scope: frozen `runs/<rid>/evidence/<id>/poc/verification.jsonl` wins, then `run` field match, then time-window; basis is the successful attempt, later failures listed separately | `tests/test_board_records.py` delta-repo block (`[board records] PASS`) |
| E02 unknown run → latest fallback | Explicit `run=` validated; 404 `unknown-run` / `not-in-run` with `latestRun` hint; case page renders an explicit unavailable state with a latest-case link | same tests + e2e "unknown run is a real error" |
| E03 mixed frozen/current evidence | Artifacts, rerun contract and source are run-scoped; historical runs without frozen evidence report partial/unavailable instead of borrowing latest; `artifactsScope` + warnings disambiguate | tests: fixture `delta` with run-B snapshot omitting the finding |
| E04 output resolved by filename | Artifact entries carry `role`/`run`/`attempt`/`producerTruncated`; proof output picked by role (`stdout`) + attempt | type-level + artifact role mapping in `board_data.py` |
| E05 raw-JSON preview tab | `ArtifactPreviewPane` — in-workspace viewer with copy/download, truncation banner, escaped mono text, Escape/close, abort-on-switch | e2e "artifact preview stays in-workspace" |
| E06 cursor split-brain (`ts:` vs `e:`) | One server-owned opaque cursor contract: `cursor=` forward, `before=` older pages (chronological), `after=` live tail; run detail ships `eventsTailCursor`; client tracks contiguous offset windows — duplication/loss structurally impossible | tests: `before=`/page-overlap assertions; e2e ledger test |
| E07 timeline without offsets | Segments and engine lanes positioned absolutely on one shared elapsed axis (left = (start-t0)/span); unknown ends render as dashed "end unknown" gaps; skipped/pending sit outside the axis; stale runs show "Last observed", not a ticking Now | visual geometry suite passes; unit-checked via e2e render |
| E08 Hunt counts beside Verify | Progress keyed to the currently running stage (+ hunt lanes override during hunt); mismatched stage counters are dropped | fixture `theta` asserts `progress is None` while parked in `poc` |
| E09 Follow live doing nothing | Only rendered on running runs; in run detail it drives the ledger (append + autoscroll, "N new events" chip when paused) | e2e "follow live only appears on a running run" |
| E10 lost run/tab context | Tabs are URL state (`?tab=proof|source|reproduction|fix|history`, `repro` normalized); "Open full case" carries `run` + active `tab`; findings rows open the case with the row's run; return URL restores queue | e2e "finding case preserves run scope and tab in URL" |
| E11 findings without inspector | `findings-grid` 60/40 list + inspector with compact ProofPanel; filters (status/severity/class/engine/nofix/sort/size/page) all live in the URL; "No passing fix recorded" label with correct semantics; dismissed hidden by default with a note; hidden selection closes with an explanation | e2e "findings row selection opens the inspector" |
| E12 overview select/detail conflation | Row select control (radio button) + separate repo-name detail link; inventory capped at 4 rows with "View all N repositories"; findings capped at 5 with "View all N findings" | e2e bounded-inventory assertions |
| E13 active nav never styled | `Link` forwards standard anchor attributes; `aria-current="page"` survives; exactly one active item asserted | visual suite |
| E14 screenshot-only visual suite | Behavioral+visual gates: all nine routes at 1536×1024 and 1440×900, key routes at 1280×800 and 1920×1080, no horizontal overflow, geometry anchors (sidebar 200±8px, main x 216, equal lower split ±3%) | `npm run test:visual` 6/6; captures in `dashboard/shots/visual/` |
| E16 `$` on hunt budget / kv sprawl | Budget rendered as `N min hunt budget`; labeled 2-col summary grid; counts link into scoped findings filters | typecheck + e2e repo detail render |
| — | Watch registry isolation in tests: fixture root in tmp dir never reads the repo-local `watch.yaml` (registry lookup is relative to the findings root) | playwright fixture lives in `mkdtemp`; `reuseExistingServer: false` refuses foreign servers on the port |

Also: finding-id cells (`.fid`) truncate with ellipsis + full value in
`title` across all tables — fixes ID/title column overlap; lists poll only
while the tab is visible; stale runs stop elapsed at last observation;
`verdict`/`cursor` filters on Fixes moved into the URL; fix verdict copy
states that a passed local gate is not merge/deploy.

## Full verification (2026-09-20)

- `npx tsc --noEmit` clean; `npm run build` clean (JS 344.7 kB / 98.8 kB gzip).
- Vitest 5/5 (`tests/format.test.ts`).
- Playwright e2e **13/13** (`npm run test:e2e`).
- Playwright visual **6/6** (`npm run test:visual`).
- `uv run python tests/test_board_records.py` PASS (contract, security,
  torn data, read-only, exact-scope evidence, cursors, progress isolation).
- `bash tests/verify.sh`: selfcheck OK, all unit suites ok
  (paging, issues, fix, rerank, ops, sie, rank_semantic, dedup_semantic,
  board, tail, audit_fixes), calibration **5/5** hits, doctor READY.

## Open (not claimed)

- Human visual review against the approved concept + regression baselines
  from the approved render (spec §8.2 requires approval before baselining).
- Performance re-measurement on the 50-repo/10k-finding/100k-event fixture
  after these changes, and the 15-minute live-session check.
- Manual keyboard walkthrough sign-off + measured contrast report.
- Mobile/narrow refinement (deferred by decision), dark mode, write actions.
- P2 residuals: per-page title deduplication polish (E15) partially landed;
  Repositories page search/filter affordances are minimal.

## Earlier record (superseded)

The previous "complete" section claimed all gates green from the original
spec. The refinement audit found it overstated; see
`docs/design/dashboard-audit/checkpoint.md` and the refinement spec's
finding table. Historical notes: router is hand-rolled; icons
`@phosphor-icons/react`; fonts self-hosted IBM Plex; rename `crs` →
`indictment` landed mid-build.
