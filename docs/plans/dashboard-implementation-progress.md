# Dashboard implementation progress

Executing `2026-09-20-dashboard-spec.md` + `DESIGN.md`. Reference:
`docs/design/dashboard-concepts/04-approved-workspace.png` (1536×1024).

Status: **complete** — all nine routes live, all release gates green.

## Gates

| Step | Status | Evidence |
| --- | --- | --- |
| 1. Fixture + shell | done | `tests/fixture_board.py` (normal/live/stale/corrupt/never-scanned/degraded + `--big`); Playwright projects `e2e` + `visual` in `dashboard/playwright.config.ts` |
| 2. Read contracts (/api/v1) | done | `indictment/board_data.py` projections + `indictment/board.py` routes; `tests/test_board_records.py` PASS (contract, error envelope, traversal, torn JSONL, read-only) |
| 3. Structured producer records | done | `events.py` (stage-start/end, engine-outcome, verification-result), `pipeline.py` (run.json, stage boundaries, run snapshot, frozen source), `poc.py` (verification.jsonl), `fix.py` (verdict.json + gate.json) |
| 4. Connected Overview + Findings | done | e2e tests 1–3; repo scans, selected run panel, findings table, inspector |
| 5. Cases and artifacts | done | FindingCase with proof/evidence/fix/issue tabs; artifact preview + download with post-open identity revalidation |
| 6. Runs and Repositories | done | e2e tests 4–5; timelines, engine lanes, event ledger |
| 7. Fixes | done | e2e test 6; verdict + gate checks |
| 8. Distribution + review | done | `indictment/board_dist/` built (JS 342KB / 98KB gzip, CSS 17KB / 4.3KB gzip); `./indict --board` serves SPA + legacy `/api/state`; Node not needed at runtime |

## Verification evidence

- `npx tsc --noEmit` clean; `npm run build` clean.
- Vitest: 5/5 (`tests/format.test.ts`).
- Playwright e2e: **8/8** across all routes incl. keyboard nav + deep-link reload.
- Playwright visual: **5/5** viewport passes (1536×1024, 1280×900, 1100×900 rail, 820×1100, 390×844) — 25 screenshots in `dashboard/shots/visual/`.
- `bash tests/verify.sh`: selfcheck OK, all unit suites ok (paging, issues, fix, rerank, ops, sie, rank_semantic, dedup_semantic, board, tail), calibration **5/5** hits, doctor READY.
- Perf: `/api/v1/overview` p95 = 19ms real data, **62ms** on `--big` fixture (50 repos / 10k findings) vs 500ms target.

## Decisions

- Router: small hand-rolled history router (no react-router) — keeps JS
  budget and matches spec's "small client router".
- Icons: `@phosphor-icons/react` (DESIGN.md's named fallback; no icon
  family installed).
- Fonts: `@fontsource/ibm-plex-sans` 400/500/600 + `@fontsource/ibm-plex-mono`
  400 — self-hosted woff2 via the bundle, `font-display: swap`. Latin
  subsets only to keep generated asset volume down.
- Run records: `runs/<run>/run.json` + `runs/<run>/findings.jsonl` written
  by pipeline; `poc/<id>/verification.jsonl` per attempt; `fixes/<id>/gate.json`
  structured checks. Legacy data without these records reads as
  unknown/unavailable, never fabricated.
- Vite `base: '/'` — relative base broke asset URLs on deep-route reloads.
- Legacy `/api/state` + `/api/finding` retained for the old board path.
- Package rename `crs` → `indictment`, CLI `scan` → `indict` landed
  mid-build; all dashboard + backend files follow the new names.
- `watch.py` alert kinds are now honest (`new-{status}` → `new-candidate`
  is a real kind); `test_ops.py` assertion updated to match.

## Deviations from reference

- None blocking. Findings/run tables use `table-layout: fixed` + 2-line
  title clamps so long mono paths can't push the inspector off-canvas —
  a readability refinement, not a visual departure.

## Next

- Optional follow-ups: live tailing on the events ledger (SSE or poll),
  run-vs-latest diff affordance in the case view.
