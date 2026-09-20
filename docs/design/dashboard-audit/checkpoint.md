# Dashboard audit checkpoint

Review date: 2026-09-20. Scope: current INDICT dashboard, read-only assessment and follow-up specification. No application changes authorized or made by this audit.

Reviewed all nine route implementations, API projections, timeline/proof components, existing tests and completion checkpoint. Ran TypeScript checking, five Vitest tests, and board-record HTTP tests successfully. Browser fixture served on localhost:8743 from /tmp/indict-dashboard-audit; no golden scans run.

Confirmed: active navigation attribute is dropped by Link; Findings lacks inspector; case links drop run; tab state is local; proof output relies on a filename absent in fixture; preview opens API JSON; event Load more duplicates/reorders latest events; timeline lacks actual start offsets for engine lanes; visual suite only captures five routes with no assertions.

Repository source changed during audit (board_data.py and runview.tsx among others); distinguish browser-served build and reviewed source. Recheck high-priority findings before implementation, retain anchors by function rather than assuming line numbers persist.

Next: finish narrow-screen inspection, save API reproduction evidence, write prioritized specification and audit report with measured scope and verification limits.

## Completed

The follow-up specification is saved at `docs/plans/2026-09-20-dashboard-refinement-spec.md`. User explicitly deferred mobile responsiveness. New release scope is desktop-only; mobile observations are retained as audit evidence but are not implementation requirements.

API repro confirmed: an unknown requested run falls back to latest; adding a newer failed verification record changed a historical case's proof basis while reproduced remained true. Only the isolated scratch fixture was altered and restored. Browser repro confirmed raw JSON preview in a new tab, duplicate/reordered Load more history, ignored tab query, absent active nav semantics, and missing primary output preview. Evidence is in api-evidence.json and captured screenshots.
