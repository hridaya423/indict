# Dashboard concept exploration

Status: visual exploration, not an approved specification. Application code remains unchanged. All numbers, repository names, and finding examples in generated images are illustrative.

## Product intent

An internal security analyst needs to find the next useful action, inspect the evidence behind a finding, and know when scan output is incomplete. Use a dense desktop workspace with readable text and restrained status colors.

Domain vocabulary: candidate, adjudication, falsification, reproduced signal, sandbox, scanned revision, evidence pack, fix gate, run heartbeat.

Color direction: graphite equipment casing, white lab paper, grey metal, blue selection ink, amber caution labels, red failure marks, green passed checks. Color carries a named state; it does not decorate panels.

Signature: a finding's proof record sits beside its claim, with distinct recorded, missing, and failed checks.

Avoid equal KPI cards, decorative threat maps, and model confidence presented as proof.

## Directions

1. Triage workspace: cross-repository queue and a persistent selected-finding inspector. Recommended default. Fast comparison, explicit severity and verification state, useful filters, stable selection during updates.
2. Evidence workspace: spacious case view organized around claim, recorded test, observed signal, and fix verification. Better for deep investigation, less useful for scanning many findings.
3. Run monitor: repository/run rows, stage durations, heartbeat freshness, and exceptions. Better for operating the scanner, secondary to security triage.

## Repository evidence

The current board is a read-only Python HTTP server plus a single HTML file. `/api/state` exposes repository findings, status counts, recent events, alerts, fix verdicts, queue count, last scanned SHA, scan timestamp, and live state. `/api/finding` exposes a finding, narrative, PoC filenames and 200-character previews, associated events and alerts, fix verdict, and inferred chain references.

The UI reserves 260px for pipeline events and 290px for monitoring. It has a 1280px minimum width. Findings expand into three columns within the remaining center. The current funnel includes verified findings in both kept and verified totals. The evidence-chain UI splits narrative text; it does not establish a structured proof chain. Poll time is labeled scan time. These are observed design/data issues, not changes made in this exploration.

## Data boundaries for a later spec

Available now: status/severity filters, repository scope, finding search, scan revision and age, queue count, evidence filenames, verdict text, run events, and recorded fix outcome.

Derivable with explicit limitations: verified findings without a recorded passing fix; heartbeat age; event-based stage elapsed time when matching events exist. Current events are capped and cannot support complete historical analytics.

Needs structured data or API work: run history and reliable scan-to-scan deltas; source excerpts; full evidence downloads; exact command, environment, exit result and signal assertions; separate PoC and rescan fix checks; watched repositories with no findings; engine degradation and skipped checks; issue links; assignment and review state. Do not invent coverage percentages, exposure, confidence-of-exploit scores, or delivery receipts.

Proof must distinguish a reproduced vulnerability from a model assertion. A patch passing the local gate does not mean it is merged or deployed. Outbox entries do not prove notification delivery. Narrative chain references do not prove a composed exploit.

## User direction

The user confirmed a multipage product covering all these activities. Treat these concepts as complementary pages, not competing product scopes.

Proposed navigation: Findings, Runs, Repositories, Fixes. Evidence is a full finding detail route, reachable from every associated run and fix. An additional standalone Evidence library is optional and should only exist if cross-finding artifact retrieval proves useful.

Repositories should expose last scanned revision, freshness, watch configuration, and unscanned or partially scanned states. Fixes should connect the original reproduced signal to patch evidence and independent gate results, with merge/deployment status shown only when sourced.

## Visual review

Generated with the built-in imagegen tool. Inspected all three rendered images.

01-findings.png: useful table/inspector proportions and readable rows. The generator duplicated repository filtering, mixed Verified and Reproduced terminology, and added an unsupported Indict expansion. Consolidate the filter and settle status vocabulary before a spec.

02-evidence.png: strongest investigation layout. Source and observed output are readable together. Remove the second filled action and avoid wording that treats adjudication as confirmation. The example source and terminal output are illustrative; never ship these as real evidence.

03-runs.png: useful exception panel and repository/run relationship. The generated timeline implies future duration and progress; replace it with elapsed stage segments and an open-ended active segment. A stale heartbeat means unknown outcome, not confirmed failure. Image counts and sample history are not validated analytics.

Use one shared navigation and typography system across pages, with both light and dark themes rather than assigning themes to page types. Do not carry the generated account/avatar, branding expansions, duplicate controls, or invented dates into the specification.

## Candidate usefulness improvements

- Link a finding to its exact run, scanned revision, artifacts, related findings, and fix verdict while preserving list filters on return.
- Offer explicit queues for unvalidated candidates, reproduced findings without a passing fix, and fixes awaiting human review. Human review state requires persistence.
- Show changes since a selected comparable run once historical snapshots exist; distinguish newly observed, still present, and not evaluated from resolved.
- Make missing evidence and skipped engines visible beside results. Empty findings are not proof of a complete clean scan.
- Keep dismissals searchable with disproof and provenance. Show structured exploit-chain evidence only when parent signals and the chain marker are recorded.

Framework choice is deferred to the later specification. A React frontend can support routed pages and shared interaction state; changing frameworks alone does not resolve the information hierarchy or missing data contracts.
