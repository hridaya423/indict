# AGENTS.md — execution contract for this repo

## Never clobber golden state
`findings/<repo>/` for calibration targets holds verified demo state.
Test scans MUST use `--out <scratch-dir>`. If clobbered anyway:
`bash calibrate/golden.sh restore`.

## targets/ is read-only
`targets/` holds local clones of competition targets. Never send PRs,
push, or commit to them. Analysis only.

## The one-command checks
- Full suite: `bash tests/verify.sh` (selfcheck + scoreboard + doctor)
- Ops layer: `uv run python tests/test_ops.py`
- Semantic layer: `uv run python tests/test_sie.py && uv run python tests/test_rank_semantic.py && uv run python tests/test_dedup_semantic.py`
- Always `uv run` — deps live in the venv.

## SIE endpoints
Chat: `sie` in models.yaml (Qwen3.8-27B-FP8) — served with 8k ctx / 4k
output, so run with `CRS_MAX_TOKENS=4096 CRS_MAX_FILE_LINES=400`, never
`--frontier`. Embeddings (semantic rank + dedup) come from
`SIE_API_KEY` too; absent key = features silently off, keyword rank and
key-based dedup unchanged.

## Watch registry
`watch.yaml` is machine-local (gitignored) — copy `watch.yaml.example`.
Watch-triggered scans default to `--no-llm` sweep; LLM hunts run
manually with explicit models.

## Closed loop (issue/fix/paging)
- `./scan --issue <repo> [--file]` — drafts + files GitHub issues.
  Filing requires GITHUB_TOKEN + CRS_ISSUE_REPO AND --file; anything
  less is a recorded dry-run. Issues only ever land on repos we own —
  never scan targets.
- `./scan --fix <repo> <id>` — agent backend (CRS_FIXER: codex |
  devin-acp | command+CRS_FIX_CMD) patches in a detached worktree; the
  gate then decides mechanically (PoC dies + diff rescans clean).
- `./scan --explain <repo> <id>` — per-finding evidence trail.
- Paging channels (slack/email/sms/call) activate by env; missing creds
  degrade to findings/<repo>/alerts-outbox.jsonl — never a failure.
- CRS_AUTO_ISSUE=1 / CRS_FIX_AUTO=1 let the watch daemon run the loop
  unattended; default off.

## Invariants that keep this codebase sane
- `alerts.emit()` is the only notification seam — new transports extend
  alerts.py, callers never change.
- `findings/<repo>/` is the single source of truth — findings.jsonl for
  state, poc/<id>/ for evidence, issues.jsonl, fixes/<id>/ for the loop.
- Every network touch never raises: a dead endpoint degrades, never
  kills a scan or the daemon.
- New stages are new modules, not new flags inside old ones.
- Trust decisions are mechanical — never gate on a model's word alone.
