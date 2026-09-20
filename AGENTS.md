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
output, so run with `INDICT_MAX_TOKENS=4096 INDICT_MAX_FILE_LINES=400`, never
`--frontier`. Embeddings (semantic rank + dedup) come from
`SIE_API_KEY` too; absent key = features silently off, keyword rank and
key-based dedup unchanged.

## Watch registry
`watch.yaml` is machine-local (gitignored) — copy `watch.yaml.example`.
Watch-triggered scans default to `--no-llm` sweep; LLM hunts run
manually with explicit models.

## Live board + events
- `./indict --board [PORT]` — read-only dashboard on 127.0.0.1 (default
  8404); honors --out. Never writes; torn JSONL tails are skipped.
- `findings/<repo>/events.jsonl` is append-only across runs — rows carry
  a `run` id; readers scope by it, nothing truncates. `live.json` is the
  atomic heartbeat (fresh + not done = LIVE); watch heartbeats it.
- Falsifier kills land in the ledger as `level:"kill"` rows with the
  finding id — dismissal is first-class output, not a footnote.

## Tail stages (auto-on, env killswitches)
- writeup (INDICT_NO_WRITEUP): draft-role narrative per finding →
  writeups.jsonl keyed by id+status+sha1(verdict); regenerates only when
  the verdict changes. Presentation only — never trust input.
- learn (INDICT_NO_LEARN): verified findings → semgrep rules that MUST
  re-hit the known-bad line (±10) before landing in rules/learned/
  (global — next scan of ANY repo runs them). SIE embeddings of verified
  windows → learned-index.jsonl → rank boost. Scratch stays scratch: a
  scan run with `--out` writes its learned index under the scratch dir
  and never touches rules/learned/ or the global index. Calibration
  sweeps also run `INDICT_NO_LEARN=1` (calibrate/run_all.sh exports it)
  so learned rules never contaminate golden state.
- chain (INDICT_NO_CHAIN): composable verified pairs (ssrf→cred-leak,
  lfi→rce, ...) get one chained PoC; verified only when BOTH parents'
  recorded signals + the chain marker fire in one sandbox run.

## Evidence packs
- `./indict --pack <repo> <id>` → findings/<repo>/packs/<id>.tar.gz:
  finding record, writeup, poc dir, run_poc.sh, RUN.sh (sandboxed when
  docker exists, warned host replay otherwise; exit 0 only if the
  recorded signal fires), MANIFEST.sha256. Judge-runnable proof.

## Closed loop (issue/fix/paging)
- `./indict --issue <repo> [--file]` — drafts + files GitHub issues.
  Filing requires GITHUB_TOKEN + INDICT_ISSUE_REPO AND --file; anything
  less is a recorded dry-run. Issues only ever land on repos we own —
  never scan targets.
- `./indict --fix <repo> <id>` — agent backend (INDICT_FIXER: codex |
  devin-acp | command+INDICT_FIX_CMD) patches in a detached worktree; the
  gate then decides mechanically (PoC dies + diff rescans clean).
- `./indict --explain <repo> <id>` — per-finding evidence trail.
- Paging channels (slack/email/sms/call) activate by env; missing creds
  degrade to findings/<repo>/alerts-outbox.jsonl — never a failure.
- INDICT_AUTO_ISSUE=1 / INDICT_FIX_AUTO=1 let the watch daemon run the loop
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
