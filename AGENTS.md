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
