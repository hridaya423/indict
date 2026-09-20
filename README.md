# CRS — grafted multi-engine vulnerability discovery

One command: `./scan <git-url-or-path>` → `findings/<repo>/REPORT.md`.

Built for the AI Tinkerers × Superlinked hackathon. Grafts the proven parts of
vulnhuntr (call-chain hunting), RepoAudit (explorer→validator), IRIS
(LLM-generated taint rules), Big Sleep (variant analysis), artiphishell
(LLM fuzz harnesses) and the triage-brocards falsification gate into one
model-agnostic pipeline. See RUNBOOK.md for day-of ops.

```
ingest → recon → sweep → rank → [hunter|taintgen|explorer|variant|fuzzlite]
       → consensus → adjudicate → poc → report
```

- Engines/models are flags: `./scan repo --engines sweep,hunter --models deepseek,glm --passes 2 --workers 6`
- Ad-hoc endpoints: `--endpoint 'name|https://base/v1|model[|KEY_ENV]'` (repeatable; key env auto-defaults to `NAME_API_KEY` when set)
- `--doctor` verifies tools, docker images, and endpoints with real chat probes
- `--hunt-budget MIN` wall-clock caps the LLM stage; `--files`/`--queue-limit` focus the hunt; `--out DIR` for scratch runs; `--reuse-candidates` re-runs adjudication without hunting
- `--open-only` restricts to open-weight endpoints (rules-compliant mode)
- `--no-llm` deterministic stages only (offline smoke)
- Calibration: `python -m calibrate.score findings/` · judge demo: `bash calibrate/demo.sh` · verified state snapshot: `bash calibrate/golden.sh save|restore`
