# Indict — grafted multi-engine vulnerability discovery

One command: `./indict <git-url-or-path>` → `findings/<repo>/REPORT.md`.

Built for the AI Tinkerers × Superlinked hackathon. Grafts the proven parts of
vulnhuntr (call-chain hunting), RepoAudit (explorer→validator), IRIS
(LLM-generated taint rules), Big Sleep (variant analysis), artiphishell
(LLM fuzz harnesses) and the triage-brocards falsification gate into one
model-agnostic pipeline. See RUNBOOK.md for day-of ops.

```
ingest → recon → sweep → rank → [hunter|taintgen|explorer|variant|fuzzlite]
       → consensus → adjudicate → poc → chain → report → [writeup|learn]
```

- Engines/models are flags: `./indict repo --engines sweep,hunter --models deepseek,glm --passes 2 --workers 6`
- Ad-hoc endpoints: `--endpoint 'name|https://base/v1|model[|KEY_ENV]'` (repeatable; key env auto-defaults to `NAME_API_KEY` when set)
- `--doctor` verifies tools, docker images, and endpoints with real chat probes
- `--hunt-budget MIN` wall-clock caps the LLM stage; `--files`/`--queue-limit` focus the hunt; `--out DIR` for scratch runs; `--reuse-candidates` re-runs adjudication without hunting
- `--open-only` restricts to open-weight endpoints (rules-compliant mode)
- `--no-llm` deterministic stages only (offline smoke)
- Calibration: `python -m calibrate.score findings/` · judge demo: `bash calibrate/demo.sh` · verified state snapshot: `bash calibrate/golden.sh save|restore`
- `./indict --board` — live read-only dashboard (127.0.0.1:8404): event ledger, funnel, finding cards with draft-model writeups (incl. *why dismissed*), alerts + fix loop. Driven by append-only `events.jsonl` + `live.json` heartbeat.
- `./indict --pack <repo> <id>` — self-contained evidence tarball (PoC + manifest + `RUN.sh` self-verifying replay) a judge can run anywhere.
- Tail stages run automatically: `chain` composes verified findings into proven exploit chains; `learn` distills verified bugs into gated semgrep rules (`rules/learned/`, `INDICT_NO_LEARNED=1` for pristine calibration) + SIE similarity signatures that boost sibling code in future scans.
