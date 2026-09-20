# Day-of Runbook

## T-0 checklist (do this the night before)

```bash
# 1. deps
uv sync
brew install semgrep universal-ctags
uv tool install osv-scanner
uv tool install bandit        # python
go install github.com/securego/gosec/v2/cmd/gosec@latest

# 2. warm semgrep rule cache (needs network once, cached after)
semgrep scan --config p/security-audit --config p/owasp-top-ten --json /tmp

# 3. sandbox images (builds SEQUENTIALLY — keep the machine idle while it runs;
#    also cap Docker Desktop memory at ~8GB in Settings > Resources so builds
#    can't swap the host)
open -a Docker
bash sandbox/build_images.sh

# 4. model endpoints — fill .env from .env.example
#    verify each endpoint:
./indict --help                      # uv env resolves
./indict --doctor                    # real chat-probe per endpoint, not /models
#    VibeProxy: open -a VibeProxy, then test an actual CHAT — /models lists
#    work even when providers are logged out. A 401/"no auth available"
#    means re-login inside the app (Subscriptions pane).
curl -s http://localhost:8317/v1/chat/completions -d '{"model":"claude-sonnet-5","messages":[{"role":"user","content":"hi"}],"max_tokens":5}'

# 5. day-of endpoint injection — no yaml edit needed:
#    GLM/Z.ai-style hosted endpoint with key:
export GLM_API_KEY=<key-from-organizers>
./indict --endpoint 'glm|https://api.z.ai/api/paas/v4|glm-5' <repo> ...
#    remote PC model (keyless ollama-style):
./indict --endpoint 'big|http://<mini-tailscale-ip>:11434/v1|qwen3-30b' <repo> ...
#    several endpoints at once = real multi-model consensus:
./indict --endpoint 'glm|https://api.z.ai/api/paas/v4|glm-5' \
       --endpoint 'ds|https://openrouter.ai/api/v1|deepseek/deepseek-v4|OPENROUTER_API_KEY' \
       <repo> --passes 3

# 5. smoke (no LLM calls)
./indict --no-llm calibrate/smoke/vulnapp
# 6. live smoke with one configured model
./indict calibrate/smoke/vulnapp --engines sweep,hunter --workers 4
```

## Kickoff questions (10:30 rules talk)

- **Are open-source models required for the Indict?** If yes → `--open-only` (pre-built; DeepSeek/GLM/local only, VibeProxy off).
- Do dependency CVEs count as findings, or only novel vulns in repo code?
- Is code-level evidence enough, or must it exploit a running instance?
- Any rate limits / approved endpoint list?
- Required report format?

## On reveal (11:00)

```bash
# tmux: one pane per repo, watch candidates stream in
./indict <repo1-url> --engines sweep,hunter,taintgen,explorer,variant --passes 2 --workers 6
./indict <repo2-url> --engines sweep,hunter,taintgen,explorer,variant --passes 2 --workers 6
./indict <repo3-url> --engines sweep,hunter,taintgen,explorer,variant --passes 2 --workers 6

# if a repo is C-family or parser-heavy, add fuzzlite:
./indict <repo> --engines fuzzlite

# watch progress (operator A):
watch -n5 'wc -l findings/*/findings.jsonl'
```

## Judge demo

```bash
bash calibrate/demo.sh   # scoreboard + verified findings + live PoC replay
```

## 2-person split

- **A (pipeline)**: keep scans fed; if an engine stalls, re-run with `--engines` subset; tune `--workers` if endpoints rate-limit.
- **B (findings)**: work `findings/<repo>/REPORT.md` top-down — verify adjudicated findings, run PoC stage manually on NEEDS-POC, draft write-ups in competition format.
- **/goal loop** (Devin): `/goal work the findings queue in findings/<repo>/: pick top unverified finding, confirm or kill it via sandbox PoC, update REPORT.md` — third pair of hands.

## Time-boxes

- Engine timeout: 10 min/file; `--hunt-budget 45` caps the whole LLM stage
- PoC: 2 model attempts per finding, then a deterministic probe
  (indictment/probes.py) fires if the vuln class matches — real canned exploits,
  sandbox-verified. Verified findings embed their `run_poc.sh` reproduce cmd
- Hourly: review REPORT.md, submit anything verified; never submit unreviewed candidates
- Hard rule: every submission must have run through adjudicate (+poc if NEEDS-POC)

## Failure modes & fixes

- Rate limits → drop `--workers`, add `--models` diversity
- Malformed JSON spam → model too weak for hunter; route that role to stronger endpoint
- `semgrep: command not found` → `uv tool install semgrep`
- Docker down → PoC stage skips automatically; findings still reported as adjudicated
- Queue too big / model slow → `--queue-limit 15` or `--files path/x.py` to
  focus the hunt; `--reuse-candidates` re-runs adjudication without hunting
- Crashed/killed hunt → `./indict <repo> --resume` keeps existing candidates
  and only hunts queue files not yet covered; verified findings survive
  re-runs (status + proof carry forward, never downgrade)
- Local smoke model for harness checks: `ollama pull qwen2.5-coder:1.5b`
  (--models smoke) — fine for plumbing tests, too weak for real hunts
- Local ollama SERIALIZES requests — run ONE scan at a time locally, or set
  OLLAMA_NUM_PARALLEL=4 before `ollama serve` for real parallelism
- Scratch/test scans → `--out /tmp/scratch` so golden calibration state in
  `findings/` is never clobbered by an experiment
- Sweep is network-free: vendored semgrep packs live in `rules/` (refresh:
  `curl -sL https://semgrep.dev/c/p/<pack> -o rules/<pack>.yaml`);
  osv-scanner needs lockfiles + network (its absence just prints a note)
- file:// targets work — `./indict file:///abs/path/repo` for offline clones
- Verified calibration state is committed under `calibrate/golden/` —
  `bash calibrate/golden.sh restore` puts it back if experiments clobber
  `findings/`; `save` re-snapshots after a better run

## Tier 1+2 upgrades (post-calibration hardening)

- **Line-verified PoCs**: sandbox runs carry execution traces (python
  sitecustomize settrace / node NODE_V8_COVERAGE); a PoC only verifies if
  the reported line actually executed. Probes gate at file level (they're
  class-generic). Look for `line-verified` tags on findings.
- **Response cache**: identical prompts return recorded replies
  (.llmcache/, gitignored) — prompt iteration without re-paying latency.
  Disable day-of with `INDICT_NO_CACHE=1`.
- **Secret scanning**: sweep includes a gitleaks-style regex pack
  (AWS/GitHub/Slack/Stripe/JWT/private keys/DB URLs...). Zero deps.
- **SARIF + CWE**: every run emits `findings/<repo>/sarif.json`
  (GitHub-loadable) with CWE ids per finding.
- **CVSS-lite**: deterministic severity from class base + proof state —
  see `cvss-lite` column in REPORT.md.
- **--since REF**: differential rescan — hunts only files changed since
  the ref; verified findings carry forward.
- **Telemetry**: per-model call/latency/cache stats printed at scan end.
- **taintgen few-shot**: prompt now embeds a semgrep-validated example
  rule (verified firing) as the structural anchor.
- **--frontier**: wide profile for frontier-class endpoints — whole-file
  windows (no 1200-line truncation), 16 agent iterations, 8 context
  requests/turn, 16k max tokens, top-200 queue. Explicit env vars
  (INDICT_MAX_FILE_LINES etc.) still win over the preset.

## Local model note
qwen3-coder:30b was removed from ollama post-calibration (memory
crashes). To use `--models local` again: `ollama pull qwen3-coder:30b`.
A runtime context cap is already set (launchctl OLLAMA_CONTEXT_LENGTH=32768,
survives until reboot — re-apply after: `launchctl setenv
OLLAMA_CONTEXT_LENGTH 32768` and restart the Ollama app). That cap is
the fix for the crashes: the model defaults to a 256k context whose
KV cache blew past available RAM.
