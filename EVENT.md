# EVENT DAY — AI Tinkerers × Superlinked

## 10:30 (before targets drop) — 3-minute preflight

```bash
bash tests/verify.sh        # selfcheck + scoreboard + doctor: expect READY
```

- keys in `.env`? (DEEPSEEK_API_KEY / ZAI_API_KEY — open-weight, rules-compliant)
- or re-pull local: `ollama pull qwen3-coder:30b` (context cap already set)
- Docker running (verify.sh tells you; demo.sh auto-starts it anyway)

## 11:00 — targets revealed (3 projects)

Scan all three, sequential, bounded. One command each:

```bash
./scan <target-1-url> --frontier --open-only --hunt-budget 60 --engines sweep,hunter,explorer,taintgen,variant,fuzzlite
```

- `--open-only` = mechanical proof every model is open-weight (judge-visible)
- `--hunt-budget 60` = each target capped at an hour; 3 targets < 4h, leaves triage time
- while target N grinds: **person 2 triages** findings/<target-N-1>/ (read REPORT.md,
  kill weak findings by re-running their reproduce cmds, strengthen the good ones)
- crash/power loss: `./scan <target> --resume` — keeps candidates, hunts only
  uncovered files; verified findings always survive

## 12:30-17:00 — iterate

- per target: read REPORT.md → for each verified/adjudicated finding, check the
  PoC actually fires (`Reproduce:` line is copy-pasteable)
- SARIF (`findings/<repo>/sarif.json`) + CWE + cvss-lite are already in every report
- if a target is huge: `--queue-limit 40` then widen later
- **precision over recall**: judges manually validate — a finding we can't
  reproduce costs credibility; our funnel already dismisses those

## 17:00-18:00 — pick the story

- scoreboard of the day: verified findings per target
- pick top 2-3 findings by significance (RCE > injection > info leak)
- rehearse DEMO.md once with the day's targets swapped in for calibration

## 18:00 — finalist pitch (see DEMO.md)

1. hook: LLM scanners hallucinate; ours can't get away with it
2. pipeline: 6 engines -> consensus -> adversarial falsification ->
   sandbox PoC, line-verified
3. live: `bash calibrate/demo.sh` (5s) or the day's best reproduce cmd
4. the day's findings, severity-ordered, each with a one-line repro

## Guardrails compliance (say it, it scores)

- sandbox: no network, read-only FS, cpu/mem caps — collateral damage is
  impossible by construction
- PoCs are non-destructive by prompt AND by sandbox
- falsify gate exists so maintainers don't wade through FPs — the exact
  thing the organizers said they'd do manually

## Superlinked SIE endpoint (likely day-of option)

Most capable model in their catalog: **Qwen/Qwen3.6-27B** (Apache-2.0).
Already wired into models.yaml as `sie` — drop the key in `.env`
(SIE_API_KEY=...), then:

```bash
CRS_MAX_TOKENS=4096 CRS_MAX_FILE_LINES=400 \
  ./scan <target> --models sie --open-only
```

Why the tuned env: SIE serves it with **8k context / 4k output** — our
defaults (8k output tokens, 1200-line windows) would overflow. Do NOT
use --frontier against SIE; the agent loop's context-request protocol
(model pulls only the symbols it needs) is how depth works at 8k.
Sandbox/engines/falsify are unaffected — only the model I/O shapes.

## Winning plan (dup-proof strategy)

Scoring: valid vulns, significance-weighted, manually validated
(FPs poison credibility) + the system itself is scored. Rules don't
specify first-wins vs shared credit on duplicates — so win either way:

1. SPEED on the commons (11:00-11:15): `--no-llm` sweep on all 3 targets
   banks dep-CVEs/secrets/scanner hits in minutes, mechanically
   verified, zero model calls. Others are still prompting.
2. DEPTH on the rare: variant git-mining (sibling patterns of past
   fixes), agent-loop call chains, per-repo taint rules, fuzz crashes
   with triggering input — single-loop teams structurally can't.
3. PRECISION on everything: our submissions carry reproduce commands +
   sandbox output + line-execution trace. In shared credit, the
   verified finding survives review; in first-wins, the sweep got us
   there first.
4. SYSTEM score is fully differentiated — demo the dismissal of a
   hallucination as a feature.

## The unified system (CRS-OPS) — pitch-day commands

Three tracks, one loop: watch (continuous scanning) → funnel → alerts
(monitoring) → service probes (pen-test). All committed.

```bash
# estate at a glance — every repo, last commit scanned, verified counts
./scan --status

# continuous mode: registry-driven rescan on every new commit, alerts
# on new findings (file + terminal + CRS_ALERT_WEBHOOK if set)
cp watch.yaml.example watch.yaml   # then edit: the 4 target repos
./scan --watch                     # Ctrl-C to stop; CRS_WATCH_INTERVAL=120

# single-cycle check (rehearsal / CI)
./scan --watch-once

# live pen-test demo: snare as a real service, crafted webhooks,
# HMAC gate discrimination + command-execution side effect
bash demo/snare-chain.sh
```

Semantic layer (Superlinked): with SIE_API_KEY set, queue ranking gets
a cosine boost against vuln descriptors and findings dedupe across
locations (cos >= 0.90). Without the key: identical behavior.

Alerts land in findings/<repo>/alerts.jsonl — one JSON line per new
verified/adjudicated finding and per dep-CVE.
