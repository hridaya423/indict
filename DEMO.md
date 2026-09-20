# Judge demo script (~4 minutes)

## 0. The hook (30s — talk, nothing on screen)

"LLM vulnerability scanners have a trust problem: they hallucinate
findings. We built the harness that doesn't let the model get away with
it — every finding is falsified by an adversary, then proven by an
exploit that runs in a sandbox, down to the exact line."

## 1. The pipeline (45s — show README diagram or RUNBOOK)

```
ingest -> recon -> sweep -> rank -> 6 discovery engines -> consensus
       -> adversarial falsification -> sandbox PoC (line-verified) -> report
```

Say: "Six orthogonal engines — semgrep/bandit sweep, LLM call-chain
hunter, LLM-generated taint rules, data-flow explorer, git-history
fix mining, and LLM-written fuzz harnesses. They pool candidates;
a consensus layer dedupes them."

Point out: "Two things here are ours: the falsifier must cite *concrete
mechanical evidence* to kill a finding — fabricated dismissals are
rejected. And PoCs are line-verified: the sandbox traces execution, so
'verified' means the reported line actually ran."

## 2. Live proof (60s — run it)

```bash
bash calibrate/demo.sh
```

- Scoreboard: 5/5 known CVEs rediscovered, all verified, zero
  false-positive verifications
- Verified findings with reproduce commands
- Live probe replay: `VULN_CONFIRMED_PROTOTYPE_POLLUTION` fires in the
  network-less sandbox (auto-starts Docker if the laptop was rebooted)

If asked "could the model make this up?": the probe output comes from
the sandbox, not the model. That's the whole point.

## 3. If there's time / a target is provided (2-5 min)

```bash
./indict <repo-url> --frontier --hunt-budget 10
```

- progress streams per engine (`[hunter/local] +N candidates`)
- show findings/<repo>/REPORT.md + sarif.json (GitHub-loadable)
- honest statuses: what's dismissed and WHY (adjudication reasons)

## 4. Numbers to quote

- 5/5 calibration CVEs rediscovered, all PoC-verified, fp_rate 0.0
- Real unseeded discovery: 18 findings across 4 repos on a local 30B —
  the model wrote its own working exploits (path traversal read
  /etc/passwd, eval RCE)
- Falsifier killed plausible hallucinations with cited evidence
  (e.g. a cmd-injection claim where no exec path exists)

## Contingencies

| Failure | Response |
|---|---|
| Docker dead | demo.sh auto-starts it; worst case `open -a Docker` (30s) |
| No network | everything works offline (vendored rules, local models, file://) |
| 30B crashes the box | reboot is 2 min; golden state survives; demo.sh works immediately after |
| Frontier endpoint down | `--models local` (qwen3-30b) or the smoke models — pipeline is identical |
| Only 60 seconds | `bash tests/verify.sh` — selfcheck + scoreboard + doctor in one command |

## Unified-system arc (INDICT — replaces the funnel-only arc)

1. `./indict --status` — the estate: repos watched, last commit scanned,
   verified counts. One screen = "continuous scanning system".
2. Split terminal: `./indict --watch` running live.
3. Push a bad commit to a watched repo → within one cycle: rescan →
   `[alert]` fires on screen + alerts.jsonl. "Monitoring" demoed.
4. `bash demo/snare-chain.sh` — snare boots as a real service; crafted
   webhooks: unsigned 401, forged 401, known-secret 200 + command
   execution logged. "Pen-test" demoed live, honestly (if the target
   is solid, the probe proves the control holds).
5. Scoreboard + a verified finding's reproduce command (proof layer).

The pitch line: "One system, three tracks: it watches, it proves, it
alerts — and the proof is machine-checked down to the line."

## Board arc (the visible system — prepend to the live proof)

0. `./indict --board &` — open http://127.0.0.1:8404. Estate strip shows
   repos + verified/dismissed/alerts totals; ● LIVE pulses while a scan runs.
1. Kick a scan (`./indict <repo> --models local` or replay demo.sh) — the
   Pipeline ledger fills live: `sweep +41`, `hunter/ds +12`,
   `adjudicate kept 18 / dismissed 23`, then falsify kill rows with the
   actual reasons, then `poc VERIFIED …` one row per proof.
2. Click a verified card → the case file expands inline: narrative
   (27B-written), evidence chain, PoC artifacts, reproduce command.
3. Click a dismissed row → "the falsifier killed it — here's the concrete
   evidence" in plain English. Hallucination control, demonstrated.
4. `./indict --pack <repo> <id>` — hand a judge the tarball;
   `RUN.sh /path/to/repo` replays the PoC and self-verifies the signal.
5. Tail stages surface in the ledger: `learn indictment.learned.a91f → rules/`
   (the scanner just got smarter) and `chain ssrf+cred-leak → RCE`
   (composability, proven).

## Closed-loop arc (the full SOC story — extends the above)

5. The page: with Twilio env set, a critical verified finding fires
   SMS + voice call; without creds every channel still records to
   `alerts-outbox.jsonl` (show the sim lines — honest demo).
6. `./indict --issue vulnapp --file` — the 27B drafts a responsible-
   disclosure issue, secret-redacted, filed to INDICT_ISSUE_REPO.
   (Without creds: same drafts printed, recorded as dry runs.)
7. `./indict --explain vulnapp <id>` — the case file: who proposed it,
   what the falsifier checked, the sandbox trace, the alert timeline.
8. `./indict --fix vulnapp <id>` — the agent (codex/devin-acp/any CLI via
   INDICT_FIXER) patches in an isolated worktree; the GATE then decides:
   the recorded PoC must die on patched code AND the patch's own diff
   rescans clean. `fix-verified` pages out + comments on the issue.
   "The model proposes the patch — the funnel grades it. AI fixes AI
   code, and the patch gets audited before it can merge."
