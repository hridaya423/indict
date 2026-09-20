Compose a CHAINED exploit from two already-proven vulnerabilities in this authorized audit. The chain proves an attack path: stage 1 leaks an artifact, stage 2 consumes it. Both stages were independently verified — your job is to wire them together, not to re-derive them.

## Stage 1 — proven
- {a_title} ({a_class}) at {a_loc}
- Evidence: {a_detail}
- Recorded success signal (must appear in output when stage 1 fires): `{a_signal}`
- Proven repro script (reference only — INLINE its logic into your chain; the sandbox starts empty, no files exist):
```bash
{a_script}
```

## Stage 2 — proven
- {b_title} ({b_class}) at {b_loc}
- Evidence: {b_detail}
- Recorded success signal (must appear in output when stage 2 fires): `{b_signal}`
- Proven repro script (same — inline it, parameterized on stage 1's output):
```bash
{b_script}
```

## Rules
- ONE bash script, same network-less Docker sandbox: repo mounted read-only at /src, no pip/npm/apt, bash + language toolchains only. For Python repos use PYTHONPATH=/src (or the repo's package dir); for JS repos require() /src paths directly.
- The script MUST, in order:
  1. Run stage 1's proven repro inline.
  2. Capture the artifact stage 1 leaks (credential, token, path, session id, file contents...) using grep/awk/sed/command substitution — not a hardcoded guess.
  3. Feed that captured artifact into stage 2's attack inline.
  4. Print the `chain_complete` marker ONLY when both stages demonstrably succeeded — gate it on stage 1's signal firing AND stage 2's effect landing, e.g. `if [ -n "$LEAKED" ] && <stage2 succeeded>; then echo "CHAIN_COMPLETE_..."; fi`.
- `stage1_signal` / `stage2_signal` MUST be echoed back EXACTLY as given above — they are the mechanical contract, do not invent replacements.
- `chain_complete` MUST be a distinctive marker string (>=10 chars) that your script echoes only on full-chain success, e.g. `CHAIN_COMPLETE_RCE_VIA_LFI` — never a generic word like "error" or "true".
- Non-destructive: prove the attack path exists. No exfiltration, no persistence, no writes outside /poc or /tmp.

Reply with ONE JSON object:
```json
{{"script": "#!/bin/bash\n... complete chained script ...",
  "stage1_signal": "{a_signal}",
  "stage2_signal": "{b_signal}",
  "chain_complete": "marker printed only when the full chain fired"}}
```
