Validate a claimed data-flow path to a dangerous sink (`{sink}`). Be hostile — most claimed paths are wrong.

Claimed path: {chain}

Code evidence:
```
{code}
```

Checks — PASS only when every one survives; a single broken hop is a FAIL:
- Every hop exists and actually passes the claimed value (not just a similarly-named variable)
- Every hop names a real file:line — a hop without a code location cannot be checked
- Path conditions are SATISFIABLE — no guard on the path makes the bad input impossible
- The source is genuinely attacker-controllable
- Impact is real (code exec / privesc / info disclosure), not cosmetic
- `why_failed` names the specific hop or guard that breaks the chain

Reply with ONE JSON object:
```json
{{"verdict": "PASS|FAIL",
  "vuln_class": "...", "severity": "critical|high|medium|low",
  "confidence": 0.0, "title": "short description",
  "poc_idea": "how to trigger", "why_failed": "if FAIL"}}
```
