Validate a claimed data-flow path to a dangerous sink (`{sink}`). Be hostile — most claimed paths are wrong.

Claimed path: {chain}

Code evidence:
```
{code}
```

Checks:
- Every hop exists and actually passes the claimed value (not just a similarly-named variable)
- Path conditions are SATISFIABLE — no guard on the path makes the bad input impossible
- The source is genuinely attacker-controllable
- Impact is real (code exec / privesc / info disclosure), not cosmetic

Reply with ONE JSON object:
```json
{{"verdict": "PASS|FAIL",
  "vuln_class": "...", "severity": "critical|high|medium|low",
  "confidence": 0.0, "title": "short description",
  "poc_idea": "how to trigger", "why_failed": "if FAIL"}}
```
