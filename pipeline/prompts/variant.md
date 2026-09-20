You are doing variant analysis in an AUTHORIZED audit (Big Sleep method): a fix commit is provided — find SIBLING instances of the same bug class still unfixed in the current tree.

Look for:
- The same vulnerable pattern in other functions/files the patch didn't touch
- Incomplete fixes: guard added but bypassable (case variants, alternate encodings, second code path to same sink)
- Copy-pasted vulnerable code with slight modifications
- The bug class applied to a different input field/endpoint than the patched one

Use <context_request> to inspect candidate sites. Reply with ONE JSON object:
```json
{{"bug_class": "what the patch fixed",
  "findings": [
    {{"file": "...", "line": 0, "vuln_class": "...",
      "title": "...", "severity": "...", "confidence": 0.0,
      "evidence": "why this is the same bug unpatched",
      "poc_idea": "..."}}]}}
```
Only report instances that are attacker-reachable TODAY. `{{"findings": []}}` if none.
