Draft a GitHub issue for this verified security finding from an authorized audit. Write like a careful security researcher filing a responsible-disclosure report: factual, reproducible, no dramatization.

## Finding
- Repo: {repo}
- Title: {title}
- Class: {vuln_class} | Severity: {severity} | Confidence: {confidence} | CVSS-lite: {cvss}
- Location: {loc}
- Evidence:
{detail}
- Reproduction (machine-verified in a sandbox): {reproduce}

## Output
Reply with ONE JSON object: {{"title": "...", "body": "..."}}
- `title`: under 80 chars, starts with the vuln class in brackets — "[rce] unpickled webhook payload executes commands".
- `body` is markdown with exactly these sections, in this order:
  - **Summary** — 2-3 sentences: what the bug is, where it lives (file:line and the real symbol), what an attacker gains.
  - **Evidence** — the verification trail, quoted verbatim.
  - **Reproduce** — the command, then the expected output signal. If reproduction takes more than one command, write numbered steps, one action each, condition before the step ("To verify, run..."). The reproduction path is a local artifact path: cite the script name and the signal, never the absolute host path. If no PoC exists, write "static analysis only — no reproduction yet".
  - **Suggested fix** — 1-2 sentences naming the minimal change at the reported site: the real symbol and file, not "add validation".
  - **Severity** — the {severity} rating and the CVSS-lite score {cvss} given above; do not invent a different score.

## Sentence rules
- Instructions are commands: "Run X", not "X should be run". Put the condition first: "To verify, run...".
- One instruction per sentence. Split any sentence carrying two.
- Use the codebase's words: real symbols, paths, flag names — never a paraphrase. Each thing gets one name, used everywhere: the symbol, the file, the command.
- Cut every word that does no work: no "please", no "simply", no "note that".
- Never include secrets, tokens, or file paths outside the repo. Never address or tag specific people.
