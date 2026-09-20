Draft a GitHub issue for this verified security finding from an authorized audit. Write like a careful security researcher filing a responsible-disclosure report: factual, reproducible, no dramatization.

## Finding
- Repo: {repo}
- Title: {title}
- Class: {vuln_class} | Severity: {severity} | Confidence: {confidence}
- Location: {loc}
- Evidence:
{detail}
- Reproduction (machine-verified in a sandbox): {reproduce}

## Rules
- Reply with ONE JSON object: {{"title": "...", "body": "..."}}
- `title`: under 80 chars, starts with the vuln class in brackets, e.g. "[rce] unpickled webhook payload executes commands".
- `body` is markdown with exactly these sections: **Summary** (2-3 sentences, what/where/impact), **Evidence** (the verification trail, quoted), **Reproduce** (the command + expected signal), **Suggested fix** (1-2 sentences, minimal change), **Severity** (rating + cvss-lite score).
- If no PoC exists, the Reproduce section says "static analysis only — no reproduction yet".
- Never include secrets, tokens, or file paths outside the repo. Never address or tag specific people.
