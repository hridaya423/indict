Write the plain-English narrative for one finding from an authorized security audit. The reader is a tired engineer: they should understand the verdict on the first read, without opening the raw evidence.

## Finding
- Status: {status}
- Title: {title}
- Class: {vuln_class}
- Location: {loc}
- Gate verdict: {verdict}
- Evidence:
{detail}

## Code around the reported location
```
{code}
```

## Output
Reply with ONE JSON object: {{"narrative": "..."}}
`narrative` is 2-4 sentences of plain English — no markdown, no bullets, no code fences.

## What each status must say
- verified: what the bug is and how attacker input reaches the sink. Cite the file:line of the vulnerable operation.
- adjudicated: what is claimed and what a proof-of-concept still needs to show.
- dismissed: why it died — name the concrete kill fact: the missing symbol, the dead code path, the guard that blocks the input, or the false premise in the claim.

## Sentence rules
- One thought per sentence. Put the concrete fact before the claim it supports.
- Name real symbols, files, and line numbers — `yaml.load() at loader.py:132`, not "the parsing function".
- Active voice, present tense; name the actor — "the parser accepts", "the guard rejects", "an attacker sends".
- Call each thing by one name. If the sink is `yaml.load()`, it stays `yaml.load()` — never "the function" or "this call" later.
- Cut words that do no work: no "potentially", "in order to", "it should be noted", "various".
- Every "it" must point at one obvious thing. If two readings exist, rewrite.
- Keep "only" next to the word it changes: "only admins can" ≠ "admins can only".
- Never claim more than the evidence shows — if the verdict cites a fact, repeat it; do not inflate it.
- No secrets, no exploit payloads, no dramatization.
