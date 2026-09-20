A vulnerability was mechanically confirmed (PoC executed the reported line)
during an authorized security audit. Distill it into ONE semgrep rule that
catches the same bug CLASS anywhere — not just this exact line.

Finding: {title}
Class: {vuln_class}
Location: {loc}

Evidence:
{detail}

Code window (line numbers shown; the bug is at {loc}):
```
{code}
```

Produce ONE JSON object only:

{{"rule_yaml": "rules:\n  - id: indictment.learned.PLACEHOLDER\n    ...", "languages": ["python"]}}

Requirements for `rule_yaml`:
- `id: indictment.learned.PLACEHOLDER` literally — we rewrite it
- `severity: ERROR`
- `message:` names the vuln class (e.g. "user input reaches eval()")
- `languages` inside each rule matching the file's extension
  (.py -> [python], .js/.jsx/.mjs -> [javascript], .ts/.tsx -> [typescript],
  .go -> [go], .java -> [java], .rb -> [ruby], .php -> [php], .rs -> [rust],
  .c/.h -> [c], .cpp/.cc -> [cpp])
- `languages` in the JSON sibling field = the same list
- capture the source->sink PATTERN, not the literal identifier names:
  generalize with metavariables ($X, $FN, ...) and pattern / patterns /
  pattern-either so the rule fires on equivalent code in other files
- `mode: taint` with pattern-sources / pattern-sinks is preferred when the
  bug is a real source->sink flow; a plain pattern rule is fine otherwise
- every `pattern` must be a single EXPRESSION (call, subscript, identifier)
  — never a sentence or pseudocode
- the rule MUST still match the vulnerable line shown above — we run it
  mechanically and discard it unless it re-fires there
- valid semgrep YAML only, as the JSON string value (\n escapes are fine)

JSON only. No prose, no markdown fences.
