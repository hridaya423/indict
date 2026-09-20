Write Semgrep taint-mode rules tailored to THIS {lang} repository.

Repo entrypoints:
{entrypoints}

Hot files (first 60 lines each — look at imports to learn which frameworks/libs are used):
{heads}

Produce rules for the highest-risk flows in THIS codebase: user input -> dangerous sinks (exec, SQL, file ops, deserialization, SSRF, template render). Use actual functions/imports you see — not generic guesses.

Here is a COMPLETE working rule (validated with semgrep, fires on the flow it names) — match this exact structure:

```yaml
rules:
  - id: flask-param-to-shell
    mode: taint
    languages: [python]
    severity: ERROR
    message: "request parameter reaches a shell command"
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form[...]
      - pattern: request.get_json(...)
    pattern-sinks:
      - pattern: subprocess.check_output(..., shell=True)
      - pattern: os.system(...)
    pattern-sanitizers:
      - pattern: shlex.quote(...)
```

Rules for this structure:
- every `pattern` must be a single EXPRESSION from this repo (a call, subscript, or identifier) — never a sentence or pseudocode
- multiple sources/sinks are good: cover the framework's real input APIs and the real sink calls you saw in the imports
- omit `pattern-sanitizers` entirely unless you saw a real sanitizer call
- `id` must be unique, snake_case, and name the flow (source-kind-to-sink-kind)

Output ONLY a YAML document, no prose:

```yaml
rules:
  - id: repo-taint-sqli
    mode: taint
    languages: [{lang}]
    severity: ERROR
    message: "attacker-controlled data reaches SQL execution"
    pattern-sources:
      - pattern: <source expression you saw>
    pattern-sinks:
      - pattern: <sink expression you saw>
    pattern-sanitizers:
      - pattern: <sanitizer you saw>
```
Emit 3-8 rules covering distinct sink classes. Valid semgrep syntax only.
