Write a MINIMAL, non-destructive reproduction for this authorized-audit finding. Prove the bug exists — do not weaponize it.

## Finding
- {title} ({vuln_class}) at {loc}
- Evidence: {detail}
- Suggested trigger: {poc_idea}

## Code context
```
{code}
```

## Rules
- The script runs in a network-less Docker sandbox with the repo mounted read-only at /src.
- NO network: no pip/npm/apt. The repo itself is the dependency — for Python repos set PYTHONPATH=/src (or the repo's package dir e.g. /src/lib, /src/lib3, /src/src) so `import <pkg>` loads the audited code; for JS repos require() /src paths or run node against /src files directly.
- Use only what's available: bash, the language toolchain, the repo's own code.
- A good PoC: a failing test, a crafted input file, a function call with malicious args, a curl against a locally-started server.
- `success_signal` MUST be a distinctive marker string (>=10 chars) that you print from the script only when the bug fires, e.g. `echo "VULN_CONFIRMED_SQLI"` — never a generic word like "error" or "true".
- `script` MUST be valid bash. Embed language code via heredoc, never bare code:
  `python3 - <<'PY' ... PY` or write a file under /poc then run it.
- Example shape for a Python-library deser finding:
  ```bash
  cat > /poc/r.py <<'PY'
  import sys; sys.path.insert(0, "/src/lib3")   # or /src, /src/lib
  import yaml
  yaml.load('!!python/object/new:tuple\n- !!python/object/new:map\n- !!python/name:eval\n- ["print(\\"VULN_CONFIRMED_DESER\\")"]',
            Loader=yaml.FullLoader)
  PY
  PYTHONPATH=/src/lib3 python3 /poc/r.py
  ```

Reply with ONE JSON object:
```json
{{"script": "#!/bin/bash\n... complete repro script ...",
  "success_signal": "exact string proving the bug fired",
  "notes": "what the reviewer should look for"}}
```
