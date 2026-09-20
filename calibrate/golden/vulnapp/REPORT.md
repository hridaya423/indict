# Findings report — vulnapp

**7** findings (4 PoC-verified), 0 dismissed.

| # | status | severity | class | location | title | source |
|---|--------|----------|-------|----------|-------|--------|
| 1 | verified | high | rce | `app.js:4` | XSS via eval of 'expr' parameter | hunter/local |
| 2 | verified | high | path-traversal | `app.py:14` | Unsafe file read with user-controlled filename | hunter/local |
| 3 | verified | high | deser | `app.py:20` | Deserialization of Untrusted Data in load_blob() | hunter/smoke |
| 4 | verified | medium | rce | `app.py:9` | Avoid using `pickle`, which is known to lead to code executi | sweep/ |
| 5 | adjudicated | high | rce | `app.js:5` | Remote Code Execution via eval | hunter/smoke |
| 6 | adjudicated | high | cmd-injection | `app.js:11` | Command Injection via execSync | hunter/smoke |
| 7 | adjudicated | high | sqli | `app.py:15` | SQL Injection in get_user() | hunter/smoke |

## Dismissed (sample)
