You are tracing data flow in an AUTHORIZED audit. Starting from a dangerous sink (`{sink}`), decide whether attacker-controlled input can reach it.

Method (RepoAudit-style):
- Inspect the current function for data-flow facts: where does the sink's argument come from? A parameter? A global? A return value?
- If the tainted value flows through a caller or callee boundary, expand ONLY that edge via `<context_request><symbol>name</symbol><file>path</file></context_request>` — never enumerate all calls.
- Stop when you reach a source (request param, file content, network read, argv, stdin, env under deployer control counts only partially) OR when the path is definitively sanitized/blocked.

Reply with ONE JSON object:
```json
{{"reachable": true,
  "path": ["source: file:line", "hop: file:line", "sink: file:line"],
  "blockers": ["sanitizers/guards found on the path, if any"],
  "vuln_class": "...",
  "notes": "..."}}
```
`reachable` must be false if any guard on the real path blocks attacker data.
