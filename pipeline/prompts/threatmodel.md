Build a threat model for this open-source project. This guides an authorized vulnerability audit.

Languages: {languages}
Manifests: {manifests}
Entrypoints (files likely to handle external input):
{entrypoints}

README excerpt:
{readme}

Reply with ONE JSON object:
```json
{{"what_it_does": "one sentence",
  "attacker_surface": ["where untrusted input enters: http routes, file parsing, network protocols, IPC, plugins..."],
  "trust_boundaries": ["boundaries where data crosses privilege levels"],
  "high_value_targets": ["files/modules most likely to hold exploitable bugs"],
  "likely_classes": ["most probable vuln classes given the stack"],
  "out_of_scope": ["paths that cannot be attacker-reached"]}}
```
