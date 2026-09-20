# auto-imported by python at startup. When CRS_TRACE=1, records every
# executed (file, line) under /src and dumps /poc/trace.json at exit —
# the PoC stage checks the reported vuln line actually executed.
import atexit
import json
import os
import sys


def _dump():
    try:
        with open("/poc/trace.json", "w") as fh:
            json.dump(sorted(_seen), fh)
    except Exception:
        pass


_seen = set()
if os.environ.get("CRS_TRACE") == "1":
    def _tr(frame, event, arg):
        fn = frame.f_code.co_filename
        if not fn.startswith("/src/"):
            return None  # skip stdlib/site-packages frames entirely
        if event == "line":
            _seen.add((fn, frame.f_lineno))
        return _tr
    try:
        sys.settrace(_tr)
        threading = sys.modules.get("threading")
        if threading:  # propagate to threads the PoC spawns
            threading.settrace(_tr)
        atexit.register(_dump)
    except Exception:
        pass
