#!/usr/bin/env bash
# snare-chain.sh — live pen-test demo: boot snare (webhook daemon) as a
# real service, fire crafted webhooks at it (no sig / bad sig / valid
# sig), and show whether the HMAC gate holds or command execution fires.
# Everything stays on localhost inside a no-egress docker network.
set -e
cd "$(dirname "$0")/.."
REPO="$(pwd)/targets/snare"
[ -d "$REPO" ] || { echo "targets/snare missing — git clone it first"; exit 1; }

echo "=== booting snare service (build + up, localhost-only) ==="
uv run python - <<PY
from pathlib import Path
from crs.service import template_boot
h = template_boot(Path("service/templates/snare"), Path("$REPO"), "8011")
assert h, "boot failed — see [service] output above"
print(f"snare live at {h.base_url} (network {h.project}_default, no egress)")
PY

echo; echo "=== firing webhook probes (no sig / bad sig / valid sig) ==="
uv run python - <<PY
import pathlib
from crs.store import Finding
from crs.service import ServiceHandle, FINDINGS
from crs.httpprobes import probe_for
# reconstruct the handle the boot created (same project/shared paths)
shared = FINDINGS / "snare" / "service-shared"
h = ServiceHandle(repo="snare", base_url="http://127.0.0.1:8011",
                  project="crs-snare", shared=shared, ports=["8011"])
f = Finding(engine="demo", file="src/httpserver.rs", line=1,
            vuln_class="cmd-injection", severity="high", confidence=0.7,
            title="webhook signature gate", detail="x" * 100, poc="",
            status="adjudicated")
t = probe_for(f, h)
assert t, "no probe template for webhook shape"
script, signal = t
pdir = FINDINGS / "snare" / "poc" / "demo"
pdir.mkdir(parents=True, exist_ok=True)
(pdir / "service-probe.sh").write_text(script)
print("--- probe output ---")
out = h.run_probe(pdir, "service-probe.sh")
print(out)
print("--- verdict ---")
if signal in out:
    print("CHAIN CONFIRMED: webhook led to command execution")
else:
    print("DEFENSE HELD: HMAC gate rejected unsigned/forged requests "
          "(an honest result — the probe proves the control works)")
PY

echo; echo "=== teardown ==="
docker compose -p crs-snare -f findings/snare/compose.crs.yml down -v \
  --remove-orphans 2>/dev/null || true
echo "done."
