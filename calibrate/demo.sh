#!/usr/bin/env bash
# demo.sh — judge-facing walkthrough of verified calibration findings.
# Shows each rediscovered CVE and replays its sandbox PoC live.
set -e
cd "$(dirname "$0")/.."

# The live replay needs the Docker daemon — a rebooted laptop must not
# surface a raw docker error mid-demo. Auto-start and wait, fail loudly.
if ! docker info >/dev/null 2>&1; then
  echo "[demo] Docker daemon down — starting Docker Desktop..."
  open -a Docker 2>/dev/null || open -a "Docker Desktop" 2>/dev/null || true
  for i in $(seq 1 30); do
    docker info >/dev/null 2>&1 && break
    [ "$i" = 30 ] && { echo "[demo] FATAL: Docker did not come up in 30s — live replay will fail"; exit 1; }
    sleep 2
  done
  echo "[demo] Docker up."
fi

echo "=== Scoreboard ==="
uv run python -m calibrate.score findings/

echo; echo "=== Verified findings ==="
uv run python - <<'PY'
import json, pathlib
for f in sorted(pathlib.Path("findings").glob("*/findings.jsonl")):
    for l in f.open():
        d = json.loads(l)
        if d["status"] == "verified":
            print(f"\n■ {f.parent.name} — {d['vuln_class']} "
                  f"@ {d['file']}:{d['line']} (conf {d['confidence']})")
            for line in d["detail"].splitlines():
                if "Reproduce:" in line:
                    print("  " + line.strip())
PY

echo; echo "=== Live replay (first verified finding's probe) ==="
# find a verified finding's probe dir and rerun it
uv run python - <<'PY'
import json, pathlib, subprocess, sys
for f in sorted(pathlib.Path("findings").glob("*/findings.jsonl")):
    for l in f.open():
        d = json.loads(l)
        if d["status"] == "verified":
            for line in d["detail"].splitlines():
                if "Reproduce:" in line:
                    cmd = line.split("Reproduce:", 1)[1].strip().split()
                    print("$", " ".join(cmd))
                    sys.exit(subprocess.run(cmd).returncode)
print("no verified finding with reproduce cmd — run a scan first")
PY
