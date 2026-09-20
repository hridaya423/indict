"""--pack — export a finding's evidence as a runnable, hash-manifested
bundle. `tar xzf <id>.tar.gz && bash <id>/RUN.sh /path/to/target-repo`
replays the recorded PoC and exits 0 only if the success signal fires.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
from pathlib import Path

from .poc import RUN_POC
from .store import load as store_load, load_jsonl

RUN_SH = '''#!/usr/bin/env bash
# Usage: RUN.sh <path-to-target-repo> — replays the recorded PoC.
# Exit 0 only when the recorded success signal fires.
set -u
REPO="${1:?usage: RUN.sh <path-to-target-repo>}"
DIR="$(cd "$(dirname "$0")" && pwd)"

# the recorded contract: which script, which runtime, which signal
SCRIPT=""; SIGNAL=""; LANG="python"
if [ -f "$DIR/poc/rerun.json" ]; then
  eval "$(python3 - "$DIR/poc/rerun.json" <<'PY'
import json, shlex, sys
d = json.load(open(sys.argv[1]))
for k, v in (("SCRIPT", d.get("script", "")),
             ("LANG", d.get("lang", "python")),
             ("SIGNAL", str(d.get("signal", "")))):
    print(f"{k}={shlex.quote(str(v))}")
PY
)"
else
  for s in "$DIR"/poc/repro*.sh "$DIR"/poc/probe.sh; do
    [ -f "$s" ] && SCRIPT="$(basename "$s")" && break
  done
fi
[ -n "$SCRIPT" ] || { echo "no runnable PoC in $DIR/poc"; exit 2; }

OUT="$(mktemp -t indictment-pack)"
trap 'rm -f "$OUT"' EXIT
if command -v docker >/dev/null 2>&1; then
  bash "$DIR/run_poc.sh" "$REPO" "$DIR/poc" "$LANG" "$SCRIPT" >"$OUT" 2>&1
else
  echo "UNSANDBOXED host replay — docker unavailable" >"$OUT"
  (cd "$REPO" && PYTHONPATH="$REPO${PYTHONPATH:+:$PYTHONPATH}" \
      bash "$DIR/poc/$SCRIPT") >>"$OUT" 2>&1
fi
cat "$OUT"

if [ -z "$SIGNAL" ]; then
  echo "WARN: no rerun.json — success signal unknown, cannot self-verify"
  exit 2
fi
if grep -qF -- "$SIGNAL" "$OUT"; then
  echo "VERIFIED — recorded success signal fired"
  exit 0
fi
echo "FAILED — recorded success signal absent"
exit 1
'''


def run(repo: str, finding_id: str, out_root: Path) -> Path | None:
    fdir = out_root / repo
    f = next((x for x in store_load(fdir / "findings.jsonl")
              if x.id == finding_id or x.id.startswith(finding_id)), None)
    if f is None:
        f = next((c for c in store_load(fdir / "candidates.jsonl")
                  if c.id == finding_id or c.id.startswith(finding_id)), None)
    if f is None:
        print(f"[pack] no finding {finding_id} in {fdir}")
        return None
    src_poc = fdir / "poc" / f.id
    if not src_poc.is_dir():
        print(f"[pack] {f.id}: no poc dir at {src_poc} — nothing to bundle")
        return None

    packs = fdir / "packs"
    bdir = packs / f.id
    if bdir.exists():
        shutil.rmtree(bdir)
    bdir.mkdir(parents=True)

    (bdir / "finding.json").write_text(
        json.dumps(f.model_dump(), indent=1) + "\n")
    print(f"[pack] wrote {bdir / 'finding.json'}")

    # latest writeup for this id wins; fall back to the verdict text
    writeup = ""
    for rec in load_jsonl(fdir / "writeups.jsonl"):
        if rec.get("id") == f.id:
            writeup = rec.get("text") or writeup
    writeup = writeup or f.verdict or f.title or "(no writeup recorded)"
    (bdir / "writeup.md").write_text(writeup.rstrip("\n") + "\n")

    rpt = fdir / "findings" / f"{f.id}.md"
    if rpt.exists():
        shutil.copy2(rpt, bdir / "report.md")

    shutil.copytree(src_poc, bdir / "poc")
    shutil.copy2(RUN_POC, bdir / "run_poc.sh")
    print(f"[pack] copied {src_poc} -> {bdir / 'poc'}")

    run_sh = bdir / "RUN.sh"
    run_sh.write_text(RUN_SH)
    run_sh.chmod(0o755)

    claim = next((l.strip() for l in writeup.splitlines() if l.strip()), "")
    (bdir / "README.md").write_text(f"""# Evidence pack — {f.title or f.vuln_class}

- **ID**: `{f.id}`
- **Class**: {f.vuln_class} | **Severity**: {f.severity} \
| **Status**: {f.status}
- **Location**: `{f.file}:{f.line}`
- **Engine**: {f.engine} | **Model**: {f.model or '-'}

{claim}

## Contents
`finding.json` (finding record), `writeup.md`, `report.md`,
`poc/` (PoC artifacts; `rerun.json` holds the replay contract),
`run_poc.sh` (sandboxed runner), `RUN.sh` (replay harness),
`MANIFEST.sha256` (integrity manifest).

## Usage
```bash
shasum -c MANIFEST.sha256           # tamper check
bash RUN.sh /path/to/target-repo    # exit 0 = recorded signal fired
```

With docker, RUN.sh replays inside the locked-down indictment-sandbox container
(no network, repo read-only at /src). Without docker it runs the script
directly on the host — unsandboxed, honest about it.
""")

    lines = []
    for p in sorted(bdir.rglob("*")):
        if p.is_file() and p.name != "MANIFEST.sha256":
            lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  "
                         f"{p.relative_to(bdir).as_posix()}")
    (bdir / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")

    tar_path = packs / f"{f.id}.tar.gz"
    with tarfile.open(tar_path, "w:gz") as t:
        t.add(bdir, arcname=f.id)
    print(f"[pack] wrote {tar_path}")
    print(f"[pack] judge: tar xzf {tar_path.name} && "
          f"bash {f.id}/RUN.sh /path/to/target-repo")
    return tar_path
