"""score.py — did the pipeline rediscover the known vuln?

Usage: python -m calibrate.score <findings_dir>/<target_name>
Checks findings.jsonl for file_hint + vuln_class match against targets.yaml.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    targets = {t["name"]: t for t in
               yaml.safe_load((ROOT / "calibrate" / "targets.yaml")
                              .read_text())}
    # map findings dir name -> target (dir name is repo name)
    repo_arg = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "findings"
    if (repo_arg / "findings.jsonl").exists():
        dirs = [repo_arg]
    else:
        dirs = [d for d in sorted(repo_arg.iterdir())
                if d.is_dir() and (d / "findings.jsonl").exists()]
    rows = []
    for d in dirs:
        fjson = d / "findings.jsonl"
        if not fjson.exists():
            continue
        t = next((v for k, v in targets.items() if k.split("-")[0] in d.name),
                 None)
        finds = [json.loads(l) for l in fjson.read_text().splitlines()]
        live = [f for f in finds if f["status"] in ("adjudicated", "verified")]
        hit = None
        if t:
            hint = re.compile(t["expect"]["file_hint"], re.I)
            # verified outranks adjudicated — report the strongest match
            for f in sorted(live, key=lambda f: f["status"] != "verified"):
                if (hint.search(f["file"]) and
                        f["vuln_class"] in t["expect"]["classes"]):
                    hit = f
                    break
        rows.append({
            "repo": d.name,
            "expected": t["name"] if t else "?",
            "scored": bool(t),
            "hit": bool(hit),
            "hit_status": hit["status"] if hit else "-",
            "live_findings": len(live),
            "dismissed": sum(1 for f in finds if f["status"] == "dismissed"),
            # fraction of pipeline output killed before report — a proxy for
            # noise, not a true FP rate (unknown-target dirs aren't scored)
            "dismissed_rate": round(1 - len(live) / max(len(finds), 1), 2)})
    print(json.dumps(rows, indent=2))
    scored = [r for r in rows if r["scored"]]
    hits = sum(r["hit"] for r in scored)
    print(f"\n{hits}/{len(scored)} known vulns rediscovered"
          + (f" ({len(rows) - len(scored)} unscored dirs)" if len(rows) > len(scored) else ""))


if __name__ == "__main__":
    main()
