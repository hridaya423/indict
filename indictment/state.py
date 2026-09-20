"""Per-repo scan state — findings/<repo>/state.json, atomically written.

The watch daemon diffs last_sha/finding_ids between cycles; --status
renders the same file as a one-line health check.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path


def _default() -> dict:
    return {"last_sha": None, "last_scan": 0.0, "finding_ids": [],
            "counts": {}}


def read(repo_dir: Path) -> dict:
    try:
        return {**_default(),
                **json.loads((repo_dir / "state.json").read_text())}
    except Exception:                      # missing or corrupt — start over
        return _default()


def write(repo_dir: Path, state: dict) -> None:
    repo_dir.mkdir(parents=True, exist_ok=True)
    tmp = repo_dir / "state.json.tmp"
    tmp.write_text(json.dumps(state, indent=2))
    os.replace(tmp, repo_dir / "state.json")


def record(repo_dir: Path, root: Path, findings: list) -> dict:
    """Snapshot a finished scan: git HEAD, timestamp, live finding ids."""
    st = read(repo_dir)
    try:
        r = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            st["last_sha"] = r.stdout.strip()
    except Exception:
        pass                              # not a git repo — keep prior sha
    st["last_scan"] = time.time()
    st["finding_ids"] = sorted(f.id for f in findings
                               if f.status in ("adjudicated", "verified"))
    st["counts"] = {s: sum(1 for f in findings if f.status == s)
                    for s in ("verified", "adjudicated", "dismissed")}
    write(repo_dir, st)
    return st
