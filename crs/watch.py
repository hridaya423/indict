"""Watch daemon — rescan registry repos when new commits land.

Per entry per cycle: fetch (remote clones only), compare HEAD against the
last scanned sha in state.json, run the pipeline when it moved (full scan
first time, differential --since rescan after), then alert on any finding
id that wasn't in the previous findings.jsonl. One broken repo never kills
the daemon. Watch scans default to the deterministic sweep (no LLM) — run
LLM hunts manually via ./scan; alerts fire either way.
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import yaml

from . import alerts, pipeline, state
from .pipeline import FINDINGS
from .store import load as store_load


def _resolve(entry: dict, work_root: Path) -> Path:
    """Local paths pass through; remote URLs clone once under targets/ —
    same layout as pipeline.ingest, so scans reuse the clone."""
    url = str(entry["url"])
    p = Path(url).expanduser()
    if p.exists():
        return p.resolve()
    stem = Path(url).stem.replace(".git", "")
    local = work_root / "targets" / stem
    if not local.exists():
        local.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth", "200", url, str(local)],
                       check=True, timeout=600)
    return local


def _git(local: Path, *args: str) -> str | None:
    r = subprocess.run(["git", "-C", str(local), *args], capture_output=True,
                       text=True, timeout=60)
    return r.stdout.strip() if r.returncode == 0 else None


def _cycle(entry: dict, local: Path, work_root: Path, cli_models: list,
           budget: int, no_llm: bool) -> None:
    name = local.name
    if not Path(str(entry["url"])).expanduser().exists():   # remote clone
        try:
            subprocess.run(["git", "-C", str(local), "fetch", "--quiet",
                            "origin"], check=True, timeout=120)
            # fetch alone doesn't move HEAD — fast-forward the tracked
            # branch so new commits are actually visible to the daemon
            subprocess.run(["git", "-C", str(local), "merge", "--ff-only",
                            "--quiet"], capture_output=True, timeout=60)
        except Exception as e:
            print(f"[watch] {name}: fetch failed: {e} — skipping cycle",
                  flush=True)
            return
    head = _git(local, "rev-parse", "HEAD")
    if head is None:
        print(f"[watch] {name}: no git head", flush=True)
        return
    fdir = work_root / name          # mirrors pipeline: out_dir = work_root/root.name
    st = state.read(fdir)
    if head == st["last_sha"]:
        print(f"[watch] {name}: unchanged", flush=True)
        return
    old_ids = {f.id for f in store_load(fdir / "findings.jsonl")}
    models = [str(m) for m in (entry.get("models") or [])] or cli_models
    kw = dict(no_llm=no_llm, models_only=models or None, out_root=work_root,
              hunt_budget_min=int(entry.get("budget") or budget))
    if st["last_sha"] is None:
        print(f"[watch] {name}: first scan at {head[:8]}", flush=True)
    else:
        print(f"[watch] {name}: new commits {st['last_sha'][:8]}→"
              f"{head[:8]} — rescanning", flush=True)
        kw["since"] = st["last_sha"]
    pipeline.run(str(local), **kw)
    # pipeline recorded fresh state — alert on ids that just appeared
    new = [f for f in store_load(fdir / "findings.jsonl")
           if f.id not in old_ids and f.status != "dismissed"]
    for f in new:
        alerts.emit(name, f, "new-verified" if f.status == "verified"
                    else "new-adjudicated", out_root=work_root)
    # closed-loop opt-ins (env): auto-file issues / auto-dispatch fixes on
    # verified findings only — adjudicated stays human-triaged
    if os.environ.get("CRS_AUTO_ISSUE") == "1" and new:
        try:
            from . import issues
            from .llms import Client, load_models
            issues.run(name, work_root, Client(load_models()),
                       file_issues=True)
        except Exception as e:
            print(f"[watch] {name}: auto-issue failed: {e}", flush=True)
    if os.environ.get("CRS_FIX_AUTO") == "1":
        from . import fix
        for f in new:
            if f.status == "verified" and "fix-verified" not in f.tags:
                try:
                    fix.run(name, f.id, work_root, root=local)
                except Exception as e:
                    print(f"[watch] {name}: auto-fix {f.id} failed: {e}",
                          flush=True)


def main(registry: Path, models: str | None = None, budget: int = 0,
         once: bool = False, no_llm: bool = True,
         out_root: Path | None = None) -> None:
    registry = Path(registry)
    if not registry.exists():
        print(f"[watch] no registry at {registry} — copy watch.yaml.example",
              flush=True)
        raise SystemExit(1)
    entries = yaml.safe_load(registry.read_text()) or []
    work_root = out_root or FINDINGS
    cli_models = [m.strip() for m in models.split(",") if m.strip()] \
        if models else []
    resolved = []
    for e in entries:
        try:
            if not isinstance(e, dict) or "url" not in e:
                raise ValueError("entry must be a {url: ...} mapping")
            resolved.append((e, _resolve(e, work_root)))
        except Exception as ex:
            print(f"[watch] bad entry {e!r:.80}: {ex}", flush=True)
    try:
        while True:
            for entry, local in resolved:
                try:
                    _cycle(entry, local, work_root, cli_models, budget,
                           no_llm)
                except Exception as e:
                    print(f"[watch] {local.name}: {e}", flush=True)
            if once or os.environ.get("CRS_WATCH_ONCE") == "1":
                return
            interval = int(os.environ.get("CRS_WATCH_INTERVAL", "120"))
            print(f"[watch] sleeping {interval}s", flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("[watch] stopped", flush=True)
