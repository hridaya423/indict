"""Event stream + liveness — the board's data layer.

events.jsonl is append-only across runs; every row carries a `run` id so
readers can scope "this scan" vs history without us ever truncating.
live.json is an atomic heartbeat (tmp + os.replace, same as state.json):
any emit() touches it, the watch daemon heartbeats it, and a run-end
marks it done. Liveness = fresh mtime-side ts AND not done. Never raises.

Structured rows (schemaVersion 1) add `kind`, `stageId`, `attempt`,
`completed`/`total`/`unit`, `outcome`, `reason` — old readers ignore them,
old rows stay readable as legacy (no schemaVersion). Kinds: run-start,
stage-start, stage-progress, stage-end, finding-observed,
verification-result, engine-outcome, run-end.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

LIVE_TTL = 90.0  # seconds — a live.json older than this reads as dead
SCHEMA = 1

_beats: dict[str, threading.Event] = {}


def _touch_live(out_dir: Path, **fields) -> None:
    try:
        path = out_dir / "live.json"
        prior: dict = {}
        try:
            prior = json.loads(path.read_text())
        except Exception:
            pass
        live = {"pid": os.getpid(), "ts": time.time(),
                "daemon": False, "done": False}
        if "run" in fields:
            # a same-run emit inherits liveness flags (mid-run emits must not
            # clear `done`); a different run id resets them
            if fields["run"] == prior.get("run"):
                live["daemon"] = prior.get("daemon", False)
                live["done"] = prior.get("done", False)
        else:
            # run-less emits (writeup/learn/watch notes) must neither
            # resurrect a finished run nor unlink the live one
            for k in ("run", "daemon", "done"):
                if k in prior:
                    live[k] = prior[k]
        live.update(fields)
        # per-writer tmp name — the heartbeat thread and emit() race on a
        # shared "live.json.tmp" and one's os.replace eats the other's file
        tmp = out_dir / f"live.json.tmp.{os.getpid()}.{threading.get_ident()}"
        tmp.write_text(json.dumps(live))
        os.replace(tmp, path)
    except Exception:
        pass


def emit(out_dir: Path, stage: str, msg: str, *, level: str = "info",
         run: str | None = None, finding: str | None = None,
         **fields) -> None:
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        row = {"ts": time.time(), "run": run, "stage": stage, "msg": msg,
               "level": level, "finding": finding or ""}
        if fields:
            row["schemaVersion"] = SCHEMA
            # absent stays absent — no zeroed-out placeholders
            row.update({k: v for k, v in fields.items() if v is not None})
        with (out_dir / "events.jsonl").open("a") as f:
            f.write(json.dumps(row) + "\n")
    except Exception:
        return
    lf = {"stage": stage}
    if run is not None:
        lf["run"] = run
    _touch_live(out_dir, **lf)


def stage_start(out_dir: Path, stage_id: str, run: str | None = None,
                attempt: int = 1, msg: str | None = None) -> None:
    emit(out_dir, stage_id, msg or f"{stage_id} started", run=run,
         kind="stage-start", stageId=stage_id, attempt=attempt)


def stage_end(out_dir: Path, stage_id: str, msg: str,
              run: str | None = None, attempt: int = 1,
              outcome: str = "completed", reason: str | None = None,
              level: str = "info", finding: str | None = None,
              **fields) -> None:
    emit(out_dir, stage_id, msg, run=run, level=level, finding=finding,
         kind="stage-end", stageId=stage_id, attempt=attempt,
         outcome=outcome, reason=reason, **fields)


def progress(out_dir: Path, stage_id: str, completed: int, total: int | None,
             unit: str, run: str | None = None, attempt: int = 1,
             msg: str | None = None, **fields) -> None:
    emit(out_dir, stage_id,
         msg or (f"{completed} / {total} {unit}" if total is not None
                 else f"{completed} {unit}"),
         run=run, kind="stage-progress", stageId=stage_id, attempt=attempt,
         completed=completed, total=total, unit=unit, **fields)


def heartbeat(out_dir: Path, **fields) -> None:
    """Liveness without an event row — the watch daemon's per-cycle beat.
    A beat asserts liveness: it clears `done` and carries no run id."""
    _touch_live(out_dir, run=None, done=False, **fields)


def start_beating(out_dir: Path, run: str, interval: float = 30.0) -> None:
    """Keep live.json fresh through emit-silent stages (engine loops can go
    minutes between events — TTL is 90s). The beat exits when the run marks
    done, when a different run owns live.json, or when a later run on the
    same dir replaces it. Same-run _touch_live inherits `done`, so a beat
    can never resurrect a finished run."""
    key = str(out_dir)
    old = _beats.pop(key, None)
    if old:
        old.set()
    stop = threading.Event()
    _beats[key] = stop

    def _b() -> None:
        while not stop.wait(interval):
            cur = live(out_dir) or {}
            if cur.get("done") or cur.get("run") not in (None, run):
                break
            _touch_live(out_dir, run=run, stage=cur.get("stage"))

    threading.Thread(target=_b, daemon=True).start()


def begin_run(out_dir: Path, run: str) -> None:
    emit(out_dir, "run", "scan started", run=run, kind="run-start")


def end_run(out_dir: Path, run: str, ok: bool = True,
            reason: str | None = None) -> None:
    emit(out_dir, "run", "scan complete" if ok else "scan failed",
         level="info" if ok else "kill", run=run, kind="run-end",
         outcome="completed" if ok else "failed", reason=reason)
    _touch_live(out_dir, run=run, stage="run", done=True)


def read(out_dir: Path, limit: int = 0) -> list[dict]:
    path = out_dir / "events.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue  # torn tail line mid-write — skip it, keep the rest
    return out[-limit:] if limit else out


def live(out_dir: Path) -> dict | None:
    """live.json contents with a computed `live` flag; None if unreadable."""
    try:
        d = json.loads((out_dir / "live.json").read_text())
    except Exception:
        return None
    d["live"] = (not d.get("done")) and (time.time() - d.get("ts", 0)
                                         <= LIVE_TTL)
    return d
