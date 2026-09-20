"""Board data — read-only projections over findings/<repo>/ for /api/v1.

The scanner writes; the board reads. Everything here tolerates missing,
torn, or legacy records: unknown stays null, never zeroed or inferred.
Per-repo parse failures surface as warnings + an unavailable repo row —
one corrupt directory never disappears and never sinks the board.

Identity rules:
- runs come from runs/<run>/run.json + run-scoped events; legacy rows
  (no schemaVersion) synthesize intervals from first-seen stage order.
- findings for the latest run read current findings.jsonl (that run wrote
  it); historical runs read their frozen snapshot or report "unavailable".
- `verified` + no verification.jsonl => "recorded-verified" — never claim
  a signal matched without the structured record.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

from . import events as ev
from .state import read as state_read
from .store import load as store_load
from .writeup import load as writeup_load

LIVE_TTL = ev.LIVE_TTL
STATUSES = ("candidate", "adjudicated", "verified", "dismissed")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
STATUS_ORDER = {"verified": 0, "adjudicated": 1, "candidate": 2,
                "dismissed": 3}
STAGE_LABELS = {"poc": "Verify", "adjudicate": "Adjudicate",
                "sweep": "Sweep", "rank": "Rank", "ingest": "Ingest",
                "recon": "Recon", "consensus": "Consensus", "hunt": "Hunt",
                "report": "Report", "writeup": "Writeup", "learn": "Learn",
                "chain": "Chain", "run": "Run", "falsify": "Falsify",
                "watch": "Watch", "since": "Scope"}
REPO_MARKERS = ("findings.jsonl", "events.jsonl", "live.json",
                "state.json", "runs", "candidates.jsonl")
PREVIEW_CAP = 64 * 1024
SOURCE_PAD = 100

_cache: dict = {}
_CACHE_MAX = 4000


def _stat_key(path: Path) -> tuple | None:
    try:
        s = path.stat()
    except OSError:
        return None
    return (s.st_mtime_ns, s.st_size)


def _cached(path: Path, loader):
    """Stat-keyed parse cache — rewrite/replace invalidates; a truncated
    or appended file re-parses. Bounded so a polling session can't grow
    it forever."""
    try:
        key = (str(path), _stat_key(path))
    except Exception:
        return loader(path)
    if key[1] is None:
        return loader(path)
    if key in _cache:
        return _cache[key]
    if len(_cache) > _CACHE_MAX:
        _cache.clear()
    val = loader(path)
    _cache[key] = val
    return val


def _jsonl(path: Path) -> tuple[list[dict], int]:
    """(rows, malformed) — torn tails skipped; committed-but-malformed rows
    counted so the API can report incomplete data."""
    if not path.exists():
        return [], 0
    rows, bad = [], 0
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception:
            bad += 1
            continue
        if isinstance(row, dict):
            rows.append(row)
        else:
            bad += 1
    return rows, bad


def _json(path: Path) -> dict | None:
    try:
        d = json.loads(path.read_text(errors="replace"))
        return d if isinstance(d, dict) else None
    except Exception:
        return None


def _fid(row: dict) -> str:
    if row.get("id"):
        return row["id"]
    raw = f"{row.get('engine', '')}|{row.get('file', '')}|" \
          f"{row.get('line', 0)}|{row.get('vuln_class', '')}|" \
          f"{row.get('title', '')}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def _calib_names(root: Path) -> set:
    """calibrate/targets.yaml names — golden fixtures, hidden from the board."""
    for cand in (root.parent / "calibrate" / "targets.yaml",
                 Path(__file__).resolve().parent.parent /
                 "calibrate" / "targets.yaml"):
        if cand.exists():
            try:
                import yaml
                return {str(e.get("name")) for e in
                        (yaml.safe_load(cand.read_text()) or [])
                        if isinstance(e, dict) and e.get("name")}
            except Exception:
                return set()
    return set()


def _repo_dirs(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    calib = _calib_names(root)
    out = []
    for d in sorted(root.iterdir(), key=lambda p: p.name):
        if not d.is_dir() or d.name in ("targets", "packs") or d.name in calib:
            continue
        if any((d / m).exists() for m in REPO_MARKERS):
            out.append(d)
    return out


def _registry(root: Path) -> list[dict]:
    """watch.yaml entries — registered repos that may have no results yet."""
    for cand in (root.parent / "watch.yaml",
                 Path(__file__).resolve().parent.parent / "watch.yaml"):
        if cand.exists():
            try:
                import yaml
                entries = yaml.safe_load(cand.read_text()) or []
                return [e for e in entries if isinstance(e, dict)
                        and e.get("url")]
            except Exception:
                return []
    return []


def _reg_name(url: str) -> str:
    p = Path(url).expanduser()
    if p.exists():
        return p.resolve().name
    return Path(url).stem.replace(".git", "") or url


def _events(repo_dir: Path) -> tuple[list[dict], int]:
    return _cached(repo_dir / "events.jsonl", _jsonl)


def _live(repo_dir: Path) -> dict | None:
    d = ev.live(repo_dir)
    if d is not None:
        d["stale"] = not d.get("done") and not d.get("live")
    return d


def _run_ids(repo_dir: Path) -> dict[str, dict]:
    """run id -> {record, events} from runs/<run>/run.json + events.jsonl."""
    runs: dict[str, dict] = {}
    rroot = repo_dir / "runs"
    if rroot.is_dir():
        for d in sorted(rroot.iterdir()):
            if not d.is_dir():
                continue
            rec = _json(d / "run.json") if (d / "run.json").exists() else None
            if rec is not None or (d / "findings.jsonl").exists():
                runs[d.name] = {"record": rec, "events": []}
    for e in _events(repo_dir)[0]:
        r = e.get("run")
        if r:
            runs.setdefault(r, {"record": None, "events": []})[
                "events"].append(e)
    return runs


def _stages(evts: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """(intervals, pending, lanes) — structured stage-start/end pairs win;
    legacy rows synthesize intervals from first-seen stage order. Engine
    outcomes become their own lanes (concurrent work never sums into
    elapsed wall time)."""
    if any(e.get("kind") in ("stage-start", "stage-end") for e in evts):
        intervals, pending, open_ = [], [], {}
        for e in evts:
            kind = e.get("kind")
            sid = e.get("stageId") or e.get("stage")
            if not sid or kind not in ("stage-start", "stage-end"):
                continue
            if kind == "stage-start":
                iv = {"id": sid, "label": STAGE_LABELS.get(sid, sid),
                      "startedAt": e["ts"], "endedAt": None,
                      "state": "running", "attempt": e.get("attempt", 1),
                      "reason": None}
                open_[(sid, e.get("attempt", 1))] = iv
                intervals.append(iv)
            else:
                outcome = e.get("outcome") or "completed"
                iv = open_.pop((sid, e.get("attempt", 1)), None)
                if iv is None:
                    if outcome == "skipped":
                        pending.append(
                            {"id": sid, "label": STAGE_LABELS.get(sid, sid),
                             "state": "skipped", "reason": e.get("reason")})
                        continue
                    iv = {"id": sid, "label": STAGE_LABELS.get(sid, sid),
                          "startedAt": None, "state": outcome,
                          "attempt": e.get("attempt", 1)}
                    intervals.append(iv)
                iv["endedAt"] = e["ts"]
                if e.get("durationMs") is not None:
                    iv["startedAt"] = e["ts"] - e["durationMs"] / 1000.0
                iv["state"] = outcome
                iv["reason"] = e.get("reason")
                iv["msg"] = e.get("msg")
        for iv in open_.values():
            iv["state"] = "running"
        lanes = [{"id": e.get("stage") or e.get("engine"),
                  "label": e.get("stage") or e.get("engine"),
                  "engine": e.get("engine"), "model": e.get("model"),
                  "outcome": e.get("outcome"), "reason": e.get("reason"),
                  "added": e.get("added"),
                  "startedAt": (e["ts"] - e["durationMs"] / 1000.0)
                  if e.get("durationMs") is not None else None,
                  "endedAt": e["ts"],
                  "state": e.get("outcome") or "completed"}
                 for e in evts if e.get("kind") == "engine-outcome"]
        return intervals, pending, lanes
    first, last = {}, {}
    for e in evts:
        s = e.get("stage") or "run"
        if s == "run":
            continue
        first.setdefault(s, e["ts"])
        last[s] = e["ts"]
    order = sorted(first.items(), key=lambda kv: kv[1])
    keys = [k for k, _ in order]
    intervals = []
    for i, (sid, t0) in enumerate(order):
        end = first[keys[i + 1]] if i + 1 < len(keys) else last[sid]
        intervals.append({"id": sid, "label": STAGE_LABELS.get(sid, sid),
                          "startedAt": t0, "endedAt": end,
                          "state": "completed", "attempt": 1,
                          "reason": None})
    return intervals, [], []


def _progress(evts: list[dict]) -> dict | None:
    rows = [e for e in evts if e.get("kind") == "stage-progress"]
    src = rows[-1] if rows else None
    if src is None:
        ends = [e for e in evts
                if e.get("kind") == "stage-end" and e.get("total")]
        src = ends[-1] if ends else None
    if src is None:
        return None
    return {"completed": src.get("completed"), "total": src.get("total"),
            "unit": src.get("unit"), "stage": src.get("stageId"),
            "msg": src.get("msg")}


def _pid_alive(pid) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except ProcessLookupError:
        return False
    except Exception:                    # EPERM etc — exists, not ours
        return True


# canonical pipeline order — weight ≈ each stage's share of wall clock on a
# mid-size hunt. Used only to fold per-stage progress into one fraction.
STAGE_W = {"ingest": .01, "recon": .02, "sweep": .03, "rank": .01,
           "hunt": .60, "consensus": .01, "adjudicate": .20,
           "poc": .10, "report": .02}
LLM_ENGINES = {"hunter", "taintgen", "explorer", "variant", "fuzzlite"}


def _hunt_units(rec: dict | None) -> int:
    """Expected engine lanes for a run — hunter/explorer run once per pass,
    the rest once. Mirrors the unit list pipeline.run builds."""
    passes = (rec or {}).get("passes") or 1
    n = 0
    for e in (rec or {}).get("engines") or []:
        if e in ("hunter", "explorer"):
            n += max(1, passes)
        elif e in LLM_ENGINES:
            n += 1
    return n


def _eta(rec: dict | None, intervals: list[dict], pending: list[dict],
         lanes: list[dict], evts: list[dict], state: str,
         started: float | None, now: float) -> int | None:
    """Seconds-remaining estimate for a running run. Stage weights carry the
    shape; stage-progress rows (completed/total) and finished engine lanes
    fill in the fraction. Monotone by construction — the number only drifts
    down as work lands, never jumps."""
    if state != "running" or not started:
        return None
    if not any(e.get("schemaVersion") for e in evts):
        return None                       # legacy run — no structured stages
    units_exp = _hunt_units(rec)
    prog: dict[str, float] = {}
    for e in evts:                        # latest progress row per stage
        if e.get("kind") == "stage-progress" and e.get("total"):
            prog[e.get("stageId") or e.get("stage")] = \
                (e.get("completed") or 0) / max(1, e["total"])
    # pending = stage-end rows with outcome "skipped" — a skipped stage did
    # zero work AND took zero time, so it leaves the denominator entirely
    # (crediting it would say "60% done" 30s into a --reuse-candidates run)
    skipped = {p["id"] for p in pending}
    w_sum = sum(w for sid, w in STAGE_W.items() if sid not in skipped)
    if w_sum <= 0:
        return None
    achieved = 0.0
    for iv in intervals:
        w = STAGE_W.get(iv["id"], 0.0)
        if not w:
            continue
        if iv.get("state") == "running":
            if iv["id"] == "hunt":
                done = len(lanes)
                achieved += w * min(0.95, done / max(units_exp, done + 1))
            elif iv["id"] in prog:
                achieved += w * min(0.97, prog[iv["id"]])
            else:
                achieved += w * 0.4       # underway, no counter to cite
        elif iv["id"] not in skipped:
            achieved += w
    frac = min(0.97, max(achieved / w_sum, 0.03))
    return int((now - started) * (1 - frac) / frac)





def _run_state(rid: str, rec: dict | None, evts: list[dict],
               live: dict | None) -> tuple[str, str]:
    """(state, freshness) — separate axes. run.json wins; else terminal
    event rows; else live.json linkage. Stale never implies failed."""
    if rec and rec.get("state"):
        state = rec["state"]
        if state in ("completed", "failed"):
            return state, "unavailable"
        if live and live.get("run") == rid and live.get("live"):
            return state, "fresh"
        if live and live.get("run") == rid:
            return state, "stale"
        # not the live-linked run: the id embeds the launching pid — a dead
        # pid means killed without a terminal record, never "running"
        m = re.match(r"^\d{8}-\d{6}-(\d+)$", rid or "")
        if m and not _pid_alive(int(m.group(1))):
            return "unknown", "unavailable"
        return state, "unavailable"
    term = [e for e in evts if e.get("kind") == "run-end"
            or (e.get("stage") == "run" and str(e.get("msg", ""))
                .startswith(("scan complete", "scan failed")))]
    if term:
        e = term[-1]
        failed = e.get("outcome") == "failed" or e.get("level") == "kill" \
            or "failed" in str(e.get("msg", ""))
        return ("failed" if failed else "completed"), "unavailable"
    if live and live.get("run") == rid:
        if live.get("done"):
            return "completed", "unavailable"
        if live.get("live"):
            return "running", "fresh"
        # heartbeat stale — the pid is the ground truth: alive means the
        # run is just quiet (emit-silent stage), dead means it crashed
        # without ever writing a terminal record
        if _pid_alive(live.get("pid")):
            return "running", "stale"
        return "unknown", "stale"
    if evts:
        return "unknown", "unavailable"
    return "pending", "unavailable"


def _heartbeat(rid: str | None, live: dict | None) -> dict | None:
    if live is None:
        return None
    return {"ts": live.get("ts"), "live": bool(live.get("live")),
            "done": bool(live.get("done")),
            "daemon": bool(live.get("daemon")), "run": live.get("run"),
            "stale": bool(live.get("stale")),
            "matchesRun": bool(rid and live.get("run") == rid)}


def _engine_health(evts: list[dict]) -> str:
    outs = [e for e in evts if e.get("kind") == "engine-outcome"]
    if not outs:
        return "unknown"
    if any(e.get("outcome") == "failed" for e in outs):
        return "degraded"
    return "complete"


def _run_summary(repo_dir: Path, rid: str, rec: dict | None,
                 evts: list[dict], live: dict | None) -> dict:
    state, freshness = _run_state(rid, rec, evts, live)
    intervals, pending, lanes = _stages(evts)
    started = (rec or {}).get("startedAt") \
        or (evts[0]["ts"] if evts else None)
    ended = (rec or {}).get("endedAt")
    if ended is None and state in ("completed", "failed") and evts:
        ended = evts[-1]["ts"]
    running_iv = next((i for i in reversed(intervals)
                       if i.get("state") == "running"), None)
    prog = _progress(evts)
    if running_iv and running_iv["id"] == "hunt":
        # during hunt the file-queue counter drains before engines finish
        # (14/14 files while hunters still churn) — engine lanes are the
        # real completion signal
        exp = _hunt_units(rec)
        if exp:
            prog = {"completed": min(len(lanes), exp), "total": exp,
                    "unit": "engines", "stage": "hunt"}
    elif running_iv and prog and prog.get("stage") \
            and prog.get("stage") != running_iv["id"]:
        # finished stage's counter (poc's "9/10") lingering through the
        # next stage reads as stuck — drop the number, keep nothing stale
        prog = None
    snap = (repo_dir / "runs" / rid / "findings.jsonl").exists()
    return {"id": rid, "state": state, "freshness": freshness,
            "startedAt": started, "endedAt": ended,
            "revision": (rec or {}).get("revision"),
            "target": (rec or {}).get("target"),
            "engines": (rec or {}).get("engines"),
            "models": (rec or {}).get("models"),
            "scope": (rec or {}).get("scope"),
            "error": (rec or {}).get("error"),
            "outcome": (rec or {}).get("outcome"),
            "currentStage": ({"id": running_iv["id"],
                              "label": running_iv["label"]}
                             if running_iv else None),
            "progress": prog,
            "etaSec": _eta(rec, intervals, pending, lanes, evts, state,
                           started, time.time()),
            "stages": intervals, "pendingStages": pending, "lanes": lanes,
            "heartbeat": _heartbeat(rid, live),
            "engineHealth": _engine_health(evts),
            "findingsSource": ("snapshot" if snap else
                               "events" if any(e.get("finding")
                                               for e in evts) else "none"),
            "legacy": not any(e.get("schemaVersion") for e in evts)}


def _latest_run(repo_dir: Path) -> str | None:
    runs = _run_ids(repo_dir)
    if not runs:
        return None
    live = _live(repo_dir)
    if live and live.get("live") and live.get("run") in runs \
            and not live.get("daemon"):
        return live["run"]
    def key(rid: str) -> float:
        rec = runs[rid]["record"] or {}
        evs = runs[rid]["events"]
        return rec.get("startedAt") or (evs[0]["ts"] if evs else 0)
    return max(runs, key=key)


def _verification(repo_dir: Path, fid: str) -> list[dict]:
    rows, _ = _cached(repo_dir / "poc" / fid / "verification.jsonl", _jsonl)
    return rows


SUCCESS_OUTCOMES = ("matched", "verified")


def _scoped_verification(repo_dir: Path, fid: str, rid: str | None,
                         runs: dict, latest: str | None) -> tuple[list, str]:
    """(records, scope) — proof resolved to the exact run, never borrowed.
    Frozen run evidence wins; explicit-run records match by run id; records
    with no run field belong to the run whose time window contains them;
    anything left is the latest run's (mutable) poc dir only."""
    if rid:
        frozen = repo_dir / "runs" / rid / "evidence" / fid / "poc" \
            / "verification.jsonl"
        if frozen.exists():
            rows, _ = _cached(frozen, _jsonl)
            return rows, "frozen"
    rows = _verification(repo_dir, fid)
    if not rid or rid == latest:
        return rows, "current"
    rec = (runs.get(rid) or {}).get("record") or {}
    w0, w1 = rec.get("startedAt"), rec.get("endedAt")
    scoped = []
    for r in rows:
        rr = r.get("run")
        if rr is not None:
            if rr == rid:
                scoped.append(r)
            continue
        t = r.get("endedAt") or r.get("startedAt")
        if t is not None and w0 is not None and w1 is not None \
                and w0 <= t <= w1:
            scoped.append(r)
    return scoped, "run-window"


def _ver_display(repo_dir: Path, row: dict, rid: str | None = None,
                 runs: dict | None = None, latest: str | None = None) -> str:
    st = row.get("status")
    if st != "verified":
        return {"adjudicated": "awaiting", "candidate": "candidate",
                "dismissed": "dismissed"}.get(st, st or "unknown")
    recs, _ = _scoped_verification(
        repo_dir, _fid(row), rid, runs or _run_ids(repo_dir),
        latest if latest is not None else _latest_run(repo_dir))
    return "reproduced" \
        if any(r.get("outcome") in SUCCESS_OUTCOMES for r in recs) \
        else "recorded-verified"


def _fix_map(repo_dir: Path) -> dict[str, dict]:
    """finding id -> verdict.json merged with gate.json checks."""
    out = {}
    fdir = repo_dir / "fixes"
    if not fdir.is_dir():
        return out
    for d in sorted(fdir.iterdir()):
        if not d.is_dir():
            continue
        v = _cached(d / "verdict.json", _json)
        if not v:
            continue
        g = _cached(d / "gate.json", _json)
        out[d.name] = {"verdict": v.get("verdict"),
                       "reason": v.get("reason"),
                       "backend": v.get("backend"), "ts": v.get("ts"),
                       "checks": (g or {}).get("checks"),
                       "baseSha": (g or {}).get("baseSha")}
    return out


def _frow(repo_dir: Path, repo: str, row: dict, fixes: dict,
          latest_run: str | None, source: str,
          runs: dict | None = None, latest: str | None = None) -> dict:
    fid = _fid(row)
    fix = fixes.get(fid)
    return {"id": fid, "repo": repo,
            "title": row.get("title") or "(untitled)",
            "file": row.get("file") or "", "line": row.get("line") or 0,
            "severity": row.get("severity") or "medium",
            "status": row.get("status") or "candidate",
            "verification": _ver_display(repo_dir, row, latest_run,
                                         runs, latest),
            "vulnClass": row.get("vuln_class") or "",
            "engine": row.get("engine") or "",
            "model": row.get("model") or "",
            "confidence": row.get("confidence"),
            "tags": list(row.get("tags") or []),
            "verdict": row.get("verdict") or "",
            "detail": row.get("detail") or "",
            "latestRun": latest_run, "runScope": source,
            "fix": {"verdict": fix["verdict"], "ts": fix["ts"]}
            if fix else None}


def _findings_rows(repo_dir: Path) -> tuple[list[dict], int]:
    return _cached(repo_dir / "findings.jsonl", _jsonl)


def _repo_overview(repo_dir: Path) -> dict:
    name = repo_dir.name
    warnings = []
    live = _live(repo_dir)
    st = state_read(repo_dir)
    rows, bad = _findings_rows(repo_dir)
    funnel = {s: sum(1 for f in rows if f.get("status") == s)
              for s in STATUSES}
    runs = _run_ids(repo_dir)
    rid = _latest_run(repo_dir)
    run = None
    if rid and rid in runs:
        run = _run_summary(repo_dir, rid, runs[rid]["record"],
                           runs[rid]["events"], live)
    _, ebad = _events(repo_dir)
    if bad or ebad:
        warnings.append(
            f"{bad + ebad} malformed record(s) skipped")
    return {"name": name, "registered": None,
            "daemonAlive": bool(live and live.get("daemon")
                                and live.get("live")),
            "state": "ok",
            "lastScan": {"sha": st.get("last_sha"),
                         "ts": st.get("last_scan") or None}
            if st.get("last_scan") else None,
            "latestRun": run, "counts": funnel, "warnings": warnings}


def _run_findings(repo_dir: Path, rid: str) -> dict:
    """Findings scoped to one run: frozen snapshot > current findings.jsonl
    (only when rid IS the latest run — that run wrote it) > event ids."""
    snap = repo_dir / "runs" / rid / "findings.jsonl"
    fixes = _fix_map(repo_dir)
    if snap.exists():
        rows, _ = _cached(snap, _jsonl)
        items = [_frow(repo_dir, repo_dir.name, r, fixes, rid, "snapshot")
                 for r in rows]
        return {"items": items, "total": len(items), "source": "snapshot"}
    if rid == _latest_run(repo_dir):
        rows, _ = _findings_rows(repo_dir)
        items = [_frow(repo_dir, repo_dir.name, r, fixes, rid, "latest")
                 for r in rows]
        return {"items": items, "total": len(items), "source": "latest"}
    ids = [e["finding"] for e in _events(repo_dir)[0]
           if e.get("run") == rid and e.get("finding")]
    byid = {_fid(r): r for r in _findings_rows(repo_dir)[0]}
    items = [_frow(repo_dir, repo_dir.name, byid[i], fixes, rid, "events")
             for i in dict.fromkeys(ids) if i in byid]
    return {"items": items, "total": len(items), "source": "events",
            "referenced": len(set(ids))}


def _run_detail(repo_dir: Path, rid: str) -> dict | None:
    runs = _run_ids(repo_dir)
    if rid not in runs:
        return None
    live = _live(repo_dir)
    s = _run_summary(repo_dir, rid, runs[rid]["record"],
                     runs[rid]["events"], live)
    s["repo"] = repo_dir.name
    s["eventsTail"] = runs[rid]["events"][-3:]
    s["eventsTotal"] = len(runs[rid]["events"])
    s["eventsTailCursor"] = f"e:{max(0, len(runs[rid]['events']) - 3)}"
    fl = _run_findings(repo_dir, rid)
    s["findingsTotal"] = fl["total"]
    s["findingsSource"] = fl["source"]
    return s


def overview(root: Path, repo: str | None = None, run: str | None = None,
             finding: str | None = None) -> dict:
    warnings: list[str] = []
    repos = []
    reg = {_reg_name(e["url"]): e for e in _registry(root)}
    seen = set()
    for d in _repo_dirs(root):
        seen.add(d.name)
        try:
            r = _repo_overview(d)
            r["registered"] = d.name in reg
            repos.append(r)
            warnings.extend(f"{d.name}: {w}" for w in r["warnings"])
        except Exception as e:
            warnings.append(f"{d.name}: unreadable ({e.__class__.__name__})")
            repos.append({"name": d.name, "registered": d.name in reg,
                          "daemonAlive": False, "state": "corrupt",
                          "lastScan": None, "latestRun": None,
                          "counts": {}, "warnings": [
                              f"unreadable: {e.__class__.__name__}"]})
    for nm, e in reg.items():
        if nm not in seen:
            repos.append({"name": nm, "registered": True,
                          "daemonAlive": False, "state": "never-scanned",
                          "lastScan": None, "latestRun": None,
                          "counts": {}, "warnings": [],
                          "watch": {"url": e.get("url"),
                                    "models": e.get("models"),
                                    "budget": e.get("budget")}})

    def rank(r: dict):
        lr = r.get("latestRun")
        if r["state"] == "corrupt":
            return (4, r["name"])
        if lr and lr["state"] == "running" and lr["freshness"] == "fresh":
            return (0, r["name"])
        if lr and (lr["state"] == "running" or lr["freshness"] == "stale"):
            return (1, r["name"])
        if lr:
            return (2, -(lr.get("endedAt") or lr.get("startedAt") or 0))
        return (3, r["name"])

    repos.sort(key=rank)
    counts = {"repos": len(repos), "active": 0, "stale": 0, "complete": 0,
              "failed": 0, "unknown": 0, "neverScanned": 0}
    for r in repos:
        lr = r.get("latestRun")
        if r["state"] == "never-scanned":
            counts["neverScanned"] += 1
        elif not lr:
            counts["unknown"] += 1
        elif lr["state"] == "running" and lr["freshness"] == "fresh":
            counts["active"] += 1
        elif lr["state"] == "running" or lr["freshness"] == "stale":
            counts["stale"] += 1
        elif lr["state"] == "completed":
            counts["complete"] += 1
        elif lr["state"] == "failed":
            counts["failed"] += 1
        else:
            counts["unknown"] += 1

    names = {r["name"] for r in repos}
    sel_repo = repo if repo in names else None
    if sel_repo is None:
        cand = next((r for r in repos if r.get("latestRun")), None)
        sel_repo = cand["name"] if cand else None
    selected = None
    if sel_repo:
        repo_dir = (root / sel_repo).resolve()
        rid = run if (run and run in _run_ids(repo_dir)) \
            else _latest_run(repo_dir)
        rdet = _run_detail(repo_dir, rid) if rid else None
        fl = (_run_findings(repo_dir, rid)
              if rid else {"items": [], "total": 0, "source": "none"})
        selected = {"repo": sel_repo, "run": rdet,
                    "findings": {"items": fl["items"], "total": fl["total"],
                                 "source": fl["source"]}}
        if not finding and fl["items"]:
            pick = next(
                (f for f in fl["items"]
                 if f.get("verification") in ("reproduced", "recorded-verified")),
                fl["items"][0])
            finding = pick["id"]
        if finding:
            selected["proof"] = finding_case(root, sel_repo, finding,
                                             run=rid)
    return {"generatedAt": time.time(), "warnings": warnings,
            "policy": {"heartbeatTtlSeconds": LIVE_TTL},
            "counts": counts, "repos": repos, "selected": selected}


def _eoff(cur: str | None) -> int | None:
    if cur and cur.startswith("e:") and cur[2:].isdigit():
        return int(cur[2:])
    return None


def run_events(repo_dir: Path, rid: str, cursor: str | None, limit: int,
               before: str | None = None,
               after: str | None = None) -> dict | None:
    """Server-owned opaque cursors over the append-only event ledger.
    ?cursor=e:N pages forward from N; ?before=e:N returns up to `limit`
    events immediately preceding N (chronological order); ?after=e:N
    returns everything after N (live tail). Clients never construct
    cursors — they echo back nextCursor/prevCursor."""
    runs = _run_ids(repo_dir)
    if rid not in runs:
        return None
    evs = runs[rid]["events"]
    n = len(evs)
    if before is not None:
        b = _eoff(before)
        b = n if b is None else max(0, min(b, n))
        lo = max(0, b - limit)
        page = evs[lo:b]
        return {"items": page, "total": n,
                "nextCursor": f"e:{b}" if b < n else None,
                "prevCursor": f"e:{lo}" if lo > 0 else None,
                "legacy": not any(e.get("schemaVersion") for e in page),
                "generatedAt": time.time()}
    if after is not None:
        a = _eoff(after)
        a = 0 if a is None else max(0, min(a, n))
        page = evs[a:]
        return {"items": page, "total": n,
                "nextCursor": f"e:{n}" if a < n else None,
                "prevCursor": f"e:{a}" if a > 0 else None,
                "legacy": not any(e.get("schemaVersion") for e in page),
                "generatedAt": time.time()}
    off = _eoff(cursor) or 0
    page = evs[off:off + limit]
    nxt = off + limit
    return {"items": page, "total": n,
            "nextCursor": f"e:{nxt}" if nxt < n else None,
            "prevCursor": f"e:{off}" if off > 0 else None,
            "legacy": not any(e.get("schemaVersion") for e in page),
            "generatedAt": time.time()}


def runs_list(root: Path, repo: str | None, state: str | None,
              cursor: str | None, limit: int) -> dict:
    items = []
    dirs = _repo_dirs(root)
    if repo:
        dirs = [d for d in dirs if d.name == repo]
    for d in dirs:
        live = _live(d)
        runs = _run_ids(d)
        for rid, rec in runs.items():
            s = _run_summary(d, rid, rec["record"], rec["events"], live)
            s["repo"] = d.name
            items.append(s)
    items.sort(key=lambda r: -(r.get("startedAt") or 0))
    if state:
        if state == "stale":
            items = [r for r in items if r["freshness"] == "stale"]
        else:
            items = [r for r in items if r["state"] == state]
    off = int(cursor[2:]) if cursor and cursor.startswith("e:") else 0
    page = items[off:off + limit]
    nxt = off + limit
    return {"items": page, "total": len(items),
            "nextCursor": f"e:{nxt}" if nxt < len(items) else None,
            "generatedAt": time.time(), "warnings": []}


def findings_list(root: Path, repo: str | None, run: str | None,
                  q: str | None, status: str | None, severity: str | None,
                  vclass: str | None, engine: str | None, nofix: bool,
                  sort: str | None, page: int, limit: int) -> dict:
    dirs = _repo_dirs(root)
    warnings = []
    if repo:
        dirs = [d for d in dirs if d.name == repo]
        if not dirs:
            return {"items": [], "total": 0, "page": 1, "pages": 0,
                    "nextCursor": None, "generatedAt": time.time(),
                    "warnings": [f"unknown repo {repo!r}"], "counts": {}}
    scoped = []
    for d in dirs:
        fixes = _fix_map(d)
        latest = _latest_run(d)
        if run:
            if run not in _run_ids(d):
                continue
            fs = _run_findings(d, run)["items"]
        else:
            fs = [_frow(d, d.name, r, fixes, latest, "latest")
                  for r in _findings_rows(d)[0]]
        scoped.extend(fs)
    if q:
        needle = q.lower()
        scoped = [r for r in scoped if needle in r["id"].lower()
                  or needle in r["title"].lower()
                  or needle in r["file"].lower()
                  or needle in r["repo"].lower()
                  or needle in r["vulnClass"].lower()]
    counts = {s: sum(1 for r in scoped if r["status"] == s)
              for s in STATUSES}
    rows = scoped
    if status == "all":
        pass
    elif status in STATUSES:
        rows = [r for r in rows if r["status"] == status]
    else:  # default: dismissed excluded, visibly
        rows = [r for r in rows if r["status"] != "dismissed"]
    if severity:
        rows = [r for r in rows if r["severity"] == severity]
    if vclass:
        rows = [r for r in rows if r["vulnClass"] == vclass]
    if engine:
        rows = [r for r in rows if r["engine"] == engine]
    if nofix:
        rows = [r for r in rows
                if (r.get("fix") or {}).get("verdict") != "fix-verified"]
    if sort == "recent":
        rows.sort(key=lambda r: r["id"], reverse=True)
    else:
        # default: verified (reproduced/recorded) first — proven results lead,
        # then severity ranks within each trust level
        rows.sort(key=lambda r: (STATUS_ORDER.get(r["status"], 4),
                                 SEV_ORDER.get(r["severity"], 5),
                                 r["id"]))
    total = len(rows)
    start = max(0, (page - 1) * limit)
    items = rows[start:start + limit]
    nxt = start + limit
    return {"items": items, "total": total, "page": page,
            "pages": (total + limit - 1) // limit if limit else 1,
            "nextCursor": f"e:{nxt}" if nxt < total else None,
            "generatedAt": time.time(), "warnings": warnings,
            "counts": counts}


def _artifact_id(repo: str, rel: str) -> str:
    return base64.urlsafe_b64encode(
        f"{repo}\0{rel}".encode()).decode().rstrip("=")


def artifact_resolve(root: Path, aid: str) -> tuple[Path | None, str]:
    """Opaque id -> contained file. (path, error-code) — error empty on ok."""
    try:
        raw = base64.urlsafe_b64decode(
            aid + "=" * (-len(aid) % 4)).decode()
        repo, rel = raw.split("\0", 1)
    except Exception:
        return None, "unknown-artifact"
    if ".." in Path(rel).parts or rel.startswith("/"):
        return None, "traversal"
    p = (root / repo / rel).resolve()
    try:
        p.relative_to(root.resolve())
    except ValueError:
        return None, "traversal"
    if not p.is_file():
        return None, "missing"
    return p, ""


TEXT_TYPES = {".txt", ".json", ".jsonl", ".md", ".diff", ".patch",
              ".sh", ".py", ".js", ".ts", ".rs", ".go", ".c", ".java",
              ".log", ".sarif", ".csv", ".yml", ".yaml", ".toml"}


def _artifact_role(rel: str, name: str) -> str:
    """Producer-side role mapping — the UI picks by role, never filename."""
    if rel.startswith("packs/"):
        return "pack"
    n = name.lower()
    if n == "verification.jsonl":
        return "verification"
    if n.startswith("source."):
        return "source"
    if n.endswith((".diff", ".patch")):
        return "patch"
    if re.match(r"^stderr\d*\.txt$", n):
        return "stderr"
    if re.match(r"^(output\d*|service_probe_output|probe_output)\.txt$", n):
        return "stdout"
    if n.endswith(".sh") or n in ("poc.py", "poc.js"):
        return "script"
    return "other"


def _artifact_attempt(name: str) -> int | None:
    m = re.match(r"^(?:output|repro|stderr)(\d+)\.", name)
    if m:
        return int(m.group(1)) + 1
    if re.match(r"^(?:output|repro|stderr)\.", name):
        return 1
    return None


def _artifact_entry(repo: str, rel: str, path: Path,
                    run: str | None = None,
                    trunc: dict | None = None) -> dict:
    try:
        size = path.stat().st_size
    except OSError:
        size = None
    name = path.name
    return {"id": _artifact_id(repo, rel), "name": name, "path": rel,
            "size": size, "type": path.suffix.lstrip(".") or "file",
            "previewable": path.suffix.lower() in TEXT_TYPES,
            "role": _artifact_role(rel, name), "run": run,
            "attempt": _artifact_attempt(name),
            "producerTruncated": bool((trunc or {}).get(name))}


def _dir_artifacts(repo: str, base: Path, repo_dir: Path,
                   run: str | None = None, trunc: dict | None = None
                   ) -> list[dict]:
    out = []
    if not base.is_dir():
        return out
    for p in sorted(base.rglob("*")):
        if p.is_file():
            out.append(_artifact_entry(
                repo, p.relative_to(repo_dir).as_posix(), p,
                run=run, trunc=trunc))
    return out


def _checkout_for(root: Path, repo_dir: Path,
                  rec: dict | None) -> Path | None:
    """A configured local checkout — never cloned/fetched on a GET."""
    cands = []
    tgt = (rec or {}).get("target")
    if tgt:
        base = str(tgt).split("#")[0]
        if Path(base).expanduser().exists():
            cands.append(Path(base).expanduser())
    cands += [root / "targets" / repo_dir.name,
              Path(__file__).resolve().parent.parent / "targets"
              / repo_dir.name]
    for e in _registry(root):
        u = str(e.get("url", ""))
        if _reg_name(u) == repo_dir.name and Path(u).expanduser().exists():
            cands.append(Path(u).expanduser())
    for c in cands:
        try:
            if c.is_dir() and (c / ".git").exists():
                return c.resolve()
        except OSError:
            continue
    return None


def _source_excerpt(root: Path, repo_dir: Path, f: dict, rid: str | None,
                    rec: dict | None,
                    allow_lastscan: bool = True) -> dict:
    """Frozen run evidence first (authoritative recorded revision), then a
    configured checkout at the recorded sha. Never substitutes HEAD. A
    historical run request never borrows the last-scan revision."""
    fid = _fid(f)
    if rid:
        frozen = repo_dir / "runs" / rid / "evidence" / fid
        sj = _json(frozen / "source.json")
        st_file = frozen / "source.txt"
        if sj and st_file.exists():
            return {"available": True, "source": "run-evidence",
                    "revision": (rec or {}).get("revision"),
                    "path": sj.get("file") or f.get("file"),
                    "line": sj.get("line") or f.get("line"),
                    "from": sj.get("from"), "to": sj.get("to"),
                    "lines": st_file.read_text(
                        errors="replace").splitlines()}
    revision = (rec or {}).get("revision")
    rev_src = "run-record"
    if not revision and allow_lastscan:
        revision = state_read(repo_dir).get("last_sha")
        rev_src = "last-scan"
    if not revision:
        return {"available": False,
                "reason": "revision not recorded for this run"}
    checkout = _checkout_for(root, repo_dir, rec)
    if checkout is None:
        return {"available": False,
                "reason": "no local checkout recorded for this repository"}
    try:
        r = subprocess.run(
            ["git", "-C", str(checkout), "show", f"{revision}:{f.get('file')}"],
            capture_output=True, timeout=15)
        if r.returncode != 0:
            return {"available": False,
                    "reason": f"path absent at recorded revision "
                              f"{str(revision)[:8]}"}
        lines = r.stdout.decode(errors="replace").splitlines()
    except Exception:
        return {"available": False, "reason": "checkout unreadable"}
    line = min(max(f.get("line") or 1, 1), len(lines)) if lines else 1
    lo, hi = max(0, line - SOURCE_PAD), min(len(lines), line + SOURCE_PAD)
    return {"available": True, "source": f"git:{rev_src}",
            "revision": revision, "path": f.get("file"), "line": line,
            "from": lo + 1, "to": hi, "lines": lines[lo:hi],
            "truncated": hi < len(lines) or lo > 0}


def finding_case(root: Path, repo: str, fid: str,
                 run: str | None = None) -> dict:
    """One finding case at an exact scope. An explicit run is validated;
    proof/source/artifacts resolve to that run's frozen or window-scoped
    records — current mutable evidence is never presented as historical."""
    out = {"finding": None, "warnings": [], "latestRun": None}
    try:
        repo_dir = (root / repo).resolve()
        if repo_dir != root.resolve() \
                and root.resolve() not in repo_dir.parents:
            return out
    except OSError:
        return out
    if not repo_dir.is_dir():
        return out
    runs = _run_ids(repo_dir)
    latest = _latest_run(repo_dir)
    out["latestRun"] = latest
    if run and run not in runs:
        out["runError"] = "unknown-run"
        return out
    rid = run or latest
    rec = (runs.get(rid) or {}).get("record") if rid else None
    rows, _ = _findings_rows(repo_dir)
    f = None
    snap_used = False
    if rid and rid in runs:
        snap = repo_dir / "runs" / rid / "findings.jsonl"
        if snap.exists():
            snap_used = True
            snap_rows, _ = _cached(snap, _jsonl)
            f = next((x for x in snap_rows if _fid(x) == fid), None)
            if f is None:
                if run:
                    out["runError"] = "not-in-run"
                    return out
                f = next((x for x in rows if _fid(x) == fid), None)
                if f is not None:
                    out["warnings"].append(
                        "finding absent from the latest run's snapshot; "
                        "showing the current record")
        else:
            f = next((x for x in rows if _fid(x) == fid), None)
            if f is not None and rid != latest:
                out["warnings"].append(
                    "no snapshot for this run — showing the current finding "
                    "record; run-scoped fields may differ")
    else:
        f = next((x for x in rows if _fid(x) == fid), None)
    if f is None:
        return out
    fid = _fid(f)
    is_latest = rid is None or rid == latest
    fixes = _fix_map(repo_dir)
    out["finding"] = {
        **_frow(repo_dir, repo, f, fixes, rid,
                "snapshot" if snap_used else "latest",
                runs=runs, latest=latest),
        "poc": f.get("poc") or ""}
    out["writeup"] = writeup_load(repo_dir).get(fid, "")
    if rid and rid in runs:
        state, freshness = _run_state(rid, rec, runs[rid]["events"],
                                      _live(repo_dir))
        out["run"] = {"id": rid, "state": state, "freshness": freshness,
                      "revision": (rec or {}).get("revision")}
    else:
        out["run"] = None
    vrecs, vscope = _scoped_verification(repo_dir, fid, rid, runs, latest)
    if vscope == "run-window":
        out["warnings"].append(
            "verification predates run-scoped capture; records matched to "
            "this run's time window")
    success = [r for r in vrecs if r.get("outcome") in SUCCESS_OUTCOMES]
    basis = success[-1] if success else None
    later = [r for r in vrecs
             if basis is not None and r is not basis
             and (r.get("endedAt") or 0) > (basis.get("endedAt") or 0)
             and r.get("outcome") not in SUCCESS_OUTCOMES]
    rerun = None
    if is_latest or (rid and (repo_dir / "runs" / rid / "evidence" / fid
                              / "poc" / "rerun.json").exists()):
        rerun = _json(repo_dir / "poc" / fid / "rerun.json")
        if rerun and rid and not is_latest:
            frozen_rc = _json(repo_dir / "runs" / rid / "evidence" / fid
                              / "poc" / "rerun.json")
            rerun = frozen_rc or rerun
    out["proof"] = {"claim": f.get("title"), "verdict": f.get("verdict") or "",
                    "basis": basis,
                    "attempts": vrecs,
                    "laterFailures": later,
                    "reproduced": f.get("status") == "verified"
                    and basis is not None,
                    "recordedVerified": f.get("status") == "verified"
                    and basis is None,
                    "rerunContract": rerun}
    evs = [e for e in _events(repo_dir)[0] if e.get("finding") == fid]
    scoped = [e for e in evs if e.get("run") == rid] if rid else []
    if run and not scoped:
        out["events"] = []
        out["eventsAll"] = evs
        out["eventsScope"] = "run-empty"
    else:
        out["events"] = scoped or evs
        out["eventsScope"] = "run" if scoped else "all-runs"
    trunc = {r.get("outputFile"): bool(r.get("producerTruncated"))
             for r in vrecs if r.get("outputFile")}
    frozen_dir = repo_dir / "runs" / rid / "evidence" / fid / "poc" \
        if rid else None
    art = []
    if frozen_dir is not None and frozen_dir.is_dir():
        art += _dir_artifacts(repo, frozen_dir, repo_dir, run=rid,
                              trunc=trunc)
    if is_latest:
        art += _dir_artifacts(repo, repo_dir / "poc" / fid, repo_dir,
                              trunc=trunc)
    elif not art:
        out["warnings"].append(
            "this run froze no evidence artifacts; current artifacts are "
            "deliberately withheld from historical scope")
    out["artifactsScope"] = ("run" if frozen_dir is not None
                             and frozen_dir.is_dir() and not is_latest
                             else "mixed" if frozen_dir is not None
                             and frozen_dir.is_dir() else "current")
    pack = repo_dir / "packs" / f"{fid}.tar.gz"
    out["pack"] = (_artifact_entry(repo, f"packs/{fid}.tar.gz", pack)
                   if pack.exists() and is_latest else None)
    out["artifacts"] = art
    fx = fixes.get(fid)
    if fx:
        fdir = repo_dir / "fixes" / fid
        fx = {**fx, "artifacts": _dir_artifacts(repo, fdir, repo_dir)}
        issue = None
        for r in _jsonl(repo_dir / "issues.jsonl")[0]:
            if r.get("finding_id") == fid \
                    and "/issues/" in str(r.get("url", "")):
                issue = r.get("url")
        fx["issue"] = issue
    if fx:
        fx["scope"] = "current"
    out["fix"] = fx
    related = []
    if fid.startswith("chain-"):
        for pid in fid[len("chain-"):].split("-"):
            pf = next((x for x in rows if _fid(x) == pid), None)
            if pf:
                related.append({"id": _fid(pf),
                                "title": pf.get("title"),
                                "kind": "chain-parent"})
    for o in rows:
        oid = _fid(o)
        if oid != fid and fid in (o.get("detail") or ""):
            related.append({"id": oid, "title": o.get("title"),
                            "kind": "mentioned-in-narrative"})
    out["related"] = related
    out["source"] = _source_excerpt(root, repo_dir, f, rid, rec,
                                    allow_lastscan=is_latest
                                    or rid is None)
    out["snapshot"] = snap_used
    return out


def fixes_list(root: Path, repo: str | None, verdict: str | None,
               cursor: str | None, limit: int) -> dict:
    items = []
    dirs = _repo_dirs(root)
    if repo:
        dirs = [d for d in dirs if d.name == repo]
    for d in dirs:
        byid = {_fid(r): r for r in _findings_rows(d)[0]}
        for fid, fx in _fix_map(d).items():
            f = byid.get(fid) or {}
            items.append({"findingId": fid, "repo": d.name,
                          "title": f.get("title") or "",
                          "severity": f.get("severity") or "",
                          "status": f.get("status") or "",
                          "verdict": fx["verdict"], "reason": fx["reason"],
                          "backend": fx["backend"], "ts": fx["ts"],
                          "checks": fx.get("checks")})
    items.sort(key=lambda x: -(x.get("ts") or 0))
    if verdict and verdict != "all":
        items = [x for x in items if x["verdict"] == verdict]
    off = int(cursor[2:]) if cursor and cursor.startswith("e:") else 0
    page = items[off:off + limit]
    nxt = off + limit
    return {"items": page, "total": len(items),
            "nextCursor": f"e:{nxt}" if nxt < len(items) else None,
            "generatedAt": time.time(), "warnings": []}


def fix_detail(root: Path, repo: str, fid: str) -> dict:
    out = {"fix": None, "finding": None, "warnings": []}
    try:
        repo_dir = (root / repo).resolve()
        if repo_dir != root.resolve() \
                and root.resolve() not in repo_dir.parents:
            return out
    except OSError:
        return out
    if not repo_dir.is_dir():
        return out
    fx = _fix_map(repo_dir).get(fid)
    if fx is None:
        return out
    fdir = repo_dir / "fixes" / fid
    g = _cached(fdir / "gate.json", _json) or {}
    row = next((r for r in _findings_rows(repo_dir)[0]
                if _fid(r) == fid), None)
    out["finding"] = row
    issue = None
    for r in _jsonl(repo_dir / "issues.jsonl")[0]:
        if r.get("finding_id") == fid and "/issues/" in str(r.get("url")):
            issue = r.get("url")
    rescan = []
    scan_root = fdir / "scan"
    if scan_root.is_dir():
        for fj in scan_root.rglob("findings.jsonl"):
            rescan += [r for r in _jsonl(fj)[0]
                       if r.get("status") != "dismissed"]
    out["fix"] = {**fx, "gate": g.get("checks"), "gateTs": g.get("ts"),
                  "artifacts": _dir_artifacts(repo, fdir, repo_dir),
                  "issue": issue, "latest": True,
                  "rescanFindings": rescan}
    return out


def repos_list(root: Path) -> dict:
    ov = overview(root)
    items = []
    for r in ov["repos"]:
        counts = r.get("counts") or {}
        lr = r.get("latestRun")
        items.append({"name": r["name"], "state": r["state"],
                      "registered": r["registered"],
                      "daemonAlive": r["daemonAlive"],
                      "watch": r.get("watch"), "lastScan": r["lastScan"],
                      "latestRun": ({"id": lr["id"], "state": lr["state"],
                                     "freshness": lr["freshness"],
                                     "startedAt": lr["startedAt"],
                                     "endedAt": lr["endedAt"]}
                                    if lr else None),
                      "counts": counts,
                      "warnings": r["warnings"]})
    return {"items": items, "total": len(items),
            "generatedAt": time.time(), "warnings": ov["warnings"]}


def repo_detail(root: Path, repo: str) -> dict:
    try:
        repo_dir = (root / repo).resolve()
        if repo_dir != root.resolve() \
                and root.resolve() not in repo_dir.parents:
            return {"repo": repo, "state": "unknown",
                    "warnings": [f"unknown repo {repo!r}"]}
    except OSError:
        return {"repo": repo, "state": "unknown", "warnings": []}
    if not repo_dir.is_dir():
        return {"repo": repo, "state": "unknown",
                "warnings": [f"unknown repo {repo!r}"]}
    ov = _repo_overview(repo_dir)
    live = _live(repo_dir)
    runs = [_run_summary(repo_dir, rid, rec["record"], rec["events"], live)
            for rid, rec in _run_ids(repo_dir).items()]
    runs.sort(key=lambda r: -(r.get("startedAt") or 0))
    reg = next((e for e in _registry(root)
                if _reg_name(str(e.get("url", ""))) == repo), None)
    fixes = _fix_map(repo_dir)
    return {"repo": repo, "state": ov["state"], "counts": ov["counts"],
            "warnings": ov["warnings"], "lastScan": ov["lastScan"],
            "daemonAlive": ov["daemonAlive"], "latestRun": ov["latestRun"],
            "runs": runs,
            "watch": ({"url": reg.get("url"), "models": reg.get("models"),
                       "budget": reg.get("budget")} if reg else None),
            "fixesPassed": sum(1 for v in fixes.values()
                               if v.get("verdict") == "fix-verified"),
            "fixesTotal": len(fixes), "generatedAt": time.time()}
