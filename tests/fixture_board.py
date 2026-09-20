"""Deterministic synthetic findings root for board/API testing.

    uv run python tests/fixture_board.py <outdir> [--big]

Normal mode creates five repos covering every UI state:
  alpha    — completed structured run (run.json + snapshot + events +
             verification.jsonl + fix gate)
  beta     — live running run (fresh heartbeat, mid-stage progress)
  gamma    — stale run (old heartbeat, not done)
  legacy   — pre-records run (events only, no run.json)
  corrupt  — torn findings.jsonl tail + malformed committed row

--big adds 50 repos x 200 findings + ~100k events for perf work.
"""
from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

T0 = 1_760_000_000  # fixed epoch — deterministic


def _w(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _j(path: Path, rows: list[dict]) -> None:
    _w(path, "".join(json.dumps(r) + "\n" for r in rows))


def _finding(i: int, status: str = "adjudicated") -> dict:
    return {
        "id": f"f{i:08x}"[-12:],
        "engine": ["hunter", "sie", "semgrep"][i % 3],
        "file": f"src/mod{i % 7}/handler{i}.py",
        "line": 10 + i,
        "vuln_class": ["rce", "path-traversal", "cred-leak",
                       "deser", "xss"][i % 5],
        "severity": ["critical", "high", "medium", "low"][i % 4],
        "status": status,
        "title": f"Synthetic finding {i} — "
                 f"{['unsafe eval', 'path escape', 'token leak'][i % 3]}",
        "verdict": "confirmed" if status == "verified" else "",
        "detail": "synthetic detail",
    }


def _run_record(rid: str, state: str, t0: float) -> dict:
    return {
        "schemaVersion": 1, "kind": "run", "id": rid,
        "repo": "fixture", "state": state,
        "startedAt": t0, "endedAt": t0 + 370 if state == "completed" else None,
        "revision": "a1b2c3d4e5f6", "target": "https://example.test/x",
        "engines": ["hunter", "sie"], "models": ["qwen"],
        "scope": {"paths": ["src/"]},
    }


def _events(rid: str, t0: float, n: int = 40) -> list[dict]:
    rows = [{"ts": t0, "run": rid, "schemaVersion": 1,
             "kind": "run-start", "stage": "", "msg": "run started"}]
    stages = [("sweep", 42), ("hunt", 130), ("poc", 90)]
    t = t0
    for si, (stage, dur) in enumerate(stages):
        rows.append({"ts": t, "run": rid, "schemaVersion": 1,
                     "kind": "stage-start", "stage": stage,
                     "stageId": stage, "attempt": 1,
                     "msg": f"{stage} started"})
        for k in range(3):
            rows.append({"ts": t + (dur * k) // 3, "run": rid,
                         "schemaVersion": 1, "kind": "stage-progress",
                         "stage": stage, "stageId": stage,
                         "completed": k + 1, "total": 3,
                         "unit": "batches", "msg": f"{stage} {k+1}/3"})
        rows.append({"ts": t + dur, "run": rid, "schemaVersion": 1,
                     "kind": "stage-end", "stage": stage, "stageId": stage,
                     "outcome": "completed", "msg": f"{stage} done"})
        t += dur
    for i in range(max(0, n - len(rows))):
        rows.append({"ts": t + i * 0.5, "run": rid, "level": "info",
                     "stage": "hunt", "msg": f"probe {i}"})
    rows.append({"ts": t + 18, "run": rid, "schemaVersion": 1,
                 "kind": "engine-outcome", "engine": "hunter",
                 "outcome": "completed", "added": 4,
                 "msg": "hunter done"})
    rows.append({"ts": t + 19, "run": rid, "schemaVersion": 1,
                 "kind": "engine-outcome", "engine": "sie",
                 "outcome": "completed", "added": 0,
                 "msg": "sie done"})
    rows.append({"ts": t + 20, "run": rid, "schemaVersion": 1,
                 "kind": "run-end", "outcome": "completed",
                 "msg": "run complete"})
    return rows


def alpha(root: Path) -> None:
    """Completed run with full structured records."""
    d = root / "alpha"
    rid = "20260101-000000-11111"
    finds = [_finding(i) for i in range(4)]
    finds[0]["status"] = "verified"
    finds[0]["verdict"] = "reproduced in sandbox"
    finds[1]["status"] = "dismissed"
    _j(d / "findings.jsonl", finds)
    _j(d / "runs" / rid / "findings.jsonl", finds)
    _w(d / "runs" / rid / "run.json",
       json.dumps(_run_record(rid, "completed", T0)))
    _j(d / "events.jsonl", _events(rid, T0))
    _w(d / "state.json", json.dumps(
        {"last_sha": "a1b2c3d4e5f6", "last_scan": T0 + 370,
         "counts": {"verified": 1, "dismissed": 1}}))
    poc = d / "poc" / finds[0]["id"]
    _w(poc / "poc.py", "print('ok')\n")
    _w(poc / "output.txt", "marker:outside-root-write\n")
    _j(poc / "verification.jsonl", [
        {"schemaVersion": 1, "kind": "verification-result",
         "attempt": 1, "mode": "sandbox", "script": "python3 poc.py",
         "signal": "marker:outside-root-write", "startedAt": T0 + 200,
         "endedAt": T0 + 201, "returnCode": 0, "basis": "signal",
         "traced": True, "outcome": "verified",
         "outputFile": "output.txt", "producerTruncated": False},
    ])
    _w(d / "runs" / rid / "evidence" / finds[0]["id"] / "source.json",
       json.dumps({"file": finds[0]["file"], "line": finds[0]["line"],
                   "from": finds[0]["line"] - 1, "to": finds[0]["line"] + 1}))
    _w(d / "runs" / rid / "evidence" / finds[0]["id"] / "source.txt",
       "    src = request.args.get('x')\n    eval(src)\n    return ok\n")
    fix = d / "fixes" / finds[0]["id"]
    _w(fix / "fix.diff", "--- a/src/mod0/handler0.py\n"
       "+++ b/src/mod0/handler0.py\n@@ -10,1 +10,1 @@\n-eval(x)\n+safe(x)\n")
    _w(fix / "verdict.json", json.dumps({
        "verdict": "fix-verified", "reason": "poc dead + rescan clean",
        "backend": "codex", "ts": T0 + 400}))
    _w(fix / "gate.json", json.dumps({
        "verdict": "fix-verified", "backend": "codex", "ts": T0 + 400,
        "baseSha": "a1b2c3d4e5f6",
        "checks": [{"id": "patch-produced", "outcome": "pass"},
                   {"id": "poc-rerun-patched", "outcome": "pass"},
                   {"id": "rescan-clean", "outcome": "pass"}]}))


def beta(root: Path) -> None:
    """Live running run — fresh heartbeat, mid-stage progress."""
    d = root / "beta"
    rid = "20260102-000000-22222"
    finds = [_finding(i) for i in range(2)]
    _j(d / "findings.jsonl", finds)
    _j(d / "runs" / rid / "findings.jsonl", finds)
    rec = _run_record(rid, "running", time.time() - 120)
    rec.pop("endedAt")
    _w(d / "runs" / rid / "run.json", json.dumps(rec))
    _j(d / "events.jsonl", _events(rid, time.time() - 120, 10)[:12])
    _w(d / "live.json", json.dumps(
        {"ts": time.time(), "run": rid, "done": False,
         "daemon": True, "live": True}))


def gamma(root: Path) -> None:
    """Stale run — heartbeat older than TTL, not done."""
    d = root / "gamma"
    rid = "20260103-000000-33333"
    _j(d / "findings.jsonl", [_finding(0)])
    _w(d / "runs" / rid / "run.json",
       json.dumps(_run_record(rid, "running", time.time() - 7200)))
    _j(d / "events.jsonl",
       [{"ts": time.time() - 7200, "run": rid, "schemaVersion": 1,
         "kind": "run-start", "stage": "sweep", "msg": "run started"}])
    _w(d / "live.json", json.dumps(
        {"ts": time.time() - 3600, "run": rid, "done": False,
         "live": False}))


def legacy(root: Path) -> None:
    """Pre-records run — events only."""
    d = root / "legacy"
    rid = "20250901-000000-44444"
    finds = [_finding(0, "verified")]
    _j(d / "findings.jsonl", finds)
    _j(d / "events.jsonl", [
        {"ts": T0 - 86400, "run": rid, "stage": "hunt",
         "msg": "+3 candidates"},
        {"ts": T0 - 86000, "run": rid, "stage": "poc",
         "msg": "VERIFIED x", "finding": finds[0]["id"]},
    ])


def corrupt(root: Path) -> None:
    d = root / "corrupt"
    d.mkdir(parents=True)
    (d / "findings.jsonl").write_text(
        json.dumps(_finding(0)) + "\n"
        '{"id":"half","status":"veri\n{"broken')   # torn tail
    (d / "events.jsonl").write_text(
        '{"ts":1,"run":"x","msg":"ok"}\n{"ts":2,"run":"x","ms')


def delta(root: Path) -> None:
    """Two runs, one shared finding — a later FAILED attempt from run B
    must not rewrite run A's successful observation or its artifacts."""
    d = root / "delta"
    rid_a, rid_b = "20260105-000000-66666", "20260106-000000-77777"
    f = _finding(9, "verified")
    f["verdict"] = "reproduced in sandbox"
    _j(d / "findings.jsonl", [f])
    _j(d / "events.jsonl",
       _events(rid_a, T0 + 90000, 6) + _events(rid_b, T0 + 99000, 6))
    _w(d / "runs" / rid_a / "run.json",
       json.dumps(_run_record(rid_a, "completed", T0 + 90000)))
    _j(d / "runs" / rid_a / "findings.jsonl", [f])
    # run B rescanned and the bug did not reproduce / re-appear there
    _w(d / "runs" / rid_b / "run.json",
       json.dumps(_run_record(rid_b, "completed", T0 + 99000)))
    _j(d / "runs" / rid_b / "findings.jsonl", [_finding(10)])
    poc = d / "poc" / f["id"]
    _w(poc / "output.txt", "scope-marker-a\n")
    _w(poc / "repro.sh", "#!/bin/bash\necho scope-marker-a\n")
    _j(poc / "verification.jsonl", [
        {"schemaVersion": 1, "kind": "verification-result", "attempt": 1,
         "mode": "sandbox", "script": "repro.sh", "signal": "scope-marker-a",
         "startedAt": T0 + 90200, "endedAt": T0 + 90210, "returnCode": 0,
         "basis": "signal", "outcome": "matched", "run": rid_a,
         "outputFile": "output.txt", "producerTruncated": False},
        {"schemaVersion": 1, "kind": "verification-result", "attempt": 2,
         "mode": "sandbox", "script": "repro.sh", "signal": "scope-marker-a",
         "startedAt": T0 + 99200, "endedAt": T0 + 99210, "returnCode": 1,
         "basis": None, "outcome": "no-signal", "run": rid_b,
         "outputFile": "output.txt", "producerTruncated": False},
    ])
    _w(d / "state.json", json.dumps(
        {"last_sha": "a1b2c3d4e5f6", "last_scan": T0 + 99370}))


def theta(root: Path) -> None:
    """Running run parked in Verify — the finished Hunt stage's counter
    must not read as Verify's progress."""
    d = root / "theta"
    rid = "20260107-000000-88888"
    rec = _run_record(rid, "running", time.time() - 120)
    rec.pop("endedAt")
    _w(d / "runs" / rid / "run.json", json.dumps(rec))
    now = time.time()
    _j(d / "events.jsonl", [
        {"ts": now - 120, "run": rid, "schemaVersion": 1,
         "kind": "run-start", "msg": "run started"},
        {"ts": now - 100, "run": rid, "schemaVersion": 1,
         "kind": "stage-start", "stage": "hunt", "stageId": "hunt"},
        {"ts": now - 80, "run": rid, "schemaVersion": 1,
         "kind": "stage-progress", "stage": "hunt", "stageId": "hunt",
         "completed": 3, "total": 3, "unit": "batches"},
        {"ts": now - 60, "run": rid, "schemaVersion": 1,
         "kind": "stage-end", "stage": "hunt", "stageId": "hunt",
         "outcome": "completed"},
        {"ts": now - 30, "run": rid, "schemaVersion": 1,
         "kind": "stage-start", "stage": "poc", "stageId": "poc"},
    ])
    _j(d / "findings.jsonl", [])
    _w(d / "live.json", json.dumps(
        {"ts": now, "run": rid, "done": False, "daemon": False,
         "live": True}))


def big(root: Path) -> None:
    rnd = random.Random(7)
    for ri in range(50):
        d = root / f"bulk-{ri:02d}"
        rid = f"20260201-{ri:06d}-99999"
        finds = [_finding(ri * 200 + i, rnd.choice(
            ["verified", "adjudicated", "dismissed", "candidate"]))
            for i in range(200)]
        _j(d / "findings.jsonl", finds)
        _w(d / "runs" / rid / "run.json",
           json.dumps(_run_record(rid, "completed", T0 + ri)))
        _j(d / "events.jsonl",
           [{"ts": T0 + ri + i / 100, "run": rid, "stage": "hunt",
             "msg": f"bulk event {i}"} for i in range(2000)])


def main() -> None:
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    alpha(out)
    beta(out)
    gamma(out)
    legacy(out)
    corrupt(out)
    delta(out)
    theta(out)
    if "--big" in sys.argv:
        big(out)
    print(f"fixture: {out}")


if __name__ == "__main__":
    main()
