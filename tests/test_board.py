"""Board tests — /api/state aggregation, liveness, case file, tolerance
for missing/torn artifacts. Run: uv run python tests/test_board.py"""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from indictment import events                              # noqa: E402
from indictment.store import Finding, dump as store_dump   # noqa: E402


def _get(port: int, path: str) -> tuple[int, dict | str]:
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}{path}", timeout=5) as r:
            body = r.read().decode()
            return r.status, (json.loads(body)
                              if path.startswith("/api") else body)
    except Exception as e:
        return -1, str(e)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="crsboard") as td:
        root = Path(td)
        repo = root / "vulnapp"
        repo.mkdir()
        live_f = Finding(engine="hunter", file="app.py", line=88,
                         vuln_class="rce", severity="critical",
                         status="verified", title="eval RCE",
                         verdict="confirmed by PoC",
                         detail="Reproduce: bash repro.sh")
        dead_f = Finding(engine="hunter", file="main.py", line=210,
                         vuln_class="cmd-injection", status="dismissed",
                         title="cmd inj", verdict="mechanical: dead code")
        store_dump(repo / "findings.jsonl", [live_f, dead_f])
        events.emit(repo, "poc", "VERIFIED rce app.py:88",
                    run="r1", finding=live_f.id)
        events.emit(repo, "falsify", "cmd-injection — dead code",
                    level="kill", run="r1", finding=dead_f.id)
        (repo / "alerts.jsonl").write_text(json.dumps(
            {"ts": time.time(), "repo": "vulnapp", "kind": "new-verified",
             "vuln_class": "rce", "severity": "critical", "cvss_lite": 10.0,
             "file": "app.py", "line": 88, "title": "eval RCE",
             "id": live_f.id, "extra": ""}) + "\n")
        (repo / "alerts-outbox.jsonl").write_text(json.dumps(
            {"ts": time.time(), "channel": "sms", "text": "paged"}) + "\n")
        (repo / "writeups.jsonl").write_text(json.dumps(
            {"id": live_f.id, "status": "verified", "vsha": "x",
             "model": "stub", "text": "input reaches eval", "ts": 1}) + "\n")
        (repo / "state.json").write_text(json.dumps(
            {"last_sha": "abc123def", "last_scan": time.time(),
             "finding_ids": [live_f.id], "counts": {"verified": 1}}))
        pdir = repo / "poc" / live_f.id
        pdir.mkdir(parents=True)
        (pdir / "output.txt").write_text("PWNED")
        torn = root / "tornrepo"
        torn.mkdir()
        (torn / "findings.jsonl").write_text('{"id":"x"\n{"broken"')  # torn

        from indictment import board
        port = 8641
        t = threading.Thread(target=board.serve, args=(root, port),
                             daemon=True)
        t.start()
        time.sleep(0.8)

        code, st = _get(port, "/api/state")
        assert code == 200, st
        assert st["estate"]["repos"] >= 1
        assert st["estate"]["verified"] >= 1
        r = next(r for r in st["repos"] if r["name"] == "vulnapp")
        assert r["funnel"]["verified"] == 1 and r["funnel"]["dismissed"] == 1
        assert r["live"] and r["live"]["live"] is True  # fresh emit = live
        assert len(r["events"]) >= 2
        assert any(e["finding"] == live_f.id for e in r["events"])
        assert len(r["alerts"]) == 2            # alerts + outbox merged
        w = next(f for f in r["findings"] if f["id"] == live_f.id)
        assert w["writeup"] == "input reaches eval"
        assert w["reproduce"].startswith("bash")
        # torn repo doesn't kill the board
        assert any(x["name"] == "tornrepo" for x in st["repos"])

        code, cf = _get(port, f"/api/finding?repo=vulnapp&id={live_f.id}")
        assert code == 200, cf
        assert cf["finding"]["id"] == live_f.id
        assert cf["writeup"] == "input reaches eval"
        assert cf["poc"] and cf["poc"][0]["name"] == "output.txt"
        assert cf["alerts"] and cf["alerts"][0]["id"] == live_f.id

        # liveness flips when the run ends
        events.end_run(repo, "r1", ok=True)
        time.sleep(0.2)
        _, st2 = _get(port, "/api/state")
        r2 = next(r for r in st2["repos"] if r["name"] == "vulnapp")
        assert r2["live"]["live"] is False

        code, html = _get(port, "/")
        assert code == 200 and "INDICT" in html
        print("PASS board: /api/state schema, liveness, case file, "
              "torn-line tolerance")


if __name__ == "__main__":
    main()
