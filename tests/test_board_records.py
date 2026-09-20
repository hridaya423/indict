"""Board v1 API tests — projections, security, torn data, read-only.

    uv run python tests/test_board_records.py
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _get(port: int, path: str, host: str = "127.0.0.1",
         method: str = "GET") -> tuple[int, dict]:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", method=method,
        headers={"Host": host})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}


def _snap(root: Path) -> dict[str, str]:
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out[str(p.relative_to(root))] = hashlib.sha256(
                p.read_bytes()).hexdigest()
    return out


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="boardrec") as td:
        root = Path(td) / "findings"
        subprocess.run([sys.executable,
                        str(Path(__file__).parent / "fixture_board.py"),
                        str(root)], check=True, capture_output=True)

        from indictment import board
        port = 8660
        t = threading.Thread(target=board.serve, args=(root, port),
                             daemon=True)
        t.start()
        time.sleep(0.8)

        before = _snap(root)

        # ── overview contract ────────────────────────────────────────
        code, ov = _get(port, "/api/v1/overview")
        assert code == 200, ov
        for k in ("generatedAt", "warnings", "policy", "counts",
                  "repos", "selected"):
            assert k in ov, k
        c = ov["counts"]
        assert c["repos"] >= 5 and c["complete"] >= 1, c
        assert c["stale"] >= 1 and c["active"] >= 1, c
        names = {r["name"] for r in ov["repos"]}
        assert {"alpha", "beta", "gamma", "legacy", "corrupt"} <= names
        sel = ov["selected"]
        assert sel and sel["run"] and sel["findings"], sel

        # ── runs list + detail ───────────────────────────────────────
        code, runs = _get(port, "/api/v1/runs?limit=100")
        assert code == 200 and runs["total"] >= 3, runs
        for k in ("items", "total", "nextCursor", "generatedAt",
                  "warnings"):
            assert k in runs, k
        ids = {r["id"]: r for r in runs["items"]}
        a = ids["20260101-000000-11111"]
        assert a["state"] == "completed" and a["stages"], a
        assert a["engineHealth"] == "complete", a["engineHealth"]
        b = ids["20260102-000000-22222"]
        assert b["state"] == "running" and b["freshness"] == "fresh", b
        g = ids["20260103-000000-33333"]
        assert g["freshness"] == "stale", g

        code, rd = _get(port,
                        "/api/v1/repos/alpha/runs/20260101-000000-11111")
        assert code == 200, rd
        assert rd["stages"] and rd["eventsTail"] is not None
        assert rd["findingsTotal"] == 4, rd["findingsTotal"]

        code, ev = _get(port,
                        "/api/v1/repos/alpha/runs/20260101-000000-11111"
                        "/events?limit=5")
        assert code == 200 and len(ev["items"]) == 5
        assert ev["nextCursor"], ev
        code, ev2 = _get(port,
                         "/api/v1/repos/alpha/runs/20260101-000000-11111"
                         f"/events?limit=5&cursor={ev['nextCursor']}")
        assert code == 200 and ev2["items"][0]["ts"] >= \
            ev["items"][-1]["ts"]

        code, bad = _get(port, "/api/v1/repos/alpha/runs/nope/events")
        assert code == 404 and bad["error"]["code"] == "unknown-run"

        # ── findings ─────────────────────────────────────────────────
        code, fl = _get(port, "/api/v1/findings?limit=50")
        assert code == 200 and fl["total"] > 0, fl
        assert "counts" in fl and "pages" in fl
        code, v = _get(port, "/api/v1/findings?status=verified")
        assert all(f["status"] == "verified" for f in v["items"])
        code, qq = _get(port, "/api/v1/findings?q=eval")
        assert all("eval" in (f["title"] + f["file"]).lower()
                   for f in qq["items"]), qq["items"]
        code, big = _get(port, "/api/v1/findings?limit=9999")
        assert code == 200 and len(big["items"]) <= 100  # capped

        # ── finding case ─────────────────────────────────────────────
        code, vf = _get(port,
                        "/api/v1/findings?repo=alpha&status=verified")
        assert code == 200 and vf["items"], vf
        fid = vf["items"][0]["id"]
        code, fc = _get(port,
                        f"/api/v1/repos/alpha/findings/{fid}")
        assert code == 200, fc
        assert fc["finding"]["id"] == fid
        assert fc["proof"]["reproduced"] is True
        assert fc["proof"]["basis"]["signal"] == "marker:outside-root-write"
        assert fc["artifacts"], "expected poc artifacts"
        assert fc["fix"]["verdict"] == "fix-verified"
        assert fc["source"]["available"] is True, fc["source"]
        code, nf = _get(port, "/api/v1/repos/alpha/findings/deadbeefdead")
        assert code == 404, nf

        # ── fixes ────────────────────────────────────────────────────
        code, fx = _get(port, "/api/v1/fixes")
        assert code == 200 and fx["total"] >= 1
        code, fd = _get(port,
                        f"/api/v1/repos/alpha/fixes/{fid}")
        assert code == 200 and fd["fix"]["gate"], fd
        assert fd["fix"]["gate"][0]["id"] == "patch-produced"

        # ── artifacts + security ─────────────────────────────────────
        art = next(a for a in fc["artifacts"]
                   if a["name"] == "output.txt")
        code, prev = _get(port,
                          f"/api/v1/artifacts/{art['id']}?preview=1")
        assert code == 200 and prev["previewable"], prev
        assert "outside-root-write" in prev["text"]

        import base64
        evil = base64.urlsafe_b64encode(
            b"alpha\0../../etc/passwd").decode().rstrip("=")
        code, e = _get(port, f"/api/v1/artifacts/{evil}")
        assert code == 400 and e["error"]["code"] == "traversal", e
        code, e = _get(port, "/api/v1/artifacts/bm90aGluZw")
        assert code in (400, 404), e

        code, e = _get(port, "/api/v1/overview", host="evil.test")
        assert code == 403 and e["error"]["code"] == "forbidden-host"
        code, _ = _get(port, "/api/v1/overview", method="POST")
        assert code in (403, 405, 501), code

        # ── torn data tolerance ──────────────────────────────────────
        code, cor = _get(port, "/api/v1/repos/corrupt")
        assert code == 200, cor
        code, ov2 = _get(port, "/api/v1/overview")
        assert code == 200 and any("corrupt" in w
                                   for w in ov2["warnings"]), ov2

        # ── read-only invariance ─────────────────────────────────────
        assert _snap(root) == before, "GETs mutated findings/"

        print("PASS board records: v1 contract, security, torn data, "
              "read-only")


if __name__ == "__main__":
    main()
