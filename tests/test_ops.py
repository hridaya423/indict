"""Ops tests (W2+W3) — state snapshots, alert bus, --status, watch cycle.
Run: uv run python tests/test_ops.py (plain asserts, no framework)."""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crs import alerts, state, watch                    # noqa: E402
from crs.main import status as main_status             # noqa: E402
from crs.pipeline import run as pipeline_run          # noqa: E402
from crs.store import Finding, dump as store_dump      # noqa: E402


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                    *args], cwd=cwd, check=True, capture_output=True)


def _head(repo: Path) -> str:
    return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True,
                          check=True).stdout.strip()


def t_state(tmp: Path) -> None:
    d = tmp / "fdir"
    assert state.read(d) == {"last_sha": None, "last_scan": 0.0,
                             "finding_ids": [], "counts": {}}
    st = {"last_sha": "abc123", "last_scan": 1.0, "finding_ids": ["x"],
          "counts": {"verified": 1}}
    state.write(d, st)
    assert state.read(d) == st
    (d / "state.json").write_text("{corrupt")     # corrupt -> defaults
    assert state.read(d)["last_sha"] is None
    repo = tmp / "src"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n")
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "init")
    live = Finding(engine="t", file="a.py", line=1, vuln_class="sqli",
                   status="verified")
    dead = Finding(engine="t", file="a.py", line=2, vuln_class="xss",
                  status="dismissed")
    rec = state.record(tmp / "out", repo, [live, dead])
    assert rec["last_sha"] == _head(repo)
    assert rec["finding_ids"] == [live.id]
    assert rec["counts"] == {"verified": 1, "adjudicated": 0, "dismissed": 1}
    assert state.read(tmp / "out") == rec
    print("PASS state: defaults, round-trip, corrupt-safe, record()")


def t_alerts(tmp: Path) -> None:
    os.environ.pop("CRS_ALERT_WEBHOOK", None)   # webhook path stays skipped
    f = Finding(engine="t", file="a.py", line=3, vuln_class="dep-cve",
                severity="high", status="verified", title="CVE-1 in foo")
    alerts.emit("testrepo", f, "new-verified", out_root=tmp)
    p = tmp / "testrepo" / "alerts.jsonl"
    assert p.exists()
    rec = json.loads(p.read_text().strip())
    assert set(rec) >= {"ts", "repo", "kind", "vuln_class", "severity",
                        "cvss_lite", "file", "line", "title", "id"}
    assert rec["kind"] == "new-verified" and rec["repo"] == "testrepo"
    assert rec["cvss_lite"] > 0
    noise = Finding(engine="t", file="b.py", vuln_class="sqli",
                    status="candidate")
    adj = Finding(engine="t", file="lock", vuln_class="dep-cve",
                  status="adjudicated", title="CVE-2 in bar")
    alerts.dep_cve_alerts("testrepo", [f, noise, adj], out_root=tmp)
    lines = [l for l in p.read_text().splitlines() if l.strip()]
    assert len(lines) == 3, lines    # f + adj emitted; noise (sqli) skipped
    assert json.loads(lines[1])["kind"] == "dep-cve"
    assert json.loads(lines[2])["kind"] == "dep-cve"
    print("PASS alerts: emit jsonl line, dep-cve filter, webhook skipped")


def t_status(tmp: Path) -> None:
    d = tmp / "testrepo"
    d.mkdir(parents=True)
    f = Finding(engine="t", file="a.py", line=1, vuln_class="sqli",
                status="verified", title="sqli")
    store_dump(d / "findings.jsonl", [f])
    state.write(d, {"last_sha": "deadbeefcafe", "last_scan": time.time(),
                   "finding_ids": [f.id],
                   "counts": {"verified": 2, "adjudicated": 1,
                              "dismissed": 0}})
    alerts.emit("testrepo", f, "new-verified", out_root=tmp)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main_status(tmp)
    out = buf.getvalue()
    assert "testrepo" in out and "verified=2" in out and "adj=1" in out, out
    assert "deadbeef" in out and "alerts=1" in out, out
    print("PASS status: repo line with sha, counts, alert count")


def t_watch(tmp: Path) -> None:
    repo = tmp / "src" / "repoW"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text(
        'AWS_KEY = "AKIAIOSFODNN7REALKEY123"\n'
        "import pickle\n\n"
        "def load(x):\n    return pickle.loads(x)\n")
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "seed")
    out_root = tmp / "out"
    pipeline_run(str(repo), no_llm=True, out_root=out_root)   # seed state
    fdir = out_root / "repoW"
    st0 = state.read(fdir)
    assert st0["last_sha"] == _head(repo), st0
    (repo / "creds2.py").write_text('AWS2 = "AKIAIOSFODNN7REALKE9"\n')
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "add creds2")
    head2 = _head(repo)
    reg = tmp / "watch.yaml"
    reg.write_text(f"- url: {repo}\n")
    watch.main(reg, once=True, out_root=out_root)
    st1 = state.read(fdir)
    assert st1["last_sha"] == head2, (st1["last_sha"], head2)
    lines = [l for l in (fdir / "alerts.jsonl").read_text().splitlines()
             if l.strip()]
    assert lines, "watch cycle raised no alerts"
    kinds = {json.loads(l)["kind"] for l in lines}
    assert kinds <= {"new-verified", "new-adjudicated"} and kinds, kinds
    print(f"PASS watch: new commit -> differential rescan, "
          f"{len(lines)} alert(s), state head advanced")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="crsops") as td:
        tmp = Path(td)
        t_state(tmp / "state")
        t_alerts(tmp / "alerts")
        t_status(tmp / "status")
    with tempfile.TemporaryDirectory(prefix="crswatch") as td:
        t_watch(Path(td))
    print("OPS TESTS OK")


if __name__ == "__main__":
    main()
