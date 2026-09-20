"""Audit-fix regressions — each test pins one bug the audit found:
absolute-path SKIP_DIRS, consensus adjacency data loss, adjudicate path
escapes, fuzz stderr blindness, resolver recursion, learn scratch
isolation, service internal_base, O(n^2) JSON parse.
Run: uv run python tests/test_audit_fixes.py
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from indictment import adjudicate, consensus, events, learn, rank, service
from indictment.llms import _parse_json
from indictment.resolver import Resolver, guard
from indictment.store import Finding
from engines.fuzzlite import _has_crash


def mkrepo(td: Path, name: str = "repo") -> Path:
    root = td / name
    root.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "app.py").write_text(
        "import sys, os\n\ndef main():\n    eval(sys.argv[1])\n")
    (root / "util.py").write_text("def helper():\n    return 1\n")
    return root


def F(**kw) -> Finding:
    base = dict(engine="t", file="app.py", line=4, vuln_class="rce",
                severity="high", confidence=0.8, title="t", detail="x" * 90)
    base.update(kw)
    return Finding(**base)


def test_rank_relative_skip_dirs():
    """Repo living under a skip-named ancestor (tmp/build/test) must still
    produce a queue — the old absolute-parts check zeroed it silently."""
    with tempfile.TemporaryDirectory() as tds:
        root = mkrepo(Path(tds) / "build" / "nested", "repo")
        q = rank.rank(root, [])
        files = {x["file"] for x in q}
        assert "app.py" in files and "util.py" in files, files
    # and skip dirs still apply INSIDE the repo
    with tempfile.TemporaryDirectory() as tds:
        root = mkrepo(Path(tds))
        (root / "tests").mkdir()
        (root / "tests" / "test_x.py").write_text("eval('x')\n")
        q = rank.rank(root, [])
        assert "tests/test_x.py" not in {x["file"] for x in q}
    print("PASS rank: repo-relative SKIP_DIRS (ancestor dirs no longer "
          "blanket-skip)")


def test_consensus_keeps_losers():
    """Two different classes 5 lines apart are two possible bugs — the
    adjacency pass may flag them as siblings but must not delete one."""
    a = F(line=10, vuln_class="sqli", title="sqli a")
    b = F(line=14, vuln_class="xss", title="xss b", confidence=0.6)
    out = consensus.pool([a, b])
    assert len(out) == 2, [f.vuln_class for f in out]
    best = next(f for f in out if "location-agree" in f.tags)
    sib = next(f for f in out if f is not best)
    assert "location-sibling" in sib.tags
    assert "location-consensus" in best.detail
    # same class + same line still collapses to one
    c, d = F(line=10, vuln_class="sqli", model="m1"), \
        F(line=10, vuln_class="sqli", model="m2")
    assert len(consensus.pool([c, d])) == 1
    print("PASS consensus: location-cluster losers survive as siblings")


def test_adjudicate_path_escape_and_carried():
    with tempfile.TemporaryDirectory() as tds:
        root = mkrepo(Path(tds))
        evil = F(file="../outside.py", line=1)
        esc = adjudicate.judge(root, Resolver(root), None, [evil])[0]
        assert esc.status == "dismissed" and "escapes" in esc.verdict
        # carried findings pass through untouched — reviewed state doesn't
        # get re-falsified by a flaky rerun
        carried = F(status="adjudicated", tags=["carried"])
        out = adjudicate.judge(root, Resolver(root), None, [carried])[0]
        assert out.status == "adjudicated"
        # a normal finding with no client stays candidate (mechanical ran)
        cand = F()
        out = adjudicate.judge(root, Resolver(root), None, [cand])[0]
        assert out.status == "candidate"
    print("PASS adjudicate: path escape dismissed, carried passes through")


def test_resolver_guard_window_iterative():
    with tempfile.TemporaryDirectory() as tds:
        td = Path(tds)
        root = mkrepo(td)
        (td / "outside.py").write_text("SECRET = 1\n")
        assert guard(root, "app.py") is not None
        assert guard(root, "../outside.py") is None
        assert guard(root, "/etc/passwd") is None
        r = Resolver(root)
        # window() refuses to read outside the repo
        assert r.window("../outside.py", 1) == ""
        # deep nesting must not RecursionError the index walk
        (root / "deep.py").write_text("x = " + "(" * 3000 + "1" + ")" * 3000)
        Resolver(root)  # would raise RecursionError under recursive _walk
        assert "main" in r.defs
    print("PASS resolver: guard + iterative walk + path-safe window")


def test_fuzzlite_stderr():
    out = _has_crash("", "panic: runtime error: index out of range\n")
    assert out, "stderr panic invisible — the original bug"
    assert _has_crash("SUMMARY: AddressSanitizer: heap", "")
    assert not _has_crash("all tests passed", "ok")
    print("PASS fuzzlite: crash scan covers stderr")


def test_parse_json_raw_decode():
    assert _parse_json('{"a": 1}') == {"a": 1}
    assert _parse_json('prose before {"a": 1} prose after') == {"a": 1}
    assert _parse_json('```json\n{"a": 2}\n```') == {"a": 2}
    # an intact object buried in malformed wrapping still parses
    assert _parse_json('{"x": {' * 5 + '"a": 1}}') == {"x": {"a": 1}}
    # but pure garbage returns None promptly (no O(n^2) suffix scan)
    assert _parse_json('{"x": {' * 500) is None
    assert _parse_json("no json at all") is None
    print("PASS llms: raw_decode JSON parsing")


def test_service_internal_base_and_rewrite():
    compose = {"services": {
        "web": {"ports": ["8080:80"], "image": "x"},
        "db": {"ports": ["5432:5432"], "image": "y"}}}
    fixed, ports, first = service._rewrite_local(compose)
    assert fixed["services"]["web"]["ports"] == ["127.0.0.1:8080:80"]
    assert fixed["services"]["db"]["ports"] == ["127.0.0.1:5432:5432"]
    assert ports == ["8080", "5432"]
    # in-network probes address the service by its compose name at the
    # CONTAINER port — not the invented "target" at the host port
    assert first == ("web", "80")
    print("PASS service: localhost rewrite + real service-name internal_base")


def test_learn_scratch_isolation(tmp: Path | None = None):
    """--out scratch scans must never touch rules/learned or the global
    index — even when the client and semgrep are both willing."""
    import indictment.sie as sie
    with tempfile.TemporaryDirectory() as tds:
        td = Path(tds)
        root = mkrepo(td)
        out_dir = td / "scratch" / "repo"
        out_dir.mkdir(parents=True)
        f = F(status="verified", tags=["poc-verified"])

        class StubResolver:
            def window(self, file, line, pad=30):
                return "code"

        class BoomClient:
            def chat(self, *a, **k):
                raise AssertionError("distill must not run for scratch")

        # rule side: global_ok=False breaks the distill loop outright
        assert learn.run("repo", root, StubResolver(), out_dir,
                         BoomClient(), [f], global_ok=False) == []

        # index side: embed still writes the run-local copy, never global
        old_embed = sie.embed
        sie.embed = lambda texts: [[0.1] * 8 for _ in texts]
        gpath = td / "global-index.jsonl"
        os.environ["INDICT_LEARNED_INDEX"] = str(gpath)
        try:
            n = learn._embed_index(root, "repo", StubResolver(), out_dir,
                                   [f], global_ok=False)
            assert n == 1
            assert (out_dir / "learned-index.jsonl").exists()
            assert not gpath.exists(), "scratch scan wrote the global index"
        finally:
            sie.embed = old_embed
            os.environ.pop("INDICT_LEARNED_INDEX", None)
    print("PASS learn: --out scratch stays scratch")


def test_events_tmp_race():
    with tempfile.TemporaryDirectory() as tds:
        od = Path(tds)
        events.emit(od, "t", "m", run="r1")
        events._touch_live(od)
        stray = [p.name for p in od.glob("live.json.tmp*")]
        assert not stray, f"tmp side file leaked/raced: {stray}"
        assert json.loads((od / "live.json").read_text())["run"] == "r1"
    print("PASS events: per-writer tmp names for live.json")


def test_models_yaml_smoke_roles():
    """Toy models must never silently answer real hunts — smoke/smoke2 are
    cheap-role only."""
    from indictment.llms import load_models
    ms = {m.name: m for m in load_models()}
    for name in ("smoke", "smoke2"):
        if name in ms:  # ollama keyless — usable() passes when listed
            assert ms[name].roles == ["cheap"], ms[name].roles
    # parse the yaml directly too — usable() filtering can hide them
    import yaml
    raw = yaml.safe_load(
        (Path(__file__).parent.parent / "models.yaml").read_text())
    for m in raw["models"]:
        if m["name"] in ("smoke", "smoke2"):
            assert m.get("roles") == ["cheap"], m
    print("PASS models: smoke endpoints can't backstop real roles")


def main():
    test_rank_relative_skip_dirs()
    test_consensus_keeps_losers()
    test_adjudicate_path_escape_and_carried()
    test_resolver_guard_window_iterative()
    test_fuzzlite_stderr()
    test_parse_json_raw_decode()
    test_service_internal_base_and_rewrite()
    test_learn_scratch_isolation()
    test_events_tmp_race()
    test_models_yaml_smoke_roles()
    print("AUDIT-FIX TESTS OK")


if __name__ == "__main__":
    main()
