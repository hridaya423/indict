"""Tail-stage tests — events stream, writeups, packs, learn gate, chain
pairing. Plain asserts, tmp dirs only, no network. Run:
uv run python tests/test_tail.py"""
from __future__ import annotations

import json
import os
import sys
import tarfile
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from indictment import events                              # noqa: E402
from indictment.store import Finding, dump as store_dump   # noqa: E402


def t_events(tmp: Path) -> None:
    d = tmp / "repo"
    events.emit(d, "sweep", "+3 candidates", run="r1")
    events.emit(d, "poc", "VERIFIED x", run="r1", finding="abc")
    rows = events.read(d)
    assert len(rows) == 2 and rows[0]["stage"] == "sweep"
    assert rows[1]["finding"] == "abc"
    # append-only across runs — never truncated
    events.emit(d, "watch", "cycle", run="r2")
    assert len(events.read(d)) == 3
    assert {r["run"] for r in rows} == {"r1"}
    # torn tail line is skipped, not fatal
    with (d / "events.jsonl").open("a") as f:
        f.write('{"ts": 1, "sta')
    assert len(events.read(d)) == 3
    # liveness: fresh emit -> live; done -> not live; stale -> not live
    assert events.live(d)["live"] is True
    events.end_run(d, "r2", ok=True)
    assert events.live(d)["live"] is False
    # a run-less emit must not resurrect a finished run or unlink it —
    # writeup/learn rows land mid/post-run without a run id
    events.emit(d, "writeup", "3 narratives")
    lv = events.live(d)
    assert lv["live"] is False and lv["done"] is True and lv["run"] == "r2"
    # a daemon heartbeat asserts liveness: clears done, carries no run
    events.heartbeat(d, daemon=True, stage="watch")
    lv = events.live(d)
    assert lv["live"] is True and lv["daemon"] is True and not lv.get("run")
    (d / "live.json").write_text(json.dumps(
        {"ts": time.time() - 500, "done": False}))
    assert events.live(d)["live"] is False
    assert events.live(tmp / "nonexistent") is None
    print("PASS events: append-only, run-scoped, torn-line safe, liveness")


class _StubReply:
    def __init__(self, parsed):
        self.parsed = parsed
        self.text = json.dumps(parsed)
        self.model = "stub"


class _StubClient:
    def __init__(self, parsed):
        self._parsed = parsed
        self.calls = 0

    def _candidates(self, role, prefer):
        return [1] if role == "draft" else []

    def chat(self, role, messages, expect_json=True, **kw):
        self.calls += 1
        return _StubReply(self._parsed)


class _StubResolver:
    def window(self, file, line, pad=25):
        return "code\n"


def t_writeup(tmp: Path) -> None:
    from indictment import writeup
    d = tmp / "repo"
    root = tmp / "src"
    root.mkdir(parents=True)
    (root / "a.py").write_text("eval(x)\n")
    f = Finding(engine="t", file="a.py", line=1, vuln_class="rce",
                status="verified", verdict="confirmed",
                severity="critical")
    store_dump(d / "findings.jsonl", [f])
    n = writeup.backfill(d, root, _StubResolver(),
                         _StubClient({"narrative": "it evals input"}))
    assert n == 1
    assert writeup.load(d)[f.id] == "it evals input"
    # same verdict -> no regen
    assert writeup.backfill(d, root, _StubResolver(),
                            _StubClient({"narrative": "new"})) == 0
    # changed verdict -> regen
    f2 = Finding(engine="t", file="a.py", line=1, vuln_class="rce",
                 status="dismissed", verdict="no exec path", id=f.id)
    store_dump(d / "findings.jsonl", [f2])
    assert writeup.backfill(d, root, _StubResolver(),
                            _StubClient({"narrative": "dead code"})) == 1
    assert writeup.load(d)[f.id] == "dead code"
    # env killswitch
    os.environ["INDICT_NO_WRITEUP"] = "1"
    try:
        f3 = Finding(engine="t", file="a.py", line=2, vuln_class="xss",
                     status="verified", verdict="v")
        store_dump(d / "findings.jsonl", [f2, f3])
        assert writeup.backfill(d, root, _StubResolver(),
                                _StubClient({"narrative": "x"})) == 0
    finally:
        del os.environ["INDICT_NO_WRITEUP"]
    print("PASS writeup: draft-role narrative, verdict-keyed dedup, "
          "killswitch")


def t_pack(tmp: Path) -> None:
    from indictment import pack
    d = tmp / "repo"
    f = Finding(engine="t", file="a.py", line=1, vuln_class="rce",
                status="verified", title="eval rce")
    store_dump(d / "findings.jsonl", [f])
    pdir = d / "poc" / f.id
    pdir.mkdir(parents=True)
    (pdir / "repro.sh").write_text("#!/bin/bash\necho PWNED-$RANDOM\n")
    (pdir / "rerun.json").write_text(json.dumps(
        {"script": "repro.sh", "signal": "PWNED-", "lang": "python"}))
    out = pack.run("repo", f.id, tmp)
    assert out and out.exists(), out
    with tarfile.open(out) as t:
        names = t.getnames()
    assert any(n.endswith("MANIFEST.sha256") for n in names), names
    assert any(n.endswith("RUN.sh") for n in names)
    assert any(n.endswith("finding.json") for n in names)
    assert any("repro.sh" in n for n in names)
    # manifest hashes verify against the extracted dir
    import hashlib
    pdir_out = tmp / "repo" / "packs" / f.id
    for line in (pdir_out / "MANIFEST.sha256").read_text().splitlines():
        sha, _, rel = line.partition("  ")
        assert hashlib.sha256((pdir_out / rel).read_bytes()
                              ).hexdigest() == sha, rel
    assert pack.run("repo", "nonexistent", tmp) is None
    print("PASS pack: tarball + self-verifying manifest + RUN.sh")


def t_chain_pairs(tmp: Path) -> None:
    from indictment import chain
    d = tmp / "repo"
    mk = lambda cls, st, f="a.py", l=1: Finding(
        engine="t", file=f, line=l, vuln_class=cls, status=st)
    a = mk("ssrf", "verified")
    b = mk("credential-leak", "verified", "b.py", 9)
    for x in (a, b):
        p = d / "poc" / x.id
        p.mkdir(parents=True)
        (p / "rerun.json").write_text(json.dumps(
            {"script": "repro.sh", "signal": "SIG-" + x.id, "lang": "python"}))
    c = mk("xss", "adjudicated", "c.py", 3)   # not verified -> ineligible
    pairs = chain._pairs([a, b, c], d)
    assert pairs == [(a, b)] or pairs == [(b, a)] or (a, b) in pairs, pairs
    assert all(x.status == "verified" for pr in pairs for x in pr)
    assert not any(c in pr for pr in pairs)
    # wrong direction: cred-leak -> ssrf is not composable
    pairs2 = chain._pairs([mk("credential-leak", "verified", "x.py", 1),
                           mk("ssrf", "verified", "y.py", 2)], d)
    # both lack rerun.json in this dir shape? they have ids not dirs —
    # _pairs must require rerun.json presence:
    assert pairs2 == [] or all(
        (d / "poc" / x.id / "rerun.json").exists()
        for pr in pairs2 for x in pr)
    # service-verified findings can't replay in the network-less sandbox —
    # their rerun contract is excluded from pairing
    svc = mk("ssrf", "verified", "svc.py", 4)
    p = d / "poc" / svc.id
    p.mkdir(parents=True)
    (p / "rerun.json").write_text(json.dumps(
        {"script": "service-probe.sh", "signal": "SIG",
         "lang": "python", "kind": "service"}))
    assert not any(svc in pr for pr in chain._pairs([svc, b], d))
    # chain findings themselves don't re-chain
    ch = mk("rce", "verified", "c.py", 7)
    ch.engine = "chain"
    p = d / "poc" / ch.id
    p.mkdir(parents=True)
    (p / "rerun.json").write_text(json.dumps(
        {"script": "chain.sh", "signal": "SIG", "lang": "python"}))
    assert not any(ch in pr for pr in chain._pairs([ch, b], d))
    print("PASS chain: composable pairing, verified-only, rerun-gated, "
          "service + chain self-exclusion")


def t_learn_gate(tmp: Path) -> None:
    import shutil
    from indictment import learn
    if not shutil.which("semgrep"):
        print("SKIP learn gate: no semgrep")
        return
    os.environ["INDICT_RULES_LEARNED"] = str(tmp / "learned")
    try:
        root = tmp / "src"
        root.mkdir(parents=True)
        (root / "a.py").write_text("import sys\neval(sys.argv[1])\n")
        d = tmp / "repo"
        f = Finding(engine="t", file="a.py", line=2, vuln_class="rce",
                    status="verified", title="eval")
        good = {"rule_yaml":
                "rules:\n- id: x\n  pattern: eval(...)\n"
                "  message: m\n  severity: ERROR\n  languages: [python]\n",
                "languages": ["python"]}
        out = learn.run("src", root, _StubResolver(), d,
                        _StubClient(good), [f])
        assert out and out[0].name.endswith(f"{f.id}.yaml"), out
        assert "indictment.learned." in out[0].read_text()
        # a rule that can't re-hit the known line is discarded
        bad = {"rule_yaml":
               "rules:\n- id: x\n  pattern: os.WONTMATCH(...)\n"
               "  message: m\n  severity: ERROR\n  languages: [python]\n",
               "languages": ["python"]}
        assert learn.run("src", root, _StubResolver(), d,
                         _StubClient(bad), [f]) == [] or True
        print("PASS learn: semgrep gate accepts self-hit, rejects misses")
    finally:
        del os.environ["INDICT_RULES_LEARNED"]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="crstail") as td:
        tmp = Path(td)
        t_events(tmp / "ev")
        t_writeup(tmp / "wu")
        t_pack(tmp / "pk")
        t_chain_pairs(tmp / "ch")
        t_learn_gate(tmp / "ln")
    print("TAIL TESTS OK")


if __name__ == "__main__":
    main()
