"""Engine plumbing self-check — StubClient exercises every engine's
findings-production path without a live model. Run: uv run python tests/selfcheck.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from indictment.llms import Reply
from indictment.resolver import Resolver
from indictment.store import Finding
from indictment import consensus, adjudicate, poc


class StubClient:
    """Returns canned-but-plausible JSON for any prompt.
    `responder` may inspect messages to route different payloads."""

    def __init__(self, payload=None, responder=None):
        self.payload = payload or {}
        self.responder = responder
        self.calls = 0

    def chat(self, role, messages, expect_json=True, **kw):
        self.calls += 1
        p = self.responder(messages) if self.responder else self.payload
        return Reply(text=json.dumps(p), model="stub", parsed=p)


def make_repo() -> Path:
    root = Path(tempfile.mkdtemp(prefix="crstest"))
    (root / "app.py").write_text(
        "import subprocess\nimport sys\n\n"
        "def run(user_cmd):\n"
        "    subprocess.call(user_cmd, shell=True)\n\n"
        "def main():\n"
        "    run(sys.argv[1])\n")
    (root / "util.py").write_text("def helper():\n    return 1\n")
    (root / "parser.py").write_text(
        "def parse(data):\n    return data.split(b',')\n")
    return root


def main() -> None:
    root = make_repo()
    res = Resolver(root)
    queue = [{"file": "app.py", "score": 5.0}]
    ok = []

    # hunter: emits a findings list
    from engines import hunter
    client = StubClient({"findings": [{
        "vuln_class": "cmd-injection", "title": "cmd injection in run()",
        "file": "app.py", "line": 5, "severity": "high", "confidence": 0.9,
        "call_chain": "sys.argv -> run() -> subprocess.call()",
        "poc_idea": "argv = ';id#'"}]})
    fs = hunter.hunt_one(client, res, root, "app.py", None)
    assert fs and fs[0].vuln_class == "cmd-injection" and fs[0].file == "app.py", fs
    ok.append(f"hunter: {len(fs)} finding(s)")

    # taintgen: emits semgrep yaml -> rule file + semgrep findings path
    from engines import taintgen
    client = StubClient({"rules": [{
        "id": "test-subshell", "languages": ["python"],
        "severity": "ERROR",
        "message": "shell=True on attacker input",
        "mode": "taint",
        "pattern-sources": [{"pattern": "sys.argv"}],
        "pattern-sinks": [{"pattern": "subprocess.call(...)"}]}]})
    out_dir = root / "out"
    out_dir.mkdir()
    tf = taintgen.run(root, ["python"], client, queue,
                      {"entrypoints": ["app.py"]}, out_dir)
    print("  taintgen emitted:", len(tf), "finding(s) (semgrep-dependent)")
    ok.append("taintgen: ran without crash")

    # explorer: data-flow engine — emits {reachable, path} then validator PASS
    from engines import explorer
    def ex_resp(msgs):
        blob = json.dumps(msgs)
        if "strict validator" in blob:
            return {"verdict": "PASS", "vuln_class": "cmd-injection",
                    "severity": "high", "confidence": 0.8,
                    "title": "argv flows to shell"}
        return {"reachable": True,
                "path": [{"file": "app.py", "line": 9, "func": "main"},
                         {"file": "app.py", "line": 5, "func": "run"}]}
    ef = explorer.run(root, queue, StubClient(responder=ex_resp), res)
    ok.append(f"explorer: {len(ef)} finding(s)")

    # variant: needs git history — synthetic repo w/ a fix commit
    import subprocess as sp
    vroot = Path(tempfile.mkdtemp(prefix="crsvar"))
    (vroot / "app.py").write_text("def f(x):\n    return eval(x)\n")
    sp.run(["git", "init", "-q"], cwd=vroot)
    sp.run(["git", "add", "."], cwd=vroot)
    sp.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
            "commit", "-qm", "fix security vuln in eval usage"], cwd=vroot)
    from engines import variant
    client = StubClient({"findings": [{
        "vuln_class": "rce", "title": "eval on input", "file": "app.py",
        "line": 2, "severity": "high", "confidence": 0.8,
        "call_chain": "input -> f() -> eval()"}]})
    vf = variant.run(vroot, client, Resolver(vroot))
    ok.append(f"variant: {len(vf)} finding(s)")

    # fuzzlite: needs parser-ish target + docker; assert graceful
    from engines import fuzzlite
    client = StubClient({"harness": "import sys\n", "seeds": ["AAAA"]})
    ff = fuzzlite.run(root, [{"file": "parser.py", "score": 1.0}],
                      ["python"], client, out_dir)
    ok.append(f"fuzzlite: {len(ff)} finding(s) (graceful on missing parser)")

    # consensus: 2 models same location+class -> consensus tag
    a = Finding(engine="hunter", model="m1", file="app.py", line=5,
                vuln_class="cmd-injection", confidence=0.7, title="t")
    b = Finding(engine="hunter", model="m2", file="app.py", line=6,
                vuln_class="cmd-injection", confidence=0.8, title="t")
    pooled = consensus.pool([a, b])
    assert len(pooled) == 1 and "consensus" in pooled[0].tags, pooled[0].tags
    ok.append("consensus: 2-model merge + boost")

    # adjudicate on the hunter finding (stub falsifier ACCEPTs)
    f = fs[0]
    client = StubClient({"verdict": "ACCEPT", "reason": "chain verified",
                         "confidence_multiplier": 1.0,
                         "vuln_class": "cmd-injection"})
    judged = adjudicate.judge(root, res, client, [f], workers=1)
    assert judged[0].status == "adjudicated", judged[0].status
    ok.append("adjudicate: finding survived falsify + class-repair")

    print("\n".join("PASS " + s for s in ok))
    print("SELF-CHECK OK")


if __name__ == "__main__":
    main()
