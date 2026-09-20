"""Fix gate: the mechanical verdict — PoC must die, patch must rescan
clean, empty diffs reject. Agent/dispatch are faked; nothing leaves tmp."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from indictment import fix
from indictment.store import Finding, dump


def mkrepo(td: Path):
    root = td / "vulnrepo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "app.py").write_text(
        "import sys\ndef main():\n    eval(sys.argv[1])\n")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.email=t@t",
                    "-c", "user.name=t", "commit", "-qm", "init"],
                   check=True)
    return root


def mkfinding(root: Path, fdir: Path) -> Finding:
    f = Finding(engine="hunter", file="app.py", line=3,
                vuln_class="rce", severity="critical",
                title="eval on argv", status="verified",
                tags=["poc-verified"], detail="eval(input) at app.py:3")
    pdir = fdir / "poc" / f.id
    pdir.mkdir(parents=True)
    (pdir / "repro.sh").write_text(
        '#!/bin/bash\npython3 /src/app.py "print(\\"VULN_FIRED_XYZ\\")"\n')
    (pdir / "rerun.json").write_text(json.dumps(
        {"script": "repro.sh", "signal": "VULN_FIRED_XYZ",
         "lang": "python"}))
    dump(fdir / "findings.jsonl", [f])
    return f


def main():
    with tempfile.TemporaryDirectory() as tds:
        td = Path(tds)
        root = mkrepo(td)
        fdir = td / "findings" / "vulnrepo"
        f = mkfinding(root, fdir)
        fixdir = fdir / "fixes" / f.id

        pdir = fdir / "poc" / f.id
        # packaging: the agent contract carries everything the gate needs
        task = fix.package(root, f, fixdir, pdir)
        t = task.read_text()
        for k in ("app.py:3", "eval", "VULN_FIRED_XYZ", "must FAIL"):
            assert k in t, k
        assert json.loads((fixdir / "task.json").read_text())["poc"][
            "success_signal"] == "VULN_FIRED_XYZ"
        print("PASS package: task.md + task.json carry finding+PoC+rules")

        wt, base = fix._worktree(root, fixdir)
        # fake a real fix: agent removes the eval
        (wt / "app.py").write_text(
            "import sys\ndef main():\n    print(sys.argv[1])\n")

        def poc_dead(repo, pdir, lang, script):
            return "clean output, no marker"

        verdict, reason = fix._gate(root, wt, base, fixdir, f, pdir,
                                    run_poc=poc_dead,
                                    rescan=lambda: None)
        assert verdict == "fix-verified", (verdict, reason)
        assert (fixdir / "patch.diff").exists()
        print("PASS gate: real patch + dead PoC -> fix-verified")

        # same gate, exploit still fires
        wt2, base2 = fix._worktree(root, fixdir / "second")
        (wt2 / "app.py").write_text(
            "import sys\ndef main():\n    eval(sys.argv[1])  # moved\n")

        def poc_alive(repo, pdir, lang, script):
            return "VULN_FIRED_XYZ"

        verdict, reason = fix._gate(root, wt2, base2, fixdir / "second", f, pdir,
                                    run_poc=poc_alive,
                                    rescan=lambda: None)
        assert verdict == "fix-rejected" and "still fires" in reason
        print("PASS gate: surviving PoC -> fix-rejected")

        # no change at all
        wt3, base3 = fix._worktree(root, fixdir / "third")
        verdict, reason = fix._gate(root, wt3, base3, fixdir / "third", f, pdir,
                                    run_poc=poc_dead,
                                    rescan=lambda: None)
        assert verdict == "fix-rejected" and "no change" in reason
        print("PASS gate: empty diff -> fix-rejected")

        # patch kills the bug but introduces a new candidate
        wt4, base4 = fix._worktree(root, fixdir / "fourth")
        (wt4 / "app.py").write_text("def main():\n    pass\n")
        dirty = fixdir / "fourth" / "scan" / "wt"
        dirty.mkdir(parents=True)
        dump(dirty / "findings.jsonl",
             [Finding(engine="sweep", file="app.py", line=1,
                      vuln_class="credential-leak", severity="high",
                      title="new key", status="adjudicated")])
        verdict, reason = fix._gate(root, wt4, base4, fixdir / "fourth", f, pdir,
                                    run_poc=poc_dead,
                                    rescan=lambda: None)
        assert verdict == "fix-rejected" and "introduces" in reason
        print("PASS gate: dirty patch -> fix-rejected")

        # baseline subtraction: rescan re-surfacing a PRE-EXISTING finding
        # (same file+class, drifted line) must not reject the patch — the
        # old gate auto-rejected on any scanner noise in the repo
        prior = fixdir.parent.parent / "findings.jsonl"
        dump(prior, [f, Finding(engine="sweep", file="app.py", line=1,
                                vuln_class="credential-leak", status="candidate",
                                title="pre-existing key")])
        wt5, base5 = fix._worktree(root, fixdir / "fifth")
        (wt5 / "app.py").write_text("def main():\n    pass\n")
        stale = fixdir / "fifth" / "scan" / "wt"
        stale.mkdir(parents=True)
        dump(stale / "findings.jsonl",
             [Finding(engine="sweep", file="app.py", line=2,  # drifted ±1
                      vuln_class="credential-leak", status="candidate",
                      title="same pre-existing key")])
        verdict, reason = fix._gate(root, wt5, base5, fixdir / "fifth", f, pdir,
                                    run_poc=poc_dead,
                                    rescan=lambda: None)
        assert verdict == "fix-verified", (verdict, reason)
        print("PASS gate: pre-existing finding subtracted -> fix-verified")

        # a rescan hit in a file the patch never touched is also ignored —
        # only the diff's own files can convict it
        wt6, base6 = fix._worktree(root, fixdir / "sixth")
        (wt6 / "app.py").write_text("def main():\n    pass\n")
        stray = fixdir / "sixth" / "scan" / "wt"
        stray.mkdir(parents=True)
        dump(stray / "findings.jsonl",
             [Finding(engine="sweep", file="other.py", line=9,
                      vuln_class="sqli", status="candidate",
                      title="unrelated")])
        verdict, reason = fix._gate(root, wt6, base6, fixdir / "sixth", f, pdir,
                                    run_poc=poc_dead,
                                    rescan=lambda: None)
        assert verdict == "fix-verified", (verdict, reason)
        print("PASS gate: untouched-file finding ignored -> fix-verified")

        # rescan itself blowing up is "unverifiable", not a silent reject
        def boom():
            raise RuntimeError("rescan exploded")
        wt7, base7 = fix._worktree(root, fixdir / "seventh")
        (wt7 / "app.py").write_text("def main():\n    pass\n")
        verdict, reason = fix._gate(root, wt7, base7, fixdir / "seventh",
                                    f, pdir, run_poc=poc_dead, rescan=boom)
        assert verdict == "fix-unverifiable", (verdict, reason)
        print("PASS gate: rescan crash -> fix-unverifiable (not reject)")

    print("FIX TESTS OK")


if __name__ == "__main__":
    main()
