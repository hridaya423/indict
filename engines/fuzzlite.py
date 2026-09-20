"""E6 fuzzlite — artiphishell/oss-fuzz-gen lite: LLM writes a fuzz harness +
seed corpus for parser-ish targets, we run short dockerized fuzz sessions.
Crashes become candidates WITH a built-in PoC input.

Scope: go (native `go test -fuzz`), c/c++ (clang -fsanitize=fuzzer,address),
rust/python (dumb mutator loop driving a stdin binary). Runs are time-boxed.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from crs.llms import Client
from crs.store import Finding
from crs.util import prompt

PARSER_HINTS = ("parse", "decode", "unmarshal", "read", "load", "import",
                "deserial", "unpack", "tokeniz", "lex")
IMG = {"go": "crs-sandbox-go", "c": "crs-sandbox-c", "cpp": "crs-sandbox-c",
       "rust": "crs-sandbox-rust", "python": "crs-sandbox-python",
       "java": "crs-sandbox-java"}


def _targets(queue: list[dict], langs: list[str]) -> list[dict]:
    return [q for q in queue
            if any(h in q["file"].lower() for h in PARSER_HINTS)
            and any(q["file"].endswith(e) for e in
                    (".go", ".c", ".cc", ".cpp", ".rs", ".py", ".java"))][:6]


def run(root: Path, queue: list[dict], langs: list[str], client: Client,
        out_dir: Path, seconds: int = 90, **kw) -> list[Finding]:
    if not shutil.which("docker"):
        return []
    targets = _targets(queue, langs)
    if not targets:
        return []
    deadline = kw.get("deadline")
    fdir = out_dir / "fuzz"
    fdir.mkdir(parents=True, exist_ok=True)
    out: list[Finding] = []
    for t in targets:
        if deadline and time.time() > deadline:
            break
        rel = t["file"]
        lang = next((l for l, exts in
                     (("go", ".go"), ("c", ".c"), ("cpp", ".cpp|.cc"),
                      ("rust", ".rs"), ("python", ".py"), ("java", ".java"))
                     if any(rel.endswith(e) for e in exts.split("|"))), "python")
        try:
            code = (root / rel).read_text(errors="replace")[:6000]
        except OSError:
            continue  # stale queue entry — file moved/deleted
        r = client.chat("poc", [
            {"role": "system", "content":
             "You write minimal fuzz harnesses. Output ONLY code."},
            {"role": "user", "content": prompt("fuzzlite", lang=lang,
                                             file=rel, code=code)}],
            expect_json=False)
        harness = r.text
        if "```" in harness:
            harness = harness.split("```")[1].split("```")[0]
        work = fdir / Path(rel).stem
        work.mkdir(parents=True, exist_ok=True)
        (work / "harness.txt").write_text(harness)
        run_sh = work / "run.sh"
        run_sh.write_text(
            "#!/bin/bash\nset -x\n"
            f"cd /src && timeout {seconds} bash /poc/runner.sh\n")
        # harness is model output; runner compiles+runs inside the sandbox img
        (work / "runner.sh").write_text(harness if harness.startswith("#!")
                                        else f"#!/bin/bash\n{harness}\n")
        img = IMG.get(lang, "crs-sandbox-python")
        try:
            res = subprocess.run(
                ["docker", "run", "--rm", "--network", "none", "--memory", "2g",
                 "--cpus", "2", "-v", f"{root}:/src:ro",
                 "-v", f"{work.resolve()}:/poc:rw",
                 img, "bash", "/poc/run.sh"],
                capture_output=True, text=True, timeout=seconds + 120)
        except Exception as e:
            print(f"[fuzzlite] {t['file']}: {e}", flush=True)
            continue
        crashes = [l for l in res.stdout.splitlines()
                   if any(k in l for k in
                          ("ERROR: AddressSanitizer", "panic:", "SIGSEGV",
                           "runtime error", "SUMMARY:", "Test unit written"))]
        if crashes:
            out.append(Finding(
                engine="fuzzlite", model=r.model, file=rel,
                vuln_class="memory-corruption", severity="high",
                confidence=0.85,
                title=f"fuzz crash in {rel}",
                detail="\n".join(crashes[:20])[:3000],
                poc=f"docker artifacts under {work}", tags=["fuzz-verified"]))
    return out
