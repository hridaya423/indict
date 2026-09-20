"""E6 fuzzlite — artiphishell/oss-fuzz-gen lite: LLM writes a fuzz harness +
seed corpus for parser-ish targets, we run short dockerized fuzz sessions.
Crashes become candidates WITH a built-in PoC input.

Scope: go (native `go test -fuzz`), c/c++ (clang -fsanitize=fuzzer,address),
rust/python (dumb mutator loop driving a stdin binary). Runs are time-boxed.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path

from indictment.llms import Client
from indictment.store import Finding
from indictment.util import prompt

PARSER_HINTS = ("parse", "decode", "unmarshal", "read", "load", "import",
                "deserial", "unpack", "tokeniz", "lex")
IMG = {"go": "indictment-sandbox-go", "c": "indictment-sandbox-c", "cpp": "indictment-sandbox-c",
       "rust": "indictment-sandbox-rust", "python": "indictment-sandbox-python",
       "java": "indictment-sandbox-java"}


def _targets(queue: list[dict], langs: list[str]) -> list[dict]:
    return [q for q in queue
            if any(h in q["file"].lower() for h in PARSER_HINTS)
            and any(q["file"].endswith(e) for e in
                    (".go", ".c", ".cc", ".cpp", ".rs", ".py", ".java"))][:6]


CRASH_KEYS = ("ERROR: AddressSanitizer", "panic:", "SIGSEGV",
              "runtime error", "SUMMARY:", "Test unit written")


def _has_crash(stdout: str, stderr: str) -> list[str]:
    """Crash reports land on stderr (ASan, go panic, libFuzzer) — stdout
    alone is blind."""
    return [l for l in (stdout + "\n" + stderr).splitlines()
            if any(k in l for k in CRASH_KEYS)]


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
            block = harness.split("```")[1].lstrip("\n")
            # drop a markdown language tag (```bash) — a bare first word is
            # the fence label, not runnable script
            if re.match(r"^(bash|sh|zsh|shell|python|py|javascript|js|node)"
                        r"\n", block):
                block = block.split("\n", 1)[1]
            harness = block
        # stem alone collides — src/parse.go and lib/parse.go share a dir;
        # keep the path shape under fuzz/
        work = fdir / Path(rel).with_suffix("")
        work.mkdir(parents=True, exist_ok=True)
        (work / "harness.txt").write_text(harness)
        run_sh = work / "run.sh"
        run_sh.write_text(
            "#!/bin/bash\nset -x\n"
            f"cd /src && timeout {seconds} bash /poc/runner.sh\n")
        # harness is model output; runner compiles+runs inside the sandbox img
        (work / "runner.sh").write_text(harness if harness.startswith("#!")
                                        else f"#!/bin/bash\n{harness}\n")
        img = IMG.get(lang, "indictment-sandbox-python")
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
        crashes = _has_crash(res.stdout, res.stderr)
        if crashes:
            out.append(Finding(
                engine="fuzzlite", model=r.model, file=rel,
                vuln_class="memory-corruption", severity="high",
                confidence=0.85,
                title=f"fuzz crash in {rel}",
                detail="\n".join(crashes[:20])[:3000],
                poc=f"docker artifacts under {work}", tags=["fuzz-verified"]))
    return out
