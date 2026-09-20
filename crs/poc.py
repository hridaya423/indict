"""PoC stage — Naptime principle: a finding only counts if it reproduces.

For top adjudicated findings the model writes a minimal repro script plus a
success signal; we run it in the network-less sandbox and keep the evidence.
Sandbox runs carry execution traces (python: settrace via sitecustomize,
node: NODE_V8_COVERAGE) so a "verified" finding means the reported line
actually executed — a signal from the wrong site doesn't count.
"""
from __future__ import annotations

import bisect
import json
import os
import re
import subprocess
import time
from pathlib import Path

from .llms import Client
from .probes import probe_for
from .resolver import Resolver
from .store import Finding
from .util import prompt

RUN_POC = Path(__file__).resolve().parent.parent / "sandbox" / "run_poc.sh"
EXT_IMG = {".py": "python", ".js": "node", ".ts": "node", ".go": "go",
           ".rs": "rust", ".c": "c", ".java": "java", ".rb": "python"}


def _node_lines(cov_files: list[Path], root: Path, rel: str) -> set[int]:
    """Map v8 coverage byte-offset ranges to covered line numbers.
    ponytail: v8 offsets are utf-16 code units; we treat them as chars —
    fine for ascii source, slight drift on heavy-unicode files."""
    try:
        src = (root / rel).read_text(errors="replace")
    except OSError:
        return set()
    starts = [0]
    for ln in src.splitlines(keepends=True):
        starts.append(starts[-1] + len(ln))
    lines: set[int] = set()
    for cf in cov_files:
        try:
            data = json.loads(cf.read_text())
        except Exception:
            continue
        for r in data.get("result", []):
            if not str(r.get("url", "")).endswith("/" + rel):
                continue
            for fn in r.get("functions", []):
                for rng in fn.get("ranges", []):
                    if rng.get("count", 0) > 0:
                        a = bisect.bisect_right(starts, rng["startOffset"])
                        b = bisect.bisect_right(starts, rng["endOffset"])
                        lines.update(range(max(a, 1), max(b, a) + 1))
    return lines


def _trace_ok(pdir: Path, root: Path, f: Finding,
              file_level: bool = False) -> bool | None:
    """True = reported line executed (file_level: any line of the file);
    False = it never ran (signal fired from the wrong site);
    None = no trace data (untraced runtime)."""
    rel, want = f.file, f.line or 0
    lines_hit: set[int] | None = None
    tj = pdir / "trace.json"
    if tj.exists():
        try:
            data = json.loads(tj.read_text())
            lines_hit = {ln for fn, ln in data if fn.endswith("/" + rel)}
        except Exception:
            return None
    else:
        cov = sorted(pdir.glob("coverage-*.json"))
        if cov:
            lines_hit = _node_lines(cov, root, rel)
    if lines_hit is None:
        return None
    if not lines_hit:
        return False  # the file never executed — signal came from elsewhere
    if file_level or not want:
        return True  # generic probes can't know wrapper names — file counts
    return any(abs(ln - want) <= 10 for ln in lines_hit)


def prove(root: Path, resolver: Resolver, client: Client | None,
          findings: list[Finding], out_dir: Path,
          cap: int | None = None,
          deadline: float | None = None) -> list[Finding]:
    if client is None or not RUN_POC.exists():
        return findings
    cap = cap if cap is not None else int(os.environ.get("CRS_POC_CAP", "10"))
    todo = sorted([f for f in findings if f.status == "adjudicated"],
                  key=lambda f: ({"critical": 0, "high": 1}.get(f.severity, 2),
                                 -f.confidence))
    if len(todo) > cap:
        # more candidates than PoC slots — a cross-encoder picks which
        # findings deserve the expensive verification, replacing
        # model-asserted confidence with measured query relevance
        try:
            from . import sie as _sie
            scores = _sie.rerank(
                "remotely exploitable vulnerability with attacker-controlled "
                "input reaching a dangerous sink",
                [f"{f.title}\n{(f.detail or '')[:400]}" for f in todo])
            if scores is not None:
                order = sorted(range(len(todo)), key=lambda i: -scores[i])
                todo = [todo[i] for i in order]
                print(f"[poc] reranker prioritized {len(todo)} findings "
                      f"(SIE cross-encoder)", flush=True)
        except Exception as e:
            print(f"[poc] rerank failed: {e}", flush=True)
    todo = todo[:cap]
    for f in todo:
        if deadline and time.time() > deadline:
            print("[poc] budget reached — remaining findings stay adjudicated",
                  flush=True)
            break
        code = resolver.window(f.file, f.line or 1, pad=50)
        convo = [
            {"role": "system", "content":
             "You write minimal reproductions for authorized security audits. "
             "Non-destructive PoCs only: prove the bug exists."},
            {"role": "user", "content": prompt("poc",
                title=f.title, vuln_class=f.vuln_class,
                loc=f"{f.file}:{f.line}", detail=f.detail[:2000],
                poc_idea=f.poc or "n/a", code=code)}]
        lang = EXT_IMG.get(Path(f.file).suffix, "python")
        pdir = (out_dir / "poc" / f.id).resolve()
        for attempt in range(2):
            try:
                r = client.chat("poc", convo, expect_json=True)
            except Exception as e:
                f.tags.append("poc-error")
                f.verdict += f" | poc gen failed: {e}"[:120]
                break
            pv = r.parsed or {}
            script, signal = pv.get("script", ""), str(pv.get("success_signal", ""))
            # weak models pick trivial signals — require a distinctive marker
            if not script or len(signal.strip()) < 8 or signal.lower() in (
                    "error", "true", "success", "crash", "vulnerable"):
                break
            convo.append({"role": "assistant", "content": r.text})
            pdir.mkdir(parents=True, exist_ok=True)
            sname = f"repro{'' if attempt == 0 else attempt}.sh"
            (pdir / sname).write_text(
                script if script.startswith("#!") else f"#!/bin/bash\n{script}\n")
            try:
                res = subprocess.run(
                    ["bash", str(RUN_POC), str(root.resolve()), str(pdir),
                     lang, sname],
                    capture_output=True, text=True, timeout=180)
                output = res.stdout + res.stderr
            except Exception as e:
                output = str(e)
            (pdir / f"output{'' if attempt == 0 else attempt}.txt").write_text(
                output[:20000])
            # script must actually reach the vuln — env/script failures don't count
            dead = any(s in output for s in (
                "command not found", "syntax error near", "Read-only file system",
                "ModuleNotFoundError", "Cannot find module", "bash: line",
                "ImportError"))
            hit = (signal in output and not dead) or \
                  "AddressSanitizer" in output or "panic:" in output
            traced = _trace_ok(pdir, root, f)
            if hit and traced is False:
                # signal fired but the reported line never executed —
                # the script proved some OTHER site. Not a verification.
                f.tags.append("poc-line-miss")
                f.verdict += f" | signal fired but {f.file}:{f.line} never executed"
                hit = False  # treat as failed attempt; model gets feedback
            if hit:
                f.status = "verified"
                f.tags.append("poc-verified")
                f.confidence = 0.98 if traced else 0.97
                if traced:
                    f.tags.append("line-verified")
                # the fix gate re-runs this script on patched code and
                # requires the signal to disappear — record the contract
                (pdir / "rerun.json").write_text(json.dumps(
                    {"script": sname, "signal": signal, "lang": lang}))
                f.detail += (f"\nPoC evidence ({pdir}):\n{output[:800]}"
                           f"\nReproduce: bash {RUN_POC} {root.resolve()} "
                           f"{pdir} {lang} {sname}")
                break
            if attempt == 0:
                # feed the failure back — the model fixes its own script
                convo.append({"role": "user", "content": (
                    "That script failed in the sandbox. Error output:\n```\n" +
                    output[-1500:] +
                    "\n```\nFix it and reply with ONE JSON object again. "
                    "Remember: /src is read-only, no network, import the "
                    "repo's own package via PYTHONPATH.")})
            else:
                f.tags.append("poc-failed")
                f.verdict += " | PoC did not reproduce"
        if f.status == "verified":
            continue
        # pen-test layer: if this repo boots as a live service, attack the
        # REAL app with a class-matched probe before falling back to the
        # generic sandbox probe. Upgrade-only — never downgrades.
        try:
            from . import service as _svc
            from . import httpprobes as _http
            handle = _svc.booted(root)
            if handle:
                t = _http.probe_for(f, handle)
                if t:
                    sscript, ssignal = t
                    (pdir / "service-probe.sh").write_text(sscript)
                    soutput = handle.run_probe(pdir, "service-probe.sh")
                    (pdir / "service_probe_output.txt").write_text(
                        soutput[:20000])
                    dead = any(s in soutput for s in (
                        "runner failed", "Connection refused",
                        "Name or service not known"))
                    if ssignal in soutput and not dead:
                        # service probes need a live redeploy to re-verify —
                        # the fix gate can't rerun them against patched code
                        (pdir / "rerun.json").write_text(json.dumps(
                            {"script": "service-probe.sh", "signal": ssignal,
                             "lang": lang, "kind": "service"}))
                        f.status = "verified"
                        f.tags += ["poc-verified", "service-verified"]
                        f.confidence = max(f.confidence, 0.98)
                        f.detail += (
                            f"\nService PoC evidence ({pdir}, live app at "
                            f"{handle.base_url}):\n{soutput[:800]}"
                            f"\nReproduce: see {pdir}/service-probe.sh — "
                            f"service {handle.base_url}, network "
                            f"{handle.project}_default")
        except Exception as e:
            print(f"[poc] service probe skipped: {e}", flush=True)
        if f.status == "verified":
            continue
        # last resort: deterministic probe skeleton for this vuln class
        probe = probe_for(f.vuln_class, f.file, f.id)
        if probe:
            script, signal = probe
            pdir.mkdir(parents=True, exist_ok=True)
            (pdir / "probe.sh").write_text(script)
            try:
                res = subprocess.run(
                    ["bash", str(RUN_POC), str(root.resolve()), str(pdir),
                     lang, "probe.sh"],
                    capture_output=True, text=True, timeout=180)
                output = res.stdout + res.stderr
            except Exception as e:
                output = str(e)
            (pdir / "probe_output.txt").write_text(output[:20000])
            dead = any(s in output for s in (
                "command not found", "syntax error near",
                "Read-only file system", "ModuleNotFoundError",
                "Cannot find module", "bash: line", "ImportError"))
            if signal in output and not dead:
                # probes are class-generic — they can't call a repo's wrapper
                # by name, so gate at file level (the claimed file must run)
                traced = _trace_ok(pdir, root, f, file_level=True)
                if traced is False:
                    # probe fired on the file but not the reported line —
                    # the class is exploitable somewhere in this file, not
                    # necessarily at the claimed site. Honest tag, no verify.
                    f.tags += ["probe", "probe-line-miss"]
                    f.verdict += (f" | probe fired but {f.file}:{f.line} "
                                  f"never executed — wrong site claimed")
                else:
                    (pdir / "rerun.json").write_text(json.dumps(
                        {"script": "probe.sh", "signal": signal,
                         "lang": lang}))
                    f.status = "verified"
                    f.tags += ["poc-verified", "probe"]
                    f.confidence = 0.96 if traced else 0.95
                    if traced:
                        f.tags.append("line-verified")
                    f.detail += (f"\nProbe evidence ({pdir}):\n{output[:800]}"
                               f"\nReproduce: bash {RUN_POC} {root.resolve()} "
                               f"{pdir} {lang} probe.sh")
    return findings
