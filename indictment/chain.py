"""Chain stage — compose proven exploits into attack paths, sandbox-gated.

When two verified findings form a composable pair (stage-1 primitive leaks
an artifact a stage-2 sink consumes), the model writes ONE chained PoC:
rerun stage 1's proven repro, capture what it leaks, feed it to stage 2.
A chain only counts when BOTH stages' recorded success signals plus a
chain-complete marker fire in a single sandbox run — machine-proven like
everything else, and rerun.json'd so the fix gate can re-kill it.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from . import events
from .poc import DEAD_MARKERS, GENERIC_SIGNALS, RUN_POC
from .store import Finding
from .util import prompt

# stage-1 class leaks something a stage-2 class consumes — ordered pairs
COMPOSABLE = {("ssrf", "credential-leak"), ("path-traversal", "credential-leak"),
              ("lfi", "rce"), ("sqli", "credential-leak"),
              ("auth-bypass", "idor"), ("idor", "credential-leak"),
              ("xss", "credential-leak"), ("prototype-pollution", "rce"),
              ("template-injection", "rce"), ("deser", "rce"),
              ("lfi", "credential-leak"), ("ssrf", "rce")}

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_UP = {"info": "low", "low": "medium", "medium": "high",
          "high": "critical", "critical": "critical"}  # a chain is worse


def _rerun(out_dir: Path, fid: str) -> dict | None:
    try:
        return json.loads(
            (out_dir / "poc" / fid / "rerun.json").read_text())
    except Exception:
        return None


def _pairs(findings: list[Finding], out_dir: Path,
           cap: int | None = None) -> list[tuple[Finding, Finding]]:
    """Eligible ordered pairs (a=stage1, b=stage2), cross-file first then
    summed severity rank, capped at INDICT_CHAIN_CAP (default 4)."""
    cap = cap if cap is not None else int(os.environ.get("INDICT_CHAIN_CAP", "4"))
    elig = []
    for f in findings:
        # chains don't re-chain silently; service-verified findings can't
        # replay — their rerun contract needs a live compose network
        if f.status != "verified" or f.engine == "chain":
            continue
        rr = _rerun(out_dir, f.id)
        if rr and rr.get("kind") != "service":
            elig.append(f)
    pairs = [(a, b) for a in elig for b in elig
             if a is not b and (a.vuln_class, b.vuln_class) in COMPOSABLE]
    pairs.sort(key=lambda p: (p[0].file == p[1].file,
                              -(SEV_RANK.get(p[0].severity, 0)
                                + SEV_RANK.get(p[1].severity, 0))))
    return pairs[:cap]


def _attempt(root: Path, client, a: Finding, b: Finding,
             out_dir: Path) -> Finding | None:
    """One pair: prompt -> validate contract -> sandbox -> mechanical gate.
    Returns a verified chain Finding or None (kill event already emitted)."""
    # the finding's id IS its poc dir name — pack/board/fix/_evidence all
    # resolve artifacts via poc/<f.id>, so they must not diverge
    cid = f"chain-{a.id}-{b.id}"
    pdir = (out_dir / "poc" / cid).resolve()
    pdir.mkdir(parents=True, exist_ok=True)
    ra = _rerun(out_dir, a.id) or {}
    rb = _rerun(out_dir, b.id) or {}
    a_signal, b_signal = str(ra["signal"]), str(rb["signal"])
    lang = rb.get("lang", "python")
    a_script = (out_dir / "poc" / a.id / ra["script"]).read_text(
        errors="replace")[:4000]
    b_script = (out_dir / "poc" / b.id / rb["script"]).read_text(
        errors="replace")[:4000]
    r = client.chat("poc", [
        {"role": "system", "content":
         "You compose proven exploits into attack chains for authorized "
         "audits. Non-destructive; sandbox has no network and a read-only "
         "/src."},
        {"role": "user", "content": prompt("chain",
            a_title=a.title, a_class=a.vuln_class,
            a_loc=f"{a.file}:{a.line}", a_detail=a.detail[:1200],
            a_script=a_script, a_signal=a_signal,
            b_title=b.title, b_class=b.vuln_class,
            b_loc=f"{b.file}:{b.line}", b_detail=b.detail[:1200],
            b_script=b_script, b_signal=b_signal)}],
        expect_json=True)
    pv = r.parsed or {}
    script = str(pv.get("script", ""))
    marker = str(pv.get("chain_complete", ""))
    # the model must echo back the recorded signals — a mismatch means it's
    # hallucinating a gate it never saw
    ok = (script.strip()
          and str(pv.get("stage1_signal", "")) == a_signal
          and str(pv.get("stage2_signal", "")) == b_signal
          and len(marker.strip()) >= 8
          and marker.lower() not in GENERIC_SIGNALS)
    if not ok:
        events.emit(out_dir, "chain",
                    f"{a.vuln_class}→{b.vuln_class} chain proposal rejected "
                    "(signal mismatch or weak marker)", level="kill")
        return None
    (pdir / "chain.sh").write_text(
        script if script.startswith("#!") else f"#!/bin/bash\n{script}\n")
    try:
        res = subprocess.run(
            ["bash", str(RUN_POC), str(root.resolve()), str(pdir),
             lang, "chain.sh"],
            capture_output=True, text=True, timeout=180)
        output = res.stdout + res.stderr
    except Exception as e:
        output = str(e)
    (pdir / "output.txt").write_text(output[:20000])
    dead = any(s in output for s in DEAD_MARKERS)
    if not (a_signal in output and b_signal in output
            and marker in output and not dead):
        events.emit(out_dir, "chain",
                    f"{a.vuln_class}→{b.vuln_class} chain did not reproduce",
                    level="kill")
        return None
    f = Finding(id=cid, engine="chain", model=r.model, file=b.file,
                line=b.line,
                vuln_class=b.vuln_class, severity=SEV_UP.get(b.severity,
                                                           b.severity),
                confidence=0.97, status="verified",
                title=(f"chain: {a.vuln_class} → {b.vuln_class} "
                       f"({a.file}:{a.line} ⇒ {b.file}:{b.line})"),
                tags=["chain", "poc-verified"],
                detail=(f"Chain of {a.id} + {b.id}.\n"
                        f"Stage 1 ({a.vuln_class}): {a.title}\n"
                        f"Stage 2 ({b.vuln_class}): {b.title}\n"
                        f"Chain evidence ({pdir}):\n{output[:800]}\n"
                        f"Reproduce: bash {RUN_POC} {root.resolve()} "
                        f"{pdir} {lang} chain.sh"))
    # the fix gate re-runs this chain on patched code — record the contract
    (pdir / "rerun.json").write_text(json.dumps(
        {"script": "chain.sh", "signal": marker, "lang": lang}))
    events.emit(out_dir, "chain",
                f"⚡ {a.vuln_class}+{b.vuln_class} → {b.vuln_class} VERIFIED",
                finding=f.id)
    return f


def run(root: Path, resolver, client, findings: list, out_dir: Path,
        deadline: float | None = None) -> list:
    """Return NEW verified chain findings — caller extends its list; the
    input list is never mutated."""
    if client is None or os.environ.get("INDICT_NO_CHAIN") \
            or not RUN_POC.exists():
        return []
    pairs = _pairs(findings, out_dir)
    if not pairs:
        return []
    print(f"[chain] {len(pairs)} composable pair(s)", flush=True)
    new: list[Finding] = []
    for a, b in pairs:
        if deadline and time.time() > deadline:
            print("[chain] budget reached — remaining pairs skipped",
                  flush=True)
            break
        try:
            f = _attempt(root, client, a, b, out_dir)
            if f is not None:
                new.append(f)
        except Exception as e:
            # a bad pair must never kill the stage
            try:
                events.emit(out_dir, "chain",
                            f"{a.vuln_class}→{b.vuln_class} chain error: "
                            f"{e.__class__.__name__}: {e}"[:200],
                            level="kill")
            except Exception:
                pass
    print(f"[chain] {len(new)} chain(s) verified", flush=True)
    return new
