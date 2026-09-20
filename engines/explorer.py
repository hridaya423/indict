"""E4 explorer — RepoAudit-style: initiator seeds -> on-demand data-flow
traversal -> validator. Explorer only expands edges it judges relevant (the
cheap-traversal trick); validator then tries to break the claimed path.
"""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from indictment.llms import Client
from indictment.resolver import Resolver
from indictment.store import Finding
from indictment.util import prompt
from .agent_loop import run_agent
from .hunter import _norm_class

SINK_RE = re.compile(
    r"eval\(|exec\(|os\.system|subprocess|shell_exec|pickle\.loads|yaml\.load|"
    r"innerHTML|document\.write|strcpy|sprintf|memcpy|system\(|"
    r"execute\(|\.raw\(|sendFile|readFile|deserialize|unserialize|Runtime\.getRuntime|"
    # proto-pollution merges, dynamic regex (redos), header/credential forwards
    r"Object\.assign|\.merge\(|defaultsDeep|zipObject|__proto__|"
    r"new RegExp|re\.compile|Proxy-Authorization|Authorization")

SEVERITY = {"critical", "high", "medium", "low", "info"}


def _seeds(root: Path, queue: list[dict]) -> list[dict]:
    seeds = []
    for q in queue[:40]:
        try:
            text = (root / q["file"]).read_text(errors="replace")
        except Exception:
            continue
        per_file = 0
        for i, line in enumerate(text.splitlines(), 1):
            m = SINK_RE.search(line)
            if m:
                seeds.append({"file": q["file"], "line": i,
                              "sink": m.group(0).rstrip("(")})
                per_file += 1
                if per_file >= 3:  # big files have several distinct sinks
                    break
    return seeds[:30]


def explore_one(client: Client, resolver: Resolver, root: Path,
                seed: dict, model: str | None = None,
                deadline: float | None = None) -> list[Finding]:
    code = resolver.window(seed["file"], seed["line"], pad=40)
    res = run_agent(client, resolver, root,
                    prompt("explorer", sink=seed["sink"]),
                    (f"Seed: `{seed['sink']}` at {seed['file']}:{seed['line']}\n\n"
                     f"<code>\n{code}\n</code>\n\n"
                     "Trace backwards: can attacker-controlled input reach this "
                     "sink? Expand callers/callees via <context_request> only "
                     "where the edge looks relevant — don't enumerate."),
                    role="hunt", prefer=[model] if model else None,
                    deadline=deadline)
    if not isinstance(res.parsed, dict):
        return []
    raw_path = res.parsed.get("path") or []
    if not res.parsed.get("reachable") or not raw_path:
        return []
    # hops are {file, line, hop, note} objects; tolerate "file:line" strings
    # from models that ignored the schema
    hops = []
    for p in raw_path:
        if isinstance(p, dict):
            hops.append({"file": str(p.get("file") or ""),
                         "line": int(p.get("line") or 0),
                         "note": str(p.get("note") or p.get("hop") or "")})
        else:
            m = re.search(r"([\w./-]+\.\w+):(\d+)", str(p))
            hops.append({"file": m.group(1), "line": int(m.group(2)),
                         "note": str(p)} if m
                        else {"file": "", "line": 0, "note": str(p)})
    chain = " -> ".join(f"{h['file']}:{h['line']}" if h["file"]
                       else h["note"] for h in hops)
    # the validator reads every hop's code, not just the sink's — a claimed
    # path it can't see is unverifiable, which is the point
    windows = [f"--- sink site {seed['file']}:{seed['line']} ---\n{code}"]
    seen = {(seed["file"], seed["line"] // 80)}
    for h in hops:
        if len(windows) >= 4 or not h["file"]:
            break
        key = (h["file"], h["line"] // 80)
        if key in seen:
            continue
        seen.add(key)
        w = resolver.window(h["file"], h["line"] or 1, pad=40)
        if w:
            windows.append(f"--- hop {h['file']}:{h['line']} ---\n{w}")
    v = client.chat("triage", [
        {"role": "system", "content":
         "You are a strict validator. Kill weak claims."},
        {"role": "user", "content": prompt("validator",
            chain=chain, sink=seed["sink"],
            code="\n\n".join(windows))}],
        expect_json=True, prefer=[model] if model else None)
    pv = v.parsed or {}
    if pv.get("verdict") != "PASS":
        return []
    return [Finding(
        engine="explorer", model=res.model, file=seed["file"],
        line=seed["line"],
        vuln_class=_norm_class(str(pv.get("vuln_class", "")),
                               str(pv.get("title", seed["sink"]))),
        severity=pv.get("severity", "high") if pv.get("severity") in SEVERITY else "high",
        confidence=min(0.85, float(pv.get("confidence", 0.7))),
        title=pv.get("title", f"taint path to {seed['sink']}")[:200],
        detail=("data-flow path: " + chain + "\n" +
                "\n".join(f"  {h['file']}:{h['line']} — {h['note']}"
                          for h in hops if h["note"]))[:3000],
        poc=pv.get("poc_idea", "")[:1500], tags=["validated-path"])]


def run(root: Path, queue: list[dict], client: Client, resolver: Resolver,
        workers: int = 4, model: str | None = None, **kw) -> list[Finding]:
    deadline = kw.get("deadline")
    out: list[Finding] = []
    seeds = _seeds(root, queue)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = []
        for s in seeds:
            if deadline and time.time() > deadline:
                break
            futs.append(ex.submit(explore_one, client, resolver, root, s,
                                  model, deadline))
        for fut, s in zip(futs, seeds):
            try:
                out.extend(fut.result())
            except Exception as e:
                print(f"[explorer] {s['file']}:{s['line']}: {e}", flush=True)
    return out
