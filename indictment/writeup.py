"""Writeup stage — draft-role model turns terse verdicts into narratives."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from .issues import redact
from .report import SEV_RANK
from .store import load as store_load, load_jsonl
from .util import prompt

STATUS_RANK = {"verified": 0, "adjudicated": 1, "dismissed": 2}
# candidates never get a narrative — there is no verdict to explain


def load(out_dir: Path) -> dict[str, str]:
    """finding id -> latest narrative text."""
    latest: dict[str, str] = {}
    for r in load_jsonl(out_dir / "writeups.jsonl"):
        if r.get("id") and r.get("text"):
            latest[r["id"]] = r["text"]
    return latest


def backfill(out_dir: Path, root: Path, resolver, client,
             cap: int | None = None) -> int:
    """Append up to `cap` narratives to writeups.jsonl; returns count.

    A row is current when its (id, status, sha1(verdict)) matches the
    finding's latest writeup — re-runs regenerate only on verdict or
    status change, so this is cheap to call at the end of every scan."""
    if client is None or os.environ.get("INDICT_NO_WRITEUP"):
        return 0
    try:
        if not client._candidates("draft", None):
            return 0  # no draft-capable model — don't burn hunt-role models
    except Exception:
        pass          # a Client exists, so it has models — proceed
    if cap is None:
        try:
            cap = int(os.environ.get("INDICT_WRITEUP_MAX", "15"))
        except ValueError:
            cap = 15

    wpath = out_dir / "writeups.jsonl"
    current: dict[str, tuple] = {}
    for r in load_jsonl(wpath):
        if r.get("id"):
            current[r["id"]] = (r.get("status"), r.get("vsha"))

    todo = [f for f in store_load(out_dir / "findings.jsonl")
            if f.status in STATUS_RANK]
    todo.sort(key=lambda f: (STATUS_RANK[f.status],
                             SEV_RANK.get(f.severity, 3), -f.confidence))

    n = 0
    for f in todo:
        if n >= cap:
            break
        vsha = hashlib.sha1((f.verdict or "").encode()).hexdigest()
        if current.get(f.id) == (f.status, vsha):
            continue
        try:
            code = resolver.window(f.file, f.line or 1, pad=25)[:3000]
            r = client.chat("draft", [
                {"role": "system", "content":
                 "You write concise security-audit narratives. Plain "
                 "English, evidence-bound, JSON only."},
                {"role": "user", "content": prompt("writeup",
                    status=f.status, title=f.title,
                    vuln_class=f.vuln_class, loc=f"{f.file}:{f.line}",
                    verdict=f.verdict or "n/a",
                    detail=redact((f.detail or "")[:1200]), code=code)}],
                expect_json=True)
            text = str((r.parsed or {}).get("narrative") or "").strip()
            if not text:
                continue
            row = {"id": f.id, "status": f.status, "vsha": vsha,
                   "model": r.model, "text": text, "ts": time.time()}
            wpath.parent.mkdir(parents=True, exist_ok=True)
            with wpath.open("a") as fh:
                fh.write(json.dumps(row) + "\n")
            current[f.id] = (f.status, vsha)
            n += 1
        except Exception:
            continue  # one bad finding never kills the stage
    if n:
        try:
            from . import events
            events.emit(out_dir, "writeup", f"{n} narratives", run=None)
        except Exception:
            pass
    return n
