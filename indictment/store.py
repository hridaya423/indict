"""Findings store — append-only JSONL so every stage is resumable/watchable."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel, Field

# Canonical vuln classes — shared by hunter normalization and adjudication
# class-repair.
VULN_CLASSES = ["sqli", "rce", "lfi", "afo", "xss", "ssrf", "idor", "deser",
                "path-traversal", "prototype-pollution", "cmd-injection", "xxe",
                "auth-bypass", "credential-leak", "crypto-misuse", "race",
                "redos", "memory-corruption", "template-injection", "dos",
                "dep-cve", "other"]


class Finding(BaseModel):
    id: str = ""
    engine: str
    model: str = ""
    file: str
    line: int = 0
    vuln_class: str = ""
    severity: str = "medium"           # critical|high|medium|low|info
    confidence: float = 0.5
    title: str = ""
    detail: str = ""                   # call chain / evidence / rule msg
    poc: str = ""                      # repro idea or script
    status: str = "candidate"          # candidate|adjudicated|verified|dismissed
    verdict: str = ""
    tags: list[str] = Field(default_factory=list)

    def model_post_init(self, __ctx):
        if not self.id:
            raw = f"{self.engine}|{self.file}|{self.line}|{self.vuln_class}|{self.title}"
            self.id = hashlib.sha1(raw.encode()).hexdigest()[:12]

    def dedup_key(self) -> str:
        return hashlib.sha1(
            f"{self.file}|{self.vuln_class}|{self.line // 10}".encode()
        ).hexdigest()[:16]


def dump(path: Path, items: Iterable[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for it in items:
            f.write(it.model_dump_json() + "\n")


def append(path: Path, items: Iterable[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        for it in items:
            f.write(it.model_dump_json() + "\n")


def load(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    out = []
    for l in path.read_text().splitlines():
        if not l.strip():
            continue
        try:
            out.append(Finding(**json.loads(l)))
        except Exception:
            # a crashed write leaves a torn last line — don't let it nuke
            # every finding before it
            continue
    return out


def load_jsonl(path: Path) -> list[dict]:
    """Tolerant dict-row reader for sidecar streams (events, alerts,
    writeups, outbox) — torn tail lines and non-dict rows are skipped."""
    if not path.exists():
        return []
    out = []
    for l in path.read_text(errors="replace").splitlines():
        if not l.strip():
            continue
        try:
            row = json.loads(l)
        except Exception:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out
