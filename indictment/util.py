"""Shared helpers: prompt loading, XML context-request parsing, misc."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPT_DIRS = [ROOT / "pipeline" / "prompts", ROOT / "hunter" / "prompts"]


def prompt(name: str, **fmt) -> str:
    for d in PROMPT_DIRS:
        p = d / f"{name}.md"
        if p.exists():
            t = p.read_text()
            return t.format(**fmt)  # {{ }} in files render as { }
    raise FileNotFoundError(f"prompt {name}.md not found in {PROMPT_DIRS}")


CTX_RE = re.compile(
    r"<context_request>\s*(?:<symbol>(.*?)</symbol>)?\s*(?:<file>(.*?)</file>)?\s*"
    r"(?:<line>(.*?)</line>)?\s*</context_request>", re.S)


def context_requests(text: str) -> list[dict]:
    out = []
    for sym, f, line in CTX_RE.findall(text):
        out.append({"symbol": (sym or "").strip() or None,
                    "file": (f or "").strip() or None,
                    "line": int(line) if line.strip().isdigit() else None})
    return out


def git(root: Path, *args) -> str:
    r = subprocess.run(["git", "-C", str(root), *args],
                       capture_output=True, text=True, timeout=60)
    return r.stdout


def detect_languages(root: Path,
                     files: list[str] | None = None) -> dict[str, int]:
    """ext -> count of files, mapped to languages. `files` lets a caller
    that already walked the tree (inventory) reuse the listing."""
    from .resolver import EXT_LANG
    counts: dict[str, int] = {}
    if files is None:
        files = subprocess.run(["rg", "--files"], cwd=root,
                               capture_output=True
                               ).stdout.decode().splitlines()
    for rel in files:
        lang = EXT_LANG.get(Path(rel).suffix.lower())
        if lang and not rel.startswith(("node_modules/", "vendor/", ".git/")):
            counts[lang] = counts.get(lang, 0) + 1
    return counts
