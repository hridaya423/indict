"""E3 hunter — vulnhuntr-style call-chain analysis, language-agnostic.

Per prioritized file: the model hunts entry->sink chains, requesting missing
context iteratively (agent_loop), then emits a JSON verdict. Grafted from
protectai/vulnhuntr (0day-proven pattern) onto our shared resolver + client.
"""
from __future__ import annotations

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from crs.llms import Client
from crs.resolver import EXT_LANG, Resolver
from crs.store import Finding
from crs.util import prompt
from .agent_loop import run_agent

PACKS = yaml.safe_load(
    (Path(__file__).parent.parent / "hunter" / "prompts" / "packs.yaml").read_text())
# big-context models (GLM-class) should see most of the file up front;
# the agent loop can still <context_request> anything elided.
# --frontier raises this; lazy read so CLI flags apply post-import
def _max_file_lines() -> int:
    return int(os.environ.get("CRS_MAX_FILE_LINES", "1200"))


def _pack(file: str) -> tuple[str, dict]:
    lang = EXT_LANG.get(Path(file).suffix.lower(), "python")
    pack = PACKS.get(lang) or PACKS.get("generic", {})
    return lang, pack


from crs.store import VULN_CLASSES as _CLASSES
_CLASS_ALIAS = {"proto-pollution": "prototype-pollution",
                "deserialization": "deser", "command-injection": "cmd-injection",
                "path_traversal": "path-traversal",
                "mass-assignment": "other", "jwt-misuse": "auth-bypass",
                "info-leak": "credential-leak", "information-disclosure": "credential-leak",
                "prototype_pollution": "prototype-pollution",
                # pack-vocabulary names -> canonical buckets
                "buffer-overflow": "memory-corruption",
                "heap-overflow": "memory-corruption",
                "stack-overflow": "memory-corruption",
                "uaf": "memory-corruption",
                "use-after-free": "memory-corruption",
                "double-free": "memory-corruption",
                "format-string": "memory-corruption",
                "integer-overflow": "memory-corruption",
                "oob-read": "memory-corruption",
                "oob-write": "memory-corruption",
                "unsafe-memory": "memory-corruption",
                "memory-safety": "memory-corruption",
                "unwrap-dos": "dos", "goroutine-leak-dos": "dos",
                "denial-of-service": "dos",
                "logic-auth-bypass": "auth-bypass",
                "spel-injection": "rce", "ssti": "template-injection"}

_CLASS_HINTS = {  # natural-language words small models use -> canonical
    "deserial": "deser", "prototype": "prototype-pollution",
    "proto": "prototype-pollution",
    "sql": "sqli", "command": "cmd-injection", "exec": "rce", "injection": "cmd-injection",
    "traversal": "path-traversal", "lfi": "lfi", "file inclusion": "lfi",
    "rce": "rce", "xss": "xss", "cross-site": "xss", "scripting": "xss",
    "ssrf": "ssrf", "idor": "idor", "xxe": "xxe", "pollution": "prototype-pollution",
    "auth": "auth-bypass", "jwt": "auth-bypass", "crypto": "crypto-misuse",
    "redos": "redos", "regex": "redos", "race": "race",
    # deterministic-scanner vocabulary (bandit/semgrep/gosec message text)
    "pickle": "deser", "yaml.load": "deser", "unserialize": "deser",
    "marshal": "deser", "shell": "cmd-injection", "subprocess": "cmd-injection",
    "hash": "crypto-misuse", "md5": "crypto-misuse", "sha1": "crypto-misuse",
    "weak": "crypto-misuse", "random": "crypto-misuse",
    "buffer": "memory-corruption", "overflow": "memory-corruption",
    "cve-": "dep-cve"}


def _norm_class(raw: str, title: str) -> str:
    """Small models often echo the enum ("sqli|rce|...") or use natural
    words ("deserialization"). Normalize to one canonical class."""
    r = _CLASS_ALIAS.get(raw.strip().lower(), raw.strip().lower())
    if r in _CLASSES:
        return r
    toks = [t for t in re.split(r"[|/,;\s]+", r) if t in _CLASSES]
    if len(toks) == 1:
        return toks[0]
    # 0 or >=2 class tokens: enum echo / garbage -> infer from title
    blob = f"{r} {title.lower()}"
    for hint, cls in _CLASS_HINTS.items():
        if hint in blob:
            return cls
    return "other"


_SEVS = {"critical", "high", "medium", "low"}


def _norm_sev(raw: str) -> str:
    for tok in re.split(r"[|/,;\s]+", raw.strip().lower()):
        if tok in _SEVS:
            return tok
    return "medium"


def _content(root: Path, rel: str) -> str:
    text = (root / rel).read_text(errors="replace")
    lines = text.splitlines()
    if len(lines) <= _max_file_lines():
        return text
    return ("\n".join(lines[:200]) +
            f"\n... [{len(lines) - 400} lines elided] ...\n" +
            "\n".join(lines[-200:]))


def hunt_one(client: Client, resolver: Resolver, root: Path, rel: str,
             model: str | None, threat_model: dict | None = None,
             deadline: float | None = None) -> list[Finding]:
    lang, pack = _pack(rel)
    system = prompt("hunter_system",
                    vuln_classes="\n".join(f"- {c}" for c in pack.get("classes", [])),
                    sinks="\n".join(f"- {s}" for s in pack.get("sinks", [])),
                    sources="\n".join(f"- {s}" for s in pack.get("sources", [])),
                    lang=lang)
    tm_hint = ""
    if threat_model:
        tm_hint = ("\nThreat model for this repo: "
                   f"{json.dumps(threat_model)[:1500]}\n")
    user = (f"File: {rel}\nAnalyze for remotely-exploitable vulnerabilities. "
            f"Trace attacker input to dangerous sinks across the call chain."
            f"{tm_hint}\n<code>\n{_content(root, rel)}\n</code>")
    res = run_agent(client, resolver, root, system, user, role="hunt",
                    prefer=[model] if model else None, deadline=deadline)
    out = []
    for f in (res.parsed or {}).get("findings", []) if isinstance(res.parsed, dict) else []:
        out.append(Finding(
            engine="hunter", model=res.model,
            file=f.get("file") or rel,
            line=int(f.get("line") or 0),
            vuln_class=_norm_class(str(f.get("vuln_class", "")),
                                   str(f.get("title", ""))),
            severity=_norm_sev(str(f.get("severity", "medium"))),
            confidence=float(f.get("confidence") or 0.5),
            title=str(f.get("title", ""))[:200],
            detail=str(f.get("call_chain", f.get("evidence", "")))[:3000],
            poc=str(f.get("poc_idea", ""))[:1500],
            tags=[lang]))
    return out


def run(root: Path, queue: list[dict], client: Client, resolver: Resolver,
        workers: int = 4, model: str | None = None,
        threat_model: dict | None = None, **kw) -> list[Finding]:
    deadline = kw.get("deadline")
    out: list[Finding] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {}
        for q in queue:
            if deadline and time.time() > deadline:
                break  # submit lazily so the budget actually bites
            futs[ex.submit(hunt_one, client, resolver, root, q["file"],
                           model, threat_model, deadline)] = q
        for fut, q in futs.items():
            try:
                out.extend(fut.result())
            except Exception as e:
                print(f"[hunter] {q['file']}: {e}", flush=True)
    return out
