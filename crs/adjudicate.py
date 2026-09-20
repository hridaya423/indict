"""Adjudication gate — the precision engine. Three filters, in order:

1. mechanical: file exists, line in range, claimed code actually present
2. path check: each call-chain hop resolves via the Resolver
3. falsification: LLM must try to KILL the finding (brocards + threat model)

Findings that survive become 'adjudicated'; losers become 'dismissed' with a
recorded reason (dismissal notes are themselves useful for the report).
"""
from __future__ import annotations

import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .llms import Client
from .resolver import Resolver
from .store import Finding, VULN_CLASSES
from .util import prompt

CODE_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_.<>]*\(")


def _mechanical(root: Path, f: Finding) -> str | None:
    p = root / f.file
    if not p.exists():
        return f"file {f.file} does not exist"
    if f.line:
        n = len(p.read_text(errors="replace").splitlines())
        if not (0 < f.line <= n + 5):
            return f"line {f.line} out of range ({n} lines)"
    return None


# Generic chain vocabulary — these are protocol words from the prompt
# template, not resolvable symbols. Never penalize them.
GENERIC_HOPS = {"input", "sink", "source", "attacker", "user", "data",
                "request", "response", "output", "arg", "args", "argv",
                "value", "payload", "param", "params", "entry", "this",
                "self", "attacker_input", "remote", "untrusted", "taint",
                "stdin", "env", "http", "api", "url", "body", "query",
                "fn", "func", "foo", "bar", "baz", "caller", "callee",
                "callback", "handler", "method", "function", "input_data",
                # http/web concept words — appear in prose chains, not defs
                "redirect", "scheme", "host", "proxy", "header", "headers",
                "server", "client", "endpoint", "target", "port", "domain",
                "cookie", "session", "origin", "destination", "redirect_uri"}


def _path_check(resolver: Resolver, f: Finding) -> str | None:
    if not f.detail or "->" not in f.detail:
        return None
    hops = re.findall(r"([A-Za-z_][A-Za-z0-9_]+)\s*(?:\(|->)", f.detail)
    # fn1/func2/handle_x style placeholders are template vocab, not symbols
    hops = [h for h in hops if h.lower() not in GENERIC_HOPS
            and not re.fullmatch(r"(fn|func|f|cb|handler|step)\d*", h.lower())]
    # dotted usages (subprocess.call() -> 'call') are methods of a module —
    # bare-name resolution can't verify them, don't count them as missing
    hops = [h for h in hops
            if not re.search(rf"\.{re.escape(h)}\s*\(", f.detail)]
    missing = [h for h in hops if not resolver.resolve(h)][:3]
    if len(missing) >= 2:
        return f"unresolvable call-chain hops: {missing}"
    return None


def _evidence_real(root: Path, mech: str) -> bool:
    """Verify the falsifier's cited evidence actually exists in the repo —
    weak models fabricate sanitizers. Probe literal 5-word windows."""
    words = mech.split()
    probes = [" ".join(words[i:i + 5]) for i in range(0, len(words) - 4, 5)]
    for p in probes[:8]:
        if len(p) < 10:
            continue
        try:
            if subprocess.run(["rg", "-F", "-q", "--", p], cwd=root,
                              timeout=15).returncode == 0:
                return True
        except Exception:
            continue
    return False


def _falsify(client: Client, resolver: Resolver, root: Path, f: Finding,
             strict: bool) -> dict:
    code = resolver.window(f.file, f.line or 1, pad=35)
    r = client.chat("triage", [
        {"role": "system", "content":
         "You are a hostile reviewer whose job is to DISPROVE vulnerability "
         "reports. Authorized audit context — no exploit content needed."},
        {"role": "user", "content": prompt("falsify",
            title=f.title, vuln_class=f.vuln_class,
            loc=f"{f.file}:{f.line}", detail=f.detail or f.title,
            code=code, strict="STRICT mode: reject unless strong." if strict
                            else "standard scrutiny.")}],
        expect_json=True)
    return r.parsed or {}


def _repair_class(client: Client, resolver: Resolver, f: Finding) -> None:
    """Weak models mislabel vuln_class at generation time but classify
    correctly when shown the code and a closed list. One cheap call that
    fixes class noise on surviving findings."""
    code = resolver.window(f.file, f.line or 1, pad=25)[:4000]
    r = client.chat("triage", [
        {"role": "system", "content":
         "You assign vulnerability classes to security findings. Reply with "
         "ONE JSON object only."},
        {"role": "user", "content":
         f"Finding titled \"{f.title}\" claims class `{f.vuln_class}` at "
         f"{f.file}:{f.line}.\nCode:\n```\n{code}\n```\n"
         f"Pick the single best vuln_class from: {', '.join(VULN_CLASSES)}.\n"
         'Reply: {"vuln_class": "..."}'}], expect_json=True)
    cls = str((r.parsed or {}).get("vuln_class", "")).strip().lower()
    if cls in VULN_CLASSES and cls != f.vuln_class:
        f.detail += f"\n[class repaired {f.vuln_class}->{cls} in adjudication]"
        f.tags.append("class-repaired")
        f.vuln_class = cls


def judge(root: Path, resolver: Resolver, client: Client | None,
          findings: list[Finding], workers: int = 4) -> list[Finding]:
    def one(f: Finding) -> Finding:
        if f.status == "verified":
            return f
        if err := _mechanical(root, f):
            f.status, f.verdict = "dismissed", f"mechanical: {err}"
            return f
        if err := _path_check(resolver, f):
            f.status, f.verdict = "dismissed", f"path: {err}"
            return f
        if client is None:
            # deterministic checks passed but no falsification ran —
            # "candidate", not "adjudicated" (scorer/report only count
            # adjudicated|verified, so no-llm sweeps can't fake precision)
            f.status = "candidate"
            f.tags.append("no-falsify")
            return f
        strict = "single-model" in f.tags
        try:
            pv = _falsify(client, resolver, root, f, strict)
        except Exception as e:
            # triage failure must never nuke the run — keep the finding
            f.status = "adjudicated"
            f.tags.append("triage-error")
            f.verdict = f"triage error: {e}"[:300]
            return f
        verdict = str(pv.get("verdict", "")).upper()
        mech = str(pv.get("mechanical_evidence", "") or "")
        if verdict == "DISMISS" and mech and _evidence_real(root, mech):
            f.status = "dismissed"
        elif verdict == "DISMISS":
            # fabricated or missing kill evidence -> don't let it die
            f.status = "adjudicated"
            f.tags += ["needs-poc", "unverified-dismissal"]
        else:
            f.status = "adjudicated"
            if verdict == "NEEDS-POC" or verdict not in ("ACCEPT", "DISMISS"):
                f.tags.append("needs-poc")
            try:
                mult = float(pv.get("confidence_multiplier", 1.0))
            except (TypeError, ValueError):
                mult = 1.0
            f.confidence = min(0.97, f.confidence * mult)
        f.verdict = str(pv.get("reason", ""))[:500]
        if pv.get("threat_model"):
            f.detail += f"\nthreat model: {pv['threat_model']}"
        try:
            _repair_class(client, resolver, f)
        except Exception:
            pass
        return f

    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(one, findings))
