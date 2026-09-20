"""Learn stage — the flywheel: a verified finding teaches the scanner.

(a) The model distills the vuln's source->sink shape into a semgrep rule
    that must mechanically RE-HIT the known-bad line before it lands in
    rules/learned/ — global, so future scans of ANY repo pick it up via
    engines/sweep. The model proposes; semgrep disposes.
(b) The finding's code window is embedded via SIE into a learned index
    that rank._semantic_boost loads as extra vuln descriptors.

Never raises: every failure mode degrades to "nothing learned".
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import yaml

from . import events
from .store import Finding, load_jsonl
from .util import prompt

ROOT = Path(__file__).resolve().parent.parent
RULES_LEARNED = ROOT / "rules" / "learned"      # default; env may override
GLOBAL_INDEX = ROOT / "findings" / "learned-index.jsonl"

_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _rules_dir() -> Path:
    # resolved per call so tests can point INDICT_RULES_LEARNED at a tmp dir
    return Path(os.environ.get("INDICT_RULES_LEARNED") or RULES_LEARNED)


def _index_path() -> Path:
    # same env override rank.py reads — writers and readers stay paired
    return Path(os.environ.get("INDICT_LEARNED_INDEX") or GLOBAL_INDEX)


def _gate(root: Path, f: Finding, rule_yaml: str,
          langs: list | None = None) -> str | None:
    """Return the id-rewritten yaml iff the candidate rule re-fires on the
    finding's own file within ±10 lines (same tolerance as the poc trace
    check). Anything else -> None."""
    try:
        doc = yaml.safe_load(rule_yaml)
    except Exception:
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        return None
    for i, r in enumerate(doc["rules"]):  # ids must self-describe
        if not isinstance(r, dict):
            continue
        r["id"] = f"indictment.learned.{f.id}" + (f".{i}" if i else "")
        if langs and "languages" not in r:
            r["languages"] = langs
    rewritten = yaml.safe_dump(doc, sort_keys=False)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml",
                                         delete=False) as t:
            t.write(rewritten)
            tmp = t.name
        # gate = re-hit the known-bad line on f.file — scan just that file
        # first (a full-repo semgrep run per candidate rule is the slow
        # path), falling back to the repo only when a cross-file taint flow
        # legitimately needs it
        data = _semgrep(tmp, f.file, root)
        if not _self_hit(data, root, f):
            data = _semgrep(tmp, ".", root)
    except Exception:
        return None
    finally:
        if tmp:
            Path(tmp).unlink(missing_ok=True)
    return rewritten if _self_hit(data, root, f) else None


def _semgrep(config: str, target: str, root: Path) -> dict:
    r = subprocess.run(["semgrep", "scan", "--config", config, "--json",
                        "--quiet", "--timeout", "60", target],
                       cwd=root, capture_output=True, text=True,
                       timeout=180)
    return json.loads(r.stdout) if r.stdout.strip() else {}


def _self_hit(data: dict, root: Path, f: Finding) -> bool:
    for m in data.get("results", []):
        p = m.get("path", "")
        rel = str(Path(p).relative_to(root)) if Path(p).is_absolute() else p
        if (Path(rel) == Path(f.file)
                and abs(m.get("start", {}).get("line", 0) - f.line) <= 10):
            return True
    return False


def _distill(repo: str, root: Path, resolver, out_dir: Path, client,
             f: Finding) -> Path | None:
    code = resolver.window(f.file, f.line or 1, pad=35)
    reply = client.chat("triage", [
        {"role": "system", "content":
         "You distill confirmed vulnerabilities into semgrep rules for "
         "authorized audits. JSON only."},
        {"role": "user", "content": prompt(
            "learnrule", title=f.title, vuln_class=f.vuln_class,
            loc=f"{f.file}:{f.line}", detail=(f.detail or "")[:1500],
            code=code)}],
        expect_json=True)
    parsed = reply.parsed if isinstance(reply.parsed, dict) else {}
    rule_yaml = parsed.get("rule_yaml")
    if not isinstance(rule_yaml, str) or not rule_yaml.strip():
        events.emit(out_dir, "learn",
                    f"rule for {f.id} failed gate (no usable yaml)",
                    level="kill", finding=f.id)
        return None
    langs = parsed.get("languages")
    rewritten = _gate(root, f, rule_yaml,
                      langs if isinstance(langs, list) else None)
    if rewritten is None:
        events.emit(out_dir, "learn",
                    f"rule for {f.id} failed gate (no self-hit)",
                    level="kill", finding=f.id)
        return None
    dest = _rules_dir() / f"{repo}__{f.id}.yaml"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(rewritten)
    events.emit(out_dir, "learn",
                f"rule indictment.learned.{f.id} → rules/learned", finding=f.id)
    return dest


def _index_ids(path: Path) -> set[str]:
    """Ids already in the global learned index."""
    return {row["id"] for row in load_jsonl(path) if row.get("id")}


def _embed_index(root: Path, repo: str, resolver, out_dir: Path,
                 verified: list[Finding],
                 global_ok: bool = True) -> int:
    """Append {id,repo,file,vuln_class,vec} rows to the run-local index and
    — when global_ok — the repo-global one rank reads. SIE-optional: no
    key -> embed() -> None -> silent skip. Ids already global are skipped;
    same-id rewrites across runs are fine (readers take the latest row)."""
    from . import sie  # late: keeps sie out of the learn import path
    gpath = _index_path()
    known = _index_ids(gpath)
    rows, seen = [], set()
    for f in verified:
        if f.id in known or f.id in seen:
            continue
        seen.add(f.id)
        code = resolver.window(f.file, f.line or 1, pad=35)
        if not code:
            continue
        try:
            vecs = sie.embed([code])
        except Exception:
            vecs = None
        if not vecs:
            continue
        rows.append({"id": f.id, "repo": repo, "file": f.file,
                     "vuln_class": f.vuln_class, "vec": vecs[0]})
    if rows:
        for path in ((out_dir / "learned-index.jsonl", gpath) if global_ok
                     else (out_dir / "learned-index.jsonl",)):
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a") as fh:
                    for r in rows:
                        fh.write(json.dumps(r) + "\n")
            except Exception:
                pass
    return len(rows)


def run(repo: str, root: Path, resolver, out_dir: Path, client,
        findings: list, global_ok: bool = True) -> list[Path]:
    """Distill verified findings into gated rules + index their windows.
    global_ok=False (scratch --out runs) skips every write to global
    flywheel state: rules/learned/ and the shared learned-index.
    Returns rule paths written; never raises."""
    why = ("no client" if client is None
           else "INDICT_NO_LEARN set" if os.environ.get("INDICT_NO_LEARN")
           else "semgrep not installed" if not shutil.which("semgrep")
           else None)
    if why:
        print(f"[learn] skipped: {why}", flush=True)
        return []
    verified = [f for f in findings
                if getattr(f, "status", "") == "verified"]
    verified.sort(key=lambda f: (_SEV.get(f.severity, 9), -f.confidence))
    verified = verified[:int(os.environ.get("INDICT_LEARN_MAX", "5"))]
    written: list[Path] = []
    for f in verified:
        if not global_ok:
            break  # rules/learned is global state — scratch scans keep out
        try:
            p = _distill(repo, root, resolver, out_dir, client, f)
            if p is not None:
                written.append(p)
        except Exception as e:  # one bad finding must not kill the stage
            print(f"[learn] {f.id}: {e}", flush=True)
    n_idx = _embed_index(root, repo, resolver, out_dir, verified,
                         global_ok=global_ok)
    if written or n_idx:
        events.emit(out_dir, "learn",
                    f"learned {len(written)} rules + {n_idx} signatures")
    return written
