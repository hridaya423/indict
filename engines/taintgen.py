"""E2 taintgen — IRIS-lite: LLM writes repo-specific semgrep taint rules.

Pass 1: model sees entrypoints + imports + hot files, emits sources/sinks/
sanitizers as a semgrep taint-mode YAML. Pass 2: semgrep runs it — free
deterministic intra-file taint tracking tailored to THIS codebase.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from indictment.llms import Client
from indictment.store import Finding
from indictment.util import prompt
from .hunter import _norm_class


def run(root: Path, langs: list[str], client: Client, queue: list[dict],
        recon: dict, out_dir: Path, **kw) -> list[Finding]:
    if not shutil.which("semgrep"):
        return []
    deadline = kw.get("deadline")
    if deadline and time.time() > deadline:
        return []
    hot = queue[:25]
    imports = []
    for q in hot:
        try:
            head = "\n".join((root / q["file"]).read_text(errors="replace")
                             .splitlines()[:60])
            imports.append(f"### {q['file']}\n{head}")
        except Exception:
            pass
    out: list[Finding] = []
    # top-2 languages by file count — mixed repos deserve a ruleset each
    for lang in langs[:2] or ["python"]:
        if deadline and time.time() > deadline:
            break
        out.extend(_gen_and_scan(root, lang, client, recon, imports, out_dir))
    return out


def _gen_and_scan(root: Path, lang: str, client: Client, recon: dict,
                  imports: list[str], out_dir: Path) -> list[Finding]:
    r = client.chat("triage", [
        {"role": "system", "content":
         "You write Semgrep taint-mode rules. Output ONLY valid YAML."},
        {"role": "user", "content": prompt("taintgen", lang=lang,
            entrypoints="\n".join(recon.get("entrypoints", [])[:20]),
            heads="\n\n".join(imports[:15]))}],
        expect_json=False)
    rules_yaml = r.text
    if "```" in rules_yaml:
        # longest fenced block is the yaml doc; strip its language tag
        blocks = rules_yaml.split("```")
        rules_yaml = max(blocks[1::2], key=len, default=rules_yaml)
        if rules_yaml.lstrip().startswith("yaml"):
            rules_yaml = rules_yaml.lstrip()[4:]
        rules_yaml = rules_yaml.strip()
    ldir = out_dir / "rules" / lang
    ldir.mkdir(parents=True, exist_ok=True)
    (ldir / "rules.yml").write_text(rules_yaml)
    chk = subprocess.run(["semgrep", "--validate", "--config", str(ldir)],
                         capture_output=True, text=True, timeout=60)
    if chk.returncode != 0:
        (ldir / "INVALID.txt").write_text(chk.stderr + chk.stdout)
        return []
    res = subprocess.run(["semgrep", "scan", "--config", str(ldir), "--json",
                          "--quiet", "--timeout", "60"], cwd=root,
                         capture_output=True, text=True, timeout=300)
    try:
        data = json.loads(res.stdout)
    except Exception:
        (ldir / "SCAN_ERROR.txt").write_text(res.stderr[:2000])
        return []
    return [Finding(
        engine="taintgen", file=m["path"],
        line=m.get("start", {}).get("line", 0),
        vuln_class=_norm_class(
            m.get("check_id", "").split(".")[-1],
            m.get("extra", {}).get("message", "")),
        severity="high", confidence=0.7,
        title=m.get("extra", {}).get("message", "")[:200],
        detail=f"taint path {m.get('check_id','')} "
               f"{m.get('extra',{}).get('dataflow_trace','')}"[:1500],
        tags=["llm-taint-rule"]) for m in data.get("results", [])]
