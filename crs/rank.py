"""Rank stage — attack-surface hotspot scoring -> priority queue.

Zero-model stage: filename signals + sink-keyword density + entrypoint bonus +
sweep-hit bonus. Cheap enough to run on every file in the repo.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from .resolver import EXT_LANG
from .store import Finding

FILE_RE = re.compile(
    r"auth|jwt|token|session|crypto|upload|download|parse|serial|pickle|exec|"
    r"sql|admin|middle|permission|privilege|login|oauth|saml|webhook|payment|"
    r"redirect|proxy|request|eval|render|template|file|path|import|load",
    re.I)
ENTRY_FILE_RE = re.compile(
    r"(^|[/_.-])(index|main|init|__init__|mod|server|cli|route|handler|"
    r"middleware|app)([/_.-]|$)", re.I)

SINKS = re.compile(
    r"eval\(|exec\(|execSync|os\.system|subprocess|child_process|shell_exec|"
    r"pickle\.loads?|yaml\.load\(|marshal\.loads|unserialize|ObjectInputStream|"
    r"innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|"
    r"strcpy|strcat|sprintf|gets\(|memcpy|scanf|system\(|popen|"
    r"cursor\.execute|\.raw\(|executeQuery|SELECT .*\+|"
    r"requests\.(get|post)|fetch\(|http\.Get|urllib|"
    r"render_template|Template\(|compile\(|new Function|setTimeout\(.*\+|"
    r"readFile|open\(.*request|sendFile|download|"
    r"deserialize|fromJson|JSON\.parse.*req|jwt\.decode|verify.*false|"
    r"mktemp|tmpnam|chmod|chown|rm -rf|Runtime\.getRuntime|"
    # prototype-pollution + ReDoS sinks
    r"__proto__|prototype\.|setWith|defaultsDeep|mergeDeep|zipObject|"
    r"new RegExp|RegExp\(|\.match\(|\.replace\(/",
    re.I)

ENTRY_RE = re.compile(
    r"@app\.(route|get|post)|@.*\.route|app\.(get|post|put|delete|use)|"
    r"http\.(HandleFunc|Handle)|router\.|express\(\)|"
    r"def (get|post|put|delete|handle)_|HttpServlet|@RequestMapping|"
    r"if __name__|func main\(|public static void main|argparse|click\.|"
    r"process\.argv|sys\.argv|os\.Args|flag\.(String|Parse)",
    re.I)

SKIP_DIRS = ("test", "tests", "spec", "docs", "examples", ".git",
             "node_modules", "vendor", "dist", "build", "__pycache__",
             "min", "perf", "benchmark", "benchmarks", "coverage",
             "scripts", "tools", ".github", "tmp", "locale", "locales",
             "i18n", "lang", "languages", "meteor")

# minified bundles / generated build tooling — never the vuln site, and
# their keyword density outranks real source
SKIP_FILE_RE = re.compile(r"\.min\.|^build[-_.]|[.-]bundle\.", re.I)


def score_file(root: Path, rel: str, sweep_hits: int = 0) -> float:
    try:
        text = (root / rel).read_text(errors="replace")
    except Exception:
        return 0.0
    if not text.strip():
        return 0.0
    n = max(text.count("\n"), 1)
    score = 0.5                       # baseline: every source file is queueable
    if FILE_RE.search(rel):
        score += 3.0
    if ENTRY_FILE_RE.search(rel):
        score += 2.0
    score += min(len(SINKS.findall(text)), 12) * 1.5
    score += min(len(ENTRY_RE.findall(text)), 6) * 1.0
    score += sweep_hits * 2.0
    # huge files are less tractable but still queueable — sink/entry density
    # already rewards them; soften the penalty for single-file-lib targets
    return score * min(1.0, 1500 / n)


def rank(root: Path, candidates: list[Finding],
         top: int | None = None,
         tm_targets: list[str] | None = None) -> list[dict]:
    if top is None:  # env-tunable — --frontier widens the funnel
        top = int(os.environ.get("CRS_QUEUE_TOP", "80"))
    hits: dict[str, int] = {}
    for c in candidates:
        hits[c.file] = hits.get(c.file, 0) + 1
    queue = []
    for p in root.rglob("*"):
        if not p.is_file() or any(d in p.parts for d in SKIP_DIRS):
            continue
        rel = str(p.relative_to(root))
        if SKIP_FILE_RE.search(p.name):
            continue
        if Path(rel).suffix.lower() not in EXT_LANG:
            continue
        s = score_file(root, rel, hits.get(rel, 0))
        # threat-model boost: the recon model named this high-value
        if tm_targets and any(t in rel for t in tm_targets):
            s += 4.0
        queue.append({"file": rel, "score": round(s, 2)})
    queue.sort(key=lambda q: -q["score"])
    return queue[:top]
