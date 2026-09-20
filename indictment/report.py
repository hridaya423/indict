"""Report stage — ranked REPORT.md, per-finding markdown, summary.json."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .store import Finding

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# canonical vuln_class -> CWE for SARIF export and finding headers
CWE = {
    "sqli": "CWE-89", "cmd-injection": "CWE-78", "rce": "CWE-94",
    "deser": "CWE-502", "xss": "CWE-79", "path-traversal": "CWE-22",
    "lfi": "CWE-98", "ssrf": "CWE-918", "xxe": "CWE-611",
    "prototype-pollution": "CWE-1321", "redos": "CWE-1333",
    "credential-leak": "CWE-798", "auth-bypass": "CWE-287",
    "crypto-misuse": "CWE-327", "race": "CWE-362",
    "memory-corruption": "CWE-787", "template-injection": "CWE-1336",
    "dos": "CWE-400", "idor": "CWE-639", "dep-cve": "CWE-1395",
    "other": "CWE-693",
}
_SARIF_LEVEL = {"critical": "error", "high": "error",
                "medium": "warning", "low": "warning", "info": "note"}

# deterministic severity: class base impact, bumped by proof state.
# Defensible in front of a judge vs model-asserted vibes.
_CLASS_BASE = {"rce": 9.8, "cmd-injection": 9.8, "memory-corruption": 8.8,
               "deser": 8.8, "sqli": 8.6, "template-injection": 8.0,
               "ssrf": 7.0, "xxe": 7.5, "path-traversal": 7.5, "lfi": 7.5,
               "credential-leak": 7.5, "auth-bypass": 7.5, "xss": 6.1,
               "prototype-pollution": 6.5, "crypto-misuse": 7.5,
               "race": 5.9, "idor": 6.5, "redos": 5.9, "dos": 5.3,
               "dep-cve": 7.5, "other": 4.0}


def cvss_lite(f: Finding) -> float:
    base = _CLASS_BASE.get(f.vuln_class, 5.0)
    if f.status == "verified":
        base = min(10.0, base + 0.5)  # PoC-proven in the sandbox
    if "line-verified" in f.tags:
        base = min(10.0, base + 0.2)  # reported line executed
    if f.confidence < 0.5:
        base *= 0.8  # uncorroborated single-source claim
    return round(base, 1)


def _sarif(findings: list[Finding], repo: str) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Indict vulnerability-discovery harness",
                "informationUri": "https://github.com/local/indictment"}},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": f"file://{repo}/"}},
            "results": [{
                "ruleId": f"Indict/{f.vuln_class}",
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.title or f.vuln_class},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(f.line, 1)}}}],
                "cwe": {"id": int((CWE.get(f.vuln_class, "CWE-693")
                                   or "CWE-693").split("-")[1])},
                "properties": {
                    "status": f.status, "severity": f.severity,
                    "confidence": f.confidence, "engine": f.engine,
                    "model": f.model, "tags": f.tags},
            } for f in findings],
        }],
    }


def render(findings: list[Finding], out_dir: Path, repo: str,
           root: Path | None = None) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    live = [f for f in findings if f.status in ("adjudicated", "verified")]
    dead = [f for f in findings if f.status == "dismissed"]
    unreviewed = [f for f in findings if f.status == "candidate"]
    live.sort(key=lambda f: (f.status != "verified",
                             SEV_RANK.get(f.severity, 3), -f.confidence))
    fdir = out_dir / "findings"
    fdir.mkdir(exist_ok=True)
    # stale per-finding files from earlier runs must not linger — a later
    # run that drops a finding would otherwise keep showing it as verified
    for stale in fdir.glob("*.md"):
        stale.unlink()
    for f in live:
        # verified findings must always carry a reproduce command — synthesize
        # one from the poc dir if an older run predates the embedded line
        if f.status == "verified" and "Reproduce:" not in f.detail and root:
            pdir = (out_dir / "poc" / f.id).resolve()
            script = next((s for s in ("probe.sh", "repro.sh")
                           if (pdir / s).exists()), None)
            if script:
                from .poc import EXT_IMG, RUN_POC
                lang = EXT_IMG.get(Path(f.file).suffix, "python")
                f.detail += (f"\nReproduce: bash {RUN_POC} {root.resolve()} "
                             f"{pdir} {lang} {script}")
        (fdir / f"{f.id}.md").write_text(
            f"# {f.title or f.vuln_class}\n\n"
            f"- **Status**: {f.status}\n- **Severity**: {f.severity} "
            f"(confidence {f.confidence:.2f}, cvss-lite {cvss_lite(f)})\n"
            f"- **Class**: {f.vuln_class} ({CWE.get(f.vuln_class, 'n/a')})"
            f"\n- **Location**: `{f.file}:{f.line}`\n"
            f"- **Engine**: {f.engine} | **Model**: {f.model} | "
            f"**Tags**: {', '.join(f.tags)}\n\n"
            f"## Detail\n{f.detail}\n\n## PoC\n{f.poc or 'n/a'}\n\n"
            f"## Adjudication\n{f.verdict or 'n/a'}\n")
    rows = "\n".join(
        f"| {i+1} | {f.status} | {f.severity} | {cvss_lite(f)} | "
        f"{f.vuln_class} | "
        f"`{f.file}:{f.line}` | {f.title[:60]} | {f.engine}/{f.model} |"
        for i, f in enumerate(live))
    n_ver = sum(1 for f in live if f.status == "verified")
    headline = (f"**{len(live)}** findings ({n_ver} PoC-verified), "
                f"{len(dead)} dismissed")
    if unreviewed:
        headline += (f", {len(unreviewed)} unreviewed candidates "
                     "(no LLM gate ran)")
    (out_dir / "REPORT.md").write_text(
        f"# Findings report — {repo}\n\n{headline}.\n\n"
        f"| # | status | severity | cvss-lite | class | location | title | source |\n"
        f"|---|--------|----------|-----------|-------|----------|-------|--------|\n{rows}\n\n"
        f"## Dismissed (sample)\n" + "\n".join(
            f"- {f.title[:70]} — {f.verdict[:80]}" for f in dead[:15]))
    (out_dir / "sarif.json").write_text(json.dumps(
        _sarif(live, repo), indent=1))
    summary = {
        "repo": repo, "total": len(findings), "live": len(live),
        "unreviewed": len(unreviewed),
        "verified": sum(1 for f in live if f.status == "verified"),
        "dismissed": len(dead),
        "max_cvss_lite": max((cvss_lite(f) for f in live), default=0.0),
        "by_severity": Counter(f.severity for f in live),
        "by_engine": Counter(f.engine for f in live),
        "by_model": Counter(f.model for f in live),
        "dismiss_reasons": Counter(f.verdict.split(":")[0] for f in dead),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2,
                                                   default=dict))
    return summary
