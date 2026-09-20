"""E5 variant — Big Sleep style: mine git history for security fixes, then
hunt for sibling instances of the same bug class elsewhere in the tree.
"""
from __future__ import annotations

import re
import time
from pathlib import Path

from crs.llms import Client
from crs.resolver import Resolver
from crs.store import Finding
from crs.util import git, prompt
from .agent_loop import run_agent
from .hunter import _norm_class, _norm_sev

FIX_RE = re.compile(r"fix|secur|vuln|cve|overflow|inject|xss|ssrf|travers|"
                    r"rce|auth|sanitize|escape|overflow", re.I)


def run(root: Path, client: Client, resolver: Resolver, **kw) -> list[Finding]:
    if not (root / ".git").exists():
        return []
    git(root, "fetch", "--unshallow", "--quiet")  # no-op on full clones
    log = git(root, "log", "--oneline", "-i", "--grep=fix",
              "--grep=secur", "--grep=CVE", "--grep=vuln", "--grep=overflow",
              "--grep=inject", "--grep=xss", "--grep=ssrf", "--grep=travers",
              "--grep=auth", "--grep=sanitize", "-n", "30")
    shas = [l.split()[0] for l in log.splitlines() if l.strip()][:10]
    deadline = kw.get("deadline")
    out: list[Finding] = []
    for sha in shas:
        if deadline and time.time() > deadline:
            break
        diff = git(root, "show", "--stat", "--format=%s", sha)
        if not FIX_RE.search(diff):
            continue
        patch = git(root, "show", "--format=", "--unified=6", sha)[:8000]
        if not patch.strip():
            continue
        res = run_agent(client, resolver, root,
                        prompt("variant"), 
                        (f"This fix patched a vulnerability:\n\n{diff}\n\n"
                         f"<patch>\n{patch}\n</patch>\n\n"
                         "Identify the bug CLASS, then check the CURRENT tree "
                         "for sibling instances: same pattern unfixed, "
                         "same bypass incomplete, or copy-pasted vulnerable "
                         "code elsewhere. Use <context_request> to inspect."),
                        role="hunt", max_iters=6, deadline=deadline)
        if not isinstance(res.parsed, dict):
            continue
        for f in res.parsed.get("findings", []):
            out.append(Finding(
                engine="variant", model=res.model,
                file=f.get("file", ""), line=int(f.get("line") or 0),
                vuln_class=_norm_class(str(f.get("vuln_class", "")),
                                       str(f.get("title", ""))),
                severity=_norm_sev(str(f.get("severity", "medium"))),
                confidence=float(f.get("confidence") or 0.5),
                title=f"[variant of {sha}] {f.get('title','')}"[:200],
                detail=str(f.get("evidence", ""))[:3000],
                poc=str(f.get("poc_idea", ""))[:1500],
                tags=["variant"]))
    return out
