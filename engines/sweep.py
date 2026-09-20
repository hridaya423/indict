"""E1 sweep — deterministic scanners, zero model calls, free findings."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from crs.rank import SKIP_DIRS
from crs.store import Finding
from .hunter import _norm_class

# vendored registry packs (rules/) — refresh with:
#   curl -sL https://semgrep.dev/c/p/<pack> -o rules/<pack>.yaml
# local files keep sweep working with zero network on event day
_RULES = Path(__file__).resolve().parent.parent / "rules"
SEMGREP_CONFIGS = [str(p) for p in sorted(_RULES.glob("*.yaml"))]


def _skippable(rel: str) -> bool:
    return any(d in Path(rel).parts for d in SKIP_DIRS)


def which(tool: str) -> str | None:
    return (shutil.which(tool)
            or shutil.which(tool, path=os.path.expanduser("~/go/bin") + ":" + os.environ.get("PATH", "")))


# secret-scan pack — gitleaks-style regexes, zero dependencies. Each entry:
# name -> (compiled re, description). Line-scoped so findings carry line #s.
_SECRET_PATTERNS = {
    "aws-key": (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    "github-pat": (re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}"),
                   "GitHub token"),
    "gitlab-pat": (re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), "GitLab token"),
    "slack-token": (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    "stripe-key": (re.compile(r"[srp]k_live_[A-Za-z0-9]{20,}"), "Stripe live key"),
    "google-api": (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "Google API key"),
    "private-key": (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
                    "embedded private key"),
    "jwt": (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\."),
            "hardcoded JWT"),
    "telegram-bot": (re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}"), "Telegram bot token"),
    "openai-key": (re.compile(r"sk-(proj-)?[A-Za-z0-9_\-]{32,}"), "OpenAI-style API key"),
    "sendgrid": (re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"), "SendGrid key"),
    "npm-token": (re.compile(r"npm_[A-Za-z0-9]{36}"), "npm token"),
    "db-url": (re.compile(r"(postgres(ql)?|mysql|mongodb(\+srv)?|redis)://"
                          r"[^:\s/@]+:[^@\s/]+@(?!localhost|127\.0\.0\.1)"),
               "DB connection string with credentials"),
}
_SECRET_FPS = re.compile(r"xxxx|example|sample|placeholder|<[^>]+>|\{\{|chomp", re.I)
# public alias — issues.py redacts outgoing issue text with the same pack
SECRET_RES = _SECRET_PATTERNS
_MAX_PER_FILE = 3


def _secrets(root: Path) -> list[Finding]:
    out: list[Finding] = []
    for p in root.rglob("*"):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            continue
        if (not p.is_file() or p.stat().st_size > 1_000_000
                or any(d in Path(rel).parts for d in SKIP_DIRS)):
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        hits = 0
        for i, line in enumerate(text.splitlines(), 1):
            for name, (rx, desc) in _SECRET_PATTERNS.items():
                m = rx.search(line)
                if m and not _SECRET_FPS.search(line):
                    out.append(Finding(
                        engine="sweep", file=rel, line=i,
                        vuln_class="credential-leak", severity="high",
                        confidence=0.75,
                        title=f"{desc} in {rel.split('/')[-1]}",
                        detail=f"secret-scan:{name}: {m.group(0)[:12]}...",
                        tags=["secret"]))
                    hits += 1
                    if hits >= _MAX_PER_FILE:
                        break
            if hits >= _MAX_PER_FILE:
                break
    return out


def _run(cmd: list[str], cwd: Path, timeout: int = 300) -> dict:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout)
        if r.returncode != 0 and r.stderr.strip():
            print(f"[sweep] {cmd[0]} rc={r.returncode}: "
                  f"{r.stderr.strip()[:200]}", flush=True)
        return json.loads(r.stdout) if r.stdout.strip() else {}
    except Exception as e:
        print(f"[sweep] {cmd[0]} failed: {e}", flush=True)
        return {}


def run(root: Path, langs: list[str], **kw) -> list[Finding]:
    out: list[Finding] = []
    if which("semgrep"):
        cfg = sum([["--config", c] for c in SEMGREP_CONFIGS], [])
        data = _run(["semgrep", "scan", *cfg, "--json", "--quiet",
                     "--timeout", "60", "--no-git-ignore"], root)
        for m in data.get("results", []):
            rel = (str(Path(m["path"]).relative_to(root))
                   if Path(m["path"]).is_absolute() else m["path"])
            if _skippable(rel):
                continue  # hits in tests/docs are never the vuln
            sev = m.get("extra", {}).get("severity", "WARNING").lower()
            out.append(Finding(
                engine="sweep", file=rel,
                line=m.get("start", {}).get("line", 0),
                vuln_class=_norm_class(
                    m.get("check_id", "").split(".")[-1],
                    m.get("extra", {}).get("message", "")),
                severity={"error": "high", "warning": "medium"}.get(sev, "low"),
                confidence=0.6,
                title=m.get("extra", {}).get("message", m.get("check_id", ""))[:200],
                detail=f"semgrep:{m.get('check_id', '')}",
                tags=["semgrep"]))
    if which("osv-scanner"):
        data = _run(["osv-scanner", "scan", "source", "-r", "--format", "json",
                     "--verbosity", "error", str(root.resolve())], root)
        for res in data.get("results", []):
            for pkg in res.get("packages", []):
                for v in pkg.get("vulnerabilities", []):
                    out.append(Finding(
                        engine="sweep", file=res.get("source", {}).get("path", ""),
                        vuln_class="dep-cve", severity="high",
                        confidence=0.9,
                        title=f"{v.get('id','')} in {pkg.get('package',{}).get('name','')}",
                        detail="; ".join(v.get("aliases", []))[:300],
                        tags=["dep-cve"]))
    if "python" in langs and which("bandit"):
        data = _run(["bandit", "-r", "-f", "json", "-q", "."], root)
        for m in data.get("results", []):
            rel = m.get("filename", "").lstrip("./")
            if _skippable(rel):
                continue
            out.append(Finding(
                engine="sweep", file=rel,
                line=m.get("line_number", 0),
                vuln_class=_norm_class(m.get("test_id", ""),
                                       m.get("issue_text", "")),
                severity=m.get("issue_severity", "medium").lower(),
                confidence=m.get("issue_confidence", 0.5)
                    if isinstance(m.get("issue_confidence"), float) else 0.5,
                title=m.get("issue_text", "")[:200], detail="bandit",
                tags=["bandit"]))
    if "go" in langs and which("gosec"):
        data = _run(["gosec", "-fmt", "json", "./..."], root)
        for m in (data.get("Issues") or []):
            rel = m.get("file", "").lstrip("./")
            if _skippable(rel):
                continue
            out.append(Finding(
                engine="sweep", file=rel,
                line=int(m.get("line", "0") or 0),
                vuln_class=_norm_class(m.get("rule_id", ""),
                                       m.get("details", "")),
                severity=m.get("severity", "medium").lower(),
                confidence=0.6, title=m.get("details", "")[:200],
                detail="gosec", tags=["gosec"]))
    out.extend(_secrets(root))
    return out
