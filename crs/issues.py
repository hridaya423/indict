"""Autonomous issue filing — a small model drafts the report, GitHub REST
files it. Our repos only: CRS_ISSUE_REPO must point somewhere we own;
without it (or GITHUB_TOKEN) every call is a recorded dry-run. Never
raises: issue filing is ops sugar, not part of the funnel.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx

from .report import cvss_lite
from .store import Finding, dump as store_dump, load as store_load
from .util import prompt

API = "https://api.github.com"


def redact(text: str) -> str:
    """Outgoing text passes the same secret pack the sweep scanner uses —
    the writeup must never re-leak the credential it reported."""
    from engines.sweep import SECRET_RES
    for rx, _desc in SECRET_RES.values():
        text = rx.sub("[redacted]", text)
    return text


def _reproduce(f: Finding) -> str:
    for line in (f.detail or "").splitlines():
        if line.startswith("Reproduce:"):
            return line.split(":", 1)[1].strip()
    return "static analysis only — no reproduction yet"


def draft(client, f: Finding, repo: str) -> dict:
    r = client.chat("draft", [
        {"role": "system", "content":
         "You write responsible-disclosure issue reports — factual, "
         "minimal, never weaponizing beyond the PoC already produced."},
        {"role": "user", "content": prompt("issue",
            repo=repo, title=f.title, vuln_class=f.vuln_class,
            severity=f.severity, confidence=f"{f.confidence:.2f}",
            loc=f"{f.file}:{f.line}", detail=(f.detail or "")[:1500],
            reproduce=_reproduce(f))}], prefer=["sie-small"])
    pv = r.parsed or {}
    title = redact(str(pv.get("title") or f"[{f.vuln_class}] {f.title}")[:120])
    body = redact(str(pv.get("body") or f.detail or f.title))
    return {"title": title, "body": body}


def file(repo: str, f: Finding, issue: dict, out_root: Path,
         dry: bool) -> str:
    """Append the issue record; POST to GitHub only when creds + repo are
    configured and the caller passed --file. Returns url|'dry'|'skipped'."""
    target = os.environ.get("CRS_ISSUE_REPO", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    url = "dry"
    if not dry and target and token:
        try:
            r = httpx.post(f"{API}/repos/{target}/issues",
                headers={"Authorization": f"Bearer {token}",
                         "Accept": "application/vnd.github+json"},
                json={"title": issue["title"], "body": issue["body"],
                      "labels": ["security", "crs-ops"]}, timeout=20)
            url = r.json().get("html_url", "filed") if r.status_code < 300 \
                else f"http-{r.status_code}"
        except Exception as e:
            url = f"failed:{e.__class__.__name__}"
    elif not dry:
        url = "skipped:no-creds"
    try:
        path = out_root / repo / "issues.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as fh:
            fh.write(json.dumps({"ts": time.time(), "finding_id": f.id,
                                 "title": issue["title"], "url": url}) + "\n")
    except Exception as e:
        print(f"[issue] record failed: {e}", flush=True)
    return url


def run(repo: str, out_root: Path, client, file_issues: bool) -> None:
    fdir = out_root / repo
    findings = store_load(fdir / "findings.jsonl")
    todo = [f for f in findings
            if f.status in ("verified", "adjudicated")
            and "issue-filed" not in f.tags]
    if not todo:
        print(f"[issue] {repo}: nothing new to file")
        return
    live = bool(file_issues and os.environ.get("CRS_ISSUE_REPO")
                and os.environ.get("GITHUB_TOKEN"))
    mode = "LIVE" if live else "draft"
    for f in todo:
        try:
            issue = draft(client, f, repo)
        except Exception as e:
            print(f"[issue] draft failed for {f.id}: {e}", flush=True)
            continue
        url = file(repo, f, issue, out_root, dry=not file_issues)
        print(f"[issue] {mode} {f.id}: {issue['title'][:70]} -> {url}",
              flush=True)
        if url and not url.startswith(("dry", "skipped", "failed", "http-")):
            f.tags.append("issue-filed")
            f.detail += f"\nIssue: {url}"
    store_dump(fdir / "findings.jsonl", findings)
