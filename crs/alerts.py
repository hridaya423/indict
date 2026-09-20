"""Alert bus — new findings land in alerts.jsonl, the terminal and an
optional webhook (CRS_ALERT_WEBHOOK, Slack-style {"text": ...} payload).
Never raises: alerting must not kill a scan or the watch daemon.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx

from .report import cvss_lite

FINDINGS_ROOT = Path(__file__).resolve().parent.parent / "findings"


def emit(repo: str, finding, kind: str, out_root: Path | None = None) -> None:
    out_root = out_root or FINDINGS_ROOT
    try:
        line = {"ts": time.time(), "repo": repo, "kind": kind,
                "vuln_class": finding.vuln_class,
                "severity": finding.severity,
                "cvss_lite": cvss_lite(finding),
                "file": finding.file, "line": finding.line,
                "title": finding.title, "id": finding.id}
        path = out_root / repo / "alerts.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as f:
            f.write(json.dumps(line) + "\n")
    except Exception as e:
        print(f"[alert] write failed: {e}", flush=True)
    print(f"[alert] {repo}: {kind} {finding.severity} {finding.vuln_class} "
          f"@ {finding.file}:{finding.line} — {finding.title[:60]}",
          flush=True)
    hook = os.environ.get("CRS_ALERT_WEBHOOK")
    if not hook:
        return
    try:
        httpx.post(hook, json={"text": f"[{repo}] {kind}: {finding.severity} "
                                f"{finding.vuln_class} @ {finding.file}:"
                                f"{finding.line} — {finding.title[:80]}"},
                   timeout=10)
    except Exception as e:
        print(f"[alert] webhook failed: {e}", flush=True)


def dep_cve_alerts(repo: str, findings,
                   out_root: Path | None = None) -> None:
    for f in findings:
        if f.vuln_class == "dep-cve" and f.status in ("adjudicated", "verified"):
            emit(repo, f, "dep-cve", out_root=out_root)
