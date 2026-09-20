"""Alert bus — new findings land in alerts.jsonl, the terminal, and a
severity-routed set of paging channels (Slack webhook, email, Twilio
SMS + voice). Missing credentials degrade a channel to the local
alerts-outbox.jsonl sim log instead of failing. Never raises: alerting
must not kill a scan or the watch daemon.
"""
from __future__ import annotations

import json
import os
import smtplib
import time
from email.mime.text import MIMEText
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

import httpx

from .report import cvss_lite

FINDINGS_ROOT = Path(__file__).resolve().parent.parent / "findings"

# severity -> channels; kinds may override (a fix verdict pages differently
# than a fresh finding — verified fixes are good news, not incidents)
ROUTES = {
    "critical": ["slack", "email", "sms", "call"],
    "high":     ["slack", "email", "sms"],
    "medium":   ["slack", "email"],
    "low":      ["slack"],
}
KIND_ROUTES = {"fix-verified": ["slack", "email"],
               "fix-rejected": ["slack"],
               "fix-timeout":   ["slack"],
               "fix-unverifiable": ["slack"]}


def _slack(text: str) -> bool:
    hook = os.environ.get("CRS_ALERT_WEBHOOK")
    if not hook:
        return False
    httpx.post(hook, json={"text": text}, timeout=10)
    return True


def _email(text: str) -> bool:
    host = os.environ.get("CRS_SMTP_HOST", "")
    to = os.environ.get("CRS_EMAIL_TO", "")
    if not host or not to:
        return False
    h, _, port = host.partition(":")
    msg = MIMEText(text)
    msg["Subject"] = text.split("\n", 1)[0][:120]
    msg["To"] = to
    msg["From"] = os.environ.get("CRS_SMTP_USER", "crs-ops@localhost")
    with smtplib.SMTP(h, int(port or 587), timeout=15) as s:
        s.starttls()
        user = os.environ.get("CRS_SMTP_USER")
        if user:
            s.login(user, os.environ.get("CRS_SMTP_PASS", ""))
        s.send_message(msg)
    return True


def _twilio(path: str, data: dict) -> bool:
    sid, tok = (os.environ.get("TWILIO_ACCOUNT_SID"),
                os.environ.get("TWILIO_AUTH_TOKEN"))
    frm, to = os.environ.get("TWILIO_FROM"), os.environ.get("TWILIO_TO")
    if not all((sid, tok, frm, to)):
        return False
    httpx.post(
        f"https://api.twilio.com/2010-04-01/Accounts/{sid}/{path}",
        auth=(sid, tok), data={"From": frm, "To": to, **data}, timeout=15)
    return True


def _sms(text: str) -> bool:
    return _twilio("Messages.json", {"Body": text[:480]})


def _call(text: str) -> bool:
    return _twilio("Calls.json", {"Twiml":
        f"<Response><Say voice=\"alice\">{xml_escape(text[:400])}</Say>"
        "</Response>"})


CHANNELS = {"slack": _slack, "email": _email, "sms": _sms, "call": _call}


def _outbox(out_root: Path, repo: str, channel: str, text: str) -> None:
    """Delivery intent lands here whenever a channel isn't live — the sim
    pager for demos/tests, and an audit record when a real send fails."""
    try:
        path = out_root / repo / "alerts-outbox.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as fh:
            fh.write(json.dumps({"ts": time.time(), "channel": channel,
                                 "text": text}) + "\n")
    except Exception:
        pass
    print(f"[page-sim] {channel}: {text[:100]}", flush=True)


def _deliver(kind: str, severity: str, text: str, out_root: Path,
             repo: str) -> None:
    route = KIND_ROUTES.get(kind) or ROUTES.get(severity, ["slack"])
    for ch in route:
        try:
            sent = CHANNELS[ch](text)
        except Exception as e:
            print(f"[alert] {ch} failed: {e}", flush=True)
            sent = False
        if not sent:
            _outbox(out_root, repo, ch, text)


def emit(repo: str, finding, kind: str, out_root: Path | None = None,
         extra: str = "") -> None:
    out_root = out_root or FINDINGS_ROOT
    try:
        line = {"ts": time.time(), "repo": repo, "kind": kind,
                "vuln_class": getattr(finding, "vuln_class", ""),
                "severity": getattr(finding, "severity", "medium"),
                "cvss_lite": cvss_lite(finding)
                    if hasattr(finding, "vuln_class") else 0.0,
                "file": getattr(finding, "file", ""),
                "line": getattr(finding, "line", 0),
                "title": getattr(finding, "title", kind), "id": finding.id,
                "extra": extra}
        path = out_root / repo / "alerts.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as f:
            f.write(json.dumps(line) + "\n")
    except Exception as e:
        print(f"[alert] write failed: {e}", flush=True)
    sev = getattr(finding, "severity", "medium")
    text = (f"[{repo}] {kind}: {sev} "
            f"{getattr(finding, 'vuln_class', '')} @ "
            f"{getattr(finding, 'file', '?')}:{getattr(finding, 'line', 0)}"
            f" — {getattr(finding, 'title', '')[:80]}"
            + (f" | {extra}" if extra else ""))
    print(f"[alert] {text}", flush=True)
    try:
        _deliver(kind, sev, text, out_root, repo)
    except Exception as e:
        print(f"[alert] deliver failed: {e}", flush=True)


def dep_cve_alerts(repo: str, findings,
                   out_root: Path | None = None) -> None:
    for f in findings:
        if f.vuln_class == "dep-cve" and f.status in ("adjudicated", "verified"):
            emit(repo, f, "dep-cve", out_root=out_root)
