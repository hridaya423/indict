"""Paging bus: severity routing, sim outbox, never-raise. No live sends —
env creds stay unset so every channel degrades to alerts-outbox.jsonl."""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.pop("CRS_ALERT_WEBHOOK", None)

from crs import alerts
from crs.store import Finding


def f(sev="high"):
    return Finding(engine="t", file="a.py", line=3, vuln_class="rce",
                   severity=sev, title="test bug")


def main():
    # routing table: critical pages, low doesn't
    assert "call" in alerts.ROUTES["critical"]
    assert "sms" in alerts.ROUTES["high"] and "call" not in alerts.ROUTES["high"]
    assert alerts.ROUTES["medium"] == ["slack", "email"]
    assert alerts.ROUTES["low"] == ["slack"]
    # fix verdicts override severity routing — good news isn't a page
    assert alerts.KIND_ROUTES["fix-verified"] == ["slack", "email"]
    print("PASS routes: severity->channel policy + kind overrides")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        # no env creds -> every routed channel degrades to the outbox
        alerts.emit("r", f("critical"), "new-verified", out_root=root)
        rows = [json.loads(l) for l in
                (root / "r" / "alerts-outbox.jsonl").read_text().splitlines()]
        assert {r["channel"] for r in rows} == {"slack", "email", "sms", "call"}
        assert "new-verified" in rows[0]["text"] and "critical" in rows[0]["text"]
        # alerts.jsonl always written regardless of channel state
        assert (root / "r" / "alerts.jsonl").exists()
        # kind override: fix-verified routes slack+email only
        (root / "r" / "alerts-outbox.jsonl").unlink()
        alerts.emit("r", f("critical"), "fix-verified", out_root=root)
        rows = [json.loads(l) for l in
                (root / "r" / "alerts-outbox.jsonl").read_text().splitlines()]
        assert {r["channel"] for r in rows} == {"slack", "email"}
        print("PASS outbox: unrouted creds -> sim record per channel")

        # never-raise: env points at dead endpoints, emit must survive
        os.environ["CRS_ALERT_WEBHOOK"] = "http://127.0.0.1:1/dead"
        os.environ["TWILIO_ACCOUNT_SID"] = "AC" + "0" * 32
        os.environ["TWILIO_AUTH_TOKEN"] = "x"
        os.environ["TWILIO_FROM"] = "+10000000000"
        os.environ["TWILIO_TO"] = "+10000000000"
        os.environ["CRS_SMTP_HOST"] = "127.0.0.1:1"
        os.environ["CRS_EMAIL_TO"] = "a@b.c"
        alerts.emit("r", f("critical"), "new-verified", out_root=root)
        print("PASS never-raise: dead endpoints can't kill emit()")
        for k in ("CRS_ALERT_WEBHOOK", "TWILIO_ACCOUNT_SID",
                  "TWILIO_AUTH_TOKEN", "TWILIO_FROM", "TWILIO_TO",
                  "CRS_SMTP_HOST", "CRS_EMAIL_TO"):
            os.environ.pop(k)

    print("PAGING TESTS OK")


if __name__ == "__main__":
    main()
