"""Issue filing: draft JSON parse, secret redaction, dry-run contract.
Nothing live — fake client, no GITHUB_TOKEN, tmp dirs only."""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
for k in ("GITHUB_TOKEN", "INDICT_ISSUE_REPO"):
    os.environ.pop(k, None)

from indictment import issues
from indictment.llms import Reply
from indictment.store import Finding, dump, load


class FakeClient:
    def chat(self, role, messages, **kw):
        assert role == "draft"
        return Reply(text="x", model="fake",
                     parsed={"title": "[rce] eval on argv",
                             "body": "## Summary\neval bug ghp_" + "a" * 36})


def f(status="verified", tags=None):
    return Finding(engine="t", file="a.py", line=3, vuln_class="rce",
                   severity="critical", title="eval bug", status=status,
                   detail="eval(input()) at a.py:3\nReproduce: bash x.sh",
                   tags=tags or ["poc-verified"])


def main():
    # redact: the sweep pack scrubs secrets from outgoing text
    assert "ghp_" not in issues.redact("token ghp_" + "a" * 36)
    assert "sk-" not in issues.redact("key sk-" + "b" * 40)
    assert "[redacted]" in issues.redact("AKIA" + "Z" * 16)
    print("PASS redact: tokens/keys scrubbed from outgoing text")

    # draft: parses the model's JSON and redacts the body
    issue = issues.draft(FakeClient(), f(), "repo")
    assert issue["title"].startswith("[rce]")
    assert "ghp_" not in issue["body"]
    print("PASS draft: JSON parsed + redacted")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        fd = root / "repo"
        fd.mkdir(parents=True)
        live_f, cand_f = f(), f(status="candidate")
        dump(fd / "findings.jsonl", [live_f, cand_f])

        # no creds -> recorded dry-run, nothing filed, no raise
        issues.run("repo", root, FakeClient(), file_issues=True)
        rows = [json.loads(l) for l in
                (fd / "issues.jsonl").read_text().splitlines()]
        assert len(rows) == 1 and rows[0]["url"] == "skipped:no-creds"
        # candidate findings never reach drafting
        assert all(r["finding_id"] == live_f.id for r in rows)
        print("PASS run: dry path records, skips candidates, never files")

        # re-run: issue-filed tag persists on real urls only — dry entries
        # don't consume the finding (still fileable later)
        live2 = f(tags=["poc-verified", "issue-filed"])
        cand2 = f(status="candidate")
        cand2.id = "c2"
        dump(fd / "findings.jsonl", [live2, cand2])
        issues.run("repo", root, FakeClient(), file_issues=True)
        rows = [json.loads(l) for l in
                (fd / "issues.jsonl").read_text().splitlines()]
        assert len(rows) == 1  # nothing new: issue-filed + candidate skip
        print("PASS rerun: filed findings don't re-draft")

    print("ISSUE TESTS OK")


if __name__ == "__main__":
    main()
