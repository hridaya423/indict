"""Semantic queue-ranking tests (indictment/rank.py + indictment/sie.py).
Run: uv run python tests/test_rank_semantic.py"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from indictment import rank, sie
from indictment.store import Finding

ROUTER = '''import sqlite3

def handle(request):
    q = request.args.get("q")
    name = request.args.get("name")
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    rows = db.cursor().execute(sql)
    more = db.cursor().execute("SELECT id FROM items WHERE a = " + q)
    return rows + more
'''
NOTES = '''# docs_notes.py
# markdown-ish notes only, no sinks, no code paths.
NOTE = """
# Usage notes
This module only holds notes for the team.
Nothing executable lives here.
"""
'''


def fake_embed(texts):
    """Descriptors -> 8 one-hot vectors in 9-dim space. Windows: a
    SELECT-bearing (sink-dense) window is collinear with descriptor 0
    (cos=1); anything else lands on the unused 9th axis (orthogonal to
    every descriptor, cos=0)."""
    if texts == list(rank.VULN_QUERIES):
        return [[1.0 if j == i else 0.0 for j in range(9)] for i in range(8)]
    return [[1.0] + [0.0] * 8 if "SELECT" in t else [0.0] * 8 + [1.0]
            for t in texts]


def main() -> None:
    ok = []
    # temp repo under the repo root — /tmp is in rank.SKIP_DIRS on Linux
    repo_root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="crsrank", dir=repo_root) as td:
        root = Path(td)
        (root / "auth_router.py").write_text(ROUTER)
        (root / "docs_notes.py").write_text(NOTES)
        # sweep hits park on the notes file so keyword scoring ranks it
        # ABOVE the neutral-named router despite the router's real sinks
        cands = [Finding(engine="sweep", file="docs_notes.py")
                 for _ in range(4)]

        # baseline: embed off -> exact keyword order, notes first
        orig = sie.embed
        sie.embed = lambda t: None
        try:
            kw = rank.rank(root, cands, top=10)
        finally:
            sie.embed = orig
        kw_order = [q["file"] for q in kw]
        kw_score = {q["file"]: q["score"] for q in kw}
        assert kw_order == ["docs_notes.py", "auth_router.py"], kw_order
        assert kw_score["auth_router.py"] < kw_score["docs_notes.py"], kw_score
        ok.append(f"keyword order preserved when embed=None "
                  f"({kw_score['docs_notes.py']} > {kw_score['auth_router.py']})")

        # semantic on: router window is collinear with a vuln descriptor,
        # notes orthogonal -> router overtakes despite lower keyword score
        sie.embed = fake_embed
        try:
            q = rank.rank(root, cands, top=10)
        finally:
            sie.embed = orig
        sem_order = [e["file"] for e in q]
        assert sem_order == ["auth_router.py", "docs_notes.py"], sem_order
        assert q[0]["score"] > q[1]["score"], q
        ok.append(f"semantic boost reordered: router "
                  f"({q[0]['score']}) now outranks notes ({q[1]['score']})")

        # no-key path: no SIE_API_KEY -> same as embed=None
        import os
        had = os.environ.pop("SIE_API_KEY", None)
        try:
            off = rank.rank(root, cands, top=10)
        finally:
            if had is not None:
                os.environ["SIE_API_KEY"] = had
        assert [e["file"] for e in off] == kw_order, off
        ok.append("no SIE key -> keyword order unchanged")

    print("\n".join("PASS " + s for s in ok))
    print("RANK SEMANTIC TESTS OK")


if __name__ == "__main__":
    main()
