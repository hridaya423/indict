"""Cross-location semantic dedup tests (indictment/consensus.py + indictment/sie.py).
Run: uv run python tests/test_dedup_semantic.py"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from indictment import consensus, sie
from indictment.store import Finding

DETAIL_A = ("User-supplied search term flows from the request handler into "
            "a string concatenation passed straight to cursor.execute, so an "
            "attacker can break out of the quoted SQL literal and read rows.")
DETAIL_B = ("The export endpoint takes a filter value from the query string "
            "and splices it into a raw SQL statement via string concatenation "
            "before executing it, enabling arbitrary SQL injection reads.")


def main() -> None:
    ok = []
    orig = sie.embed

    def mk(file, line, conf, detail, title="SQL injection via string concat"):
        return Finding(engine="hunter", model="m1", file=file, line=line,
                       vuln_class="sqli", confidence=conf, title=title,
                       detail=detail)

    # 1. cross-file near-dupes, identical vectors -> one survivor
    a = mk("web/search.py", 42, 0.9, DETAIL_A)
    b = mk("api/export.py", 88, 0.5, DETAIL_A)
    sie.embed = lambda texts: [[1.0, 0.0]] * len(texts)
    try:
        out = consensus.pool([a, b])
    finally:
        sie.embed = orig
    assert len(out) == 1, [f.file for f in out]
    assert out[0] is a and "semantic-duplicate" in out[0].tags, out[0].tags
    assert "[semantic-duplicate of api/export.py:88]" in out[0].detail
    ok.append("cross-file near-dupe merged, winner keeps tag + provenance")

    # 2. same class, different details, orthogonal vectors -> both survive
    a = mk("web/search.py", 42, 0.9, DETAIL_A)
    b = mk("api/export.py", 88, 0.5, DETAIL_B)
    sie.embed = lambda texts: [[1.0, 0.0] if i == 0 else [0.0, 1.0]
                               for i in range(len(texts))]
    try:
        out = consensus.pool([a, b])
    finally:
        sie.embed = orig
    assert len(out) == 2, [f.file for f in out]
    assert all("semantic-duplicate" not in f.tags for f in out)
    ok.append("orthogonal details -> both survive")

    # 3. embed unavailable -> both survive, nothing merged
    a = mk("web/search.py", 42, 0.9, DETAIL_A)
    b = mk("api/export.py", 88, 0.5, DETAIL_A)
    sie.embed = lambda texts: None
    try:
        out = consensus.pool([a, b])
    finally:
        sie.embed = orig
    assert len(out) == 2, [f.file for f in out]
    ok.append("embed=None -> both survive")

    # 4. same file (lines far apart so adjacency leaves them) -> semantic
    # pass must NOT merge even with identical vectors
    a = mk("web/search.py", 10, 0.9, DETAIL_A)
    b = mk("web/search.py", 100, 0.5, DETAIL_A)
    sie.embed = lambda texts: [[1.0, 0.0]] * len(texts)
    try:
        out = consensus.pool([a, b])
    finally:
        sie.embed = orig
    assert len(out) == 2, [f.file for f in out]
    assert all("semantic-duplicate" not in f.tags for f in out)
    ok.append("same file -> left to adjacency, not semantic-merged")

    # 5. short detail (<80 chars) never participates even if identical
    a = mk("web/search.py", 42, 0.9, "too short")
    b = mk("api/export.py", 88, 0.5, "also way too short")
    sie.embed = lambda texts: [[1.0, 0.0]] * len(texts)
    try:
        out = consensus.pool([a, b])
    finally:
        sie.embed = orig
    assert len(out) == 2, [f.file for f in out]
    ok.append("short details -> not eligible for semantic merge")

    print("\n".join("PASS " + s for s in ok))
    print("DEDUP SEMANTIC TESTS OK")


if __name__ == "__main__":
    main()
