"""Reranker tests — SIE /v1/score parsing + PoC prioritization ordering.
Run: uv run python tests/test_rerank.py (plain asserts, no framework)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from indictment import sie                                    # noqa: E402
from indictment.store import Finding                         # noqa: E402


class _Resp:
    def __init__(self, code, payload):
        self.status_code = code
        self._p = payload

    def json(self):
        return self._p


def t_rerank_parse() -> None:
    calls = []

    def fake_post(url, key, body):
        calls.append(url)
        # scores arrive RANKED, not input-ordered — ids must map back
        return _Resp(200, {"scores": [
            {"item_id": "2", "score": 0.9},   # doc index 2 best
            {"item_id": "0", "score": 0.5},
            {"item_id": "1", "score": 0.1}]})

    os.environ["SIE_API_KEY"] = "test-key"
    orig = sie._post
    sie._post = fake_post
    try:
        out = sie.rerank("q", ["a", "b", "c"])
    finally:
        sie._post = orig
    assert out == [0.5, 0.1, 0.9], out
    assert "/v1/score/" in calls[0]
    print("PASS rerank: input-aligned scores from ranked response")


def t_rerank_off() -> None:
    os.environ.pop("SIE_API_KEY", None)
    assert sie.rerank("q", ["a"]) is None
    os.environ["SIE_API_KEY"] = "k"

    def boom(url, key, body):
        raise RuntimeError("network down")

    orig = sie._post
    sie._post = boom
    try:
        assert sie.rerank("q", ["a"]) is None   # never raises
    finally:
        sie._post = orig
    print("PASS rerank: no key / endpoint failure -> None")


def t_poc_ordering() -> None:
    """The poc.py gate: >cap candidates + live reranker = cross-encoder
    order; <=cap or no reranker = severity/confidence order."""
    # simulate the exact ordering logic from indictment.poc.prove
    def order(findings, cap, scores=None):
        todo = sorted(findings,
                      key=lambda f: ({"critical": 0, "high": 1}.get(f.severity, 2),
                                     -f.confidence))
        if len(todo) > cap and scores is not None:
            idx = sorted(range(len(todo)), key=lambda i: -scores[i])
            todo = [todo[i] for i in idx]
        return todo[:cap]

    weak = Finding(engine="t", file="a.py", line=1, vuln_class="sqli",
                   severity="high", confidence=0.95, title="weak but confident")
    strong = Finding(engine="t", file="b.py", line=1, vuln_class="deser",
                     severity="high", confidence=0.5, title="strong but humble")
    fs = [weak, strong]
    assert order(fs, 10)[0] is weak            # no cap pressure -> confidence
    assert order(fs, 1)[0] is weak             # no reranker -> confidence
    assert order(fs, 1, scores=[0.1, 0.9])[0] is strong   # reranker flips
    print("PASS poc ordering: reranker decides under cap pressure only")


def main() -> None:
    t_rerank_parse()
    t_rerank_off()
    t_poc_ordering()
    print("RERANK TESTS OK")


if __name__ == "__main__":
    main()
