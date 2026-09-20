"""SIE embeddings client tests — plain-assert style.
Run: uv run python tests/test_sie.py"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from indictment import sie


class Resp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class PostStub:
    """Replays canned responses in order; records every call."""

    def __init__(self, *responses):
        self.seq = list(responses)
        self.calls = []

    def __call__(self, url, key, body):
        self.calls.append((url, body))
        return self.seq.pop(0)


def patch_post(stub):
    orig = sie._post
    sie._post = stub
    return lambda: setattr(sie, "_post", orig)


def main() -> None:
    os.environ["SIE_API_KEY"] = "test-key"
    ok = []

    # (a) OpenAI-shaped response -> parsed in input order, single call
    sie._CACHE.clear()
    stub = PostStub(Resp(200, {"data": [
        {"embedding": [1.0, 0.0]}, {"embedding": [0.0, 1.0]}]}))
    restore = patch_post(stub)
    try:
        v = sie.embed(["alpha", "beta"])
    finally:
        restore()
    assert v == [[1.0, 0.0], [0.0, 1.0]], v
    assert len(stub.calls) == 1 and stub.calls[0][0].endswith("/v1/embeddings"), \
        stub.calls
    assert stub.calls[0][1] == {"model": "Qwen/Qwen3-Embedding-4B",
                                "input": ["alpha", "beta"]}, stub.calls[0][1]
    ok.append("openai shape parsed, one call")

    # (b) 404 on OpenAI path -> native /encode fallback, tolerant parse
    sie._CACHE.clear()
    stub = PostStub(
        Resp(404, {}),
        Resp(200, {"embeddings": [[1.0, 1.0], [0.0, 1.0]]}))
    restore = patch_post(stub)
    try:
        v = sie.embed(["one", "two"])
    finally:
        restore()
    assert v == [[1.0, 1.0], [0.0, 1.0]], v
    assert [u for u, _ in stub.calls] == [
        stub.calls[0][0], stub.calls[0][0].replace("/v1/embeddings", "/encode")], \
        stub.calls
    assert stub.calls[1][1] == {"model": "Qwen/Qwen3-Embedding-4B",
                                "inputs": ["one", "two"]}, stub.calls[1][1]
    ok.append("404 fallback to native /encode shape")

    # native {results: [...]} dict-item shape also parses
    sie._CACHE.clear()
    stub = PostStub(Resp(200, {"results": [
        {"embedding": [2.0]}, {"embedding": [3.0]}]}))
    restore = patch_post(stub)
    try:
        v = sie.embed(["three", "four"])
    finally:
        restore()
    assert v == [[2.0], [3.0]], v
    ok.append("native results shape parsed")

    # 429 then success -> retried, not an error
    sie._CACHE.clear()
    stub = PostStub(Resp(429, {}), Resp(200, {"data": [{"embedding": [0.5]}]}))
    restore = patch_post(stub)
    orig_sleep = sie.time.sleep
    sie.time.sleep = lambda s: None
    try:
        v = sie.embed(["five"])
    finally:
        sie.time.sleep = orig_sleep
        restore()
    assert v == [[0.5]], v
    assert len(stub.calls) == 2, stub.calls
    ok.append("429 retried with backoff")

    # unparseable response -> None, never raises
    sie._CACHE.clear()
    stub = PostStub(Resp(200, {"unexpected": True}))
    restore = patch_post(stub)
    try:
        v = sie.embed(["six"])
    finally:
        restore()
    assert v is None, v
    ok.append("garbage response -> None")

    # (c) missing key -> None without any HTTP call
    del os.environ["SIE_API_KEY"]
    called = []

    def boom(url, key, body):
        called.append(url)
        raise AssertionError("must not call HTTP without a key")
    orig = sie._post
    sie._post = boom
    try:
        v = sie.embed(["anything"])
    finally:
        sie._post = orig
    assert v is None and not called, (v, called)
    ok.append("no SIE_API_KEY -> None, zero calls")

    # cos: orthogonality + self-similarity
    assert abs(sie.cos([1.0, 0.0], [0.0, 1.0])) < 1e-9
    assert abs(sie.cos([0.5, 0.5, 0.5], [0.5, 0.5, 0.5]) - 1.0) < 1e-9
    assert sie.cos([1.0, 0.0], [0.0, 0.0]) == 0.0
    ok.append("cos orthogonal=0, self=1, zero-vector guarded")

    print("\n".join("PASS " + s for s in ok))
    print("SIE TESTS OK")


if __name__ == "__main__":
    main()
