"""SIE (Superlinked) embeddings client — semantic layer for rank + dedup.

Every failure mode returns None; callers treat None as "skip the semantic
feature", so a missing key or a dead endpoint degrades the pipeline to
pure keyword scoring, never crashes it.
"""
from __future__ import annotations

import os
import time

import httpx

BATCH = 32
# ponytail: unbounded per-process cache — one pipeline run's worth of texts;
# upgrade to an LRU if this is ever imported by a long-lived service.
_CACHE: dict[tuple[str, ...], list[list[float]]] = {}


def _post(url: str, key: str, body: dict) -> httpx.Response:
    with httpx.Client(timeout=30.0) as c:
        return c.post(url, headers={"Authorization": f"Bearer {key}"}, json=body)


def _vec(x) -> list[float] | None:
    if isinstance(x, dict):
        x = x.get("embedding", x.get("vector", x.get("values")))
    if isinstance(x, list):
        return [float(n) for n in x]
    return None


def _parse(r) -> list[list[float]] | None:
    """Tolerant parse: OpenAI {data:[{embedding}]} | native
    {results|embeddings: [...]} | bare list of vectors."""
    try:
        d = r.json()
    except Exception:
        return None
    items = d.get("data") if isinstance(d, dict) else d
    if isinstance(d, dict) and not items:
        items = d.get("results") or d.get("embeddings")
    if not isinstance(items, list):
        return None
    out = [_vec(x) for x in items]
    return out if all(out) else None


def _call(url: str, key: str, body: dict):
    """One POST with 429/5xx retry (3s/6s). Returns the last response."""
    r = None
    for delay in (0, 3, 6):
        if delay:
            time.sleep(delay)
        try:
            r = _post(url, key, body)
        except Exception as e:
            print(f"[sie] embeddings unavailable: {e}", flush=True)
            return None
        if r.status_code != 429 and r.status_code < 500:
            return r
    return r  # retries exhausted — hand back for the parse-fail path


def _embed_chunk(base: str, model: str, key: str,
                 chunk: list[str]) -> list[list[float]] | None:
    r = _call(f"{base}/v1/embeddings", key,
              {"model": model, "input": list(chunk)})
    if r is not None and r.status_code in (400, 404):  # wrong shape — native
        r = _call(f"{base}/encode", key,
                  {"model": model, "inputs": list(chunk)})
    if r is None:
        return None
    vecs = _parse(r)
    if vecs is None or len(vecs) != len(chunk):
        print(f"[sie] embeddings unavailable: unparseable response "
              f"(HTTP {r.status_code})", flush=True)
        return None
    return vecs


def embed(texts: list[str]) -> list[list[float]] | None:
    if "SIE_API_KEY" not in os.environ or not texts:
        return None
    key = os.environ["SIE_API_KEY"]
    base = os.environ.get("CRS_SIE_BASE_URL",
                           "https://api.superlinked.com").rstrip("/")
    model = os.environ.get("CRS_SIE_EMBED_MODEL", "BAAI/bge-m3")
    out: list[list[float]] = []
    for i in range(0, len(texts), BATCH):
        chunk = texts[i:i + BATCH]
        k = tuple(chunk)
        if k in _CACHE:
            out.extend(_CACHE[k])
            continue
        vecs = _embed_chunk(base, model, key, chunk)
        if vecs is None:
            return None
        _CACHE[k] = vecs
        out.extend(vecs)
    return out


def cos(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


def rerank(query: str, docs: list[str]) -> list[float] | None:
    """Cross-encoder relevance scores via SIE's /v1/score (aligned with
    input order). None = no key / endpoint trouble — callers fall back to
    their existing ordering. Never raises."""
    if "SIE_API_KEY" not in os.environ or not docs:
        return None
    key = os.environ["SIE_API_KEY"]
    base = os.environ.get("CRS_SIE_BASE_URL",
                          "https://api.superlinked.com").rstrip("/")
    model = os.environ.get("CRS_SIE_RERANK_MODEL", "Qwen/Qwen3-Reranker-4B")
    body = {"query": {"text": query},
            "items": [{"id": str(i), "text": d} for i, d in enumerate(docs)]}
    try:
        r = _post(f"{base}/v1/score/{model}", key, body)
        if r.status_code != 200:
            print(f"[sie] rerank unavailable (HTTP {r.status_code})", flush=True)
            return None
        by_id = {e.get("item_id"): float(e.get("score", 0.0))
                 for e in r.json().get("scores", [])}
        return [by_id.get(str(i), 0.0) for i in range(len(docs))]
    except Exception as e:
        print(f"[sie] rerank unavailable: {e}", flush=True)
        return None
