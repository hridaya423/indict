"""Shared LLM agent loop — the vulnhuntr-style context-request protocol.

The model analyzes code, requests missing context via
  <context_request><symbol>foo</symbol><file>bar.py</file><line>12</line></context_request>
which we resolve with the Resolver, then re-analyzes. Ends with a JSON verdict.
Works with any OpenAI-compatible endpoint — no function-calling required.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

from crs.llms import Client, _parse_json
from crs.resolver import Resolver
from crs.util import context_requests


@dataclass
class AgentResult:
    parsed: dict | list | None
    model: str
    turns: int


def run_agent(client: Client, resolver: Resolver, root: Path,
              system: str, user: str, role: str = "hunt",
              max_iters: int = 0, prefer: list[str] | None = None,
              deadline: float | None = None) -> AgentResult:
    if not max_iters:
        max_iters = int(os.environ.get("CRS_MAX_ITERS", "8"))
    convo = [{"role": "system", "content": system},
             {"role": "user", "content": user}]
    model = "unknown"
    for turn in range(max_iters):
        if deadline and time.time() > deadline:
            break  # -> forcing call for a verdict on partial context
        reply = client.chat(role, convo, expect_json=False, prefer=prefer)
        model = reply.model
        convo.append({"role": "assistant", "content": reply.text})
        reqs = context_requests(reply.text)
        if reqs:
            convo.append({"role": "user", "content": _serve(resolver, root, reqs)})
            continue
        parsed = _parse_json(reply.text)
        if parsed is not None:
            return AgentResult(parsed=parsed, model=model, turns=turn + 1)
        convo.append({"role": "user", "content": (
            "If you need more code, emit <context_request>. Otherwise reply "
            "with ONE JSON object matching the required schema.")})
    # iterations exhausted without a verdict — one forcing call with the
    # client's corrective-retry loop engaged
    try:
        convo.append({"role": "user", "content":
            "Time is up. Reply with ONE JSON verdict object now — "
            "{\"findings\": [...]} — even if incomplete."})
        reply = client.chat(role, convo, expect_json=True, prefer=prefer)
        return AgentResult(parsed=reply.parsed, model=reply.model,
                           turns=max_iters + 1)
    except Exception as e:
        print(f"[agent:{role}] final verdict call failed: {e}", flush=True)
        return AgentResult(parsed=None, model=model, turns=max_iters)


def _serve(resolver: Resolver, root: Path, reqs: list[dict]) -> str:
    cap = int(os.environ.get("CRS_MAX_REQS", "4"))
    parts = []
    for r in reqs[:cap]:
        if r["symbol"]:
            hits = resolver.resolve(r["symbol"], r["file"])
            if hits:
                parts.append("<context>\n" +
                             "\n".join(s.fmt() for s in hits) + "\n</context>")
                continue
        if r["file"]:
            text = resolver.window(r["file"], r["line"] or 0,
                                   pad=120 if not r["line"] else 40)
            if text:
                parts.append(f"<context>\n### {r['file']}\n{text}\n</context>")
                continue
        parts.append(f"<context_error>could not resolve {r}</context_error>")
    return "\n".join(parts) or "<context_error>unparseable request</context_error>"
