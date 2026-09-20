#!/usr/bin/env python3
"""OpenAI-compatible /v1/chat/completions -> `devin acp` bridge.

Lets the Indict harness treat Devin (SWE-2-Max) as an endpoint. One fresh
`devin acp` child per request: initialize -> authenticate (windsurf_api_key
from ~/.local/share/devin/credentials.toml) -> session/new -> set "ask"
mode (text answers, no tool execution) -> session/prompt -> collect
agent_message_chunk stream -> OpenAI-shaped reply.

Usage: ./devin_acp_shim.py [port]   (default 8319)
"""
import json
import os
import queue
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CREDS = Path.home() / ".local/share/devin/credentials.toml"
CWD = Path(__file__).resolve().parent
MODEL_CANDIDATES = ["swe-2-max", "swe-2", "swe", None]  # None = account default
REQ_TIMEOUT = 280  # under harness's 300s client timeout

_key = None
_model_args = None
_model_lock = threading.Lock()


def api_key() -> str:
    global _key
    if _key is None:
        for line in CREDS.read_text().splitlines():
            k, _, v = line.partition("=")
            if k.strip() == "windsurf_api_key":
                _key = v.strip().strip('"')
    return _key


def spawn(model_args):
    args = ["devin", "acp"] + (model_args or [])
    return subprocess.Popen(
        args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, cwd=str(CWD),
        env={**os.environ, "WINDSURF_API_KEY": api_key()})


class ACP:
    def __init__(self, model_args):
        self.p = spawn(model_args)
        self.nid = 0
        self.lock = threading.Lock()
        # blocking readline() inside a `while < timeout` loop hangs forever
        # on a silent process — the deadline only ticks between lines. Pump
        # stdout on a daemon thread so every read carries a real deadline.
        self.q: queue.Queue = queue.Queue()

        def _pump():
            try:
                for line in self.p.stdout:
                    self.q.put(line)
            except Exception:
                pass
            self.q.put(None)                     # EOF sentinel

        threading.Thread(target=_pump, daemon=True).start()

    def _line(self, timeout: float):
        """One stdout line with a hard deadline. None = EOF, raises on
        timeout."""
        try:
            line = self.q.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("acp read timed out")
        if line is None:
            raise RuntimeError("acp stdout closed")
        return line

    def call(self, method, params, sink=None, timeout=60):
        with self.lock:
            self.nid += 1
            rid = self.nid
            self.p.stdin.write(json.dumps(
                {"jsonrpc": "2.0", "id": rid, "method": method,
                 "params": params}) + "\n")
            self.p.stdin.flush()
        t0 = time.time()
        while True:
            left = timeout - (time.time() - t0)
            if left <= 0:
                raise TimeoutError(f"{method} timed out")
            m = json.loads(self._line(left))
            if sink is not None:
                sink.append(m)
            if m.get("id") == rid:
                if "error" in m:
                    raise RuntimeError(f"{method}: {m['error'].get('message')}")
                return m.get("result", {})


def handshake(model_args) -> ACP:
    a = ACP(model_args)
    a.call("initialize", {"protocolVersion": 1, "clientCapabilities": {},
                          "clientInfo": {"name": "indictment-shim", "version": "1"}})
    a.call("authenticate", {"methodId": "devin-browser",
                            "_meta": {"api_key": api_key()}})
    return a


def detect_model():
    """First candidate whose session/new succeeds wins; cache it."""
    global _model_args
    with _model_lock:
        if _model_args is not None:
            return _model_args
        for cand in MODEL_CANDIDATES:
            args = ["--model", cand] if cand else []
            try:
                a = handshake(args)
                sid = a.call("session/new",
                             {"cwd": str(CWD), "mcpServers": []})["sessionId"]
                print(f"[shim] model arg ok: {cand or '(default)'}",
                      flush=True)
                a.p.kill()
                _model_args = args
                return args
            except Exception as e:
                print(f"[shim] model {cand or '(default)'} failed: {e}",
                      flush=True)
        raise RuntimeError("no usable devin model")


def flatten(messages) -> str:
    parts = []
    for m in messages:
        role = m.get("role", "user")
        parts.append(f"<{role}>\n{m.get('content', '')}\n</{role}>")
    parts.append("<user>\nReply to the latest user message above.\n</user>")
    return "\n".join(parts)


# Warm pool: each `devin acp` spawn pays ~seconds for CLI init + auth +
# session DB + MCP startup, and the harness makes one HTTP call per agent
# iteration — so keep handshake'd processes around and give each request a
# fresh session on a pooled process. A process is exclusive to one request
# at a time (acquire/release); PROC_MAX_USES bounds session-table leaks.
POOL_MAX = int(os.environ.get("INDICT_SHIM_POOL", "8"))
PROC_MAX_USES = 50
_pool: list = []
_pool_lock = threading.Lock()


def acquire() -> ACP:
    with _pool_lock:
        if _pool:
            return _pool.pop()
    return handshake(detect_model())  # over-commit when pool is empty


def release(a: ACP, healthy: bool) -> None:
    a.uses = getattr(a, "uses", 0) + 1
    if not healthy or a.uses >= PROC_MAX_USES:
        a.p.kill()
        return
    with _pool_lock:
        if len(_pool) < POOL_MAX:
            _pool.append(a)
            return
    a.p.kill()


def chat(messages) -> str:
    a = acquire()
    healthy = False
    try:
        sid = a.call("session/new",
                     {"cwd": str(CWD), "mcpServers": []})["sessionId"]
        try:
            a.call("session/set_mode", {"sessionId": sid, "modeId": "ask"})
        except Exception:
            pass  # older ACP: default mode still answers text
        chunks = []
        t0 = time.time()
        done = False
        with a.lock:
            a.nid += 1
            rid = a.nid
            a.p.stdin.write(json.dumps(
                {"jsonrpc": "2.0", "id": rid, "method": "session/prompt",
                 "params": {"sessionId": sid, "prompt": [
                     {"type": "text", "text": flatten(messages)}]}}) + "\n")
            a.p.stdin.flush()
        while True:
            left = REQ_TIMEOUT - (time.time() - t0)
            if left <= 0:
                break
            try:
                line = a._line(left)
            except (TimeoutError, RuntimeError):
                break
            m = json.loads(line)
            if m.get("method") == "session/update":
                u = m["params"].get("update", {})
                # only collect chunks for THIS session — a warm process can
                # still have trailing notifications from a previous one
                if (u.get("sessionUpdate") == "agent_message_chunk"
                        and m["params"].get("sessionId") == sid):
                    c = u.get("content", {})
                    chunks.append(c.get("text", "") if isinstance(c, dict)
                                  else str(c))
            elif m.get("method") and m.get("id") is not None:
                # agent->client request (fs/terminal/permission): deny
                with a.lock:
                    a.p.stdin.write(json.dumps(
                        {"jsonrpc": "2.0", "id": m["id"],
                         "error": {"code": -32603,
                                   "message": "shim: tools disabled"}}) + "\n")
                    a.p.stdin.flush()
            elif m.get("id") == rid:
                done = True
                break
        try:
            a.call("session/delete", {"sessionId": sid}, timeout=15)
        except Exception:
            pass  # proc is recycled via PROC_MAX_USES regardless
        # a proc that wedged mid-prompt never re-enters the pool — it gets
        # killed here and the next acquire() handshakes a fresh one
        healthy = done
        return "".join(chunks)
    finally:
        release(a, healthy)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.rstrip("/").endswith("models"):
            self._send(200, {"object": "list", "data": [
                {"id": "swe-2-max", "object": "model",
                 "owned_by": "devin"}]})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self.path.rstrip("/").endswith("chat/completions"):
            return self._send(404, {"error": "not found"})
        try:
            req = json.loads(self.rfile.read(
                int(self.headers["Content-Length"])))
            text = chat(req.get("messages", []))
            if not text.strip():
                raise RuntimeError("empty reply")
            self._send(200, {
                "id": "chatcmpl-devin", "object": "chat.completion",
                "created": int(time.time()), "model": "swe-2-max",
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant",
                                         "content": text}}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0,
                          "total_tokens": 0}})
        except Exception as e:
            print(f"[shim] error: {e}", flush=True)
            self._send(500, {"error": {"message": str(e),
                                       "type": "server_error"}})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8319
    detect_model()  # fail fast at boot, not mid-scan
    print(f"[shim] listening on 127.0.0.1:{port}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
