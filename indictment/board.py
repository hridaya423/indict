"""Ops board — read-only localhost surface over findings/<repo>/.

One stdlib ThreadingHTTPServer. GET / serves the compiled dashboard from
indictment/board_dist (legacy board.html when no build exists). /api/state and
/api/finding stay live for compatibility; the React app talks to the
scoped /api/v1/* projections in board_data.py. Read-only by construction:
no write routes, no PoC execution, no pack generation on GET — downloads
serve existing artifacts only. Path input is pinned inside findings_root
after symlink resolution.
"""
from __future__ import annotations

import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from . import board_data as bd
from . import events as ev
from .state import read as state_read
from .store import load as store_load
from .writeup import load as writeup_load

HERE = Path(__file__).resolve().parent
HTML = HERE / "board.html"
DIST = HERE / "board_dist"
REPRO_RE = re.compile(r"Reproduce: (.+)")
STATUSES = ("candidate", "adjudicated", "verified", "dismissed")
ASSET_TYPES = {".js": "text/javascript; charset=utf-8",
               ".css": "text/css; charset=utf-8",
               ".html": "text/html; charset=utf-8",
               ".svg": "image/svg+xml", ".png": "image/png",
               ".ico": "image/x-icon", ".woff2": "font/woff2",
               ".woff": "font/woff", ".map": "application/json"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' "
       "'unsafe-inline'; font-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; "
       "frame-ancestors 'none'")


def _jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue                    # torn tail line mid-write
        if isinstance(row, dict):
            out.append(row)
    return out


def _alerts(repo_dir: Path) -> list[dict]:
    """alerts.jsonl (kind/id carrying) merged with the outbox sim log,
    normalized to {ts, channel, kind, text, id} and sorted by ts."""
    rows = []
    for a in _jsonl(repo_dir / "alerts.jsonl"):
        text = (f"[{a.get('repo') or repo_dir.name}] {a.get('kind')}: "
                f"{a.get('severity')} {a.get('vuln_class')} @ "
                f"{a.get('file')}:{a.get('line')} — {a.get('title', '')[:80]}"
                + (f" | {a['extra']}" if a.get("extra") else ""))
        rows.append({"ts": a.get("ts", 0), "channel": "alert",
                     "kind": a.get("kind", ""), "text": text,
                     "id": a.get("id", ""),
                     "repo": a.get("repo") or repo_dir.name})
    for o in _jsonl(repo_dir / "alerts-outbox.jsonl"):
        rows.append({"ts": o.get("ts", 0), "channel": o.get("channel", ""),
                     "kind": "outbox", "text": o.get("text", ""), "id": "",
                     "repo": repo_dir.name, "sim": True})
    rows.sort(key=lambda r: r.get("ts") or 0)
    return rows[-100:]


def _fixes(repo_dir: Path) -> list[dict]:
    fdir = repo_dir / "fixes"
    if not fdir.is_dir():
        return []
    out = []
    for d in sorted(fdir.iterdir()):
        if not d.is_dir():
            continue
        try:
            j = json.loads((d / "verdict.json").read_text())
        except Exception:
            continue
        out.append({"id": d.name, "verdict": j.get("verdict", ""),
                    "reason": j.get("reason", ""),
                    "backend": j.get("backend", ""), "ts": j.get("ts", 0),
                    "repo": repo_dir.name})
    return out


def _queue(repo_dir: Path) -> int:
    q = repo_dir / "queue.jsonl"
    if not q.exists():
        return 0
    return sum(1 for l in q.read_text(errors="replace").splitlines()
               if l.strip())


def _repo(repo_dir: Path) -> dict:
    writeups = writeup_load(repo_dir)
    findings = []
    for f in store_load(repo_dir / "findings.jsonl"):
        d = f.model_dump()
        d["writeup"] = writeups.get(f.id, "")
        m = REPRO_RE.search(f.detail or "")
        d["reproduce"] = m.group(1).strip() if m else ""
        findings.append(d)
    funnel = {s: sum(1 for f in findings if f["status"] == s)
              for s in STATUSES}
    st = state_read(repo_dir)
    return {"name": repo_dir.name, "lastSha": st.get("last_sha"),
            "lastScan": st.get("last_scan") or 0, "live": ev.live(repo_dir),
            "funnel": funnel, "events": ev.read(repo_dir, limit=300),
            "findings": findings, "alerts": _alerts(repo_dir),
            "fixes": _fixes(repo_dir), "queue": _queue(repo_dir)}


def _state_payload(root: Path) -> dict:
    repos = []
    if root.is_dir():
        calib = bd._calib_names(root)
        for d in sorted(root.iterdir(), key=lambda p: p.name):
            if d.name in calib:
                continue
            if d.is_dir() and (d / "findings.jsonl").exists():
                try:
                    repos.append(_repo(d))
                except Exception:
                    continue             # one bad repo must not sink the board
    estate = {"repos": len(repos),
              "verified": sum(r["funnel"]["verified"] for r in repos),
              "adjudicated": sum(r["funnel"]["adjudicated"] for r in repos),
              "dismissed": sum(r["funnel"]["dismissed"] for r in repos),
              "alerts": sum(len(r["alerts"]) for r in repos),
              "live": any((r["live"] or {}).get("live") for r in repos)}
    return {"generatedAt": time.time(), "stale": False,
            "estate": estate, "repos": repos}


def _fix_for(repo_dir: Path, fid: str) -> dict | None:
    fdir = repo_dir / "fixes"
    if fdir.is_dir():
        for d in sorted(fdir.iterdir()):
            if not d.is_dir() or not (d.name.startswith(fid)
                                      or fid.startswith(d.name)):
                continue
            try:
                j = json.loads((d / "verdict.json").read_text())
            except Exception:
                continue
            return {"id": d.name, "verdict": j.get("verdict"),
                    "reason": j.get("reason"), "backend": j.get("backend"),
                    "ts": j.get("ts")}
    return None


def _finding_payload(root: Path, repo: str, idprefix: str) -> dict:
    out = {"finding": None, "writeup": "", "poc": [], "alerts": [],
           "fix": None, "events": [], "chain": []}
    repo_dir = (root / repo).resolve()
    if not repo or repo_dir == root or root not in repo_dir.parents \
            or not repo_dir.is_dir():
        return out
    findings = store_load(repo_dir / "findings.jsonl")
    f = next((x for x in findings
              if x.id == idprefix or x.id.startswith(idprefix)), None)
    if f is None:
        return out
    d = f.model_dump()
    d["writeup"] = writeup_load(repo_dir).get(f.id, "")
    m = REPRO_RE.search(f.detail or "")
    d["reproduce"] = m.group(1).strip() if m else ""
    out["finding"] = d
    out["writeup"] = d["writeup"]
    pdir = repo_dir / "poc" / f.id
    if pdir.is_dir():
        for p in sorted(pdir.iterdir()):
            if not p.is_file():
                continue
            try:
                head = p.read_text(errors="replace")[:200]
            except Exception:
                head = ""
            out["poc"].append({"name": p.name, "size": p.stat().st_size,
                               "head": head})
    out["alerts"] = [a for a in _alerts(repo_dir)
                     if a.get("id") == f.id
                     or f.id in (a.get("text") or "")]
    out["fix"] = _fix_for(repo_dir, f.id)
    out["events"] = [e for e in ev.read(repo_dir)
                     if e.get("finding") == f.id]
    out["chain"] = [o.model_dump() for o in findings
                    if o.id != f.id and f.id in (o.detail or "")]
    return out


def _q1(query: str, key: str, default=None):
    v = parse_qs(query).get(key)
    return v[0] if v else default


def _qint(query: str, key: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(_q1(query, key) or default)))
    except (TypeError, ValueError):
        return default


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            u = urlparse(self.path)
            host = (self.headers.get("Host") or "").split(":")[0]
            if host not in ("127.0.0.1", "localhost", "::1"):
                self._err(403, "forbidden-host", "localhost only", False)
                return
            if u.path == "/api/state":
                self._json(_state_payload(self.server.findings_root))
            elif u.path == "/api/finding":
                q = parse_qs(u.query)
                self._json(_finding_payload(
                    self.server.findings_root, q.get("repo", [""])[0],
                    q.get("id", [""])[0]))
            elif u.path.startswith("/api/"):
                self._v1(u)
            elif u.path.startswith("/assets/") or "." in \
                    u.path.rsplit("/", 1)[-1]:
                self._asset(u.path)
            else:
                # SPA fallback — any extensionless non-API path is an app
                # route (/, /findings/<id>, /runs/<id>, /repos/<id>, ...)
                self._index()
        except Exception:
            try:
                self._err(500, "internal", "unexpected server failure", True)
            except Exception:
                pass

    # ── v1 API ───────────────────────────────────────────────────────
    def _v1(self, u) -> None:
        root = self.server.findings_root
        seg = [unquote(s) for s in u.path.split("/") if s][2:]
        q = u.query
        if not seg:
            self._err(404, "unknown-route", "no such resource", False)
            return
        if seg == ["overview"]:
            self._json(bd.overview(root, repo=_q1(q, "repo"),
                                   run=_q1(q, "run"),
                                   finding=_q1(q, "finding")))
            return
        if seg == ["runs"]:
            self._json(bd.runs_list(root, repo=_q1(q, "repo"),
                                    state=_q1(q, "state"),
                                    cursor=_q1(q, "cursor"),
                                    limit=_qint(q, "limit", 50, 1, 100)))
            return
        if seg == ["findings"]:
            self._json(bd.findings_list(
                root, repo=_q1(q, "repo"), run=_q1(q, "run"),
                q=_q1(q, "q"), status=_q1(q, "status"),
                severity=_q1(q, "severity"), vclass=_q1(q, "class"),
                engine=_q1(q, "engine"),
                nofix=_q1(q, "nofix") in ("1", "true"),
                sort=_q1(q, "sort"),
                page=_qint(q, "page", 1, 1, 100000),
                limit=_qint(q, "limit", 50, 1, 100)))
            return
        if seg == ["fixes"]:
            self._json(bd.fixes_list(root, repo=_q1(q, "repo"),
                                     verdict=_q1(q, "verdict"),
                                     cursor=_q1(q, "cursor"),
                                     limit=_qint(q, "limit", 50, 1, 100)))
            return
        if seg[0] == "artifacts" and len(seg) == 2:
            self._artifact(seg[1], preview=_q1(q, "preview") == "1")
            return
        if seg[0] == "repos" and len(seg) == 1:
            self._json(bd.repos_list(root))
            return
        if seg[0] == "repos" and len(seg) >= 2:
            repo = seg[1]
            repo_dir = (root / repo).resolve()
            try:
                repo_dir.relative_to(root.resolve())
            except ValueError:
                self._err(400, "bad-scope", "repo outside root", False)
                return
            if len(seg) == 2:
                self._json(bd.repo_detail(root, repo))
                return
            if len(seg) == 4 and seg[2] == "runs":
                d = self._run_detail(repo_dir, seg[3])
                if d is None:
                    self._err(404, "unknown-run",
                              "no such run", False)
                else:
                    self._json(d)
                return
            if len(seg) == 5 and seg[2] == "runs" and seg[4] == "events":
                out = bd.run_events(repo_dir, seg[3],
                                    cursor=_q1(q, "cursor"),
                                    limit=_qint(q, "limit", 100, 1, 100),
                                    before=_q1(q, "before"),
                                    after=_q1(q, "after"))
                if out is None:
                    self._err(404, "unknown-run", "no such run", False)
                else:
                    self._json(out)
                return
            if len(seg) == 4 and seg[2] == "findings":
                out = bd.finding_case(root, repo, seg[3],
                                      run=_q1(q, "run"))
                rerr = out.get("runError")
                if rerr or out.get("finding") is None:
                    self._send(json.dumps({
                        "error": {
                            "code": rerr or "unknown-finding",
                            "message": {"unknown-run": "no such run",
                                        "not-in-run": "finding not recorded "
                                                      "in this run"}.get(
                                            rerr, "no such finding"),
                            "retryable": False},
                        "latestRun": out.get("latestRun")}).encode(),
                        "application/json", 404)
                else:
                    self._json(out)
                return
            if len(seg) == 4 and seg[2] == "fixes":
                out = bd.fix_detail(root, repo, seg[3])
                if out.get("fix") is None:
                    self._err(404, "unknown-fix", "no such fix", False)
                else:
                    self._json(out)
                return
        self._err(404, "unknown-route", "no such resource", False)

    def _run_detail(self, repo_dir: Path, rid: str):
        if not repo_dir.is_dir():
            return None
        return bd._run_detail(repo_dir, rid)

    def _artifact(self, aid: str, preview: bool) -> None:
        root = self.server.findings_root
        p, err = bd.artifact_resolve(root, aid)
        if p is None:
            code = 400 if err == "traversal" else 404
            self._err(code, err, "artifact unavailable", False)
            return
        try:
            size = p.stat().st_size
        except OSError:
            self._err(404, "missing", "artifact gone", True)
            return
        if preview:
            if p.suffix.lower() not in bd.TEXT_TYPES:
                self._json({"name": p.name, "size": size, "previewable":
                            False, "text": None})
                return
            data = p.read_bytes()[:bd.PREVIEW_CAP + 1]
            truncated = len(data) > bd.PREVIEW_CAP
            self._json({"name": p.name, "size": size, "previewable": True,
                        "text": data[:bd.PREVIEW_CAP]
                        .decode(errors="replace"),
                        "shownBytes": min(len(data), bd.PREVIEW_CAP),
                        "totalBytes": size, "truncated": truncated})
            return
        name = re.sub(r"[^A-Za-z0-9._-]", "_", p.name)
        try:
            st0 = p.stat()
            fh = p.open("rb")
            # reject if the path was swapped between resolve and open
            if not os.path.samestat(st0, os.fstat(fh.fileno())):
                fh.close()
                self._err(404, "missing", "artifact changed", True)
                return
        except OSError:
            self._err(404, "missing", "artifact gone", True)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition",
                         f'attachment; filename="{name}"')
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        try:
            while chunk := fh.read(65536):
                self.wfile.write(chunk)
        finally:
            fh.close()

    # ── static ───────────────────────────────────────────────────────
    def _index(self) -> None:
        idx = DIST / "index.html"
        if idx.exists():
            self._send_html(idx.read_bytes())
        else:
            self._send_html(HTML.read_bytes())

    def _asset(self, path: str) -> None:
        rel = unquote(path.lstrip("/"))
        p = (DIST / rel).resolve()
        try:
            p.relative_to(DIST.resolve())
        except ValueError:
            self._send(b"not found", "text/plain; charset=utf-8", 404)
            return
        if not p.is_file():
            self._send(b"not found", "text/plain; charset=utf-8", 404)
            return
        ctype = ASSET_TYPES.get(p.suffix.lower(),
                                "application/octet-stream")
        body = p.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    # ── plumbing ─────────────────────────────────────────────────────
    def _send_html(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload) -> None:
        self._send(json.dumps(payload, default=str).encode(),
                   "application/json")

    def _err(self, code: int, ecode: str, msg: str, retryable: bool) -> None:
        self._send(json.dumps({"error": {"code": ecode, "message": msg,
                                         "retryable": retryable}}).encode(),
                   "application/json", code)

    def _send(self, body: bytes, ctype: str, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


def serve(findings_root: Path, port: int) -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    srv.daemon_threads = True
    srv.findings_root = Path(findings_root).resolve()
    print(f"board: http://127.0.0.1:{srv.server_port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
