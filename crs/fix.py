"""Fix loop — dispatch a verified finding to an agent backend in an
isolated worktree, then grade its patch mechanically: the recorded PoC
must stop firing, and a --since rescan of the patch must stay clean.

The agent proposes; the funnel decides. Backends are pluggable
(CRS_FIXER: codex | devin-acp | command) — the agent never touches the
scan clone or the watcher, and nothing lands on repos we don't own.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from . import alerts
from .poc import EXT_IMG, RUN_POC
from .resolver import Resolver
from .store import Finding, load as store_load

FIX_TIMEOUT = int(os.environ.get("CRS_FIX_TIMEOUT", "900"))


def _git(root: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(root), *args],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()[:200]}")
    return r.stdout.strip()


def package(root: Path, f: Finding, fixdir: Path, pdir: Path,
            resolver=None) -> Path:
    """The contract handed to the agent: finding, code, proof, rules."""
    fixdir.mkdir(parents=True, exist_ok=True)
    resolver = resolver or Resolver(root)
    code = resolver.window(f.file, f.line or 1, pad=60)
    rerun = {}
    if (pdir / "rerun.json").exists():
        rerun = json.loads((pdir / "rerun.json").read_text())
    task = {
        "finding": {"id": f.id, "title": f.title, "vuln_class": f.vuln_class,
                    "severity": f.severity, "file": f.file, "line": f.line,
                    "detail": f.detail[:3000]},
        "code_window": code,
        "poc": {"script": str(pdir / rerun["script"]) if rerun else "",
                "success_signal": rerun.get("signal", "")},
        "rules": ["Minimal diff — fix the root cause at the reported site.",
                  "The recorded PoC must FAIL after your change.",
                  "Do not weaken unrelated validation or add dependencies.",
                  "Reply by editing files in this working directory only."],
    }
    (fixdir / "task.json").write_text(json.dumps(task, indent=2))
    md = (f"# Fix task — {f.title}\n\n"
          f"Verified `{f.vuln_class}` at `{f.file}:{f.line}` "
          f"({f.severity}, confidence {f.confidence:.2f}).\n\n"
          f"## Evidence\n{f.detail[:2500]}\n\n"
          f"## Vulnerable code\n```\n{code}\n```\n\n"
          f"## Proof of exploit (must stop firing)\n"
          f"Script: `{task['poc']['script']}`\n"
          f"Success signal: `{task['poc']['success_signal']}`\n\n"
          + "\n".join(f"- {r}" for r in task["rules"]))
    (fixdir / "task.md").write_text(md)
    return fixdir / "task.md"


def _worktree(root: Path, fixdir: Path) -> tuple[Path, str]:
    base = _git(root, "rev-parse", "HEAD")
    wt = fixdir / "wt"
    _git(root, "worktree", "add", "--detach", str(wt), base)
    return wt, base


def _dispatch(backend: str, wt: Path, task_md: Path) -> None:
    """One agent session in the worktree. Backend = env-selected, so a
    team's own agent (codex/devin/anything) plugs in without code edits."""
    if backend == "codex":
        subprocess.run(
            ["codex", "exec", "-s", "workspace-write",
             task_md.read_text()],
            cwd=wt, timeout=FIX_TIMEOUT)
    elif backend == "devin-acp":
        url = os.environ.get("CRS_DEVIN_ACP_URL", "http://127.0.0.1:8319/v1")
        model = os.environ.get("CRS_DEVIN_ACP_MODEL", "swe-2-max")
        import httpx
        r = httpx.post(f"{url.rstrip('/')}/chat/completions",
            json={"model": model, "temperature": 0.1,
                  "max_tokens": 16384,
                  "messages": [
                      {"role": "system", "content":
                       "Reply with ONE unified diff (git apply format) "
                       "fixing the task. No prose, no fences."},
                      {"role": "user", "content": task_md.read_text()}]},
            timeout=FIX_TIMEOUT)
        diff = r.json()["choices"][0]["message"]["content"]
        (wt.parent / "agent.diff").write_text(diff)
        subprocess.run(["git", "-C", str(wt), "apply", "--whitespace=fix"],
                       input=diff, text=True, check=True,
                       capture_output=True)
    elif backend == "command":
        cmd = os.environ.get("CRS_FIX_CMD")
        if not cmd:
            raise RuntimeError("CRS_FIXER=command needs CRS_FIX_CMD")
        subprocess.run(cmd, shell=True, cwd=wt, timeout=FIX_TIMEOUT,
                       env={**os.environ, "CRS_TASK": str(task_md)})
    else:
        raise RuntimeError(f"unknown fixer {backend!r}")


def _run_poc(repo: Path, pdir: Path, lang: str, script: str) -> str:
    r = subprocess.run(["bash", str(RUN_POC), str(repo.resolve()),
                        str(pdir), lang, script],
                       capture_output=True, text=True, timeout=180)
    return r.stdout + r.stderr


def _gate(root: Path, wt: Path, base: str, fixdir: Path, f: Finding,
          pdir: Path, run_poc=_run_poc, rescan=None) -> tuple[str, str]:
    """Mechanical verdict. Returns (verdict, reason)."""
    if not _git(wt, "status", "--porcelain"):
        return "fix-rejected", "agent produced no change"
    _git(wt, "add", "-A")
    _git(wt, "-c", "user.email=crs-ops@local", "-c",
         "user.name=crs-ops", "commit", "-qm", f"crs fix {f.id}")
    diff = _git(wt, "diff", base, "HEAD")
    if not diff.strip():
        return "fix-rejected", "agent produced no change"
    (fixdir / "patch.diff").write_text(diff)

    rj = pdir / "rerun.json"
    if not rj.exists():
        return "fix-unverifiable", "no recorded PoC to kill"
    rr = json.loads(rj.read_text())
    if rr.get("kind") == "service":
        return "fix-unverifiable", "service PoC needs a live redeploy"
    # rerun against the PATCHED tree; copy the poc dir so the original
    # evidence stays pristine
    re_dir = fixdir / "poc-rerun"
    shutil.copytree(pdir, re_dir, dirs_exist_ok=True)
    out = run_poc(wt, re_dir, rr["lang"], rr["script"])
    (re_dir / "gate_output.txt").write_text(out[:20000])
    if any(s in out for s in ("runner failed", "command not found",
                              "Cannot find module", "ImportError")):
        return "fix-unverifiable", "PoC environment broke on patched tree"
    if rr["signal"] in out:
        return "fix-rejected", "exploit still fires on patched code"

    if rescan is None:
        from . import pipeline
        rescan = lambda: pipeline.run(  # noqa: E731 — lazy import keeps
            str(wt), since=base, no_llm=True,  # fix.py out of the pipeline's
            out_root=fixdir / "scan")          # import cycle
    rescan()
    new = [x for x in store_load(fixdir / "scan" / wt.name / "findings.jsonl")
           if x.status != "dismissed"]
    if new:
        return "fix-rejected", f"patch introduces {len(new)} candidate(s)"
    return "fix-verified", "PoC dead + diff rescan clean"


def _comment_issue(repo: str, f: Finding, verdict: str,
                   reason: str, out_root: Path) -> None:
    """Post the gate verdict on the issue we filed — our repos only."""
    token, target = (os.environ.get("GITHUB_TOKEN"),
                     os.environ.get("CRS_ISSUE_REPO"))
    if not token or not target:
        return
    ij = out_root / repo / "issues.jsonl"
    if not ij.exists():
        return
    for l in ij.read_text().splitlines()[::-1]:
        try:
            rec = json.loads(l)
        except Exception:
            continue
        if rec.get("finding_id") == f.id and \
                "/issues/" in str(rec.get("url", "")):
            num = rec["url"].rsplit("/", 1)[-1]
            try:
                import httpx
                httpx.post(
                    f"https://api.github.com/repos/{target}/issues/{num}"
                    "/comments",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"body":
                          f"**CRS-OPS fix gate: `{verdict}`**\n\n{reason}\n\n"
                          f"Patch: `fixes/{f.id}/patch.diff`"},
                    timeout=20)
            except Exception as e:
                print(f"[fix] issue comment failed: {e}", flush=True)
            return


def run(repo: str, finding_id: str, out_root: Path,
        backend: str | None = None, root: Path | None = None) -> None:
    fdir = out_root / repo
    if root is None:
        # watch clones live in findings/targets/; manual clones in targets/;
        # a literal path arg works for local-path scans
        for cand in (out_root / "targets" / repo,
                     out_root.parent / "targets" / repo,
                     Path(repo).expanduser()):
            if cand.exists():
                root = cand.resolve()
                break
    if root is None or not root.exists():
        print(f"[fix] no checkout for {repo} — pass the repo path")
        return
    findings = store_load(fdir / "findings.jsonl")
    if finding_id == "all-verified":
        todo = [f for f in findings if f.status == "verified"
                and "fix-verified" not in f.tags]
    else:
        todo = [f for f in findings if f.id == finding_id
                or f.id.startswith(finding_id)]
    todo = [f for f in todo if f.status == "verified"]
    if not todo:
        print(f"[fix] {repo}: no verified findings matching {finding_id}")
        return
    backend = backend or os.environ.get("CRS_FIXER") or \
        ("codex" if shutil.which("codex") else "devin-acp")

    for f in todo:
        fixdir = fdir / "fixes" / f.id
        fixdir.mkdir(parents=True, exist_ok=True)
        wt = None
        verdict, reason = "fix-rejected", "dispatch did not run"
        pdir = fdir / "poc" / f.id
        try:
            task_md = package(root, f, fixdir, pdir)
            wt, base = _worktree(root, fixdir)
            print(f"[fix] {f.id}: dispatching to {backend} in {wt}",
                  flush=True)
            t0 = time.time()
            _dispatch(backend, wt, task_md)
            (fixdir / "agent.log").write_text(
                f"backend={backend} secs={time.time()-t0:.0f}\n")
            verdict, reason = _gate(root, wt, base, fixdir, f, pdir)
        except Exception as e:
            verdict, reason = "fix-rejected", f"{e.__class__.__name__}: {e}"
        finally:
            if wt is not None:
                try:
                    _git(root, "worktree", "remove", "--force", str(wt))
                except Exception:
                    pass
        (fixdir / "verdict.json").write_text(json.dumps(
            {"verdict": verdict, "reason": reason, "backend": backend,
             "ts": time.time()}, indent=2))
        f.tags.append(verdict)
        print(f"[fix] {f.id}: {verdict} — {reason}", flush=True)
        try:
            alerts.emit(repo, f, verdict, out_root=out_root, extra=reason)
            _comment_issue(repo, f, verdict, reason, out_root)
        except Exception as e:
            print(f"[fix] notify failed: {e}", flush=True)
    from .store import dump as store_dump
    store_dump(fdir / "findings.jsonl", findings)
