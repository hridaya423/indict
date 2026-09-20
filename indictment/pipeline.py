"""Pipeline orchestrator — stages write JSONL under findings/<repo>/ so a run
is resumable and watchable by a second operator in real time.

Order: ingest -> sweep -> recon -> rank -> LLM engines -> consensus ->
adjudicate -> poc -> chain -> report -> writeup -> learn

Structured run records (what the board reads): runs/<run>/run.json is the
atomic start/terminal summary (revision pinned at ingest, scope, engine
config, timestamps, outcome); runs/<run>/findings.jsonl is the run's
finding snapshot; runs/<run>/evidence/<id>/ freezes the source window and
PoC artifacts so a later scan can't rewrite history. Stage boundaries and
progress land as schemaVersion-1 rows in events.jsonl — legacy rows stay
readable.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import engines
from . import adjudicate, consensus, events, poc, rank, recon, report
from . import state as repo_state
from .llms import Client, load_models
from .resolver import Resolver
from .store import Finding, append as store_append, dump, load

FINDINGS = Path(__file__).resolve().parent.parent / "findings"
DETERMINISTIC = {"sweep"}            # engines that never touch an LLM
ALL_ENGINES = ["sweep", "hunter", "taintgen", "explorer", "variant", "fuzzlite"]


def ingest(target: str, work_root: Path) -> tuple[Path, str | None]:
    """Returns (repo root, restore-ref). A local path scanned at #ref gets
    its original HEAD restored when the run ends — we may borrow the
    checkout, we may not leave it detached."""
    # <url>#<ref> pins a tag/branch/sha — day-of targets get scanned at the
    # ref you want, not whatever HEAD happens to be
    ref = ""
    if "#" in target:
        target, _, ref = target.partition("#")
    p = Path(target).expanduser()
    if p.exists():
        root = p.resolve()
        restore = None
        if ref:
            r = subprocess.run(["git", "-C", str(root), "symbolic-ref",
                                "--short", "-q", "HEAD"],
                               capture_output=True, text=True, timeout=30)
            restore = (r.stdout.strip() if r.returncode == 0
                       and r.stdout.strip() else _head(root))
            subprocess.run(["git", "-C", str(root), "fetch", "--quiet",
                            "--tags"], timeout=120)
            subprocess.run(["git", "-C", str(root), "checkout", "--quiet",
                            ref], check=True)
        return root, restore
    if target.startswith(("http://", "https://", "git@", "file://")):
        stem = Path(target).stem.replace(".git", "")
        dest = work_root / "targets" / (stem + (f"-{ref}" if ref else ""))
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "clone", "--depth", "200", target, str(dest)],
                           check=True, timeout=600)
        if ref:
            # depth=200 may not reach the tag — deepen on demand
            subprocess.run(["git", "-C", str(dest), "fetch", "--quiet",
                            "--depth", "200", "origin", ref, "--tags"],
                           timeout=300)
            subprocess.run(["git", "-C", str(dest), "checkout", "--quiet",
                            ref], check=True)
        return dest, None
    raise SystemExit(f"target {target} is neither a path nor a git URL")


def _head(root: Path) -> str | None:
    """Recorded revision = checkout HEAD pinned at run start."""
    try:
        r = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return r.stdout.strip() or None
    except Exception:
        pass
    return None


def _run_record(out_dir: Path, run_id: str, fields: dict) -> None:
    """runs/<run>/run.json — merge-write, atomic. Telemetry never aborts."""
    try:
        rdir = out_dir / "runs" / run_id
        rdir.mkdir(parents=True, exist_ok=True)
        rj = rdir / "run.json"
        cur = {}
        if rj.exists():
            try:
                cur = json.loads(rj.read_text())
            except Exception:
                cur = {}
        tmp = rdir / "run.json.tmp"
        tmp.write_text(json.dumps({**cur, **fields}, indent=2, default=str))
        os.replace(tmp, rj)
    except Exception:
        pass


def _snapshot(out_dir: Path, run_id: str, cands: list) -> None:
    """runs/<run>/findings.jsonl — the run's own copy of the pool."""
    try:
        rdir = out_dir / "runs" / run_id
        rdir.mkdir(parents=True, exist_ok=True)
        tmp = rdir / "findings.jsonl.tmp"
        with tmp.open("w") as fh:
            for c in cands:
                fh.write(c.model_dump_json() + "\n")
        os.replace(tmp, rdir / "findings.jsonl")
    except Exception:
        pass


def _evidence(out_dir: Path, run_id: str, root: Path, cands: list) -> None:
    """Freeze per-finding proof into the run dir: the source window at the
    recorded revision plus a copy of the poc artifacts (latest-artifact dirs
    stay mutable for CLI compat; the run copy is the historical one)."""
    evroot = out_dir / "runs" / run_id / "evidence"
    base = root.resolve()
    for f in cands:
        try:
            # model-supplied paths must stay repo-relative — a ".." escape
            # would otherwise copy host files into the evidence pack
            fpath = (base / f.file).resolve()
            if base not in fpath.parents and fpath != base:
                continue
            edir = evroot / f.id
            edir.mkdir(parents=True, exist_ok=True)
            line = f.line or 1
            try:
                lines = fpath.read_text(errors="replace").splitlines()
                lo, hi = max(0, line - 100), min(len(lines), line + 100)
                (edir / "source.txt").write_text(
                    "\n".join(lines[lo:hi]))
                (edir / "source.json").write_text(json.dumps(
                    {"file": f.file, "line": f.line,
                     "from": lo + 1, "to": hi}))
            except Exception:
                pass
            pdir = out_dir / "poc" / f.id
            if pdir.is_dir():
                shutil.copytree(pdir, edir / "poc", dirs_exist_ok=True)
        except Exception:
            continue


def run(target: str, engine_names: list[str] | None = None, workers: int = 4,
        open_only: bool = False, no_llm: bool = False,
        models_only: list[str] | None = None, model_passes: int = 1,
        reuse_candidates: bool = False, out_root: Path | None = None,
        queue_limit: int = 0, only_files: list[str] | None = None,
        extra_models: list | None = None, hunt_budget_min: int = 0,
        resume: bool = False, since: str | None = None) -> Path:
    work_root = out_root or FINDINGS
    work_root.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    root, restore_ref = ingest(target, work_root)
    revision = _head(root)
    if since:
        r = subprocess.run(["git", "-C", str(root), "diff", "--name-only",
                            since], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            print(f"[since] bad ref {since!r}: {r.stderr.strip()[:120]}")
        else:
            changed = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            only_files = list(dict.fromkeys((only_files or []) + changed))
            print(f"[since] {len(only_files)} file(s) changed since {since}",
                  flush=True)
    out_dir = work_root / root.name
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}"
    events.begin_run(out_dir, run_id)
    events.start_beating(out_dir, run_id)
    # ingest spans [t0, now] — the clone/checkout already happened
    events.stage_end(out_dir, "ingest", f"{root.name} @ {root}", run=run_id,
                     outcome="completed",
                     durationMs=int((time.time() - t0) * 1000))
    if since:
        events.emit(out_dir, "since",
                    f"{len(only_files or [])} files changed since {since}",
                    run=run_id)

    models = load_models(open_only=open_only, only=models_only)
    if extra_models:
        models += [m for m in extra_models
                   if not (open_only and not m.open_weight)
                   and (not models_only or m.name in models_only)]
    enabled = engine_names or ["sweep", "hunter"]
    llm_engines = [e for e in enabled if e not in DETERMINISTIC]
    # a deterministic-only selection (--engines sweep) must not demand
    # model keys — the client is only built when something can call it
    client = None if (no_llm or not models) else Client(models)
    _run_record(out_dir, run_id, {
        "schemaVersion": 1, "run": run_id, "repo": root.name,
        "target": str(target), "revision": revision, "startedAt": t0,
        "state": "running", "engines": enabled,
        "models": [m.name for m in (client.models if client else [])],
        "scope": {"since": since, "files": only_files,
                  "queueLimit": queue_limit or None, "noLlm": no_llm,
                  "reuseCandidates": reuse_candidates, "resume": resume,
                  "huntBudgetMin": hunt_budget_min or None}})
    try:
        cand_file = out_dir / "candidates.jsonl"
        inv = recon.inventory(root)
        langs = list(inv["languages"].keys())

        tm: dict = {}
        if resume and not cand_file.exists():
            resume = False  # nothing to resume from
        if not reuse_candidates and not resume:
            cand_file.unlink(missing_ok=True)  # fresh run — don't double-count
            # --- deterministic sweep first: free findings + feeds ranking ---
            if "sweep" in enabled:
                events.stage_start(out_dir, "sweep", run=run_id)
                try:
                    got = engines.REGISTRY["sweep"].run(root=root, langs=langs)
                    store_append(cand_file, got)
                    print(f"[sweep] +{len(got)} candidates", flush=True)
                    events.stage_end(out_dir, "sweep",
                                     f"+{len(got)} candidates", run=run_id,
                                     added=len(got))
                except Exception as e:
                    print(f"[sweep] failed: {e}")
                    events.stage_end(out_dir, "sweep", "sweep failed",
                                     run=run_id, outcome="degraded",
                                     reason=str(e)[:200])

            # --- recon threat model (non-fatal) ---
            events.stage_start(out_dir, "recon", run=run_id)
            try:
                tm = recon.threat_model(client, root, inv)
            except Exception as e:
                print(f"[recon] threat model failed: {e}")
                tm = {}
            (out_dir / "recon.json").write_text(json.dumps(
                {"inventory": {k: v for k, v in inv.items() if k != "readme"},
                 "threat_model": tm}, indent=2, default=str))
            events.stage_end(out_dir, "recon",
                             f"{', '.join(langs) or 'no langs'}"
                             + (" | threat model" if tm else ""),
                             run=run_id,
                             outcome="completed" if tm or no_llm
                             else "degraded",
                             reason=None if (tm or no_llm)
                             else "threat model unavailable")
        else:
            why = "resume" if resume else "reuse-candidates"
            for sid in ("sweep", "recon"):
                events.stage_end(out_dir, sid, f"{sid} skipped", run=run_id,
                                 outcome="skipped", reason=why)

        events.stage_start(out_dir, "rank", run=run_id)
        queue = rank.rank(root, load(cand_file),
                          tm_targets=tm.get("high_value_targets"))
        if only_files:
            want = set(only_files)
            queue = [q for q in queue if q["file"] in want] or \
                    [{"file": f, "score": 1.0} for f in only_files
                     if (root / f).exists()]
        if queue_limit:
            queue = queue[:queue_limit]
        if resume:
            covered = {c.file for c in load(cand_file) if c.engine != "sweep"}
            before = len(queue)
            queue = [q for q in queue if q["file"] not in covered]
            print(f"[resume] {before - len(queue)} queue files already "
                  f"covered, {len(queue)} remaining", flush=True)
        (out_dir / "queue.jsonl").write_text(
            "\n".join(json.dumps(q) for q in queue))
        events.stage_end(out_dir, "rank", f"{len(queue)} files queued",
                         run=run_id, completed=len(queue), total=len(queue),
                         unit="files")
        resolver = Resolver(root)

        # --- LLM engines over the ranked queue; candidates append as produced ---
        deadline = (time.time() + hunt_budget_min * 60) if hunt_budget_min \
            else None
        if llm_engines and not reuse_candidates:
            if client is None:
                if no_llm:
                    print(f"[pipeline] --no-llm: skipping LLM engines "
                          f"{llm_engines}", flush=True)
                    llm_engines = []
                else:
                    raise SystemExit(
                        f"no models available for {llm_engines} — check "
                        f"--models/--endpoint names against `models.yaml`/"
                        f"`--doctor`")
        if llm_engines and not reuse_candidates:
            events.stage_start(out_dir, "hunt", run=run_id)
            # pool N passes across configured models; repeat models if fewer
            # configured than passes (same-model reruns still add coverage)
            names = [m.name for m in client.models] or [None]
            model_names = [names[i % len(names)]
                           for i in range(max(model_passes, 1))]
            # engines are independent producers over the shared queue (hunter /
            # taintgen / explorer read queue, variant mines git log — none read
            # candidates), so (engine, model) units run concurrently; each
            # appends under the lock as it finishes
            units = [(e, m) for e in llm_engines
                     for m in (model_names if e in ("hunter", "explorer")
                               else [None])]
            append_lock = threading.Lock()

            def _unit(ename, mname):
                if deadline and time.time() > deadline:
                    print(f"[pipeline] hunt budget {hunt_budget_min}min "
                          f"reached — skipping {ename}/{mname}")
                    events.emit(out_dir, f"{ename}/{mname or '-'}",
                                "skipped — hunt budget reached", run=run_id,
                                kind="engine-outcome", stageId="hunt",
                                engine=ename, model=mname,
                                outcome="skipped", reason="hunt budget")
                    return
                u0 = time.time()
                try:
                    got = engines.REGISTRY[ename].run(
                        root=root, langs=langs, client=client,
                        resolver=resolver, workers=workers, queue=queue,
                        recon=inv, out_dir=out_dir, model=mname,
                        threat_model=tm, deadline=deadline, run=run_id)
                    with append_lock:
                        store_append(cand_file, got)
                        with cand_file.open() as _fh:
                            total = sum(1 for _ in _fh)
                    print(f"[{ename}/{mname or '-'}] +{len(got)} candidates "
                          f"(total {total})", flush=True)
                    events.emit(out_dir, f"{ename}/{mname or '-'}",
                                f"+{len(got)} candidates (total {total})",
                                run=run_id, kind="engine-outcome",
                                stageId="hunt", engine=ename, model=mname,
                                outcome="completed", added=len(got),
                                durationMs=int((time.time() - u0) * 1000))
                except Exception as e:
                    print(f"[engine {ename}/{mname}] failed: {e}")
                    events.emit(out_dir, f"{ename}/{mname or '-'}",
                                "engine failed", run=run_id,
                                kind="engine-outcome", stageId="hunt",
                                engine=ename, model=mname, outcome="failed",
                                reason=str(e)[:200], level="kill")
            with ThreadPoolExecutor(
                    max_workers=min(len(units), workers)) as ex:
                list(ex.map(lambda u: _unit(*u), units))
            events.stage_end(out_dir, "hunt",
                             f"{len(units)} engine units", run=run_id)
        else:
            why = ("reuse-candidates" if reuse_candidates
                   else "no-llm" if client is None
                   else "no llm engines enabled")
            events.stage_end(out_dir, "hunt", "hunt skipped", run=run_id,
                             outcome="skipped", reason=why)

        events.stage_start(out_dir, "consensus", run=run_id)
        raw_cands = load(cand_file)
        if only_files:
            # scoped rescans: out-of-scope candidates are noise — the
            # report should reflect the diff + carried live findings only
            want = set(only_files)
            raw_cands = [c for c in raw_cands if c.file in want]
        cands = consensus.pool(raw_cands)
        # verified/adjudicated findings are reviewed state — never let a
        # re-run drop or downgrade them (reuse/adjudication rewrites
        # findings.jsonl). Match tolerates ±10 lines of drift — a one-line
        # shift must not lose a verified result.
        fj = out_dir / "findings.jsonl"
        if fj.exists():
            prior: dict[tuple, list] = {}
            for f in load(fj):
                if f.status in ("verified", "adjudicated"):
                    prior.setdefault((f.file, f.vuln_class), []).append(f)
            if prior:
                seen: set[int] = set()
                for c in cands:
                    pv = min(
                        (p for p in prior.get((c.file, c.vuln_class), [])
                         if abs(p.line - c.line) <= 10),
                        key=lambda p: abs(p.line - c.line), default=None)
                    if pv is None:
                        continue
                    seen.add(id(pv))
                    if pv.status != "verified":
                        continue  # adjudicated priors re-judge normally
                    # re-run found the same bug — it inherits verified
                    # status (probe evidence + reproduce cmd carry over)
                    c.status, c.confidence = "verified", pv.confidence
                    if "evidence" not in c.detail.lower():
                        for marker in ("\nPoC evidence", "\nProbe evidence",
                                       "\nService PoC evidence"):
                            i = pv.detail.find(marker)
                            if i >= 0:
                                c.detail += pv.detail[i:]
                                break
                    c.tags = list(dict.fromkeys(c.tags + ["poc-verified"]))
                # not rediscovered this run — carry forward untouched and
                # tagged so adjudication doesn't re-falsify proven state
                for plist in prior.values():
                    for f in plist:
                        if id(f) not in seen:
                            f.tags = list(dict.fromkeys(
                                f.tags + ["carried"]))
                            cands.append(f)
        print(f"[consensus] {len(cands)} pooled", flush=True)
        events.stage_end(out_dir, "consensus", f"{len(cands)} pooled",
                         run=run_id)

        events.stage_start(out_dir, "adjudicate", run=run_id)
        cands = adjudicate.judge(root, resolver, client, cands, workers,
                                 out_dir=out_dir, run=run_id,
                                 deadline=deadline)
        kept = sum(1 for c in cands if c.status != "dismissed")
        dead = sum(1 for c in cands if c.status == "dismissed")
        print(f"[adjudicate] {kept} kept / {dead} dismissed", flush=True)
        events.stage_end(out_dir, "adjudicate",
                         f"kept {kept} / dismissed {dead}", run=run_id)
        for c in cands:
            if c.status == "dismissed":
                # the falsifier's kill reasons are first-class ledger rows —
                # watching a hallucination die is the demo
                events.emit(out_dir, "falsify",
                            f"{c.vuln_class} @{c.file}:{c.line} — "
                            f"{c.verdict[:140]}", level="kill", run=run_id,
                            finding=c.id)
        _snapshot(out_dir, run_id, cands)

        pre_poc = {c.id for c in cands if c.status == "verified"}
        if client is None or not poc.RUN_POC.exists():
            events.stage_end(out_dir, "poc", "poc skipped", run=run_id,
                             outcome="skipped",
                             reason="no-llm" if client is None
                             else "sandbox runner unavailable")
        else:
            events.stage_start(out_dir, "poc", run=run_id)
            cands = poc.prove(root, resolver, client, cands, out_dir,
                              deadline=deadline, run=run_id)
            for c in cands:
                if c.status == "verified" and c.id not in pre_poc:
                    events.emit(out_dir, "poc",
                                f"VERIFIED {c.vuln_class} {c.file}:{c.line}",
                                run=run_id, finding=c.id,
                                kind="verification-result",
                                stageId="poc", outcome="matched")
            n_ver = sum(1 for c in cands if c.status == "verified")
            print(f"[poc] {n_ver} verified", flush=True)
            events.stage_end(out_dir, "poc", f"{n_ver} verified",
                             run=run_id)
            _snapshot(out_dir, run_id, cands)
        if client is not None:
            events.stage_start(out_dir, "chain", run=run_id)
            try:
                from . import chain
                chained = chain.run(root, resolver, client, cands, out_dir,
                                    deadline=deadline)
                if chained:
                    cands.extend(chained)
                events.stage_end(out_dir, "chain",
                                 f"{len(chained or [])} chains", run=run_id)
            except Exception as e:
                print(f"[chain] failed: {e}", flush=True)
                events.stage_end(out_dir, "chain", "chain failed",
                                 run=run_id, outcome="degraded",
                                 reason=str(e)[:200])
        else:
            events.stage_end(out_dir, "chain", "chain skipped", run=run_id,
                             outcome="skipped", reason="no-llm")
        # render may backfill a Reproduce line on verified findings — persist
        # those mutations so findings.jsonl stays the single source of truth
        for c in cands:
            c.tags = list(dict.fromkeys(c.tags))  # re-pooling re-appends tags
        events.stage_start(out_dir, "report", run=run_id)
        summary = report.render(cands, out_dir, root.name, root)
        dump(out_dir / "findings.jsonl", cands)
        events.stage_end(out_dir, "report",
                         f"{summary['live']} live, {summary['verified']} "
                         f"verified, {summary['dismissed']} dismissed",
                         run=run_id)
        _snapshot(out_dir, run_id, cands)
        # tail stages — narrative + flywheel; decoration, never fatal
        if client is not None:
            events.stage_start(out_dir, "writeup", run=run_id)
            try:
                from . import writeup
                writeup.backfill(out_dir, root, resolver, client)
                events.stage_end(out_dir, "writeup", "writeup done",
                                 run=run_id)
            except Exception as e:
                print(f"[writeup] failed: {e}", flush=True)
                events.stage_end(out_dir, "writeup", "writeup failed",
                                 run=run_id, outcome="degraded",
                                 reason=str(e)[:200])
            events.stage_start(out_dir, "learn", run=run_id)
            try:
                from . import learn
                # --out scratch scans stay scratch: learned rules/index are
                # global flywheel state, only the default findings root may
                # write them
                learn.run(root.name, root, resolver, out_dir, client, cands,
                          global_ok=work_root.resolve() == FINDINGS.resolve())
                events.stage_end(out_dir, "learn", "learn done", run=run_id)
            except Exception as e:
                print(f"[learn] failed: {e}", flush=True)
                events.stage_end(out_dir, "learn", "learn failed",
                                 run=run_id, outcome="degraded",
                                 reason=str(e)[:200])
        else:
            for sid in ("writeup", "learn"):
                events.stage_end(out_dir, sid, f"{sid} skipped", run=run_id,
                                 outcome="skipped", reason="no-llm")
        try:  # state snapshot is ops sugar — must never break a scan
            repo_state.record(out_dir, root, cands)
        except Exception as e:
            print(f"[state] record failed: {e}")
        _evidence(out_dir, run_id, root, cands)
        print(json.dumps(summary, indent=2, default=dict))
        if client is not None and client.stats:
            for name, s in sorted(client.stats.items()):
                if s["calls"]:
                    print(f"[telemetry] {name}: {s['calls']} calls "
                          f"{s['ms']/1000:.0f}s ({s['cache']} cache hits)")
        _run_record(out_dir, run_id, {
            "state": "completed", "endedAt": time.time(),
            "outcome": {"live": summary.get("live"),
                        "verified": summary.get("verified"),
                        "dismissed": summary.get("dismissed"),
                        "total": summary.get("total")}})
        events.end_run(out_dir, run_id, ok=True)
        return out_dir
    except BaseException as e:
        _run_record(out_dir, run_id, {
            "state": "failed", "endedAt": time.time(),
            "error": f"{e.__class__.__name__}: {e}"[:300]})
        try:
            events.end_run(out_dir, run_id, ok=False,
                           reason=f"{e.__class__.__name__}: {e}"[:200])
        except Exception:
            pass
        raise
    finally:
        # compose services booted for poc/chain probing must not leak —
        # this runs on success, failure, and interrupt alike
        try:
            from . import service
            service.shutdown_all()
        except Exception:
            pass
        if restore_ref:
            try:
                subprocess.run(["git", "-C", str(root), "checkout",
                                "--quiet", restore_ref], timeout=120)
            except Exception:
                pass
