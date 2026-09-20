"""Pipeline orchestrator — stages write JSONL under findings/<repo>/ so a run
is resumable and watchable by a second operator in real time.

Order: ingest -> recon -> sweep -> rank -> LLM engines -> consensus ->
adjudicate -> poc -> report
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import engines
from . import adjudicate, consensus, poc, rank, recon, report
from .llms import Client, load_models
from .resolver import Resolver
from .store import Finding, append as store_append, dump, load

FINDINGS = Path(__file__).resolve().parent.parent / "findings"
DETERMINISTIC = {"sweep"}            # engines that never touch an LLM
ALL_ENGINES = ["sweep", "hunter", "taintgen", "explorer", "variant", "fuzzlite"]


def ingest(target: str, work_root: Path) -> Path:
    # <url>#<ref> pins a tag/branch/sha — day-of targets get scanned at the
    # ref you want, not whatever HEAD happens to be
    ref = ""
    if "#" in target:
        target, _, ref = target.partition("#")
    p = Path(target).expanduser()
    if p.exists():
        root = p.resolve()
        if ref:
            subprocess.run(["git", "-C", str(root), "fetch", "--quiet",
                            "--tags"], timeout=120)
            subprocess.run(["git", "-C", str(root), "checkout", "--quiet",
                            ref], check=True)
        return root
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
        return dest
    raise SystemExit(f"target {target} is neither a path nor a git URL")


def run(target: str, engine_names: list[str] | None = None, workers: int = 4,
        open_only: bool = False, no_llm: bool = False,
        models_only: list[str] | None = None, model_passes: int = 1,
        reuse_candidates: bool = False, out_root: Path | None = None,
        queue_limit: int = 0, only_files: list[str] | None = None,
        extra_models: list | None = None, hunt_budget_min: int = 0,
        resume: bool = False, since: str | None = None) -> Path:
    work_root = out_root or FINDINGS
    work_root.mkdir(parents=True, exist_ok=True)
    root = ingest(target, work_root)
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
    cand_file = out_dir / "candidates.jsonl"

    models = load_models(open_only=open_only, only=models_only)
    if extra_models:
        models += [m for m in extra_models
                   if not (open_only and not m.open_weight)
                   and (not models_only or m.name in models_only)]
    client = None if no_llm else Client(models)
    enabled = engine_names or ["sweep", "hunter"]

    inv = recon.inventory(root)
    langs = list(inv["languages"].keys())

    tm: dict = {}
    if resume and not cand_file.exists():
        resume = False  # nothing to resume from
    if not reuse_candidates and not resume:
        cand_file.unlink(missing_ok=True)  # fresh run — don't double-count
        # --- deterministic sweep first: free findings + feeds ranking ---
        if "sweep" in enabled and not resume:
            try:
                got = engines.REGISTRY["sweep"].run(root=root, langs=langs)
                store_append(cand_file, got)
                print(f"[sweep] +{len(got)} candidates", flush=True)
            except Exception as e:
                print(f"[sweep] failed: {e}")

        # --- recon threat model (non-fatal) ---
        try:
            tm = recon.threat_model(client, root, inv)
        except Exception as e:
            print(f"[recon] threat model failed: {e}")
            tm = {}
        (out_dir / "recon.json").write_text(json.dumps(
            {"inventory": {k: v for k, v in inv.items() if k != "readme"},
             "threat_model": tm}, indent=2, default=str))

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
        print(f"[resume] {before - len(queue)} queue files already covered, "
              f"{len(queue)} remaining", flush=True)
    (out_dir / "queue.jsonl").write_text(
        "\n".join(json.dumps(q) for q in queue))
    resolver = Resolver(root)

    # --- LLM engines over the ranked queue; candidates append as produced ---
    import time as _t
    deadline = (_t.time() + hunt_budget_min * 60) if hunt_budget_min else None
    llm_engines = [e for e in enabled if e not in DETERMINISTIC]
    if llm_engines and not reuse_candidates:
        if client is None:
            print(f"[pipeline] --no-llm: skipping LLM engines {llm_engines}",
                  flush=True)
            llm_engines = []
        elif not client.models:
            raise SystemExit(
                f"no models available for {llm_engines} — check --models/"
                f"--endpoint names against `models.yaml`/`--doctor`")
    if llm_engines and not reuse_candidates:
        # pool N passes across configured models; repeat models if fewer
        # configured than passes (same-model reruns still add coverage)
        names = [m.name for m in client.models] or [None]
        model_names = [names[i % len(names)]
                       for i in range(max(model_passes, 1))]
        for ename in llm_engines:
            eng = engines.REGISTRY[ename]
            for mname in (model_names if ename in ("hunter", "explorer") else [None]):
                if deadline and _t.time() > deadline:
                    print(f"[pipeline] hunt budget {hunt_budget_min}min reached — "
                          f"skipping {ename}/{mname}")
                    break
                try:
                    got = eng.run(
                        root=root, langs=langs, client=client,
                        resolver=resolver, workers=workers, queue=queue,
                        recon=inv, out_dir=out_dir, model=mname,
                        threat_model=tm, deadline=deadline)
                    store_append(cand_file, got)
                    print(f"[{ename}/{mname or '-'}] +{len(got)} candidates "
                          f"(total {sum(1 for _ in cand_file.open())})",
                          flush=True)
                except Exception as e:
                    print(f"[engine {ename}/{mname}] failed: {e}")

    cands = consensus.pool(load(cand_file))
    # verified findings are proven state — never let a re-run drop or
    # downgrade them (reuse/adjudication rewrites findings.jsonl)
    fj = out_dir / "findings.jsonl"
    if fj.exists():
        prior = {(f.file, f.line, f.vuln_class): f
                 for f in load(fj) if f.status == "verified"}
        if prior:
            seen = set()
            for c in cands:
                pv = prior.get((c.file, c.line, c.vuln_class))
                if pv:
                    # re-run found the same bug — it inherits verified status
                    # (probe evidence + reproduce cmd carry over)
                    c.status, c.confidence = "verified", pv.confidence
                    if "PoC evidence" not in c.detail and "Probe evidence" not in c.detail:
                        c.detail += "\n" + pv.detail[pv.detail.find("\nPoC evidence")
                                                     if "\nPoC evidence" in pv.detail
                                                     else pv.detail.find("\nProbe evidence"):]
                    c.tags = list(dict.fromkeys(c.tags + ["poc-verified"]))
                    seen.add((c.file, c.line, c.vuln_class))
            cands.extend(f for k, f in prior.items() if k not in seen)
    print(f"[consensus] {len(cands)} pooled", flush=True)
    cands = adjudicate.judge(root, resolver, client, cands, workers)
    print(f"[adjudicate] "
          f"{sum(1 for c in cands if c.status != 'dismissed')} kept / "
          f"{sum(1 for c in cands if c.status == 'dismissed')} dismissed",
          flush=True)
    cands = poc.prove(root, resolver, client, cands, out_dir,
                      deadline=deadline)
    print(f"[poc] {sum(1 for c in cands if c.status == 'verified')} verified",
          flush=True)
    # render may backfill a Reproduce line on verified findings — persist
    # those mutations so findings.jsonl stays the single source of truth
    for c in cands:
        c.tags = list(dict.fromkeys(c.tags))  # re-pooling can re-append tags
    summary = report.render(cands, out_dir, root.name, root)
    dump(out_dir / "findings.jsonl", cands)
    print(json.dumps(summary, indent=2, default=dict))
    if client is not None and client.stats:
        for name, s in sorted(client.stats.items()):
            if s["calls"]:
                print(f"[telemetry] {name}: {s['calls']} calls "
                      f"{s['ms']/1000:.0f}s ({s['cache']} cache hits)")
    return out_dir
