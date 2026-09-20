"""scan <target> — one command: git URL or local path -> findings report."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from . import state
from .pipeline import ALL_ENGINES, FINDINGS, run


def main() -> None:
    ap = argparse.ArgumentParser(prog="scan",
        description="multi-engine vulnerability discovery pipeline")
    ap.add_argument("target", nargs="?", help="git URL or local path")
    ap.add_argument("--engines", help=f"comma list, subset of {ALL_ENGINES}")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--queue-limit", type=int, default=0,
                    help="cap ranked queue to top N files (0 = all)")
    ap.add_argument("--frontier", action="store_true",
                    help="wide profile for frontier-class models: whole "
                         "files (no windowing), 2x agent turns/context "
                         "requests, bigger token budget, wider hunt queue")
    ap.add_argument("--files", help="comma list of repo-relative paths — "
                    "restrict the hunt queue to exactly these files")
    ap.add_argument("--since", metavar="REF",
                    help="differential rescan — hunt only files changed since "
                         "this git ref (tag/branch/sha); prior verified "
                         "findings carry forward untouched")
    ap.add_argument("--models", help="comma list of model names from models.yaml")
    ap.add_argument("--endpoint", action="append",
                    metavar="NAME|URL|MODEL[|KEY_ENV]",
                    help="ad-hoc OpenAI-compatible endpoint, e.g. "
                    "glm|https://api.z.ai/api/paas/v4|glm-5 — repeatable, "
                    "no yaml edit; KEY_ENV names the env var holding the "
                    "API key (default: NAME_API_KEY, e.g. GLM_API_KEY)")
    ap.add_argument("--passes", type=int, default=1,
                    help="hunt passes per engine (pooled across models)")
    ap.add_argument("--open-only", action="store_true",
                    help="restrict to open_weight models (rules-compliant mode)")
    ap.add_argument("--no-llm", action="store_true",
                    help="deterministic stages only (smoke test / offline)")
    ap.add_argument("--hunt-budget", type=int, default=0, metavar="MIN",
                    help="wall-clock cap on the LLM stages — engines and PoC "
                         "verification (0 = none)")
    ap.add_argument("--reuse-candidates", action="store_true",
                    help="skip engines; adjudicate saved candidates.jsonl")
    ap.add_argument("--resume", action="store_true",
                    help="keep existing candidates; hunt only queue files "
                         "not yet covered (crash recovery for long hunts)")
    ap.add_argument("--out", metavar="DIR",
                    help="findings root (default findings/) — use a scratch "
                         "dir for test scans so golden state survives")
    ap.add_argument("--doctor", action="store_true",
                    help="check prereqs: tools, endpoints, docker images")
    ap.add_argument("--status", action="store_true",
                    help="one-line health per scanned repo: last sha, scan "
                         "age, verified/adjudicated counts, alert count")
    ap.add_argument("--watch", action="store_true",
                    help="daemon — rescan watch.yaml repos on every new "
                         "commit (Ctrl-C to stop)")
    ap.add_argument("--watch-once", action="store_true",
                    help="run a single watch cycle (testing; env "
                         "CRS_WATCH_ONCE=1 works too)")
    ap.add_argument("--registry", default="watch.yaml", metavar="YAML",
                    help="watch registry path (default watch.yaml)")
    a = ap.parse_args()
    if a.doctor:
        doctor()
        return
    if a.status:
        status()
        return
    if a.watch or a.watch_once:
        from . import watch
        watch.main(Path(a.registry).expanduser(), models=a.models,
                   budget=a.hunt_budget, once=a.watch_once)
        return
    if not a.target:
        ap.error("target required")
    if a.engines:
        bad = [e for e in a.engines.split(",") if e not in ALL_ENGINES]
        if bad:
            ap.error(f"unknown engines {bad} — choose from {ALL_ENGINES}")
    if a.resume and a.reuse_candidates:
        ap.error("--resume and --reuse-candidates are mutually exclusive")
    extra = []
    for ep in a.endpoint or []:
        parts = ep.split("|")
        if len(parts) not in (3, 4):
            ap.error("--endpoint must be NAME|BASE_URL|MODEL[|KEY_ENV]")
        from .llms import Model
        # key env is honored only when set — keyless endpoints (remote
        # ollama etc.) must not require a dummy var to be usable
        key_env = parts[3] if len(parts) == 4 \
            else f"{parts[0].upper()}_API_KEY"
        extra.append(Model(name=parts[0], base_url=parts[1],
                           model=parts[2], open_weight=True,
                           api_key_env=key_env
                           if os.environ.get(key_env) else ""))
    if a.frontier:
        # setdefault: explicit env/user values always win over the preset
        for k, v in (("CRS_MAX_FILE_LINES", "100000"),  # whole files
                     ("CRS_MAX_ITERS", "16"),           # deeper investigation
                     ("CRS_MAX_REQS", "8"),             # more context/turn
                     ("CRS_MAX_TOKENS", "16384"),       # long chain-of-thought
                     ("CRS_QUEUE_TOP", "200")):         # wider funnel
            os.environ.setdefault(k, v)
        print("[frontier] whole-file windows, 16 agent iters, "
              "8 ctx reqs/turn, 16k tokens, top-200 queue")
    run(a.target,
        engine_names=a.engines.split(",") if a.engines else None,
        workers=a.workers, open_only=a.open_only, no_llm=a.no_llm,
        models_only=a.models.split(",") if a.models else None,
        model_passes=a.passes, reuse_candidates=a.reuse_candidates,
        queue_limit=a.queue_limit,
        only_files=a.files.split(",") if a.files else None,
        since=a.since,
        extra_models=extra, hunt_budget_min=a.hunt_budget,
        out_root=Path(a.out).expanduser() if a.out else None,
        resume=a.resume)


def _age(secs: float) -> str:
    for unit, div in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= div:
            return f"{int(secs // div)}{unit} ago"
    return "just now"


def status(findings_root: Path | None = None) -> None:
    root = findings_root or FINDINGS
    dirs = sorted(d for d in root.glob("*")
                  if d.is_dir() and (d / "findings.jsonl").exists()) \
        if root.exists() else []
    if not dirs:
        print("no scans yet — run ./scan <target>")
        return
    now = time.time()
    for d in dirs:
        st = state.read(d)
        alerts_n = 0
        if (d / "alerts.jsonl").exists():
            alerts_n = sum(1 for l in (d / "alerts.jsonl").read_text()
                           .splitlines() if l.strip())
        ver = st["counts"].get("verified", 0)
        adj = st["counts"].get("adjudicated", 0)
        if not st["last_scan"]:
            # dirs scanned before state tracking existed — counts from
            # findings.jsonl so the estate view never shows false zeros
            try:
                rows = [json.loads(l) for l in
                        (d / "findings.jsonl").read_text().splitlines() if l]
                ver = sum(1 for f in rows if f.get("status") == "verified")
                adj = sum(1 for f in rows
                          if f.get("status") == "adjudicated")
            except Exception:
                pass
        age = "never" if not st["last_scan"] else _age(now - st["last_scan"])
        print(f"{'🟢' if ver else '⚪'} {d.name:30} "
              f"last={(st['last_sha'] or '')[:8] or '-'} scan={age} "
              f"verified={ver} adj={adj} "
              f"alerts={alerts_n}")


def doctor() -> None:
    import httpx
    from .llms import load_models
    ok = True
    for t in ["semgrep", "osv-scanner", "bandit", "gosec", "ctags",
              "docker", "rg", "git"]:
        hit = shutil.which(t) or shutil.which(
            t, path=os.path.expanduser("~/go/bin"))
        print(f"{'ok' if hit else 'MISS':8} tool {t}")
        ok &= bool(hit)
    usable = 0
    for m in load_models():
        # a real chat probe — /models lists fine even when auth is dead
        # (VibeProxy lesson). One tiny completion per endpoint.
        try:
            r = httpx.post(f"{m.base_url.rstrip('/')}/chat/completions",
                           headers={"Authorization": f"Bearer {m.api_key}"},
                           json={"model": m.model, "max_tokens": 4,
                                 "messages": [{"role": "user",
                                               "content": "say ok"}]},
                           timeout=45)
            up = r.status_code < 400 and \
                r.json().get("choices", [{}])[0].get("message", {})
        except Exception:
            up = False
        usable += bool(up)
        print(f"{'ok' if up else 'MISS':8} model {m.name} "
              f"({m.model} @ {m.base_url})")
    print(f"{'ok' if usable else 'MISS':8} usable endpoints: {usable}")
    ok &= usable > 0
    try:
        imgs = subprocess.run(["docker", "images", "--format",
                               "{{.Repository}}"], capture_output=True,
                              text=True, timeout=15).stdout
        n = imgs.count("crs-sandbox")
        print(f"{'ok' if n >= 6 else 'MISS':8} sandbox images: {n}/6 built")
        ok &= n >= 6
    except Exception:
        print("MISS     docker daemon"); ok = False
    print("\nREADY" if ok else "\nNOT READY — fix MISSes above")


if __name__ == "__main__":
    main()
