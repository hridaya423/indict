"""--explain — the per-finding case file: who proposed it, what the gate
checked, what the sandbox proved, where the alerts went. Pure read of the
artifacts every stage already writes; the audit trail is the product.
"""
from __future__ import annotations

import json
from pathlib import Path

from .store import load as store_load


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for l in path.read_text().splitlines():
        try:
            out.append(json.loads(l))
        except Exception:
            continue
    return out


def _poc_summary(pdir: Path) -> list[str]:
    if not pdir.exists():
        return ["  no PoC artifacts"]
    lines = []
    for p in sorted(pdir.iterdir()):
        if p.name.startswith(("output", "probe_output", "service_probe")):
            head = p.read_text(errors="replace")[:200].strip().splitlines()
            lines.append(f"  {p.name}: {head[0][:120] if head else '(empty)'}")
        else:
            lines.append(f"  {p.name} ({p.stat().st_size}b)")
    return lines


def show(repo: str, finding_id: str, out_root: Path) -> None:
    fdir = out_root / repo
    findings = store_load(fdir / "findings.jsonl")
    f = next((x for x in findings if x.id == finding_id
              or x.id.startswith(finding_id)), None)
    if f is None:
        cands = {c.id: c for c in store_load(fdir / "candidates.jsonl")}
        f = next((c for i, c in cands.items() if i.startswith(finding_id)),
                 None)
    if f is None:
        print(f"no finding {finding_id} in {fdir}")
        return

    print(f"═══ case file {f.id} — {repo} ═══")
    print(f"  {f.title}")
    print(f"  {f.vuln_class} | {f.severity} | confidence {f.confidence:.2f} "
          f"| status {f.status}")
    print(f"  location: {f.file}:{f.line}")
    print(f"\n── proposed by ──")
    print(f"  engine={f.engine}  model={f.model or '-'}")
    print(f"  tags: {', '.join(f.tags) or '-'}")
    print(f"\n── adjudication ──")
    print(f"  {f.verdict or 'no verdict recorded'}")
    if f.detail:
        print(f"\n── evidence ──")
        print("  " + "\n  ".join(f.detail.splitlines()[:25]))
    print(f"\n── proof artifacts ({fdir/'poc'/f.id}) ──")
    print("\n".join(_poc_summary(fdir / "poc" / f.id)))

    alerts = [a for a in _read_jsonl(fdir / "alerts.jsonl")
              if a.get("id") == f.id]
    if alerts:
        print(f"\n── alerts ──")
        for a in alerts:
            print(f"  {a.get('kind')} @ ts {a.get('ts'):.0f}")
    issues = [i for i in _read_jsonl(fdir / "issues.jsonl")
              if i.get("finding_id") == f.id]
    if issues:
        print(f"\n── issues ──")
        for i in issues:
            print(f"  {i.get('title', '')[:70]} -> {i.get('url')}")
    for vdir in sorted((fdir / "fixes").glob(f"{f.id}*")) \
            if (fdir / "fixes").exists() else []:
        v = vdir / "verdict.json"
        if v.exists():
            try:
                d = json.loads(v.read_text())
                print(f"\n── fix gate ──")
                print(f"  {d.get('verdict')}: {d.get('reason', '')}")
            except Exception:
                pass
    print("═══ end ═══")
