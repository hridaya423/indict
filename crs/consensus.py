"""Consensus — Aikido-backed tactic: pool hunt passes across models.

Findings backed by >=2 distinct models get boosted and standard falsification;
single-model findings get tagged for stricter treatment in adjudication.
"""
from __future__ import annotations

from .store import Finding


def pool(findings: list[Finding]) -> list[Finding]:
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.dedup_key(), []).append(f)
    out = [_pick(group) for group in groups.values()]
    # second pass: weak models agree on LOCATION more reliably than class —
    # merge leftover singles that share file+line-window but differ in class.
    # bucket by adjacency (<=10 lines apart), not floor(line/10) — floor
    # splits near-dupes straddling a boundary (69 vs 71 never merge).
    by_file: dict[str, list[Finding]] = {}
    for f in out:
        by_file.setdefault(f.file, []).append(f)
    merged = []
    for members in by_file.values():
        members.sort(key=lambda f: f.line)
        cluster = [members[0]]
        for f in members[1:]:
            if f.line - cluster[-1].line <= 10:
                cluster.append(f)
            else:
                merged.extend(_merge_cluster(cluster))
                cluster = [f]
        merged.extend(_merge_cluster(cluster))
    return _semantic_dedup(merged)


def _semantic_dedup(findings: list[Finding]) -> list[Finding]:
    """Cross-file near-duplicate merge via embedding cosine (>=0.90).

    Same-file leftovers stay untouched — adjacency clustering owns those.
    Findings with <80 chars of detail carry too little signal to compare.
    """
    from . import sie  # late: keeps sie optional at import time
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.vuln_class, []).append(f)
    out = list(findings)
    removed: set[int] = set()
    off = False
    for members in groups.values():
        if len({m.file for m in members}) < 2 or len(members) > 40:
            continue
        eligible = [m for m in members if len(m.detail) >= 80]
        if len(eligible) < 2:
            continue
        vecs = sie.embed([f"{m.title}\n{m.detail[:500]}" for m in eligible])
        if vecs is None:
            if not off:
                print("[consensus] semantic dedup off", flush=True)
                off = True
            continue
        pairs = sorted(
            ((sie.cos(vecs[i], vecs[j]), eligible[i], eligible[j])
             for i in range(len(eligible))
             for j in range(i + 1, len(eligible))),
            key=lambda p: -p[0])
        for c, a, b in pairs:
            if c < 0.90 or id(a) in removed or id(b) in removed:
                continue
            win, lose = (a, b) if a.confidence >= b.confidence else (b, a)
            win.tags.append("semantic-duplicate")
            win.detail += f"\n[semantic-duplicate of {lose.file}:{lose.line}]"
            removed.add(id(lose))
    return [f for f in out if id(f) not in removed]


def _merge_cluster(members: list[Finding]) -> list[Finding]:
    if len(members) == 1:
        return members
    best = max(members, key=lambda g: g.confidence)
    alts = sorted({m.vuln_class for m in members if m is not best})
    if alts:
        best.detail += (f"\n[location-consensus: also flagged as "
                        f"{', '.join(alts)}]")
    best.tags.append("location-agree")
    models = {m.model for m in members if m.model}
    if len(models) >= 2 and "consensus" not in best.tags:
        best.tags.append("consensus")
        if "single-model" in best.tags:
            best.tags.remove("single-model")
        best.confidence = min(0.95, best.confidence * 1.3)
        best.model = "+".join(sorted(models))
    return [best]


def _pick(group: list[Finding]) -> Finding:
    models = {g.model for g in group if g.model}
    best = max(group, key=lambda g: g.confidence)
    engines = {g.engine for g in group}
    best.tags.extend(sorted(e for e in engines if e != best.engine))
    if len(models) >= 2:
        best.tags.append("consensus")
        best.confidence = min(0.95, best.confidence * 1.3)
        best.model = "+".join(sorted(models))
    elif len(engines) >= 2:
        best.tags.append("multi-engine")
        best.confidence = min(0.9, best.confidence * 1.15)
    else:
        best.tags.append("single-model")
    return best
