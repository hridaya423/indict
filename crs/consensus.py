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
    return merged


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
