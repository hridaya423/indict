#!/usr/bin/env python3
"""Emit indict-ops.html — flat pastel-panels variant of the INDICT pipeline diagram."""
from pathlib import Path

OUT = Path(__file__).with_name("indict-ops.html")
W, H = 1440, 1532

INK, MUT, SOFT = "#1f2937", "#6b7280", "#9aa3b2"
ARROW = "#a8b0bd"

svg = []


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;")


def rpath(pts, r=10):
    """Polyline through pts with quarter-arc corners."""
    d = [f"M{pts[0][0]},{pts[0][1]}"]
    for i in range(1, len(pts) - 1):
        x0, y0 = pts[i - 1]
        x1, y1 = pts[i]
        x2, y2 = pts[i + 1]
        dx1, dy1 = (x1 - x0), (y1 - y0)
        dx2, dy2 = (x2 - x1), (y2 - y1)
        l1 = max(abs(dx1), abs(dy1))
        l2 = max(abs(dx2), abs(dy2))
        rr = min(r, l1 / 2, l2 / 2)
        a = (x1 - rr * (dx1 and dx1 // abs(dx1)), y1 - rr * (dy1 and dy1 // abs(dy1)))
        b = (x1 + rr * (dx2 and dx2 // abs(dx2)), y1 + rr * (dy2 and dy2 // abs(dy2)))
        d.append(f"L{a[0]},{a[1]} Q{x1},{y1} {b[0]},{b[1]}")
    d.append(f"L{pts[-1][0]},{pts[-1][1]}")
    return " ".join(d)


def edge(pts, dashed=False, color=ARROW, w=1.6):
    dash = ' stroke-dasharray="5,4"' if dashed else ""
    svg.append(
        f'<path d="{rpath(pts)}" fill="none" stroke="{color}" stroke-width="{w}"{dash}'
        f' marker-end="url(#ah)"/>')


def elabel(x, y, s, anchor="middle", color=MUT, size=10.5):
    tw = len(s) * size * 0.62 + 10
    svg.append(f'<rect x="{x - tw / 2:.1f}" y="{y - size - 3}" width="{tw:.0f}" height="{size + 8}" rx="3" fill="#ffffff" opacity="0.92"/>'
               if anchor == "middle" else "")
    svg.append(f'<text x="{x}" y="{y}" fill="{color}" font-size="{size}" font-family="Inter,sans-serif" text-anchor="{anchor}">{esc(s)}</text>')


def panel(x, y, w, h, fill, border, title, caption, badge=None,
          bcolor="#5b6b8c", icon=None, icolor="#4f6bed"):
    svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="{fill}" stroke="{border}" stroke-width="1.2"/>')
    tx = x + 18
    if badge is not None:
        svg.append(f'<circle cx="{x + 30}" cy="{y + 27}" r="13" fill="{bcolor}"/>')
        svg.append(f'<text x="{x + 30}" y="{y + 31}" fill="#ffffff" font-size="12" font-weight="700" font-family="Inter,sans-serif" text-anchor="middle">{badge}</text>')
        tx = x + 52
    elif icon:
        chip(x + 15, y + 9, icolor, icon)
        tx = x + 62
    svg.append(f'<text x="{tx}" y="{y + 26}" fill="{INK}" font-size="15" font-weight="700" font-family="Nunito,sans-serif">{title}</text>')
    svg.append(f'<text x="{tx}" y="{y + 42}" fill="{MUT}" font-size="11" font-family="Inter,sans-serif">{caption}</text>')


def chip(x, y, color, glyph):
    svg.append(f'<rect x="{x}" y="{y}" width="36" height="36" rx="9" fill="{color}" opacity="0.14"/>')
    svg.append(f'<g transform="translate({x + 18},{y + 18})" stroke="{color}" stroke-width="1.7" fill="none" stroke-linecap="round" stroke-linejoin="round">{glyph}</g>')


def card(x, y, w, h, icon, color, title, body, fill="#ffffff", border="rgba(31,41,55,0.14)"):
    svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{fill}" stroke="{border}" stroke-width="1.2"/>')
    chip(x + 10, y + (h - 36) / 2, color, icon)
    svg.append(f'<text x="{x + 56}" y="{y + (24 if h >= 56 else 20)}" fill="{INK}" font-size="13" font-weight="700" font-family="Nunito,sans-serif">{esc(title)}</text>')
    lines = body.split("\n")
    top = 40 if h >= 56 else 40 - len(lines) * 5
    step = 12 if h >= 64 else 11
    for i, ln in enumerate(lines):
        svg.append(f'<text x="{x + 56}" y="{y + top + i * step}" fill="{MUT}" font-size="10.5" font-family="Inter,sans-serif">{esc(ln)}</text>')


def minicard(x, y, w, h, icon, color, title, body):
    svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="#ffffff" stroke="rgba(31,41,55,0.14)" stroke-width="1.2"/>')
    svg.append(f'<rect x="{x + 9}" y="{y + 9}" width="24" height="24" rx="6" fill="{color}" opacity="0.14"/>')
    svg.append(f'<g transform="translate({x + 21},{y + 21}) scale(0.7)" stroke="{color}" stroke-width="1.7" fill="none" stroke-linecap="round" stroke-linejoin="round">{icon}</g>')
    svg.append(f'<text x="{x + 40}" y="{y + 25}" fill="{INK}" font-size="11.5" font-weight="700" font-family="Nunito,sans-serif">{esc(title)}</text>')
    svg.append(f'<text x="{x + 10}" y="{y + h - 11}" fill="{MUT}" font-size="9.5" font-family="Inter,sans-serif">{esc(body)}</text>')


def diamond(cx, cy, w, h, label):
    svg.append(f'<polygon points="{cx},{cy - h / 2} {cx + w / 2},{cy} {cx},{cy + h / 2} {cx - w / 2},{cy}" fill="#ffffff" stroke="{INK}" stroke-width="1.4"/>')
    svg.append(f'<text x="{cx}" y="{cy + 4}" fill="{INK}" font-size="12" font-weight="600" font-family="Inter,sans-serif" text-anchor="middle">{label}</text>')


# ------- icon glyphs (20px box centered on 0,0) -------
G = {
    "git": '<circle cx="-6" cy="-6" r="2.4"/><circle cx="-6" cy="6" r="2.4"/><circle cx="6" cy="-6" r="2.4"/><path d="M-6,-3.6 V3.6 M-6,-6 C2,-6 6,-6 6,-3.6"/>',
    "clock": '<circle cx="0" cy="0" r="8"/><path d="M0,-4 V0 L3,2"/>',
    "doc": '<path d="M-5,-8 H2 L6,-4 V8 H-5 Z M2,-8 V-4 H6"/><path d="M-2,0 H3 M-2,3 H3"/>',
    "scan": '<circle cx="-1" cy="-1" r="5"/><path d="M3,3 L8,8"/><path d="M-8,-6 V-8 H-6 M6,-8 H8 V-6 M8,6 V8 H6 M-6,8 H-8 V6"/>',
    "bars": '<path d="M-7,7 V1 M-1,7 V-4 M5,7 V-8"/><path d="M-9,7 H9"/>',
    "target": '<circle cx="0" cy="0" r="8"/><circle cx="0" cy="0" r="4.5"/><circle cx="0" cy="0" r="1.2" fill="currentColor"/>',
    "nodes": '<circle cx="-6" cy="-6" r="2.2"/><circle cx="6" cy="-6" r="2.2"/><circle cx="0" cy="6" r="2.2"/><path d="M-4,-4 L-1,4 M4,-4 L1,4 M-3.8,-6 H3.8"/>',
    "gear": '<circle cx="0" cy="0" r="3.2"/><path d="M0,-8 V-5 M0,5 V8 M-8,0 H-5 M5,0 H8 M-5.6,-5.6 L-3.5,-3.5 M3.5,3.5 L5.6,5.6 M5.6,-5.6 L3.5,-3.5 M-3.5,3.5 L-5.6,5.6"/>',
    "bulb": '<path d="M0,-8 A5.5,5.5 0 0 1 5.5,-2.5 C5.5,0 3,1.5 3,3.5 H-3 C-3,1.5 -5.5,0 -5.5,-2.5 A5.5,5.5 0 0 1 0,-8 Z"/><path d="M-2.5,6 H2.5 M-1.5,8.5 H1.5"/>',
    "cube": '<path d="M0,-8 L7,-4 V4 L0,8 L-7,4 V-4 Z"/><path d="M0,-8 V0 M-7,-4 L0,0 L7,-4 M0,0 V8"/>',
    "db": '<ellipse cx="0" cy="-5" rx="7" ry="3"/><path d="M-7,-5 V5 C-7,6.7 -3.8,8 0,8 C3.8,8 7,6.7 7,5 V-5"/><path d="M-7,0 C-7,1.7 -3.8,3 0,3 C3.8,3 7,1.7 7,0"/>',
    "merge": '<path d="M-6,-7 H2 L6,-3 V4 H-6 Z"/><path d="M-6,-7 H2 L6,-3"/><path d="M1,-1 L5,3 M5,-1 L1,3" opacity="0"/>',
    "scale": '<path d="M0,-8 V6 M-6,-4 H6 M0,-8 V6"/><path d="M-6,-4 L-8.5,2 A2.8,2.8 0 0 0 -3.5,2 Z M6,-4 L3.5,2 A2.8,2.8 0 0 0 8.5,2 Z"/><path d="M-4,7 H4"/>',
    "trash": '<path d="M-6,-5 H6 M-3,-5 V-7 H3 V-5 M-5,-5 L-4.5,7 H4.5 L5,-5"/><path d="M-1.5,-1 V4 M1.5,-1 V4"/>',
    "mega": '<path d="M-8,-2 L2,-6 V4 L-8,0 Z"/><path d="M-8,0 L-6,6 H-3.5 L-4.5,0.5"/><path d="M5,-3 C6.5,-2 6.5,0 5,1"/>',
    "wrench": '<path d="M-6,6 L3,-3 M6,-7 A4,4 0 0 0 2,-2 L-2,2 A4,4 0 0 0 2,6 L5.5,2.5 A4,4 0 0 0 6,-7 Z" transform="scale(0.9)"/>',
    "check": '<circle cx="0" cy="0" r="8"/><path d="M-3.5,0 L-1,3 L4,-3"/>',
    "cpu": '<rect x="-5" y="-5" width="10" height="10" rx="2"/><rect x="-2" y="-2" width="4" height="4"/><path d="M-2,-8 V-5 M2,-8 V-5 M-2,5 V8 M2,5 V8 M-8,-2 H-5 M-8,2 H-5 M5,-2 H8 M5,2 H8"/>',
    "sparkle": '<path d="M0,-8 L2,-2 L8,0 L2,2 L0,8 L-2,2 L-8,0 L-2,-2 Z"/>',
    "refresh": '<path d="M6.5,-3 A7,7 0 1 0 7,1"/><path d="M7,-6 V-1.5 H2.5" transform="translate(0,0)"/><path d="M6.5,-6 V-1.5 H2.5"/>',
    "stack": '<ellipse cx="0" cy="-4" rx="7" ry="3"/><path d="M-7,-4 V1 C-7,2.7 -3.8,4 0,4 C3.8,4 7,2.7 7,1 V-4"/><path d="M-7,4 V6 C-7,7.7 -3.8,9 0,9 C3.8,9 7,7.7 7,6" transform="translate(0,-1)"/>',
    "loop": '<path d="M0,0 C-1.5,-4.5 -8,-4.5 -8,0 C-8,4.5 -1.5,4.5 0,0 C1.5,-4.5 8,-4.5 8,0 C8,4.5 1.5,4.5 0,0 Z"/>',
}

# ============================ DRAW ============================
svg.append(f'<rect width="{W}" height="{H}" fill="#fbfcfd"/>')

# ---- header ----
dots = "".join(f'<circle cx="{44 + (i % 3) * 9}" cy="{30 + (i // 3) * 9}" r="2.6" fill="#5b6b8c"/>' for i in range(9))
svg.append(dots)
svg.append(f'<text x="80" y="50" fill="{INK}" font-size="30" font-weight="800" font-family="Nunito,sans-serif" letter-spacing="0.5">INDICT</text>')
svg.append(f'<text x="80" y="72" fill="{MUT}" font-size="12.5" font-family="Inter,sans-serif">AI-powered vulnerability hunting and proof workflow</text>')
svg.append(f'<text x="1396" y="44" fill="{INK}" font-size="13" font-weight="600" font-family="Inter,sans-serif" text-anchor="end">Find bugs. Prove them. Fix them. Repeat.</text>')

# ---- continuous-improvement wrapper (right column) ----
svg.append('<rect x="1076" y="84" width="324" height="1412" rx="16" fill="none" stroke="#b9c2d0" stroke-width="1.2" stroke-dasharray="6,5"/>')
svg.append(f'<text x="1396" y="68" fill="{SOFT}" font-size="10" font-weight="600" font-family="Inter,sans-serif" letter-spacing="2" text-anchor="end">CONTINUOUS IMPROVEMENT</text>')

# ---- panels ----
panel(360, 84, 700, 1418, "#fdfdfe", "#e2e7f0", "Core Workflow Pipeline", "From code to verified fixes.", icon=G["nodes"], icolor="#4f6bed")
panel(40, 96, 300, 190, "#f2f4ee", "#dde3d4", "AI &amp; Context", "Models and memory power the AI.", badge="0", bcolor="#7d9c6e")
panel(40, 1084, 300, 204, "#ffffff", "#e2e7f0", "Output Artifacts", "Results, reports, and evidence.", icon=G["bars"], icolor="#4f6bed")
panel(1092, 106, 280, 196, "#ffffff", "#e2e7f0", "Feedback &amp; Learning", "Models learn from outcomes.", icon=G["loop"], icolor="#7d9c6e")
panel(1092, 330, 280, 320, "#ffffff", "#e2e7f0", "AI Helper Models", "Specialized models for ranking.", icon=G["sparkle"], icolor="#2563eb")
panel(1092, 700, 280, 240, "#ffffff", "#e2e7f0", "Fix Learning Loop", "Turn fixes into better detection.", icon=G["refresh"], icolor="#0f766e")
panel(384, 140, 652, 140, "#edf0f8", "#dbe0ef", "Source", "Monitor repositories for changes.", badge="1", bcolor="#4f6bed")
panel(384, 296, 652, 188, "#f2ecf8", "#e3d8f0", "Analysis", "Scan, sweep, rank.", badge="2", bcolor="#8b5cf6")
panel(384, 492, 652, 124, "#faeceb", "#f0d9d7", "Hunters (Parallel)", "Multiple engines, parallel execution.", badge="3", bcolor="#e0784f")
panel(384, 632, 652, 316, "#ecf5ee", "#d7e7db", "Candidate Processing / Triage", "Consolidate, deduplicate, validate.", badge="4", bcolor="#3f9e63")
panel(384, 964, 652, 522, "#eaf1f8", "#d6e2ef", "Verification &amp; Reporting", "Prove, chain, report — drive fixes closed.", badge="5", bcolor="#4f6bed")

# ---- arrows under cards ----
edge([(660, 228), (750, 228)])                                   # repos -> watch
edge([(845, 256), (845, 284), (510, 284), (510, 346)])           # watch -> scan
edge([(340, 182), (384, 182)], dashed=True)                      # context -> source stage
edge([(600, 374), (720, 374)])                                   # scan -> sweep
edge([(510, 402), (510, 414)])                                   # scan -> rank
edge([(720, 442), (620, 442)], dashed=True)                      # SL -> rank
# rank -> hunters fan
for bx, hx, ty in [(450, 458, 486), (485, 584, 494), (520, 710, 502), (555, 836, 494), (590, 962, 486)]:
    edge([(bx, 470), (bx, ty), (hx, ty), (hx, 540)])
# hunters -> pile fan-in
for hx, px, ty in [(458, 593, 612), (584, 628, 620), (710, 663, 626), (836, 698, 620), (962, 733, 612)]:
    edge([(hx, 600), (hx, ty), (px, ty), (px, 690)])
edge([(663, 742), (663, 758)])                                   # pile -> dedup
edge([(790, 784), (763, 784)], dashed=True)                      # SL -> dedup
edge([(663, 810), (663, 826)])                                   # dedup -> judge
edge([(663, 878), (663, 882)])                                   # judge -> gate
edge([(608, 906), (576, 906)])                                   # gate -> dropped
edge([(663, 934), (663, 1020)])                                  # gate -> prove
edge([(790, 1044), (763, 1044)], dashed=True)                    # SL -> prove
edge([(663, 1068), (663, 1084)])                                 # prove -> chain
edge([(663, 1136), (663, 1152)])                                 # chain -> report
edge([(790, 1176), (763, 1176)], dashed=True)                    # SL -> report
edge([(563, 1178), (324, 1178)], dashed=True)                    # findings -> board
edge([(563, 1244), (324, 1244)], dashed=True)                    # finding -> pack
edge([(663, 1204), (663, 1220)])                                 # report -> notify
edge([(663, 1268), (663, 1284)])                                 # notify -> fixer
edge([(763, 1244), (1046, 1244), (1046, 782), (1108, 782)], dashed=True, color="#7d9c6e")  # verified -> learn
edge([(663, 1332), (663, 1348)])                                 # fixer -> fixgate
edge([(663, 1404), (663, 1420)])                                 # fixgate -> verified
edge([(718, 1376), (778, 1376), (778, 1190), (763, 1190)], dashed=True, color="#c08497")  # rejected -> report
# learn flywheel: learn -> learned artifacts (right edges) -> sweeps + ranks
edge([(1356, 782), (1386, 782), (1386, 186), (1356, 186)], dashed=True, color="#7d9c6e")
edge([(1386, 246), (1356, 246)], dashed=True, color="#7d9c6e")
edge([(1108, 186), (1054, 186), (1054, 374), (940, 374)], dashed=True, color="#7d9c6e")
edge([(1108, 254), (1042, 254), (1042, 442), (940, 442)], dashed=True, color="#7d9c6e")
# big rescan loop
edge([(763, 1446), (1068, 1446), (1068, 60), (845, 60), (845, 200)], dashed=True, color="#8fa3c0")

# ---- edge labels ----
elabel(660, 276, "new commits", size=9.5)
elabel(660, 366, "deterministic", size=9.5)
svg.append(f'<text x="592" y="894" fill="{MUT}" font-size="10.5" font-family="Inter,sans-serif" text-anchor="middle">fake</text>')
elabel(675, 990, "survives", anchor="start")
elabel(651, 1080, "verified", anchor="end")
elabel(651, 1148, "+ chains", anchor="end")
elabel(651, 1216, "new bug", anchor="end")
elabel(651, 1280, "dispatch", anchor="end")
elabel(651, 1344, "patch", anchor="end")
elabel(786, 1284, "rejected ·", anchor="start", color="#c08497")
elabel(786, 1296, "reopen issue", anchor="start", color="#c08497")
elabel(955, 52, "on new commit → rescan", color="#8fa3c0")
elabel(440, 1170, "events", size=9.5)
elabel(440, 1236, "--pack", size=9.5)
elabel(950, 1236, "verified findings", color="#7d9c6e", size=9.5)
elabel(995, 366, "improve detection", color="#7d9c6e", size=9.5)
elabel(995, 434, "richer similarity", color="#7d9c6e", size=9.5)

# ---- cards ----
card(56, 150, 268, 56, G["cpu"], "#4b5563", "Open models", "download · use · run · extend")
card(56, 218, 268, 56, G["db"], "#0f766e", "Memory", "known bugs & prior findings")
card(56, 1150, 268, 56, G["bars"], "#4f6bed", "Live board", "read-only · 127.0.0.1:8404\nevents.jsonl + live.json")
card(56, 1216, 268, 56, G["cube"], "#7c3aed", "Evidence pack", "runnable PoC tarball\nsha256 manifest")
card(480, 200, 180, 56, G["git"], "#d97706", "Git repos", "the code we guard")
card(750, 200, 190, 56, G["clock"], "#4f6bed", "Watch", "polls for new commits")
card(420, 346, 200, 56, G["doc"], "#4f6bed", "Scan", "clone · inventory · index")
card(720, 346, 220, 56, G["scan"], "#0d9488", "Sweep", "semgrep · secrets · CVEs\n+ learned rules")
card(420, 414, 200, 56, G["bars"], "#b45309", "Rank", "risk + semantic score\n+ learned signatures",
     fill="#fdf6e0", border="#e3c56a")
card(720, 414, 220, 56, G["sparkle"], "#2563eb", "Superlinked", "Qwen3-Embedding-4B\nsemantic boost",
     fill="#eef4fd", border="#a8c4ee")

hunters = [
    ("Hunter", "target", "reads risky files"),
    ("Explorer", "nodes", "traces sink → input"),
    ("Taintgen", "gear", "writes taint rules"),
    ("Variant", "bulb", "mines past fixes"),
    ("Fuzzlite", "cube", "writes a fuzzer"),
]
for i, (name, ic, body) in enumerate(hunters):
    minicard(400 + i * 126, 540, 116, 60, G[ic], "#7c3aed", name, body)

card(563, 690, 200, 52, G["stack"], "#0f766e", "Candidate pile", "all engine leads collected")
card(563, 758, 200, 52, G["merge"], "#0f766e", "Dedup", "same bug → one card")
card(790, 758, 220, 52, G["sparkle"], "#2563eb", "Superlinked", "Qwen3-Embedding-4B\nsemantic match", fill="#eef4fd", border="#a8c4ee")
card(563, 826, 200, 52, G["scale"], "#0f766e", "Judge", "a 2nd AI disproves it")
diamond(663, 906, 110, 56, "Real?")
card(404, 878, 172, 56, G["trash"], "#dc2626", "Dropped", "false positive\nkill → ledger",
     fill="#fdf0f0", border="#ecb8b8")

card(563, 1020, 200, 48, G["cube"], "#d97706", "Prove", "reproduce in sandbox")
card(790, 1018, 220, 52, G["sparkle"], "#2563eb", "Superlinked", "Qwen3-Reranker-4B\npicks the order",
     fill="#eef4fd", border="#a8c4ee")
card(563, 1084, 200, 52, G["nodes"], "#d97706", "Chain", "pair of proven bugs\n→ one chained PoC")
card(563, 1152, 200, 52, G["doc"], "#2563eb", "Report", "markdown · SARIF · jsonl\n+ narrative writeups")
card(790, 1150, 220, 52, G["sparkle"], "#2563eb", "Superlinked", "Qwen3.8-27B —\ndrafts the issue",
     fill="#eef4fd", border="#a8c4ee")
card(563, 1220, 200, 48, G["mega"], "#ea580c", "Page + file issue", "dispatch alert + issue")
card(563, 1284, 200, 48, G["wrench"], "#7c3aed", "Fixer agent", "patches in isolated env")
diamond(663, 1376, 110, 56, "Fix real?")
card(563, 1420, 200, 52, G["check"], "#16a34a", "Fix verified", "PoC dies + clean diff",
     fill="#effaf1", border="#a9d9b4")

# right column — continuous improvement
card(1108, 158, 248, 56, G["doc"], "#7d9c6e", "Learned rules", "from sweeps + valid findings")
card(1108, 226, 248, 56, G["db"], "#0f766e", "Learned vectors", "embeddings from real bugs")
for i, body in enumerate(["Qwen3-Embedding-4B\nsemantic boost",
                          "Qwen3-Embedding-4B\nsemantic match",
                          "Qwen3-Reranker-4B\npicks the order",
                          "Qwen3.8-27B —\ndrafts the issue"]):
    card(1108, 386 + i * 60, 248, 52, G["sparkle"], "#2563eb", "Superlinked", body,
         fill="#eef4fd", border="#a8c4ee")
card(1108, 754, 248, 56, G["bulb"], "#0f766e", "Learn", "verified bug → new rule\n+ embedding stored")

# loop-behavior mini card (inside Fix Learning Loop panel)
svg.append(f'<rect x="1108" y="826" width="248" height="92" rx="10" fill="#ffffff" stroke="rgba(31,41,55,0.14)" stroke-width="1.2"/>')
chip(1118, 838, "#4f6bed", G["refresh"])
svg.append(f'<text x="1164" y="855" fill="{INK}" font-size="12" font-weight="700" font-family="Nunito,sans-serif">Loop behavior</text>')
svg.append(f'<text x="1122" y="876" fill="{MUT}" font-size="9.5" font-family="Inter,sans-serif">· New commits trigger a rescan</text>')
svg.append(f'<text x="1122" y="892" fill="{MUT}" font-size="9.5" font-family="Inter,sans-serif">· Rejected fixes reopen the issue</text>')
svg.append(f'<text x="1122" y="908" fill="{MUT}" font-size="9.5" font-family="Inter,sans-serif">· Verified bugs teach the scanner</text>')

# straddles the AI&Context -> Source boundary; drawn late so cards don't cover it
svg.append('<rect x="302" y="146" width="120" height="36" rx="3" fill="#ffffff" opacity="0.92"/>')
svg.append(f'<text x="362" y="160" fill="{MUT}" font-size="9.5" font-family="Inter,sans-serif" text-anchor="middle">context</text>')
svg.append(f'<text x="362" y="174" fill="{MUT}" font-size="9.5" font-family="Inter,sans-serif" text-anchor="middle">powers the AI</text>')

# ---- footer ----
svg.append(f'<text x="40" y="1520" fill="{MUT}" font-size="11" font-family="Inter,sans-serif">INDICT  |  Continuous security research, from signal to fix.</text>')
svg.append(f'<text x="1400" y="1520" fill="{MUT}" font-size="11" font-family="Inter,sans-serif" letter-spacing="1" text-anchor="end">SCAN → ANALYZE → PROVE → FIX → LEARN → REPEAT</text>')


doc = f"""<!doctype html>
<html><head><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@700;800&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>html,body{{margin:0;background:#fbfcfd}}svg{{display:block}}</style>
</head><body>
<svg viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-labelledby="indictment-flat-title indictment-flat-desc" xmlns="http://www.w3.org/2000/svg">
<title id="indictment-flat-title">INDICT pipeline</title>
<desc id="indictment-flat-desc">Pipeline diagram: watched git repos are scanned and swept, five parallel hunters generate leads, dedup and an adversarial judge drop fakes, survivors are proven in a sandbox, composable pairs are chained into one PoC, reported with narratives, paged, and fixed with a verified gate; verified bugs teach the scanner new rules and vectors, a live board renders the event stream, evidence packs export runnable proof, and a rescan loop returns to the watcher.</desc>
<defs>
<marker id="ah" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
<polygon points="0 0, 8 3, 0 6" fill="{ARROW}"/></marker>
</defs>
{''.join(svg)}
</svg></body></html>"""

OUT.write_text(doc)
print(f"wrote {OUT}")
