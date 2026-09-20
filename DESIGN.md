---
version: alpha
name: Indict security workspace
description: Light desktop workspace for repository scans, findings, and recorded evidence.
colors:
  primary: "#0057D9"
  primary-hover: "#0047B3"
  canvas: "#FFFFFF"
  sidebar: "#F4F6F9"
  surface: "#FFFFFF"
  surface-inset: "#F3F5F8"
  text: "#111827"
  text-secondary: "#475569"
  text-muted: "#596579"
  border: "#DCE2EA"
  control-border: "#8793A5"
  selected: "#E8F1FF"
  hover: "#F3F7FC"
  success: "#176B3A"
  success-bg: "#DDF3E5"
  warning: "#8A4500"
  warning-bg: "#FFF0D8"
  danger: "#B42318"
  danger-bg: "#FEE9E7"
  neutral-bg: "#EDF0F5"
  progress-track: "#E1E6ED"
  progress-fill: "#1670D2"
  timeline-complete: "#D6E5F8"
  timeline-active: "#BCD8FA"
typography:
  page-title:
    fontFamily: IBM Plex Sans
    fontSize: 30px
    lineHeight: 1.2
    fontWeight: 600
    letterSpacing: -0.025em
  section-title:
    fontFamily: IBM Plex Sans
    fontSize: 18px
    lineHeight: 1.35
    fontWeight: 600
    letterSpacing: -0.01em
  body:
    fontFamily: IBM Plex Sans
    fontSize: 14px
    lineHeight: 1.5
    fontWeight: 400
    letterSpacing: 0em
  label:
    fontFamily: IBM Plex Sans
    fontSize: 14px
    lineHeight: 1.4
    fontWeight: 500
    letterSpacing: 0em
  caption:
    fontFamily: IBM Plex Sans
    fontSize: 12px
    lineHeight: 1.5
    fontWeight: 400
    letterSpacing: 0em
  code:
    fontFamily: IBM Plex Mono
    fontSize: 12px
    lineHeight: 1.6
    fontWeight: 400
    letterSpacing: 0em
rounded:
  control: 4px
  panel: 4px
  badge: 4px
  pill: 9999px
spacing:
  micro: 4px
  small: 8px
  compact: 12px
  standard: 16px
  roomy: 24px
  section: 32px
  sidebar: 200px
  control: 36px
  row: 42px
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.canvas}"
    rounded: "{rounded.control}"
    height: "{spacing.control}"
    typography: "{typography.label}"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "{colors.canvas}"
  navigation:
    backgroundColor: "{colors.sidebar}"
    textColor: "{colors.text-secondary}"
  metadata:
    textColor: "{colors.text-muted}"
  divider:
    backgroundColor: "{colors.border}"
  input-outline:
    backgroundColor: "{colors.control-border}"
  row-hover:
    backgroundColor: "{colors.hover}"
  badge-success:
    backgroundColor: "{colors.success-bg}"
    textColor: "{colors.success}"
  badge-warning:
    backgroundColor: "{colors.warning-bg}"
    textColor: "{colors.warning}"
  badge-danger:
    backgroundColor: "{colors.danger-bg}"
    textColor: "{colors.danger}"
  badge-neutral:
    backgroundColor: "{colors.neutral-bg}"
    textColor: "{colors.text-secondary}"
  progress-track:
    backgroundColor: "{colors.progress-track}"
  progress-value:
    backgroundColor: "{colors.progress-fill}"
  timeline-complete:
    backgroundColor: "{colors.timeline-complete}"
    textColor: "{colors.text}"
  timeline-active:
    backgroundColor: "{colors.timeline-active}"
    textColor: "{colors.text}"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.panel}"
    padding: "{spacing.standard}"
  row-selected:
    backgroundColor: "{colors.selected}"
    textColor: "{colors.text}"
  evidence-output:
    backgroundColor: "{colors.surface-inset}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    typography: "{typography.code}"
---

# Indict design system

## Overview

This is the implementation target for the approved [workspace concept](docs/design/dashboard-concepts/04-approved-workspace.png), not a description of the current dashboard. The reference is a 1536 × 1024 generated image. It establishes composition, density, selection, and hierarchy. The exact tokens above are proposed implementation values reconstructed from that image, not sampled CSS or an identified font. They become normative for the build; validate rendered contrast and visual fidelity before release.

Design for an analyst moving from repository status to a run, a finding, and its recorded proof. Preserve that relationship on every page. Light mode is the requested release theme. Do not spend this implementation on dark mode; use semantic tokens so it can be added separately.

The approved image outranks the three earlier concepts for appearance. Their investigation and monitoring ideas remain useful, but their dark themes, navigation variations, and branding expansions do not carry forward. Use only “Indict” as the wordmark.

The [implementation spec](docs/plans/2026-09-20-dashboard-spec.md) defines data, routes, interactions, and release gates. This document owns visual intent and tokens. When source tokens exist, keep them synchronized with this document; do not maintain two conflicting palettes.

## Colors

Use white for the working canvas, pale cool grey for navigation and code output, and charcoal for text. The narrow blue selection stripe and pale blue row connect the selected repository and finding. Blue also identifies links and the primary action. Keep borders quiet and backgrounds flat.

Severity and verification are separate dimensions. Critical uses danger; High and Medium use warning colors with explicit labels; Low and Info use neutral labels. Reproduced uses success, Awaiting test and Candidate use neutral, and Dismissed uses neutral with its reason available. Never turn a High badge green because the PoC reproduced successfully.

Use success for recorded passed checks and a completed run only when its completion is known. A stale heartbeat uses warning and “Outcome unknown”; it is not a failure. An unavailable source or artifact uses a neutral empty state unless a retrieval request actually failed.

Use text-muted for metadata, not lightened border colors. Disabled controls retain legible text and explain why they are unavailable. Control borders must remain perceptible; decorative dividers may be subtler. No opacity on whole rows to convey dismissal.

## Typography

Self-host IBM Plex Sans at weights 400, 500, and 600 and IBM Plex Mono at 400; include font licenses. Use `font-display: swap`. Sans fallback: system-ui, sans-serif. Mono fallback: ui-monospace, monospace. No external font request at runtime.

Page headings are 30/36px; panel headings are 18/24px; rows and controls are 14/21px. Captions and code are at least 12px. Use sentence case. Reserve bold for headings, repository names, and finding titles. Do not make the whole interface monospaced.

Use tabular numerals for counts, revisions, timestamps, and elapsed durations. File paths and hashes use mono. Paths may truncate in a table only if a focusable control exposes and copies the full value. Finding titles may wrap to two lines. The case page shows full titles and paths without truncation.

## Layout

### Approved overview composition

At 1536 × 1024 CSS pixels, reproduce these anchors within the spec's tolerance. Positions are reconstructed from the reference and are acceptance targets, not claims of exact raster measurements.

| Region | Target |
| --- | --- |
| Sidebar | x 0–200, full viewport height |
| Main left edge | x 216; right edge 1520 |
| Page header | y 16–88 |
| Repository panel | y 102–352 |
| Selected run panel | y 368–570 |
| Findings and proof panels | y 586–1008 |
| Lower split | approximately equal widths, 16px gutter |

Main content uses the available width, without a centered marketing-page max-width. At widths above 1920px, cap content at 1800px inside the main region and keep it left aligned. Sidebar padding is 12px; nav rows are 40px high with 8px gaps. Main gutters and panel gaps are 16px. Headers have 12–16px internal padding.

Repository rows are at least 42px. Finding rows are at least 56px and can grow for two-line titles. Do not reduce fonts to fit extra columns. On the overview show up to four repositories and five findings, with explicit “View all” links when more exist. Show total counts and visible scope separately.

At 1280–1439px, use a 176px sidebar, move file paths below finding titles, and hide optional artifact sizes. At 1024–1279px, use a 64px icon rail with accessible names and tooltips; stack findings above the inspector. Below 1024px, use a navigation drawer and single-column sections. Below 768px, render repository rows as labeled records; keep code horizontally scrollable within its own pane. No global minimum width or clipped body.

Use document scrolling for the overview. Dedicated lists may use a scrollable table with sticky header; avoid more than two independent vertical scroll regions. A short viewport may require scrolling; never compress the reference until text becomes unreadable.

### Shared page structure

Every route reuses the wordmark, navigation, main left edge, heading scale, search treatment, and selected-row language. Detail pages add a breadcrumb above their title. Context appears in this order: repository, scanned revision, run, finding. Carry selected scope in the URL.

Findings uses a queue and inspector. Full cases use a wide evidence column and a narrower provenance column. Runs uses a list, selected timeline, and event ledger. Repositories uses a scan inventory and a repository detail page. Fixes uses a verdict queue and patch/gate detail. Do not invent a different visual system for each page.

## Elevation & Depth

Use 1px borders for panel boundaries and table separators. Panels sit directly on the white canvas with no shadow. Code output is inset through background tone alone. Selected rows use a 3px blue leading stripe and selected fill.

Only transient overlays receive a soft shadow: `0 8px 24px rgb(17 24 39 / 0.12)`. Keep tooltips small and adjacent to their target. No backdrop blur, glossy cards, gradients, glowing status dots, or decorative meshes.

## Shapes

Panels, controls, badges, and output panes use 4px corners. Filter chips and switches may use pill geometry. Progress tracks are 6px high with pill ends. Icons use one installed family, 18–20px, with consistent optical weight. Prefer an existing family; if none exists, use the React Phosphor package after verifying its current API. Do not draw custom icon paths.

## Components

### Navigation and controls

Active navigation has pale blue fill, blue icon and text, and a visible label. Use a native link for navigation and `aria-current="page"`. The light-mode footer is informational in this release, not a dead switch. Search has a persistent accessible label; placeholder text is only an example.

Buttons are 36px high, with at least a 40px interactive area in dense desktop views and 44px on touch layouts. One primary filled action per working pane; segmented selection is not an action. Secondary buttons use a visible border. Link actions use blue text and underline on hover/focus. Keep “Open full case” primary on the overview. An evidence-pack action is available only when a pack exists.

Hover changes background in 100ms. Press changes tone without scaling dense table controls. Focus uses a 2px primary outline with 2px offset. Keyboard selection is immediate. Loading buttons retain width and label context. Disabled controls have explanatory text or an accessible description.

### Tables and inspectors

Use real tables for tabular data. Text aligns left; numeric totals align right. Header cells stay quieter than row titles. Show selection through fill, stripe, and programmatic selected state. Each selectable row has a keyboard-reachable primary control; don't turn a table into an ARIA grid unless full grid keyboard behavior is implemented.

Selecting a repository updates its run and findings; selecting a finding updates its proof. Preserve visible selection while polling. A filter that hides the selected row closes the inspector with a short explanation. Do not silently replace it with a different finding during refresh.

### Progress and timelines

Progress bars describe a named stage with a known denominator, such as “4 / 14 candidates tested.” Unknown totals show a stage label and elapsed time, without a fractional bar. Never label this percentage as repository security or scan coverage.

A run timeline displays recorded intervals on one elapsed-time axis. Completed segments use timeline-complete; the active segment uses timeline-active with a blue “Now” marker. Text explicitly names completed, active, failed, or skipped states. The generated image's arbitrary segment widths are not authoritative: implementation widths must match recorded durations. Pending stages sit outside the elapsed axis with no fabricated duration.

For concurrent work, use separate timeline lanes. Never sum parallel duration into elapsed wall time. If interval boundaries are unavailable, show an event sequence titled “Stage timing unavailable.”

### Evidence

Keep claim text separate from recorded output. The proof pane shows revision, run, execution mode, output, matched check, and fix state. Use a light inset output pane with copy action and visible truncation notice. Code and output preserve whitespace; do not render them as HTML.

Display actual artifact names, sizes, and availability. A model narrative does not become an evidence chain by splitting sentences. Missing evidence gets a precise message. A verified legacy record without structured execution results says “Recorded as verified; detailed execution record unavailable.”

### States and motion

Skeletons mirror the final panel geometry and never show sample data in production. Initial empty state: “No scan results yet” with a copyable CLI instruction. Filter empty state: “No findings match these filters” with Reset filters. A failed refresh retains prior data with “Last updated …” and Retry. A corrupt repository has an inline warning; the rest of the workspace stays usable.

No pulsing status indicators or animated table arrivals. Updates must not move focused content. Use at most 150ms opacity/color transitions. Respect reduced motion. Toasts are for copy/download outcomes; persistent scan failures stay in the relevant page.

## Do's and Don'ts

- Preserve the reference's hierarchy: repository inventory, run timeline, finding and proof. Keep all three visible at the reference viewport.
- Keep all pages light and visually related; use tokens rather than one-off colors and spacing.
- Show missing, partial, failed, stale, and skipped states explicitly. Never replace unknown values with zero or inferred success.
- Keep decorative analytics, global risk scores, confidence percentages, avatars, and invented branding out of this release.
- Inspect screenshots at the reference viewport and responsive widths. Token lint and passing tests do not establish visual fidelity.
- Treat readability, accessible contrast, and correct duration geometry as justified corrections to the raster; record any other deviation for review.
