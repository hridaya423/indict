#!/usr/bin/env bash
# golden.sh — snapshot/restore verified calibration state.
# findings/ is gitignored scratch space; golden/ is committed evidence.
#
#   calibrate/golden.sh save      # findings/ -> calibrate/golden/
#   calibrate/golden.sh restore   # calibrate/golden/ -> findings/
set -e
cd "$(dirname "$0")/.."

case "${1:-}" in
  save)
    for d in findings/*/; do
      name=$(basename "$d")
      [ -f "$d/findings.jsonl" ] || continue
      rm -rf "calibrate/golden/$name"
      mkdir -p "calibrate/golden/$name"
      cp "$d/findings.jsonl" "$d/summary.json" "$d/REPORT.md" \
         "calibrate/golden/$name/" 2>/dev/null || true
      [ -d "$d/findings" ] && cp -r "$d/findings" "calibrate/golden/$name/"
      [ -d "$d/poc" ] && cp -r "$d/poc" "calibrate/golden/$name/"
    done
    echo "saved -> calibrate/golden/ ($(ls calibrate/golden | wc -l | tr -d ' ') targets)"
    ;;
  restore)
    for d in calibrate/golden/*/; do
      name=$(basename "$d")
      mkdir -p "findings/$name"
      cp -r "$d"* "findings/$name/" 2>/dev/null || true
    done
    echo "restored -> findings/ ($(ls calibrate/golden | wc -l | tr -d ' ') targets)"
    ;;
  *) echo "usage: $0 save|restore" >&2; exit 1 ;;
esac
