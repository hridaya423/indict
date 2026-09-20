#!/usr/bin/env bash
# run_all.sh — sequential calibration over all pinned targets.
# Local models serialize requests; run one at a time.
# Usage: bash calibrate/run_all.sh [--models smoke,smoke2] [--queue-limit N]
set -e
cd "$(dirname "$0")/.."
# calibration runs must not mutate global learned state (AGENTS.md)
export INDICT_NO_LEARN=1
ARGS="$*"
for d in calibrate/repos/*/; do
  name=$(basename "$d")
  [ "$name" = "minimist-head" ] && continue   # variant-test clone, not a target
  echo "=== $name ==="
  ./indict "$d" --engines sweep,hunter,explorer,taintgen,variant,fuzzlite --passes 2 $ARGS || true
done
echo; echo "=== SCOREBOARD ==="
uv run python -m calibrate.score findings/
