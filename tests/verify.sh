#!/usr/bin/env bash
# verify.sh — one-command proof the harness works.
# Runs the model-free regression suite, then scores calibration state.
set -e
cd "$(dirname "$0")/.."

echo "=== selfcheck (stub client, all 6 engines) ==="
uv run python tests/selfcheck.py

echo; echo "=== unit suites (paging bus, issues, fix gate, rerank, ops) ==="
for t in test_paging test_issues test_fix test_rerank test_ops \
         test_sie test_rank_semantic test_dedup_semantic; do
  [ -f "tests/$t.py" ] || continue
  uv run python "tests/$t.py" > /tmp/crs-test-$t.log 2>&1 \
      && echo "  ok $t" \
      || { echo "  FAIL $t — see /tmp/crs-test-$t.log"; exit 1; }
done

echo; echo "=== calibration scoreboard ==="
uv run python -m calibrate.score findings/

echo; echo "=== doctor ==="
./scan --doctor
