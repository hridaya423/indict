#!/usr/bin/env bash
# verify.sh — one-command proof the harness works.
# Runs the model-free regression suite, then scores calibration state.
set -e
cd "$(dirname "$0")/.."

echo "=== selfcheck (stub client, all 6 engines) ==="
uv run python tests/selfcheck.py

echo; echo "=== calibration scoreboard ==="
uv run python -m calibrate.score findings/

echo; echo "=== doctor ==="
./scan --doctor
