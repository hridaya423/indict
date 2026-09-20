#!/usr/bin/env bash
# run_poc.sh <repo_dir> <poc_dir> <lang> [script]
# Runs /poc/<script> inside a locked-down container: no network, capped
# cpu/mem, repo mounted read-only at /src. Script output goes to stdout —
# the caller (poc.py) captures it into poc_dir/output.txt.
# <repo_dir> must be an absolute path (docker -v rejects relative paths).
set -u
REPO="${1:?repo dir}"; POC="${2:?poc dir}"; LANG="${3:-python}"; SCRIPT="${4:-repro.sh}"
IMG="crs-sandbox-${LANG}"
# execution tracing: python (sitecustomize settrace) + node (v8 native)
# write per-line coverage so poc.py can require the reported line ran
docker run --rm \
  --network none --memory 1g --cpus 1 --pids-limit 128 \
  --read-only --tmpfs /tmp:rw,noexec,size=256m \
  -e CRS_TRACE=1 -e NODE_V8_COVERAGE=/poc \
  -v "$REPO":/src:ro -v "$POC":/poc:rw \
  "$IMG" timeout 60 bash "/poc/$SCRIPT"
