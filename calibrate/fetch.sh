#!/usr/bin/env bash
# fetch.sh — clone calibration targets at their pre-CVE refs into
# calibrate/repos/. Run on good wifi; then calibration works offline.
set -e
cd "$(dirname "$0")"
mkdir -p repos
python3 - <<'PY' > /tmp/cal_targets.txt
import yaml
for t in yaml.safe_load(open("targets.yaml")):
    print(t["name"], t["repo"], t["ref"])
PY
while read -r name repo ref; do
  dest="repos/$name"
  if [ -d "$dest/.git" ]; then echo "have $name"; continue; fi
  echo "==> $name @ $ref"
  git clone --quiet "$repo" "$dest" && git -C "$dest" checkout -q "$ref"
done < /tmp/cal_targets.txt
echo "done: $(ls repos | wc -l) repos"
