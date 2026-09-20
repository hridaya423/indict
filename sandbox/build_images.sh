#!/usr/bin/env bash
# Build sandbox images SEQUENTIALLY — parallel docker builds swap hard on
# a 48GB host. Run this when the machine is otherwise idle.
set -e
cd "$(dirname "$0")/images"
for f in Dockerfile.*; do
  lang="${f#Dockerfile.}"
  echo "==> indictment-sandbox-$lang"
  docker build -q -f "$f" -t "indictment-sandbox-$lang" .
done
docker images | grep indictment-sandbox
