#!/usr/bin/env bash
# Builds the demo source repository that reach analyses for /demo/api.
#
# demo/shop-api/ is tracked in this repo as plain files. reach's local
# fetcher needs a real git repository (it runs `git archive <commit>`), so
# this script snapshots those files into demo/.repos/shop-api — gitignored,
# rebuilt on every run — and commits them on branch `main`.
#
# docker-compose.yml mounts demo/.repos read-only into the reach container
# at /demo-repos, so the Settings → Source repositories entry is:
#   namespace  /demo/api
#   repo_url   /demo-repos/shop-api
#   revision   main
#
# Usage: ./scripts/demo-repo.sh
set -euo pipefail
cd "$(dirname "$0")/.."

SRC=demo/shop-api
OUT=demo/.repos/shop-api

rm -rf "$OUT"
mkdir -p "$OUT"
cp -R "$SRC"/. "$OUT"/

git -C "$OUT" init -q -b main
git -C "$OUT" add -A
GIT_AUTHOR_NAME="Magnolia demo" GIT_AUTHOR_EMAIL="demo@magnolia.invalid" \
GIT_COMMITTER_NAME="Magnolia demo" GIT_COMMITTER_EMAIL="demo@magnolia.invalid" \
  git -C "$OUT" -c commit.gpgsign=false commit -q -m "shop-api demo snapshot"

echo "demo repo: $OUT @ $(git -C "$OUT" rev-parse HEAD)"
echo "map it in Settings → Source repositories as /demo-repos/shop-api, revision main"
