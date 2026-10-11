#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/check-release.py
if [[ -n $(git status --porcelain) ]]; then
  echo 'Commit the reviewed source before packaging.' >&2
  exit 1
fi
mkdir -p dist
NAME=quantum-seal-wallet-0.1.0
# git archive includes only the reviewed commit, never the working directory.
git archive --format=tar --prefix="$NAME/" HEAD | gzip -n > "dist/$NAME.tar.gz"
(
  cd dist
  sha256sum "$NAME.tar.gz" > SHA256SUMS
)
git rev-parse HEAD > dist/SOURCE_COMMIT
printf 'Source archive: %s/dist/%s.tar.gz\n' "$PWD" "$NAME"
