#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
NODE_BIN=${NODE_BIN:-$(command -v node)}
SOLANA_BIN=${SOLANA_BIN:-$(dirname "$(command -v solana-test-validator)")}
: "${NODE_BIN:?Node.js 24 or newer is required}"
test -x "$SOLANA_BIN/solana-test-validator"
test -f target/deploy/seal_wallet.so
mkdir -p .runtime evidence
CPUS=${QS_CPUSET:-$(python3 -c 'import os; print(",".join(map(str, sorted(os.sched_getaffinity(0))[:4])))')}
docker build -t quantum-seal-localnet:0.1.0 -f scripts/Dockerfile.localnet .
exec docker run --rm --network none --cpuset-cpus "$CPUS" --cpus 4 --memory 4g \
  --pids-limit 512 --cap-drop ALL --security-opt no-new-privileges \
  --security-opt "seccomp=$ROOT/scripts/seccomp-localnet.json" \
  --user "$(id -u):$(id -g)" --read-only --tmpfs /tmp:rw,nosuid,nodev,size=256m \
  --mount "type=bind,src=$ROOT,dst=/work" \
  --mount "type=bind,src=$NODE_BIN,dst=/tools/node,readonly" \
  --mount "type=bind,src=$SOLANA_BIN,dst=/tools/solana,readonly" \
  -e QS_ISOLATED_LOCALNET=1 -e PATH=/tools/solana:/tools:/usr/bin:/bin \
  quantum-seal-localnet:0.1.0 bash scripts/localnet-inside.sh
