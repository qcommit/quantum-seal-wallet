#!/usr/bin/env bash
set -euo pipefail
cd /work
[[ ${QS_ISOLATED_LOCALNET:-} == 1 ]] || { echo 'Run through test-localnet.sh.' >&2; exit 1; }
node scripts/localnet-keys.mjs
solana-test-validator --ledger /work/.runtime/isolated-ledger --reset \
  --bind-address 127.0.0.1 --rpc-port 18899 --faucet-port 19900 \
  --gossip-port 18001 --dynamic-port-range 18002-18030 \
  --mint "$(cat .runtime/relayer-address.txt)" \
  --account "$(cat .runtime/program-id.txt)" /work/.runtime/genesis-program.json \
  --account "$(cat .runtime/program-data-id.txt)" /work/.runtime/genesis-program-data.json \
  --ticks-per-slot 8 --rpc-pubsub-worker-threads 1 --quiet \
  > .runtime/isolated-validator.log 2>&1 &
VALIDATOR_PID=$!
trap 'kill "$VALIDATOR_PID" 2>/dev/null || true; wait "$VALIDATOR_PID" 2>/dev/null || true' EXIT
node tests/localnet.mjs
node tests/network-localnet.mjs
