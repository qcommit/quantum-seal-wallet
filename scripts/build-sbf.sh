#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
args=(build-sbf --manifest-path programs/seal-wallet/Cargo.toml)
if [[ -n ${SBF_SDK_PATH:-} ]]; then args+=(--sbf-sdk "$SBF_SDK_PATH"); fi
exec cargo "${args[@]}"
