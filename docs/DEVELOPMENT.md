# Development and reproduction

## Toolchains

Use Node 24 (`.nvmrc` pins 24.21.0), Rust 1.89.0 (`rust-toolchain.toml`) and a
compatible Linux Docker engine for local-validator testing. The recorded SBF
build used Agave `cargo-build-sbf` 3.1.10 and platform-tools v1.52. Locks are
committed. Native Rust verification does not require Node or a Solana installation.

```sh
npm ci --ignore-scripts --no-fund
npm test
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --release --workspace
cargo build --locked --release -p seal-verify
```

Verify the included SDK fixture with a **separately selected** public key. This
example extracts a known test key only to make the fixture command reproducible;
extracting a key from an arbitrary downloaded proof is not identity verification.

```sh
KEY=$(node --input-type=module -e "import fs from 'node:fs'; console.log(JSON.parse(fs.readFileSync('fixtures/sdk-approval.json')).publicKey)")
target/release/seal-verify --proof fixtures/sdk-approval.json --key "$KEY"
node sdk/src/cli.mjs verify --proof fixtures/sdk-approval.json --key "$KEY"
```

## Compile the on-chain program

Install the official Agave SBF toolchain separately and put its binaries on PATH.
The test runner does not curl and execute a remote installer.

```sh
CARGO_BUILD_JOBS=4 cargo build-sbf --manifest-path programs/seal-wallet/Cargo.toml
bash scripts/test-localnet.sh
```

`test-localnet.sh` locates `node` and `solana-test-validator` on PATH. Override
`NODE_BIN` with an absolute Node binary path and `SOLANA_BIN` with the absolute
Solana binary directory when they are installed outside PATH.

The runner builds a small Ubuntu 24.04 image, then starts the validator and tests
inside a container with **no network**, no published ports, dropped capabilities,
a read-only root, a writable project mount, four selected CPUs and a 4 GiB memory
limit. The mount exposes this project, including ignored project files, but not the
user's home directory. Never keep funded keystores in the project.
Agave requires three io_uring syscalls; the vendored Moby default seccomp profile
adds only those allowances. It does not run privileged or disable seccomp.

The ledger is `.runtime/isolated-ledger`. It is reset by this test command. A new
local-only relayer is generated under `.runtime/`; no existing wallet is loaded.
The compiled program is preloaded into the test genesis. The suite creates its
own ephemeral PQ keys, mints synthetic classic SPL tokens and ends by reclaiming
proof rent. The container and validator stop at the end, including on failure.

## Reading results

`evidence/localnet.json` records every confirmed transaction, byte length, compute
consumption, fee, execution error and test label. Transaction signatures refer to
a destroyed local ledger, not a public explorer. A negative test sends a real local
transaction and requires a confirmed rejection; it is not merely a mocked return.
The report is rewritten by a new run, so commit intentional evidence updates.

The SBF and JS code use the same account layout and intent encoding. The native
verifier independently implements the SLH algorithm. Unit tests alone do not
replace the SBF suite when instruction construction, accounts or permissions change.

## Offline key and approval tools

```sh
node sdk/src/cli.mjs keygen --out owner.keystore.json
node sdk/src/cli.mjs inspect --intent intent.bin
node sdk/src/cli.mjs sign --intent intent.bin --keystore owner.keystore.json \
  --wallet WALLET_BASE58 --program PROGRAM_BASE58 --index 0 --out approval.json
```

Key creation and signing require a TTY; passphrases are not command-line options.
Signing displays the exact intent and requires `SIGN`. Use `encodeIntent` to create
`intent.bin`; use `initializeInstruction` and the other SDK builders for local chain
operations. `tests/localnet.mjs` is a complete runnable example, including multisig,
rotation, SPL CPI and recovery. There is no hidden backend or website trust check.

## Scope of CI

The supplied GitHub workflow runs native Rust/JS tests, formatting, Clippy,
dependency advisory checks and independent fixture verification. GitHub Actions
has not run until this repository is published. SBF/local-validator validation is
performed with the explicit Docker command above; it is not silently substituted
by native tests or claimed to be covered by the current hosted workflow.
