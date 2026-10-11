# Quantum Seal Wallet

**Post-quantum transaction authorization for a permanent Solana smart-wallet address.**

Quantum Seal Wallet is a Solana program, JavaScript SDK and command line, and an independent Rust verifier. Owners approve exact transaction intents with **SLH-DSA-SHA2-128s** (NIST FIPS 205). A program-derived address (PDA) owns the assets; the program verifies the post-quantum proofs on-chain before it moves anything.

| Status | |
| --- | --- |
| Wallet program | Reproducible canonical build (`seal_wallet.so` v0.2.0, 141,888 bytes, SHA-256 `e5442efb…d00d37`, checked by CI); deployed and rehearsed on **devnet**; **not yet deployed to mainnet** |
| Network client | Mainnet-ready: pins genesis, program ID, binary hash and immutability before every submission |
| Validation | Local validator: 264 transactions across two suites; devnet: real create, SOL and SPL transfer runs against upgradeable and immutable deployments; 491 tamper cases rejected; 28 NIST vector comparisons |
| Audit | **Not independently audited.** Do not deposit real funds until a reviewed program is deployed |
| Wallet app | Command line, plus a browser extension in a separate repository (see [How people will use it](#how-people-will-use-it)) |

Website: https://quantum-seal.vercel.app

## What works

| Capability | Implementation |
| --- | --- |
| Persistent deposit address | PDA derives from a commitment to the **initial** owner policy. Key rotation and recovery preserve the address. |
| Standardized post-quantum approvals | SLH-DSA-SHA2-128s, 32-byte public key, **7,856-byte signature**; no Ed25519 authorization fallback. |
| On-chain cryptographic verification | Verify-only, `no_std` Rust implementation reconstructs the FORS and seven XMSS authentication paths, then checks the public root. |
| Large signature transport | Append-only, uploader-bound proof account; **11 chunks** of at most 768 bytes, sealed before verification. |
| Threshold authorization | 1–3 owner keys with 1-of-N, 2-of-N or 3-of-3 policy; duplicate approvals do not increase quorum. |
| Safe intent binding | Domain-separated digest commits to genesis, program ID, wallet, policy epoch, nonce, expiry, action, exact accounts and instruction data. |
| Key rotation and recovery | On-chain epoch change, replay invalidation, a delayed guardian proposal and owner veto. |
| SOL and classic SPL | Local-validator examples execute a SOL transfer and a restricted classic SPL Token transfer. |
| Independently inspectable verification | Standalone native `seal-verify` Rust CLI does not call Noble, the website or RPC. |

**Not included:** ML-DSA, public devnet deployment, a Phantom-like extension, mobile UX, hardware custody, BIP-39 recovery, arbitrary swaps, generic NFT/DeFi support, arbitrary CPI adapters, an audit or NIST cryptographic module validation.

## System overview

~~~text
                    owner keys (SLH-DSA-SHA2-128s)
                                 |
                         offline signers
                                 |
                     canonical intent + approval
                                 |
                         untrusted relayer
                                 |
           +---------------------+-------------------+
           |                     |                   |
        begin proof         append signature     seal proof
           |                     |                   |
           +---------------------+-------------------+
                                 |
                       on-chain Rust verifier
                    FORS -> 7 XMSS root checks
                                 |
                   owner quorum + nonce/epoch
                                 |
                     permanent Solana PDA
                       /               \
                 transfer SOL      restricted CPI
                                     classic SPL
~~~

Relayers pay transaction fees and proof-account rent; **relayer signatures do not authorize spending from the wallet**. The public PDA is stable across authorized policy changes. Every action binds the current policy epoch and execution nonce, and failed execution rolls back its nonce change.

The program verifies staged proofs in multiple instructions because SLH-DSA signatures exceed the wire limit of ordinary transactions. The SDK uses legacy Solana transactions capped at 1,232 bytes; this implementation does **not** depend on a larger transaction format.

## Deploy to mainnet

The program is ready to deploy; nothing in this repository deploys it automatically. The full operator procedure is in [docs/MAINNET.md](docs/MAINNET.md).

1. **Use the canonical binary**: the `seal_wallet.so` attached to the release, built by the *Reproducible program build* workflow on GitHub's x86_64 runners with Agave 3.1.10, and matching [`PROGRAM_SHA256`](PROGRAM_SHA256). Rebuilding on ARM64 gives a different hash (see [Canonical build](#canonical-build)).
2. **Choose the deployment signer and fund it.** Program rent for the 141,888-byte binary is about 0.99 SOL at mainnet rent rates (0.72 SOL on devnet, which charges less), plus about the same again held temporarily in the upload buffer during deployment and returned afterwards.
3. **Deploy to devnet first** with the official Solana tools and run the full create → transfer flow against it.
4. **Deploy the reviewed build to mainnet and make it immutable.** The mainnet client refuses mutable programs, because an upgrade authority could replace the checks protecting every wallet. Removing the upgrade authority is irreversible.
5. **Pin it:** `network-config` records the program ID, binary hash and cluster; `check-network` must pass before any wallet uses it.

## How people will use it

Users hold their own keys and pay their own fees; there is no hosted relayer.

- **Owner key (post-quantum):** an SLH-DSA key, encrypted locally, that approves transfers. It never leaves the user's device.
- **Fee key (ordinary Solana):** a separate small Ed25519 key holding a little SOL for network fees. It submits the 12 transactions a transfer needs but has no authority over the wallet's funds; losing it costs at most its fee balance. Each transfer can carry a signed fee refund (version-2 intent) that the wallet pays back to the fee key, so its balance stays topped up.
- **Wallet address:** the PDA. Deposits go here, and it stays the same across key rotation and recovery.

Today both keys are managed with the command line. The intended consumer client is a **browser extension** in the style of Phantom: it keeps the owner key in extension storage, shows the decoded transfer in its own window before sealing, signs locally, and submits with the user's fee key. That client is a separate project and needs its own security review.

## Devnet rehearsal

On devnet, `HPopUzhpfG7Zn7BBuQ9FkJKSRB9e3vfgwrySCG7b7wHy` is an immutable deployment of the v0.2.0 binary, the exact mainnet configuration; the browser extension's devnet build uses it. Earlier rehearsal deployments: `9roN31b3XtdWLeuVYer6W9WkXR64hPNHu8F382jBStqi` (immutable, v0.1.1) and `6LBRd57jagVvhmpX1idsw9QXhoNHMHWstvpeGdSZAexT` (upgradeable test deployment, since closed). An earlier immutable copy of the ARM64 build, `2o7mAz2WBJhtmTHBbddRrLF3oc7UN2G5fxHpnzyhqjhq`, remains from the first rehearsal. [`tests/devnet-rehearsal.mjs`](tests/devnet-rehearsal.mjs) runs real create → SOL transfer → classic SPL transfer flows and records [evidence/devnet-rehearsal.json](evidence/devnet-rehearsal.json) and [evidence/devnet-rehearsal-immutable.json](evidence/devnet-rehearsal-immutable.json):

| Measurement | Devnet result |
| --- | ---: |
| Transactions per transfer | 12 (open + first chunk, 9 chunks, last chunk + seal + verify, execute + refund) |
| Base fees per transfer | 60,000 lamports (0.00006 SOL) |
| Refundable proof deposit | 0.0569 SOL, returned in the same send |
| Time per transfer, end to end | 53–72 s across runs (varies with public-RPC conditions) |
| Largest compute use (verification batch) | 489,321 CU |
| Signing time (JavaScript) | about 1.0 s |

## Canonical build

The program bytes depend on the host architecture of the official toolchain: the same
source and the same Agave 3.1.10 / platform-tools v1.52 produce
different bytes on Linux x86_64 and Linux ARM64 (for v0.1.1: `c53d5da2…` and `4fbf18f6…`;
1,826 bytes of generated code differ). Both are deterministic on their own platform.
**The x86_64 build is canonical**, because that is where most verifiers build: the
*Reproducible program build* workflow rebuilds it on GitHub's runners and fails unless it
matches [`PROGRAM_SHA256`](PROGRAM_SHA256). Deploy only that binary.

## Reproduce the local checks

Prerequisites: Node **24.21.0** (see `.nvmrc`), Rust **1.89.0** (see `rust-toolchain.toml`), and a Solana-compatible SBF toolchain for on-chain builds. Lockfiles are included.

~~~sh
npm ci --ignore-scripts --no-fund
npm test
npm run format:check
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --release --workspace
cargo build --locked --release -p seal-verify
python3 scripts/check-release.py
~~~

For the Solana binary and live integration scenarios, install Agave `cargo-build-sbf` 3.1.10 and a compatible local validator, then run:

~~~sh
CARGO_BUILD_JOBS=4 cargo build-sbf --manifest-path programs/seal-wallet/Cargo.toml
bash scripts/test-localnet.sh
~~~

The localnet runner uses a **network-disabled Docker container** with synthetic funds. It **resets its isolated test ledger**. It is not a devnet deployment; do not point these commands at a funded environment.

See [development notes](docs/DEVELOPMENT.md) for exact toolchains and environment details.

## Offline inspection and signing

~~~sh
node sdk/src/cli.mjs --help

# Interactive TTY required. Prompts for a passphrase; writes a mode-0600 keystore.
node sdk/src/cli.mjs keygen --out owner.keystore.json

# Decode a canonical binary intent before approving it.
node sdk/src/cli.mjs inspect --intent intent.bin

# Only sign after reviewing the wallet, program, genesis, action, nonce and expiry.
node sdk/src/cli.mjs sign --intent intent.bin \
  --keystore owner.keystore.json \
  --wallet WALLET_BASE58 --program PROGRAM_BASE58 \
  --index 0 --out approval.json

# A public key MUST come from a separately trusted source.
node sdk/src/cli.mjs verify --proof approval.json --key TRUSTED_PUBLIC_KEY_HEX
~~~

Generate a wallet descriptor with `node sdk/src/cli.mjs descriptor --program ... --genesis ... --policy policy.json --out wallet.json`. **Address derivation alone does not initialize the wallet.** The complete initialization / approval / execution client sequence is in [tests/localnet.mjs](tests/localnet.mjs). No command in the offline signing CLI connects to a public blockchain.

To reproduce cross-implementation verification against a deliberately public fixture:

~~~sh
KEY=$(node --input-type=module -e "import fs from 'node:fs'; console.log(JSON.parse(fs.readFileSync('fixtures/sdk-approval.json')).publicKey)")
target/release/seal-verify --proof fixtures/sdk-approval.json --key "$KEY"
~~~

That extracted key is suitable **only for reproducing the known test fixture**. It is not an identity-trust procedure for downloaded proofs.

## Validation evidence

The included [validation report](evidence/validation.json) records the following on **October 11, 2026**:

| Check | Recorded result |
| --- | ---: |
| Rust test functions | 26 |
| JavaScript tests | 41 |
| Selected NIST comparisons | 28 |
| Signature-component mutations | 491 |
| Confirmed local-validator transactions | 186 (+78 in the network-client suite) |
| Expected rejected transactions | 17 |
| Devnet rehearsal transactions | 25 per run (create, SOL transfer, SPL transfer) |
| Program SBF compilation | Passed: canonical x86_64 `e5442efb…d00d37` (v0.2.0); local ARM64 `066ad312…` (141,888 bytes each) |
| Maximum observed transaction size | 1,145 bytes |
| Maximum observed transaction compute | 513,117 CU |

The recorded localnet suites exercise 2-of-2 SOL execution, replay protection, changing owner policy without changing the deposit address, old-epoch rejection, staged signature corruption, SPL Token CPI, failed-CPI rollback, delayed guardian recovery, owner cancellation, guardian approvals that try to spend, proofs from another wallet, one approval uploaded twice, signed fee refunds (including a tampered refund account and the CPI path), the expiry horizon, interrupted-upload resumption and proof-rent reclamation. They include **26 + 17 localnet assertions**.

Performance measurements are in [evidence/benchmark.json](evidence/benchmark.json) and were made on Linux ARM64 with Node 24 using ten measured samples. The median SDK signing time, **including a self-check**, was approximately **953 ms**; median SDK verification was **1.13 ms**, and the independent Rust CLI including process startup was **3.00 ms**. Those are local measurements, **not** guarantees across devices or networks.

An included fixture and a localnet pass demonstrate bounded behavior, **not** a security audit, certification, full ACVP coverage or evidence that Solana's whole stack is quantum resistant.

## Repository map

| Path | Role |
| --- | --- |
| [programs/seal-wallet](programs/seal-wallet) | Deployable Solana SBF vault program and state machine |
| [crates/slh-verify](crates/slh-verify) | Independent, verify-only `no_std` SLH-DSA implementation |
| [crates/wallet-core](crates/wallet-core) | Shared binary codec, policy checks and account layouts |
| [crates/seal-verify](crates/seal-verify) | Native offline verification executable |
| [sdk/src](sdk/src) | JavaScript signer, encrypted keystore, instruction builders and local relay client |
| [tests/localnet.mjs](tests/localnet.mjs) | Isolated live-validator positive and adversarial scenarios |
| [fixtures](fixtures) | Selected NIST and approval fixtures with checksum provenance |
| [evidence](evidence) | Machine-readable local test, benchmark and build records |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | Signed byte format, PDA seeds, instruction ABI and recovery state machine |
| [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md) | Algorithm parameters and independent-verification boundaries |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Attack scenarios, mitigations and unaddressed risk |
| [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md) | Pre-deployment review of the on-chain program and how each finding was resolved |
| [docs/LAUNCH.md](docs/LAUNCH.md) | Mainnet launch checklist: deploy, finalize, verify, pin in the extension, flip the website |
| [docs/RELEASE.md](docs/RELEASE.md) | Source-release and production-readiness checklist |

## Security and scope

The keystore uses scrypt and AES-256-GCM with restricted file permissions. JavaScript cannot guarantee secret-memory erasure, the recovery guardian represents a privileged delayed takeover path, and a wallet-program upgrade authority can bypass the authorization checks by changing the program. External CPI targets are **not** made trustworthy by signing the invocation. The original relay client accepts only loopback RPC endpoints; the network client (`sdk/src/network-cli.mjs`) targets public clusters only through a pinned, verified deployment.

Read [SECURITY.md](SECURITY.md) before running any signing code and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before making security claims. **This project has not been independently audited and has not yet been deployed to a public cluster.**

## Contributions and licensing

Development and proposed changes are described in [CONTRIBUTING.md](CONTRIBUTING.md). All changes to signed serialization, on-chain state or PDA derivation require corresponding protocol and localnet tests.

Source is MIT licensed (see [LICENSE](LICENSE)). External dependencies, licenses and fixture provenance are identified in [THIRD_PARTY.md](THIRD_PARTY.md) and [fixtures/PROVENANCE.json](fixtures/PROVENANCE.json). Release steps are tracked in [docs/RELEASE.md](docs/RELEASE.md).

