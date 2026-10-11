# Mainnet-compatible client

The network client can target mainnet-beta, devnet, or a local validator. This is
**implementation support, not a claim of a completed mainnet deployment or a
security audit**. The shipped wallet program has no published mainnet address.
Mainnet creation and transfers require an operator-deployed, reviewed program.
No script deploys a program, funds an account, or changes an upgrade authority.

## Trust and deployment checks

A network configuration pins the cluster genesis hash, program ID, exact SBF
binary byte length and SHA-256, RPC endpoint, and upgrade-authority policy.
`check-network` fetches executable accounts and verifies the deployed bytes,
including zero-only allocation padding. Loader-v2 and loader-v3 are supported;
other loaders are rejected. Mainnet mode **requires an immutable program**.
Devnet may explicitly pin a mutable upgrade authority for testing.

The mainnet and devnet genesis hashes are fixed in `sdk/src/network.mjs` and were
cross-checked against the public cluster RPCs. Merely labelling an endpoint
“mainnet” is insufficient. Public endpoints must use HTTPS. Every submitted wallet
transaction repeats the deployment checks: upgradeable deployments (test clusters) are
re-verified byte for byte each time, while an immutable deployment, whose bytes cannot
change on-chain, is verified in full once per session and then re-checked for cluster
genesis and its executable program account before each transaction. RPC reads are still trusted: this is
not a light client or cryptographic proof of cluster state.

An upgrade authority can replace the checks that protect all wallets. Making a
program immutable is irreversible and removes the ability to fix that deployment.
Use a reviewed release and a deliberate migration plan; **do not remove upgrade
authority merely to bypass a client error**. Mainnet verification does not make
Solana consensus, fee-payer signatures, external programs, or bridges post-quantum.

## Operator deployment (separate from using a wallet)

Measured on devnet (see `evidence/devnet-rehearsal.json`): the 141,744-byte program
locks about 0.72 SOL of rent on devnet and about 0.99 SOL at mainnet rent rates; a
deployment also holds a temporary upload buffer of similar size, returned when the
deployment completes. Each transfer is 16 transactions and 80,000 lamports of base fees.
Rehearse on devnet with `tests/devnet-rehearsal.mjs` (a funded devnet keypair kept
outside the repository, passed as `QS_DEVNET_FUNDER`) before any mainnet deployment.

Build with the pinned toolchains described in DEVELOPMENT.md:

```sh
bash scripts/build-sbf.sh
```

For a source-built Agave toolchain, set `SBF_SDK_PATH` to its `platform-tools-sdk/sbf`
directory. Nothing is downloaded or installed by this wrapper. Choose and verify
the program ID, deployment signer, cluster, binary and deployment budget before
using the official Solana deployment tools. Test the deployed bytecode and full
creation/transfer flow on devnet before committing to an immutable mainnet build.
No default CLI keypair or existing funded wallet is selected by this repository.

After a reviewed deployment, set `PROGRAM_ID` to its actual address. Configure
RPC separately; a private RPC URL may contain credentials and should not appear
in screenshots, source control or copied shell history.

```sh
# Example public endpoint; a dedicated production RPC may be needed.
export QS_RPC_URL=https://api.mainnet-beta.solana.com
node sdk/src/network-cli.mjs network-config \
  --cluster mainnet-beta --program "$PROGRAM_ID" \
  --binary target/deploy/seal_wallet.so --out mainnet.network.json

node sdk/src/network-cli.mjs check-network --config mainnet.network.json
```

`network-config` writes a file without contacting the chain; `check-network` does
only RPC reads and must succeed before use. A missing deployment, mutable mainnet
program, wrong genesis or wrong binary fails closed. The configuration's hash must
come from a reviewed local build, not an arbitrary downloaded proof or RPC claim.

## 1. Create a key and wallet descriptor

```sh
node sdk/src/cli.mjs keygen --out owner.keystore.json
```

The command prompts in a terminal for the passphrase and returns a public key.
Back up the encrypted keystore and preserve the public descriptor. Set
`OWNER_PUBLIC_KEY` to that printed 32-byte hexadecimal public key.

```sh
node sdk/src/network-cli.mjs create --config mainnet.network.json \
  --owner "$OWNER_PUBLIC_KEY" --out wallet.json
```

This default is a one-owner wallet with no guardian. A reviewed policy file may
instead be supplied with `--policy`. Creating `wallet.json` derives the permanent
address; it **does not yet initialize a usable on-chain wallet**. No secret signing
key is placed in the descriptor or sent to the RPC.

## 2. Initialize the on-chain wallet

Use a separate, explicitly selected conventional Solana fee payer. Its signature
pays network costs; it is not an owner authorization for withdrawing wallet funds.
Set `RELAYER_PUBLIC_KEY` and `RELAYER_KEYPAIR` yourself. The CLI never searches for
or defaults to `~/.config/solana/id.json`. Fee-payer JSON files must be mode 0600 on
POSIX systems. Prefer a dedicated low-balance fee payer; the CLI does not currently
support hardware-backed fee-payer signing.

```sh
# Plan only: show the wallet, program, fee payer and required rent top-up.
node sdk/src/network-cli.mjs initialize --config mainnet.network.json \
  --wallet wallet.json --payer "$RELAYER_PUBLIC_KEY"
```

To actually initialize after review, add `--broadcast`, `--acknowledge-unaudited`,
`--fee-payer "$RELAYER_KEYPAIR"` and `--receipt initialize.receipt.jsonl`.
The CLI requires a TTY and an exact phrase containing the cluster and wallet
address. A plan never loads the fee-payer secret. Existing initialized wallets
are detected without another initialization transaction.

```sh
node sdk/src/network-cli.mjs status --config mainnet.network.json --wallet wallet.json
```

Only after checking the initialized account and expected owner policy should a
user consider a deposit. Normal Solana transfers can send SOL to the PDA. Keep in
mind that this is unaudited software; mainnet exposure can result in total loss.

## 3. Prepare and review a transfer

```sh
node sdk/src/network-cli.mjs prepare-sol --config mainnet.network.json \
  --wallet wallet.json --to "$RECIPIENT" --amount 0.01 --out intent.bin

node sdk/src/cli.mjs inspect --intent intent.bin
```

SOL amounts are parsed into lamports using exact decimal arithmetic. Excess
precision and exponent notation are rejected, not rounded. The client checks
available balance after the wallet's rent reserve, recipient rent and current
nonce/epoch. The default expiry horizon is 3,000 slots, not a wall-clock guarantee.
Use `--expires-in-slots` when deliberately choosing a different horizon.

For classic SPL tokens, the source and destination token accounts must already
exist. The client verifies the token program, mint, source authority, initialized
state, balance and mint decimals. Token-2022 extensions are intentionally rejected.

```sh
node sdk/src/network-cli.mjs prepare-token --config mainnet.network.json \
  --wallet wallet.json --source "$SOURCE_TOKEN_ACCOUNT" --mint "$MINT" \
  --destination "$DESTINATION_TOKEN_ACCOUNT" --amount 1.25 --out token-intent.bin
```

## 4. Sign offline and independently verify

Set `WALLET_PDA` to the address in the reviewed descriptor and `PROGRAM_ID` to the
same pinned deployment used during initialization.

```sh
node sdk/src/cli.mjs sign --intent intent.bin --keystore owner.keystore.json \
  --wallet "$WALLET_PDA" --program "$PROGRAM_ID" --index 0 --out approval.json

target/release/seal-verify --proof approval.json --key "$OWNER_PUBLIC_KEY"
```

The signer prompts for transaction review and the keystore passphrase. Do not
extract an arbitrary embedded public key and call it trusted. Threshold wallets
supply separately signed approvals from distinct current owners.

## 5. Execute the signed transfer

```sh
node sdk/src/network-cli.mjs execute --config mainnet.network.json \
  --wallet wallet.json --proof approval.json --payer "$RELAYER_PUBLIC_KEY"
```

This is a plan, not a broadcast. It validates the current signatures/quorum and
prints refundable proof rent separately from the conservative fee budget. To
submit, add the same explicit broadcast options as initialization, using a new
receipt path. Repeat `--proof` for additional owner approvals.

Every network transaction is simulated with signature checks, quoted against a
per-transaction fee ceiling, and submitted with preflight enabled. Optional
`--compute-unit-price` is in micro-lamports per compute unit. `--max-fee-lamports`
is a per-transaction ceiling, not a total-cost quote. Mainnet and devnet success
requires finalized transaction metadata, not merely an RPC-returned signature.

Signatures are uploaded in eleven bounded chunks. The same on-chain verifier and
proof state machine used by the local tests authorize the final action. Proof
rent is reclaimed after success; a cleanup failure is reported separately and
must not be interpreted as a failed transfer.

## Interrupted and uncertain operations

Preserve the original approval file. The uploader checks existing signature bytes
and resumes at the exact append offset; signing the same intent again produces a
different randomized signature and is not a safe replacement for an existing upload.
On success the nonce advances once and reuse of that approval is rejected.

The receipt journal records each locally derived transaction signature and expiry
before it is broadcast, then appends confirmed outcomes. Network errors or a
confirmation timeout are **unknown outcomes**, not proof that nothing happened.
The client never automatically signs a replacement with a new blockhash. Inspect
transaction history, receipt signatures, wallet nonce and proof accounts before
retrying. RPC history absence is not a proof of non-execution.

## Validation scope

`evidence/network-localnet.json` records the new network client's actual local
wallet creation, SOL/SPL transfers, interrupted-upload resumption, replay rejection,
proof-rent cleanup and CLI checks. `sdk/test/network.test.mjs` injects wrong-cluster,
wrong-binary, mutable-deployment, fee, simulation and confirmation failures. Mock
RPC tests are not mainnet receipts. Public-mainnet deployment and funded transfers
have not been performed by this development session.

Primary references: Solana deployment and authority semantics at
https://solana.com/docs/programs/deploying ; transaction behavior at
https://solana.com/docs/core/transactions ; and genesis RPC at
https://solana.com/docs/rpc/http/getgenesishash .
