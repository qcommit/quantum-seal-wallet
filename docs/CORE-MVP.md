# Core open-source MVP

User scope clarification: wallet creation and transactions are the release
priority. A Phantom-style extension, mobile app, swaps, NFT gallery and other
consumer-wallet features are optional future work, not gates for this MVP.

## Required core

1. Generate fresh SLH-DSA owner keys and protect the signing key in an encrypted
   keystore. Derive a public wallet descriptor and initialize the wallet account.
   Deriving an address alone must not be described as completed creation.
2. Receive funds at the wallet address and execute an exact SOL transfer only
   after successful post-quantum signature and current-policy checks. Classic
   SPL-token transfers are an additional demonstrated path.
3. Reject changed recipients/amounts, corrupted proofs, insufficient approvals,
   stale policy epochs and replayed intents. The fee payer is not a spending
   authority. Report success only from confirmed execution.
4. Let another developer reproduce the flow from the source repository using
   documented commands, pinned dependencies and actual test receipts. Clearly
   distinguish local-validator results from any later public-network results.

## Current evidence

The local-validator receipt in `evidence/localnet.json` records actual wallet
initialization, deposits, SOL and classic SPL transfers, plus expected rejected
transactions. `tests/localnet.mjs` and `scripts/test-localnet.sh` reproduce those
flows. They use synthetic funds in an isolated local validator. This is core
functional evidence, not a public deployment or security audit.

## Release priorities

First make creation-to-transfer easy to reproduce and inspect: a focused
quickstart, the complete runnable example, source/license provenance, independent
verification, and a reviewed source commit/package. An honestly labelled local
research release does not require consumer-wallet feature parity or a completed
security audit.

Public devnet creation and transfers are the next network milestone. They
require an explicit deployment plan and authorization. Mainnet readiness is a
separate milestone requiring deployment/upgrade-policy decisions and independent
security review. Do not bypass the current loopback client restriction or use
real funds merely to make an open-source demonstration look complete.
