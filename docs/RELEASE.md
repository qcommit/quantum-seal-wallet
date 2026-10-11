# Public release checklist

This is a local research release candidate. Creating a public repository and
funding or deploying a wallet are separate actions. Neither is performed by the
build or test scripts.

## Repository preparation

Review `git diff --cached`, licenses, vector provenance and all tracked paths.
Run the commands in DEVELOPMENT.md, then run `python3 scripts/check-release.py`.
The path check excludes runtime keys and ledgers; it is not a comprehensive secret
scanner. Published NIST fixtures intentionally contain publicly known test values.

Create a local commit after review, then run `bash scripts/package-source.sh`.
The archive is made from that commit, not a recursive copy of the working tree.
Node modules, toolchains, keystores, relayer keys, ledgers and target artifacts do
not belong in the source release. A binary release needs a separate platform
matrix, artifact checksums and a verifiable build/attestation process.

Before publishing, select the GitHub account or organization, confirm that
repository creation and public visibility are authorized, and review the local
commit author identity. Do not infer an owner from a filesystem username. The
suggested repository name is `quantum-seal-wallet`; description:

> Experimental Solana smart-wallet authorization with SLH-DSA, permanent PDAs,
> threshold policies and an independent Rust verifier.

Suggested topics: `solana`, `post-quantum-cryptography`, `slh-dsa`, `rust`,
`smart-wallet`, `cryptography`. Enable private vulnerability reporting and branch
protection requiring Check. Avoid an “audit passed” badge, a fabricated security
score, an invented deployment address or a live-balance screenshot.

## Explicit blockers for real assets

Independent review of the FIPS 205 implementation and state machine; adversarial
program review; broader upstream corpus coverage and fuzzing; a production key
storage/recovery design; guardian monitoring and cancellation-race analysis;
external-program allowlists and transaction simulation/review; reproducible binary
builds and supply-chain review; cluster/deployment verification and an explicit
upgrade-authority policy. A public devnet deployment has not yet been tested.

A Phantom-like extension, mobile signing, arbitrary swap-route compatibility,
Token-2022 extensions, programmable/compressed NFTs, hardware custody and
production support are not included in v0.1.0. Do not advertise them as shipped.
