# Cryptographic implementation

## Why this profile

This release implements one standardized stateless hash-based profile:
SLH-DSA-SHA2-128s, NIST FIPS 205. It avoids requiring the application to manage
one-time signing-key consumption across devices. SLH-DSA itself contains WOTS+
one-time components; claiming it does not use Winternitz techniques would be
incorrect. The construction manages those components internally.

The smaller-signature profile was chosen for Solana transport. It is distinct
from Quantum Seal variants that used the 17,088-byte 128f profile. Wallet v1
accepts only 128s and its 7,856-byte signatures. ML-DSA is not implemented, and
there is no silent downgrade or algorithm fallback.

| Parameter | Value |
|---|---:|
| n | 16 bytes |
| Hypertree height h | 63 |
| Layers d | 7 |
| XMSS subtree height | 9 |
| FORS trees k | 14 |
| FORS height a | 12 |
| Winternitz base | 16 |
| WOTS+ chains | 35 |
| Message digest m | 30 bytes |
| Public key | 32 bytes |
| Secret key | 64 bytes |
| Signature | 7,856 bytes |

## Independent verification

`crates/slh-verify` is a verify-only `no_std` Rust crate with no production
cryptographic dependency. It receives SHA-256 through a small `hashv` trait.
The Solana program implements that trait with the SHA-256 syscall; `seal-verify`
implements it with RustCrypto `sha2`. The JS SDK signs with Noble. Native
verification therefore does not call Noble, Node, or the Solana RPC.

The verifier implements pure-mode message framing, SHA2 compressed addresses,
MGF1 message expansion, FORS authentication paths, WOTS+ message digits and
checksum, chain completion, XMSS authentication paths and all seven hypertree
layers. `start` recovers the FORS root; `advance` authenticates one layer; the last
advance compares the recovered public root. `verify` runs the complete process.
No unchecked indexing into an unvalidated signature length is exposed publicly.

Verification state contains only public intermediate values. The program never
accepts a user-supplied intermediate root or a client claim that verification
succeeded. It computes and stores its own progress in program-owned accounts.

## Signing and storage

Noble key generation uses system randomness. Each approval supplies fresh
16-byte signing entropy and is self-verified before export. The independent Rust
and on-chain verifiers supply separate cross-implementation checks. Deterministic
or publicly known keys are confined to published test vectors.

The signing engine, offline CLI and local relay SDK share the same intent codec.
The keystore does not change the primitive: it encrypts its 64-byte secret key
under a passphrase-derived AES-256-GCM key. See SECURITY.md for memory and
passphrase limitations. Encryption at rest is not hardware-backed custody.

## Evidence boundaries

The repository includes 14 external pure sigVer cases and 14 published sigGen
outputs for this profile. Verification of sigGen outputs is not a claim that this
Rust crate implements signing or regenerated every signature. A mutation sweep
alters one byte in each of 491 signature components and expects rejection.
Additional tests cover changed keys, messages, contexts, lengths and staged
verification. This is a selected corpus, not every FIPS 205 profile or interface.

The digest signed by the wallet is an application SHA-256 digest with a separate
SLH context. Security includes the application hash and framing, not only the
underlying SLH primitive. The formal HashSLH-DSA interface is not used.

## Primary references

- NIST FIPS 205: https://csrc.nist.gov/pubs/fips/205/final
- Published standard: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
- NIST ACVP corpus: https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files
- Noble implementation: https://github.com/paulmillr/noble-post-quantum
- Solana transaction limits: https://solana.com/docs/core/transactions
- Solana compute budget: https://solana.com/docs/core/fees/compute-budget

These references document the primitives and runtime, not an endorsement or audit
of Quantum Seal Wallet.
