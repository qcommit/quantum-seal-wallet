# Third-party material

Project-owned code is MIT licensed. Dependency licenses remain with their authors.
`Cargo.lock` and `package-lock.json` pin the dependency graphs; dependencies are
not vendored into the source archive.

| Material | Role | License / provenance |
|---|---|---|
| `@noble/post-quantum` 0.7.1 | SLH-DSA key generation, signing and SDK verification | MIT; `licenses/noble-post-quantum.txt` |
| `@noble/hashes` 2.4.0 | SDK SHA-256 | MIT; `licenses/noble-hashes.txt` |
| `@solana/web3.js` 3.0.2 | PDA derivation, instruction construction, local RPC | MIT; `licenses/solana-web3.txt` |
| RustCrypto `sha2` 0.10.9 | Independent native verifier hashing | MIT OR Apache-2.0; Cargo metadata |
| Borsh 1.5.7 | Fixed account serialization | MIT OR Apache-2.0; Cargo metadata |
| Solana Rust crates | Program ABI, CPIs and syscalls | Apache-2.0; Cargo metadata |
| NIST ACVP vector subsets | Published positive and negative cases | `fixtures/NIST-LICENSE.txt`, `fixtures/PROVENANCE.json` |
| Quantum Seal strict JSON parser | Bounded parsing with duplicate-field rejection | Adapted from the separate Quantum Seal statement project; `licenses/quantum-seal-parser.txt` |
| Moby seccomp profile | Local-validator container restrictions | Apache-2.0; `licenses/moby-profiles.txt`, `evidence/seccomp-provenance.json` |

The Rust SLH-DSA verifier in this repository implements the FIPS 205 algorithms;
it does not import Noble's signing or verification implementation. NIST vector
files contain **published test-only secret values**, not operational wallet keys.
The newly generated `fixtures/sdk-approval.json` is a separate interoperability
fixture and is not represented as a NIST vector.

The upstream provenance file also describes a key-generation subset from the
statement project. This wallet repository includes only its `sigGen.json` and
`sigVer.json` subsets; no key-generation-vector coverage is claimed here.
