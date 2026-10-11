# Threat model

The protected capability is execution by a fixed wallet program on behalf of a
permanent PDA. The attacker may control relayers, RPC responses, network messages,
proof files and all accounts not owned by the wallet program. Compromise of enough
active owner keys authorizes ordinary spending. Compromise of the guardian allows
delayed recovery unless owners veto. Compromise of the program upgrade path can
bypass the entire policy.

| Threat | Implemented defense | Remaining boundary |
|---|---|---|
| Classical fee-payer key compromise | Fee payer is not a wallet authority | Attacker can disrupt uploads, spend relayer funds and reclaim its proof rent |
| Replayed approval | Program, genesis domain, wallet, epoch, nonce and expiry bound to signed bytes | RPC must report the correct deployment and policy to a human signer |
| Redirected recipient or changed amount | Exact binary intent hash | Human transaction review and malicious UI remain risks |
| Proof account substitution | Owner, magic, exact size, PDA and wallet binding | Runtime/account isolation is trusted |
| Upload overwrite or out-of-order chunks | Uploader pin, append-only offsets, immutable seal | An uploader may abandon or close its own upload |
| Fake verification progress | Only program computes and persists roots; final root comparison required | Implementation correctness requires external review |
| Duplicate multisig signer | Distinct active keys and unique proof indices | Collusion of threshold owners is authorized |
| One-time key reuse across devices | Standardized stateless SLH-DSA, not an application-managed OTS counter | Key compromise and implementation side channels still matter |
| Reentrant or failing CPI | Signed metas, readonly PDA signer, lock and atomic nonce/action | Arbitrary callees and their upgrades are not made safe |
| Front-running initialization | Initial policy is part of the PDA commitment | Wrong public descriptors can still lead to a different address |
| Unsolicited PDA funding | Allocate/assign handles an already funded empty system account | Rent and allocation rules remain runtime dependencies |
| Stolen backup | Passphrase-derived authenticated encryption | Weak passphrase, memory inspection or hostile OS defeats this layer |
| Guardian compromise | Explicit slot delay and owner cancellation | Requires monitoring; no wall-clock SLA or guaranteed cancellation priority |
| Quantum attack on Solana infrastructure | None at network/validator/bridge layer | This is post-quantum wallet authorization, not post-quantum Solana |

## Deliberate restrictions

The shipped relay client accepts only literal loopback RPC URLs. It refuses
non-loopback configured RPC URLs. This URL check is not a sandbox against a
malicious local proxy or a caller-supplied Connection implementation.
The isolated test runner uses a network-disabled Docker container and synthetic
funds. The program itself is ordinary deployable SBF code; these client restrictions
are an operational guardrail, not an on-chain prohibition on public deployment.

There is no broad DeFi integration claim. The v1 CPI envelope permits one target,
12 unique accounts and 256 instruction bytes. It cannot encode every swap route,
NFT standard or Token-2022 extension. The classic SPL transfer test demonstrates
one concrete compatibility path, not ecosystem-wide support.

No session keys, spending limits, encrypted cloud recovery, hardware signer,
BIP-39 derivation, browser extension, mobile wallet, or production monitoring
service is included. These require their own protocols and reviews rather than
UI controls that suggest nonexistent protections.
