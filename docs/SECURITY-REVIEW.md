# Quantum Seal Wallet: pre-mainnet security review (read-only)

Date: 2026-10-11 (pre-change code). Scope: `programs/seal-wallet/src/lib.rs`, `crates/wallet-core/src/lib.rs`,
`crates/slh-verify/src/lib.rs`, the docs in `docs/` that describe the design, and the SDK
instruction and codec builders. I did not edit any source files. `cargo test --locked --release --workspace`
(4 jobs) passes: 22 tests, including the NIST sigVer/sigGen vectors, the mutation sweep and the
staged-vs-full equivalence test.

## Verdict

I found **no critical or high-severity issue**. None of these can move funds, change policy or
get around quorum: the fee payer, an uploader, someone who calls `step` or `execute`, or a
random account. Replay is blocked across wallets, programs, clusters, epochs and nonces. The
staged verifier matches FIPS 205 for SLH-DSA-SHA2-128s. The findings below are one medium-severity
design/configuration risk and several low or info items.

| # | Severity | Title |
|---|---|---|
| 1 | Medium | A 150-slot recovery delay makes the owner veto impractical, so a compromised guardian can take over the wallet in about 60 s |
| 2 | Low | A guardian can bump the nonce, which kills in-flight owner approvals, and can repeat this after every Cancel |
| 3 | Low | Intent expiry has no upper bound on-chain, so approvals stay valid until their nonce is used |
| 4 | Low | Invoke passes the wallet's signer privilege to whatever the callee calls next |
| 5 | Info | Transfer targets: rent-minimum and executable accounts make the tx fail; there is no fund risk |
| 6 | Info | Invoke can never credit lamports to the wallet or use it as a payer |
| 7 | Info | `execute`, `seal` and `step` need no signer, so anyone can run them and choose the timing |
| 8 | Info | An uploader can close its own proofs between stage 9 and execute (relayer DoS) |
| 9 | Info | A proof closed and then re-funded in the same tx leaves a dead PDA; only the uploader can do this |
| 10 | Info | The reentrancy lock never does anything under current runtime rules |
| 11 | Info | Test gaps for on-chain adversarial account substitution |

---

## Findings

### 1. Medium: the minimum recovery delay is too short for a real owner veto
- `crates/wallet-core/src/lib.rs:89` (`150..=2_000_000`), `sdk/src/codec.mjs:93`, used in `tests/localnet.mjs:108,190`.
- **Scenario:** a wallet is configured with a guardian and `recovery_delay = 150` (the minimum allowed, about 60 s). The attacker steals the guardian key, signs `ProposeRecovery(attacker_owners)`, and uploads and verifies one proof (about 14 txs). Execute sets `recovery_ready_at = slot + 150`. To veto, a threshold of owners must notice, decrypt their keystores (scrypt N=2^17), sign `CancelRecovery`/`Rotate` at nonce N+1, and upload, seal and verify 1–3 proofs of 7,856 bytes each (about 14 txs each), all before the attacker calls the permissionless `finalize` (`programs/seal-wallet/src/lib.rs:431`) exactly at maturity. For any human-in-the-loop multisig this is effectively impossible. The guardian then fully owns the wallet: it rotates owners, and the attacker's new owners can spend.
- The threat model says guardian compromise is "delayed recovery unless owners veto". At the floor value, the delay gives no real protection.
- **Fix:** raise the on-chain floor to something a human can act on, for example ≥ 216,000 slots (about 1 day). At minimum, make the SDK and CLI refuse values below about 1 day on mainnet configs, or warn loudly. Document that monitoring is mandatory. Optionally let owners pre-sign a standing `CancelRecovery` at nonce N+1 with a long expiry: it fails harmlessly with `NoRecovery` if nothing is pending.

### 2. Low: a guardian proposal consumes the owner nonce, and the guardian can re-propose after every Cancel
- `programs/seal-wallet/src/lib.rs:342-345` (the `bump_nonce` runs for every action, including the guardian path); `crates/wallet-core/src/lib.rs:168-184`.
- **Scenario:** owners have a 2-of-3 Transfer at nonce N partly uploaded or verified. A compromised (or hostile) guardian executes `ProposeRecovery` at nonce N first, which moves the nonce to N+1. Every owner proof at nonce N is now stale (`Error::Stale`). If owners respond with `CancelRecovery`, `recovery_ready_at` goes back to 0 and the guardian can immediately propose again at the new nonce. Each cycle costs the owners a fresh threshold approval plus proof rent. It costs the guardian one proof.
- The damage is bounded: while a recovery is pending the guardian cannot propose (`RecoveryPending`), and an owner `Rotate` that removes or replaces the guardian ends the loop.
- **Fix:** document that the correct veto against a hostile guardian is `Rotate`, not `CancelRecovery`. Possible protocol changes: give guardian intents their own counter (a `recovery_nonce` bound into the guardian intent), so a proposal never invalidates owner approvals; or add a cooldown after a cancel (for example, the guardian cannot propose again for `recovery_delay` slots).

### 3. Low: no maximum expiry on-chain
- `crates/wallet-core/src/lib.rs:147` (only `expiry < slot` is rejected). The SDK caps the horizon at 216,000 slots (`sdk/src/wallet.mjs:181`), but the program accepts `expiry = u64::MAX`.
- **Scenario:** a modified or compromised signing UI, or the offline CLI path, produces an intent with an enormous expiry. One owner's partial approval, or a full threshold set that was never executed, stays executable until someone uses nonce N. A later collusion or compromise of the remaining owners, or a relayer that held back a full set, can then execute it at any time while the wallet is still at nonce N. This only affects owner-signed bytes; it does not bypass quorum.
- **Fix:** enforce `expiry <= slot + MAX_HORIZON` in `check_live`, used by begin and execute, for example with a 216,000-slot horizon to match the SDK. Also tell users that the way to revoke an unexecuted approval is to use its nonce with a no-op or alternate intent.

### 4. Low: Invoke gives the callee transferable signer authority (by design, but it is the main remaining way to lose funds)
- `programs/seal-wallet/src/lib.rs:383-426`, `crates/wallet-core/src/lib.rs:328-363`.
- The wallet PDA's signer privilege lasts for the whole callee invocation, including any CPI the callee makes. An approved call to program X therefore lets X (or X's upgrade authority, which is a classical key) call SPL Token, Token-2022, the Stake program and so on with the wallet as authority. The only accounts it can touch are those in the 12 signed metas, but a signed meta list for a "harmless" call can still contain the wallet's token accounts. A relayer can also sandwich the call within the same tx (see #7).
- **Fix:** keep the documented warning. In the SDK and UI, show the callee's upgrade authority and refuse non-allowlisted callees by default. The SDK already only relays the SPL `TransferChecked` shape (`sdk/src/wallet.mjs:310+`). Keep that restriction in any mainnet UI.

### 5. Info: Transfer target edge cases fail closed
- `programs/seal-wallet/src/lib.rs:347-369`.
- A brand-new target receiving less than the rent-exempt minimum for 0 bytes (about 890,880 lamports) makes the tx fail with an insufficient-funds-for-rent error. An executable or reserved target (builtin program, sysvar) is demoted to read-only, so `writable()` fails, or the runtime rejects the lamport change. Crediting an account owned by another program (a token account, a PDA) succeeds, and that SOL is only recoverable through that program, but the owners approved that exact address. The wallet keeps `minimum_balance(334)` and every add and subtract is checked. Self-transfer and proof-as-target are both rejected.
- **Fix (UX):** in the SDK, reject recipients that are not system-owned, and reject amounts below the rent minimum when the recipient is empty.

### 6. Info: Invoke can never credit the wallet or use it as a payer
- `crates/wallet-core/src/lib.rs:346` forces the wallet to be a read-only signer inside the CPI. Closing a wallet-owned token account with destination = wallet, or creating an ATA with the wallet as funder, therefore always fails. This is safe, just limiting: a token-account close has to send its rent somewhere else.

### 7. Info: execution, sealing and stepping are permissionless
- `programs/seal-wallet/src/lib.rs:263, 275, 309`. Anyone who sees stage-9 proofs can execute the intent. The result is identical whoever submits it, but the submitter controls timing, and for Invoke can put its own instructions before or after in the same tx (AMM sandwich). Owners must encode slippage and limits inside the signed instruction data. This is not a fee-payer authority problem.

### 8. Info: an uploader can close its own proofs before execute
- `programs/seal-wallet/src/lib.rs:438-457`. A malicious relayer can let its proofs reach stage 9 and then `close` them, taking the rent back. This is documented ("may abandon or close its own upload"). Owner approvals are not consumed, so another relayer can re-upload the same signature under its own uploader key (the PDA includes `uploader`). There is no wallet impact.

### 9. Info: re-funding a closed proof in the same tx bricks only that uploader's PDA
- `programs/seal-wallet/src/lib.rs:453-456`. After `close`, the account still belongs to the program, with zeroed data, until the tx ends. If the same tx transfers lamports back into it, it survives as a zeroed, program-owned account. `load_proof` then fails (bad magic) and `begin` fails (owner is not System), so that `(wallet, digest, index, uploader)` address is permanently unusable. Only the uploader's own tx can do this, and a different uploader key gets around it.
- **Fix (optional hardening):** on close, also `realloc(0)` and assign the account to the System program, the standard close pattern.

### 10. Info: the `locked` flag cannot trigger
- `programs/seal-wallet/src/lib.rs:413-425`. Solana forbids indirect reentrancy (A→B→A gives `ReentrancyNotAllowed`), and a failed CPI rolls back the whole tx, including `locked = true` and the bumped nonce, so the lock can never stay set (the localnet test confirms this, `tests/localnet.mjs:384`). Saving the bumped nonce before the CPI and restoring the in-memory copy afterwards is correct: the callee cannot change the wallet's data (it is owned by this program), and it cannot change the wallet's lamports (the wallet is read-only in the CPI). Keep the lock as defense in depth.

### 11. Info: test gaps
The program crate has no Rust unit tests. `tests/localnet.mjs` covers the main rejections. It lacks these on-chain negative cases, which I reviewed manually and believe are safe:
a proof belonging to wallet B passed for wallet A; a guardian proof on a Transfer; two uploaders' proofs for the same owner index (expected: `DuplicateApproval`); a proof account passed as the Transfer target or as an Invoke meta; a non-executable callee; a wallet meta marked writable; append from a non-uploader; `step` after stage 9. Adding these before mainnet would turn the manual review into regression tests.

---

## Checked and found safe (one line each)

**Authority / quorum**
- Fee payer or uploader authority: none of `begin`/`append`/`seal`/`step`/`close` can write the wallet. `execute` authority comes only from stage-9 proofs whose key equals `policy.key(index)` for the current epoch (`wallet-core:388-428`).
- Quorum: distinct indices via a bitmask, `index < owners.count`, and duplicate keys are impossible (`Owners::validate`). A guardian proof (index 255) gets `Threshold` on any non-recovery action, and owner proofs cannot propose recovery.
- Proof substitution: `load_proof` checks the owner, the exact size, the magic and the PDA re-derived from stored seeds. `execute` also binds `h.wallet`, epoch, nonce, expiry and digest to the decoded intent.

**Replay**
- Replay: the digest covers program, wallet, genesis, epoch, nonce and expiry. The nonce is bumped before the action and saved atomically. Stage-9 proofs left behind after execute are stale forever, because the nonce and epoch only increase and the wallet can never be closed (Transfer keeps its rent reserve and nothing else debits it).
- Cross-cluster: `genesis` is not checked on-chain against the real cluster, but `wallet_id` commits to it. A wallet that exists on two clusters therefore has two different addresses, and `intent.wallet` binds the address. The SDK also checks the RPC genesis.

**Staged verification**
- State machine: stage 0→1 only after exactly 7,856 bytes, appends only at `offset == uploaded` and only in stage 0, stages 1..=8 each do real verification work, stage 9 is reached only through the final `advance` that compares the root, and `Progress` lives only in program-owned data. Every step re-checks liveness and the active key.
- slh-verify vs FIPS 205 (128s): H_msg = MGF1-SHA256(R‖seed‖SHA256(R‖PK‖0‖|ctx|‖ctx‖M)) truncated to 30 bytes. md, idx_tree (54 bits) and idx_leaf (9 bits) are split correctly. ADRSc is 22 bytes. FORS leaf index is i·4096+idx, and the parent's left/right bit matches. FORS_ROOTS uses type 4. The WOTS checksum and base-16 digits are right, with the shift by 4 folded in. The chain runs from msg_i to 14. XMSS keypair is cleared to 0. Each layer's tree/leaf derivation is correct and `advance` bounds-checks tree bits for every layer. All slice indices come from the fixed `SIGNATURE_BYTES`.

**Accounts and lamports**
- PDA collisions: "wallet"+id (39 bytes with bump) and "proof"+… (103 bytes) cannot collide. Canonical bumps are stored.
- Init front-running or pre-funding: the address commits to the exact policy, and the top-up+allocate+assign path tolerates dust. `payer != target` is checked.
- Duplicate accounts: Transfer target ≠ wallet and ≠ any proof. The `remaining` count is exact. Close checks proof ≠ uploader. Signer and writable checks are present where needed. Builtins and sysvars as writable targets are demoted by the runtime.
- Invoke: the callee must be executable and ≠ this program. Metas match exactly, contain no proofs, and are deduplicated. The signer flag is allowed only for the wallet, which must be read-only. Signer seeds sign only the wallet PDA.
- Arithmetic: `overflow-checks = true` in release. Nonce, epoch and recovery-slot additions are checked. Lamport math is checked.

**Recovery**
- Recovery: guardian only, delayed, vetoed by owner Cancel or Rotate (Rotate always clears pending recovery). `finalize` keeps the guardian and delay, bumps epoch and nonce, and new owners are validated to exclude the guardian.

## Resolution (applied before the first public deployment)

| # | Status | Change |
|---|---|---|
| 1 | Fixed | Wallets whose committed genesis is mainnet-beta need a recovery delay of at least 216,000 slots (~1 day) at creation and rotation (`Policy::validate_for`). The SDK refuses shorter mainnet delays when creating a descriptor. Test clusters keep the 150-slot floor. |
| 2 | Fixed | A guardian recovery proposal no longer advances the wallet nonce, so it cannot invalidate owner approvals. Replay stays impossible: a second proposal is refused while one is pending, and cancellation or finalization advances the nonce. Covered by the localnet assertion "a guardian proposal does not consume the owners nonce". |
| 3 | Fixed | `check_live` rejects approvals whose expiry is more than 216,000 slots ahead (`ExpiryTooFar`, code 7023), matching the SDK horizon. Covered by a Rust unit test and the localnet assertion "the program refuses approvals that expire beyond the horizon". |
| 4 | Accepted, mitigated in clients | CPI remains a deliberate, documented capability. The SDK transaction client and the browser extension only build the SPL `TransferChecked` shape. |
| Info | Tests added | On-chain rejection tests now cover a verified guardian approval that tries to spend (7011), a proof verified for another wallet (7013), and one owner approval uploaded by two uploaders (7012). |

The same release adds version-2 intents (a signed fee refund paid by the wallet to its fee
payer); see `docs/PROTOCOL.md`. Localnet tests cover the exact refund, a tampered refund
account, and the refund on the CPI path. This review was performed by an automated reviewer
with read access to the source; it is not an independent third-party audit.
