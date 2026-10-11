# Security policy

**Research software. No independent security audit. No production deployment is
supported. Do not deposit real assets into addresses created by this prototype.**

The NIST-standardized primitive is not the same thing as a NIST-validated
cryptographic module. Published-vector tests and successful local transactions
are evidence of specific behavior, not a certification or proof of safety.

## What is protected

The program requires SLH-DSA-SHA2-128s authorizations against its current owner
policy before transfers, policy rotation or arbitrary permitted CPI. A recovery
guardian can propose delayed owner replacement, not directly transfer assets.
A conventional relayer key pays fees and owns temporary proof rent; it is not a
wallet spending key. Its compromise can disrupt uploads or steal its own funds.

## Remaining trust

An upgrade authority able to replace the wallet program bypasses its signature
checks. A production release would need an explicitly reviewed deployment and
upgrade policy; making a program immutable is irreversible and is not performed
by these scripts. Solana consensus, validators, RPCs, external programs and
bridges remain outside this project's post-quantum authorization boundary.
A signed call into an upgradeable or malicious external program can still lose
assets. No generic CPI allowlist or token-extension safety policy is implemented.

The guardian is a delayed alternative authority. A compromised guardian can
recover the wallet if owners fail to veto in time. Slot delays are not wall-clock
SLAs. Monitoring, cancellation races and disaster recovery require further review.

## Key handling

New CLI keystores use scrypt (N=131072, r=8, p=1) and AES-256-GCM, a random 32-byte
salt and 12-byte nonce, authenticated format metadata and a public-key binding.
Files are created exclusively with mode 0600. A minimum passphrase length is
not an entropy guarantee. Back up the encrypted file and public descriptor.

JavaScript does not provide guaranteed secret zeroization. Best-effort byte-array
clearing cannot erase immutable strings, garbage-collected copies, swap, core
dumps, debugger access or a compromised operating system. This is not a hardware
wallet, encrypted recovery-service integration, or BIP-39 seed implementation.
Do not run it on a machine used to hold valuable production keys.

## Reporting

Before public launch the maintainer must configure a private vulnerability
reporting channel. After GitHub private vulnerability reporting is enabled, use
the repository Security tab. Until then, do not publish exploit details or
funded-wallet material in public issues; contact the repository maintainer through
an established private channel. There is no funded bug bounty or response SLA.

See [THREAT_MODEL.md](docs/THREAT_MODEL.md) and the release blockers in
[RELEASE.md](docs/RELEASE.md).
