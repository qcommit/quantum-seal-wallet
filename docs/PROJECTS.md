# Separate projects

`quantum-seal-wallet` is the open-source core: Solana program, SLH-DSA verifier,
wallet protocol, Node SDK/CLI, tests and technical documentation. It must remain
usable without a website, hosted account, browser extension or developer-operated
signing service. Wallet creation and transaction execution are the MVP.

`../quantum-seal-website` is a separate local project with its own Git repository,
static assets and publication decision. Website source must not be included in
the core release archive or npm package. It may explain the protocol and link to
a verified core release; it must not collect secret keys or claim a live deployment
that has not been verified.

`../quantum-seal-extension` is the browser extension: a send/receive/hold wallet built
on this SDK, working on devnet with its own security review and end-to-end tests, not
yet in the Chrome Web Store. The extension must keep secret-key operations
out of page scripts and expose a tightly reviewed request interface. Arbitrary
Solana `signTransaction` compatibility must not be advertised: PQ wallet approvals
are canonical program intents, not Ed25519 transaction signatures.

## PaperFills reference

The publicly accessible repository found during research was
https://github.com/PatanL/paperfills-privacy . Its privacy page describes a local
paper-trading extension, narrow permissions, no developer analytics backend, and
no wallet-key or real-order handling. These are product-separation and disclosure
references, not reusable custody or signing code.

The actual PaperFills website/extension source repository was not available in
this session. No website/extension source was copied or claimed to have been
reviewed. The public privacy repository does not establish a license for unrelated
code. Do not reuse its page-context trading hooks or unencrypted ledger storage
for a wallet that handles real keys. Use an exact repository URL and license review
before a later source-level comparison.
