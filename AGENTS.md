# Development boundaries

This repository is independent of the existing Quantum Seal statement signer.
Use local-validator funds only. Never read existing wallet seeds, fund an account,
publish a repository, change upgrade authority, or deploy to a public cluster
without explicit approval. Keep generated keys and ledgers in .runtime/.

Cryptographic claims require reproducible tests. Do not call this audited,
FIPS-validated, production-ready, or quantum-secure end to end. Changes to the
signature transcript, state machine, or PDA seeds require protocol tests.

Run builds with bounded parallelism on the Spark. Do not use GPUs or stop other
users' processes. Keep shell scripts local, explicit, and fail-closed.
