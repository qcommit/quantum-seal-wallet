# Contributing

Use synthetic keys and local-validator funds. Do not attach a keystore, a seed,
a browser profile, or a real-wallet transaction to an issue.

Read [PROTOCOL.md](docs/PROTOCOL.md) before changing serialization or account
state. `seal-slh-verify` is deliberately verify-only and depends on a minimal
hash interface. Keep secret-key operations out of the on-chain crate.

Run `npm ci --ignore-scripts`, `npm test`, `cargo fmt --all -- --check`,
`cargo clippy --locked --workspace --all-targets -- -D warnings`, and
`cargo test --locked --release --workspace`. Changes to the program, transcript
or SDK instruction builders also require the isolated local-validator suite in
[DEVELOPMENT.md](docs/DEVELOPMENT.md).

Add an adversarial test for each authorization change. A positive transfer test
alone does not demonstrate replay resistance, account binding or atomicity.
Do not weaken a test or add a skip to make an unsupported environment pass.
Keep benchmark raw samples and the exact environment next to summaries.

Use factual commit messages. Comments should explain an invariant or a design
constraint, not restate the code. Dependency updates require lockfile changes,
vector tests and cross-implementation verification.
