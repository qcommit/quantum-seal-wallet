# Mainnet launch checklist

Everything before step 3 is done and recorded in this repository. Steps 3–7 are the
manual deployment and the follow-up edits in the extension and website.

## 1. Reviewed, reproducible build (done)

- Release `v0.1.1`, canonical `seal_wallet.so` (built on Linux x86_64), 141,744 bytes,
  SHA-256 `c53d5da22ae1b2d2d7be9d568a646db79b8ee6a0e1e1bb4cd33735602ed96bc0`, also recorded in
  `PROGRAM_SHA256` and re-checked by the *Reproducible program build* workflow.
- Do not deploy a binary built on an ARM64 machine (including the Spark): it is valid but
  has a different hash (`4fbf18f6…`), so third parties building on x86_64 could not match it.
- Download the release asset and check it before deploying:

```sh
gh release download v0.1.1 -R qcommit/quantum-seal-wallet -p seal_wallet.so
sha256sum --check PROGRAM_SHA256
```

## 2. Rehearsed on devnet (done)

- Upgradeable copy `6LBRd57jagVvhmpX1idsw9QXhoNHMHWstvpeGdSZAexT` and an immutable copy
  `9roN31b3XtdWLeuVYer6W9WkXR64hPNHu8F382jBStqi` (the mainnet configuration), both the
  canonical binary, ran
  real create → SOL → SPL flows; see `evidence/devnet-rehearsal*.json`.
- The browser extension created, set up and sent on devnet in its own smoke test.

## 3. Decide before deploying

- **Deployment key.** A fresh key used only for this deployment; it becomes irrelevant once
  the program is immutable. Do not use `~/.config/solana/id.json` by accident: pass
  `--keypair` explicitly.
- **Program address.** Generate a dedicated program keypair (`solana-keygen new`), keep it
  until the deployment completes, then it is no longer needed.
- **Budget.** About 0.99 SOL of program rent, plus about the same held in the upload
  buffer during deployment and returned when it completes, plus fees. Fund ~2.1 SOL.
- **Dependencies.** Open Dependabot PRs that touch `solana-program`,
  `solana-system-interface` or `sha2` change the program bytes. Merge them *before* the
  release you deploy, or not until the next program version.

## 4. Deploy and make immutable

```sh
solana program deploy seal_wallet.so \
  --program-id program-keypair.json --keypair deployer.json \
  --url https://api.mainnet-beta.solana.com --with-compute-unit-price 1000
solana program set-upgrade-authority <PROGRAM_ID> --final \
  --keypair deployer.json --url https://api.mainnet-beta.solana.com
solana program show <PROGRAM_ID> --url https://api.mainnet-beta.solana.com   # Authority: none
```

Making the program immutable is irreversible and is required: the mainnet client
refuses any program that still has an upgrade authority.

## 5. Verify like a user's client would

```sh
export QS_RPC_URL=https://api.mainnet-beta.solana.com
node sdk/src/network-cli.mjs network-config --cluster mainnet-beta --program <PROGRAM_ID> \
  --binary seal_wallet.so --out mainnet.network.json
node sdk/src/network-cli.mjs check-network --config mainnet.network.json
```

`check-network` must report the release hash and `"immutable": true`.

## 6. Pin it in the extension

```sh
cd ../quantum-seal-extension
node scripts/pin-deployment.mjs --cluster mainnet-beta --program <PROGRAM_ID> \
  --binary /path/to/release/seal_wallet.so
npm run build && npm test && npm run e2e
```

The script re-verifies the deployment on-chain before it writes the pins.

## 7. Flip the website to the live state

In `quantum-seal-website/public/site.config.mjs`, set `programId` to the program address
and redeploy the site (`vercel deploy --prod --yes`). The "Live on Solana mainnet" badge
and explorer link appear; no page copy changes.
