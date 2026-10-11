# Mainnet launch checklist

Everything before step 3 is done and recorded in this repository. Steps 3–7 are the
manual deployment and the follow-up edits in the extension and website.

## 1. Reviewed, reproducible build (done)

- Release `v0.1.0`, `seal_wallet.so`, 141,744 bytes,
  SHA-256 `4fbf18f66470322941b907adf03ebcd995385d35ac8c7ae4e3aa5ef63dd7a049`.
- Rebuild from a clean clone and compare before deploying:

```sh
git checkout v0.1.0 && bash scripts/build-sbf.sh && sha256sum target/deploy/seal_wallet.so
```

## 2. Rehearsed on devnet (done)

- Upgradeable copy `6LBRd57jagVvhmpX1idsw9QXhoNHMHWstvpeGdSZAexT` and an immutable copy
  `2o7mAz2WBJhtmTHBbddRrLF3oc7UN2G5fxHpnzyhqjhq` (the mainnet configuration) both ran
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
solana program deploy target/deploy/seal_wallet.so \
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
  --binary target/deploy/seal_wallet.so --out mainnet.network.json
node sdk/src/network-cli.mjs check-network --config mainnet.network.json
```

`check-network` must report the release hash and `"immutable": true`.

## 6. Pin it in the extension

```sh
cd ../quantum-seal-extension
node scripts/pin-deployment.mjs --cluster mainnet-beta --program <PROGRAM_ID> \
  --binary ../quantum-seal-wallet/target/deploy/seal_wallet.so
npm run build && npm test && npm run e2e
```

The script re-verifies the deployment on-chain before it writes the pins.

## 7. Flip the website to the live state

In `quantum-seal-website/public/site.config.mjs`, set `programId` to the program address
and redeploy the site (`vercel deploy --prod --yes`). The "Live on Solana mainnet" badge
and explorer link appear; no page copy changes.
