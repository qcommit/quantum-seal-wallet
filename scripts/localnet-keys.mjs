import { Keypair, PublicKey } from '@solana/web3.js';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
if (process.env.QS_ISOLATED_LOCALNET !== '1') throw new Error('Local test container required.');
const program = await Keypair.fromSecretKey(
  Uint8Array.from(JSON.parse(readFileSync('target/deploy/seal_wallet-keypair.json'))),
);
writeFileSync('.runtime/program-id.txt', program.publicKey.toBase58() + '\n');
if (!existsSync('.runtime/relayer.keypair.json')) {
  const payer = await Keypair.generate();
  writeFileSync(
    '.runtime/relayer.keypair.json',
    JSON.stringify(Array.from(await payer.secretKey)),
    { flag: 'wx', mode: 0o600 },
  );
}
const payer = await Keypair.fromSecretKey(
  Uint8Array.from(JSON.parse(readFileSync('.runtime/relayer.keypair.json'))),
);
writeFileSync('.runtime/relayer-address.txt', payer.publicKey.toBase58() + '\n');

// Write immutable loader-v3 accounts directly into the isolated test genesis.
const loader = new PublicKey('BPFLoaderUpgradeab1e11111111111111111111111');
const [programData] = await PublicKey.findProgramAddress([program.publicKey.toBytes()], loader);
const code = readFileSync('target/deploy/seal_wallet.so');
const programHeader = Buffer.alloc(36);
programHeader.writeUInt32LE(2, 0);
programHeader.set(programData.toBytes(), 4);
const dataHeader = Buffer.alloc(45);
dataHeader.writeUInt32LE(3, 0);
// Option<Pubkey>::None at byte 12; the binary begins at the fixed 45-byte offset.
function genesisAccount(key, data, executable, path) {
  writeFileSync(
    path,
    JSON.stringify({
      pubkey: key.toBase58(),
      account: {
        lamports: 10000000000,
        data: [data.toString('base64'), 'base64'],
        owner: loader.toBase58(),
        executable,
        rentEpoch: 0,
        space: data.length,
      },
    }),
  );
}
genesisAccount(program.publicKey, programHeader, true, '.runtime/genesis-program.json');
genesisAccount(
  programData,
  Buffer.concat([dataHeader, code]),
  false,
  '.runtime/genesis-program-data.json',
);
writeFileSync('.runtime/program-data-id.txt', programData.toBase58() + '\n');
