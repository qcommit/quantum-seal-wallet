#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { Keypair } from '@solana/web3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { GENESIS, parseNetwork, openNetwork } from './network.mjs';
import { hex } from './codec.mjs';
import { integerAmount } from './transport.mjs';
import { parseStrictJson } from './strict-json.mjs';
import {
  createDescriptor,
  parseDescriptor,
  walletStatus,
  initializeWallet,
  prepareSolTransfer,
  prepareTokenTransfer,
  validateApprovals,
  executionCost,
  executeApprovals,
} from './wallet.mjs';

const HELP = `Quantum Seal Wallet — network tools

  network-config --cluster mainnet-beta --program BASE58 --binary wallet.so --out mainnet.network.json
                 RPC is read from QS_RPC_URL; localnet also requires --genesis BASE58.
  create         --config network.json --owner PUBLIC_KEY_HEX --out wallet.json
  check-network  --config network.json
  status         --config network.json --wallet wallet.json
  initialize     --config network.json --wallet wallet.json --payer FEE_PAYER_PUBLIC_KEY
  prepare-sol    --config network.json --wallet wallet.json --to BASE58 --amount 0.01 --out intent.bin
  prepare-token  --config network.json --wallet wallet.json --source TOKEN_ACCOUNT --mint BASE58
                 --destination TOKEN_ACCOUNT --amount 1.25 --out intent.bin
  execute        --config network.json --wallet wallet.json --proof approval.json [--proof second.json]
                 --payer FEE_PAYER_PUBLIC_KEY

initialize and execute PLAN by default. To submit, additionally provide:
  --broadcast --fee-payer PATH --receipt receipt.jsonl
Mainnet additionally requires --acknowledge-unaudited and interactive confirmation.
Optional: --max-fee-lamports 100000 --compute-unit-price 0
No automatic program deployment, funding, fallback signer, or new-blockhash retry.
Use sdk/src/cli.mjs for offline keygen, inspect, sign, and independent proof checks.
`;
const json = (value) =>
  JSON.stringify(value, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2) + '\n';
async function read(path, limit, text = true, privateFile = false) {
  if (!path) throw new Error('Required input path is missing.');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await file.stat();
    if (
      !info.isFile() ||
      info.size > limit ||
      (privateFile && process.platform !== 'win32' && info.mode & 0o077)
    )
      throw new Error('Input must be a bounded regular file; fee-payer files require mode 0600.');
    const bytes = Buffer.alloc(limit + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const n = (await file.read(bytes, offset, bytes.length - offset, null)).bytesRead;
      if (!n) break;
      offset += n;
    }
    if (offset > limit) throw new Error('Input grew beyond its size limit.');
    const result = bytes.subarray(0, offset);
    return text ? new TextDecoder('utf-8', { fatal: true }).decode(result) : result;
  } finally {
    await file.close();
  }
}
async function write(path, value) {
  if (!path) throw new Error('--out is required.');
  const file = await open(path, 'wx', 0o600);
  try {
    await file.writeFile(value);
    await file.sync();
  } finally {
    await file.close();
  }
}
function required(values, names) {
  for (const name of names) if (!values[name]) throw new Error(`--${name} is required.`);
}
async function confirmation(network, wallet, verb, values) {
  if (!process.stdin.isTTY || !process.stderr.isTTY)
    throw new Error('Network broadcasts require an interactive terminal.');
  if (network.cluster === 'mainnet-beta' && !values['acknowledge-unaudited'])
    throw new Error('Mainnet broadcast requires --acknowledge-unaudited.');
  const phrase = `${verb} ${network.cluster} ${wallet}`;
  console.error(
    'Unaudited software. Real funds may be lost. Review the complete action and fee/rent budget above.',
  );
  const reader = createInterface({ input: process.stdin, output: process.stderr });
  try {
    if ((await reader.question(`Type ${phrase} to broadcast: `)) !== phrase)
      throw new Error('Cancelled. Nothing submitted.');
  } finally {
    reader.close();
  }
}
async function payer(path, expected) {
  const secret = parseStrictJson(await read(path, 4096, true, true), 4096);
  if (
    !Array.isArray(secret) ||
    secret.length !== 64 ||
    secret.some((n) => !Number.isInteger(n) || n < 0 || n > 255)
  )
    throw new Error('Fee payer must be an explicitly supplied Solana keypair JSON.');
  const bytes = Uint8Array.from(secret);
  secret.fill(0);
  try {
    const key = await Keypair.fromSecretKey(bytes);
    if (key.publicKey.toBase58() !== expected)
      throw new Error('Fee-payer key does not match the reviewed public key.');
    return key;
  } finally {
    bytes.fill(0);
  }
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (!command || ['--help', 'help', '-h'].includes(command)) {
    console.log(HELP);
    return;
  }
  const table = {
    'network-config': ['cluster', 'program', 'binary', 'out', 'genesis', 'upgrade-authority'],
    create: ['config', 'owner', 'policy', 'out'],
    'check-network': ['config'],
    status: ['config', 'wallet'],
    initialize: [
      'config',
      'wallet',
      'payer',
      'fee-payer',
      'receipt',
      'broadcast',
      'acknowledge-unaudited',
      'max-fee-lamports',
      'compute-unit-price',
    ],
    'prepare-sol': ['config', 'wallet', 'to', 'amount', 'out', 'expires-in-slots'],
    'prepare-token': [
      'config',
      'wallet',
      'source',
      'mint',
      'destination',
      'amount',
      'out',
      'expires-in-slots',
    ],
    execute: [
      'config',
      'wallet',
      'proof',
      'payer',
      'fee-payer',
      'receipt',
      'broadcast',
      'acknowledge-unaudited',
      'max-fee-lamports',
      'compute-unit-price',
    ],
  };
  const allowed = table[command];
  if (!allowed) throw new Error(`Unknown command: ${command}`);
  const { values, tokens } = parseArgs({
    args,
    tokens: true,
    options: Object.fromEntries(
      allowed.map((key) => [
        key,
        ['broadcast', 'acknowledge-unaudited'].includes(key)
          ? { type: 'boolean' }
          : key === 'proof'
            ? { type: 'string', multiple: true }
            : { type: 'string' },
      ]),
    ),
  });
  const names = tokens.filter((t) => t.kind === 'option' && t.name !== 'proof').map((t) => t.name);
  if (new Set(names).size !== names.length) throw new Error('Repeated options are not allowed.');
  if (command === 'network-config') {
    required(values, ['cluster', 'program', 'binary', 'out']);
    if (!process.env.QS_RPC_URL)
      throw new Error('Set QS_RPC_URL explicitly. No default RPC is inferred.');
    const binary = await read(values.binary, 10485760, false);
    const config = parseNetwork({
      format: 'quantum-seal/network/1',
      cluster: values.cluster,
      rpc: process.env.QS_RPC_URL,
      genesis: GENESIS[values.cluster] ?? values.genesis,
      program: values.program,
      programSize: binary.length,
      programSha256: hex(sha256(binary)),
      upgradeAuthority: values['upgrade-authority'] ?? null,
    });
    await write(values.out, json(config));
    console.log(
      'Network configuration written. No deployment was performed or verified. Run check-network before use.',
    );
    return;
  }
  required(values, ['config']);
  const config = parseNetwork(await read(values.config, 8192));
  if (command === 'create') {
    required(values, ['out']);
    if (!!values.owner === !!values.policy)
      throw new Error('Choose exactly one of --owner or --policy.');
    const policy = values.policy
      ? parseStrictJson(await read(values.policy, 4096), 4096)
      : { keys: [values.owner], threshold: 1 };
    const descriptor = await createDescriptor({
      program: config.program,
      genesis: config.genesis,
      policy,
    });
    await write(values.out, json(descriptor));
    console.log(
      json({
        wallet: descriptor.wallet,
        initialized: false,
        message:
          'Public descriptor saved. Initialize and verify on-chain ownership before depositing.',
      }),
    );
    return;
  }
  const network = await openNetwork(config);
  if (command === 'check-network') {
    const { connection, ...report } = network;
    console.log(json(report));
    return;
  }
  required(values, ['wallet']);
  const descriptor = await parseDescriptor(await read(values.wallet, 8192));
  if (command === 'status') {
    const s = await walletStatus(network, descriptor);
    console.log(
      json({
        cluster: network.cluster,
        wallet: descriptor.wallet,
        initialized: s.initialized,
        balanceLamports: s.balanceLamports,
        reserveLamports: s.reserveLamports,
        availableLamports: s.availableLamports,
        epoch: s.state?.epoch ?? null,
        nonce: s.state?.nonce ?? null,
        threshold: s.state?.policy.threshold ?? null,
        ownerKeys: s.state?.policy.keys.map(hex) ?? [],
        recoveryReadyAt: s.state?.recoveryReadyAt ?? null,
      }),
    );
    return;
  }
  if (command.startsWith('prepare-')) {
    required(
      values,
      command === 'prepare-sol'
        ? ['to', 'amount', 'out']
        : ['source', 'mint', 'destination', 'amount', 'out'],
    );
    const args = { ...values, expiresInSlots: values['expires-in-slots'] };
    const result =
      command === 'prepare-sol'
        ? await prepareSolTransfer(network, descriptor, args)
        : await prepareTokenTransfer(network, descriptor, args);
    await write(values.out, result.bytes);
    console.log(result.summary);
    console.log('Unsigned intent saved. Review and sign offline; nothing submitted.');
    return;
  }
  required(values, ['payer']);
  const options = {
    maxFeeLamports: integerAmount(values['max-fee-lamports'] ?? 100000n),
    computeUnitPrice: integerAmount(values['compute-unit-price'] ?? 0n),
  };
  let approvals, plan;
  if (command === 'execute') {
    required(values, ['proof']);
    approvals = await Promise.all(values.proof.map((path) => read(path, 32768)));
    const ready = await validateApprovals(network, descriptor, approvals);
    console.log(ready.summary);
    plan = await executionCost(network, approvals.length, options.maxFeeLamports);
  } else {
    const current = await walletStatus(network, descriptor);
    plan = {
      initialized: current.initialized,
      topUpLamports: current.initialized
        ? 0n
        : current.reserveLamports > current.balanceLamports
          ? current.reserveLamports - current.balanceLamports
          : 0n,
      maxFeeLamports: options.maxFeeLamports,
    };
  }
  console.log(
    json({
      cluster: network.cluster,
      program: network.program,
      wallet: descriptor.wallet,
      feePayer: values.payer,
      plan,
    }),
  );
  if (!values.broadcast) {
    console.log('PLAN ONLY. No fee-payer key was loaded and no transaction was submitted.');
    return;
  }
  required(values, ['fee-payer', 'receipt']);
  await confirmation(
    network,
    descriptor.wallet,
    command === 'execute' ? 'SEND' : 'INITIALIZE',
    values,
  );
  const key = await payer(values['fee-payer'], values.payer);
  const journal = await open(values.receipt, 'wx', 0o600);
  options.onRecord = async (record) => {
    await journal.writeFile(
      JSON.stringify(record, (_, v) => (typeof v === 'bigint' ? v.toString() : v)) + '\n',
    );
    await journal.sync();
  };
  try {
    const result =
      command === 'execute'
        ? await executeApprovals(network, key, descriptor, approvals, options)
        : await initializeWallet(network, key, descriptor, options);
    console.log(json(result));
  } finally {
    await journal.close();
  }
}
main().catch((error) => {
  console.error(`ERROR: ${error.message}`);
  process.exitCode = 1;
});
