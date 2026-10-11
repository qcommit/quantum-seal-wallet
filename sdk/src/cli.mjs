#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { open } from 'node:fs/promises';
import { StringDecoder } from 'node:string_decoder';
import { createInterface } from 'node:readline/promises';
import { randomBytes } from 'node:crypto';
import {
  generateKeypair,
  encryptKey,
  decryptKey,
  signApproval,
  verifyApproval,
  serializeApproval,
} from './crypto.mjs';
import { decodeIntent, displayIntent, hex, deriveWallet } from './codec.mjs';
import { parseStrictJson } from './strict-json.mjs';

const HELP = `Quantum Seal Wallet — offline research tools

  keygen --out owner.keystore.json
  descriptor --program BASE58 --genesis BASE58 --policy policy.json --out wallet.json
  sign --intent intent.bin --keystore owner.keystore.json --wallet BASE58 --program BASE58 --index 0 --out approval.json
  verify --proof approval.json --key TRUSTED_PUBLIC_KEY_HEX [--wallet BASE58] [--program BASE58]
  inspect --intent intent.bin

Signing requires an interactive terminal, a passphrase and explicit confirmation.
No command connects to a public blockchain. Never put passphrases in arguments.
The independent Rust verifier is: cargo run --release -p seal-verify -- --help
`;
async function bounded(path, limit, encoding) {
  if (!path) throw new Error('Required input path is missing.');
  const file = await open(path, 'r');
  try {
    const info = await file.stat();
    if (!info.isFile() || info.size > limit)
      throw new Error(`Input must be a regular file of at most ${limit} bytes.`);
    const bytes = Buffer.alloc(limit + 1);
    let total = 0;
    while (total < bytes.length) {
      const { bytesRead } = await file.read(bytes, total, bytes.length - total, null);
      if (!bytesRead) break;
      total += bytesRead;
    }
    if (total > limit) throw new Error('File grew beyond the input limit.');
    const result = bytes.subarray(0, total);
    return encoding
      ? new TextDecoder('utf-8', { fatal: true }).decode(result)
      : Uint8Array.from(result);
  } finally {
    await file.close();
  }
}
async function exclusive(path, text) {
  if (!path) throw new Error('--out is required.');
  const file = await open(path, 'wx', 0o600);
  try {
    await file.writeFile(text, 'utf8');
    await file.sync();
  } finally {
    await file.close();
  }
}
function password(prompt) {
  if (!process.stdin.isTTY || !process.stderr.isTTY)
    throw new Error('An interactive terminal is required for private-key operations.');
  return new Promise((resolve, reject) => {
    const chars = [],
      decoder = new StringDecoder('utf8');
    const oldRaw = process.stdin.isRaw;
    const done = (error) => {
      process.stdin.off('data', onData);
      process.stdin.setRawMode(!!oldRaw);
      process.stdin.pause();
      process.stderr.write('\n');
      if (error) reject(error);
      else resolve(chars.join(''));
      chars.fill('');
    };
    const onData = (chunk) => {
      for (const char of typeof chunk === 'string' ? chunk : decoder.write(chunk)) {
        if (char === '\u0003' || char === '\u0004') return done(new Error('Cancelled.'));
        if (char === '\r' || char === '\n') return done();
        if (char === '\u007f' || char === '\b') {
          chars.pop();
          continue;
        }
        if (char >= ' ' && chars.length < 1024) chars.push(char);
      }
    };
    // Disable terminal echo before making the prompt visible.
    process.stdin.setRawMode(true);
    process.stdin.on('data', onData);
    process.stdin.resume();
    process.stderr.write(prompt);
  });
}
function mandatory(values, names) {
  for (const name of names) if (!values[name]) throw new Error(`--${name} is required.`);
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (!command || ['help', '--help', '-h'].includes(command)) {
    process.stdout.write(HELP);
    return;
  }
  const allowed = {
    keygen: ['out'],
    descriptor: ['program', 'genesis', 'policy', 'out'],
    sign: ['intent', 'keystore', 'wallet', 'program', 'index', 'out'],
    verify: ['proof', 'key', 'wallet', 'program'],
    inspect: ['intent'],
  }[command];
  if (!allowed) throw new Error(`Unknown command: ${command}`);
  const { values, tokens } = parseArgs({
    args,
    options: Object.fromEntries(allowed.map((k) => [k, { type: 'string' }])),
    tokens: true,
  });
  const names = tokens.filter((t) => t.kind === 'option').map((t) => t.name);
  if (new Set(names).size !== names.length) throw new Error('Repeated options are not allowed.');
  if (command === 'keygen') {
    mandatory(values, ['out']);
    const first = await password('New passphrase: '),
      second = await password('Repeat passphrase: ');
    if (first !== second) throw new Error('Passphrases do not match.');
    const key = generateKeypair();
    try {
      const store = await encryptKey(key.secretKey, first);
      await exclusive(values.out, JSON.stringify(store, null, 2) + '\n');
      console.log(
        JSON.stringify(
          { algorithm: 'SLH-DSA-SHA2-128s', publicKey: hex(key.publicKey), keystore: values.out },
          null,
          2,
        ),
      );
    } finally {
      key.secretKey.fill(0);
    }
    return;
  }
  if (command === 'descriptor') {
    mandatory(values, ['program', 'genesis', 'policy', 'out']);
    const policy = parseStrictJson(await bounded(values.policy, 4096, 'utf8'), 4096);
    const known = ['keys', 'threshold', 'guardian', 'recoveryDelay'];
    if (Object.keys(policy).some((k) => !known.includes(k)))
      throw new Error('Unknown policy fields.');
    const salt = randomBytes(32),
      derived = await deriveWallet(values.program, values.genesis, salt, policy);
    const descriptor = {
      format: 'quantum-seal/wallet-descriptor/1',
      program: values.program,
      genesis: values.genesis,
      wallet: derived.wallet.toBase58(),
      id: hex(derived.id),
      salt: hex(salt),
      initialPolicy: policy,
    };
    await exclusive(values.out, JSON.stringify(descriptor, null, 2) + '\n');
    console.log(
      `Uninitialized wallet address: ${descriptor.wallet}\nInitialize and inspect the on-chain policy before making any deposit.`,
    );
    return;
  }
  if (command === 'inspect') {
    mandatory(values, ['intent']);
    console.log(displayIntent(decodeIntent(await bounded(values.intent, 850))));
    return;
  }
  if (command === 'verify') {
    mandatory(values, ['proof', 'key']);
    const result = verifyApproval(await bounded(values.proof, 32768, 'utf8'), {
      expectedKey: values.key,
      expectedWallet: values.wallet,
      expectedProgram: values.program,
    });
    console.log(
      JSON.stringify(
        result,
        (_, value) => (typeof value === 'bigint' ? value.toString() : value),
        2,
      ),
    );
    if (!result.valid) process.exitCode = 1;
    return;
  }
  mandatory(values, ['intent', 'keystore', 'wallet', 'program', 'index', 'out']);
  if (!['0', '1', '2', '255'].includes(values.index))
    throw new Error('Index must be 0, 1, 2 or 255.');
  const bytes = await bounded(values.intent, 850),
    intent = decodeIntent(bytes);
  if (intent.wallet.toBase58() !== values.wallet || intent.program.toBase58() !== values.program)
    throw new Error('Intent does not match the pinned wallet and program.');
  if (!process.stdin.isTTY) throw new Error('Interactive transaction review is required.');
  console.log(displayIntent(intent));
  console.log(
    'This tool cannot establish the current on-chain nonce, policy, or expiry. Review the genesis hash and all action fields.',
  );
  const reader = createInterface({ input: process.stdin, output: process.stderr });
  try {
    if ((await reader.question('Type SIGN to authorize exactly these bytes: ')) !== 'SIGN')
      throw new Error('Cancelled.');
  } finally {
    reader.close();
  }
  const store = await bounded(values.keystore, 4096, 'utf8'),
    passphrase = await password('Keystore passphrase: ');
  const secret = await decryptKey(store, passphrase);
  try {
    await exclusive(
      values.out,
      serializeApproval(signApproval(bytes, secret, Number(values.index))),
    );
  } finally {
    secret.fill(0);
  }
  console.log(`Approval written to ${values.out}. It has not been submitted or executed.`);
}
main().catch((error) => {
  console.error(`ERROR: ${error.message}`);
  process.exitCode = 1;
});
