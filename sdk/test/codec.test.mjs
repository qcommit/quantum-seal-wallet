import test from 'node:test';
import assert from 'node:assert/strict';
import { PublicKey, Connection, Keypair } from '@solana/web3.js';
import { readFileSync } from 'node:fs';
import {
  encodeIntent,
  decodeIntent,
  intentDigest,
  hex,
  fromHex,
  u64,
  encodePolicy,
  deriveWallet,
  deriveProof,
} from '../src/codec.mjs';
import { parseStrictJson } from '../src/strict-json.mjs';
import { requireLocalConnection } from '../src/client.mjs';
const key = (n) => new Uint8Array(32).fill(n);
const base = {
  genesis: new PublicKey(key(1)),
  program: new PublicKey(key(2)),
  wallet: new PublicKey(key(3)),
  epoch: 4n,
  nonce: 5n,
  expiry: 1000n,
  action: { kind: 'transfer', to: new PublicKey(key(4)), lamports: 123n },
};

test('binary intent is stable and round trips without JSON canonicalization', () => {
  const bytes = encodeIntent(base);
  assert.equal(bytes.length, 162);
  const decoded = decodeIntent(bytes);
  assert.equal(decoded.nonce, 5n);
  assert.equal(decoded.action.lamports, 123n);
  assert.deepEqual(encodeIntent(decoded), bytes);
});
test('truncation at every byte and trailing bytes are rejected', () => {
  const bytes = encodeIntent(base);
  for (let n = 0; n < bytes.length; n++) assert.throws(() => decodeIntent(bytes.slice(0, n)));
  assert.throws(() => decodeIntent(Uint8Array.from([...bytes, 0])));
});
test('every authorization field changes the intent digest', () => {
  const bytes = encodeIntent(base),
    original = hex(intentDigest(bytes));
  for (let i = 1; i < bytes.length; i++) {
    if (i === 121) continue;
    const changed = bytes.slice();
    changed[i] ^= 1;
    assert.notEqual(hex(intentDigest(changed)), original, `byte ${i}`);
  }
});
test('integer encoding rejects rounded numbers, negative values and noncanonical strings', () => {
  for (const n of [Number.MAX_SAFE_INTEGER + 1, -1n, 1n << 64n, '01', '-1', '1.0', NaN, null])
    assert.throws(() => u64(n));
  assert.equal(hex(u64('18446744073709551615')), 'ffffffffffffffff');
});
test('owner policies require distinct keys, a valid threshold and separate guardian', () => {
  const policy = { keys: [key(1), key(2)], threshold: 2, guardian: key(3), recoveryDelay: 150n };
  assert.equal(encodePolicy(policy).length, 138);
  for (const bad of [
    { ...policy, threshold: 3 },
    { ...policy, keys: [key(1), key(1)] },
    { ...policy, guardian: key(1) },
    { ...policy, recoveryDelay: 149n },
    { keys: [key(0)], threshold: 1 },
  ])
    assert.throws(() => encodePolicy(bad));
});
test('PDA initialization binds the original policy, salt, program and genesis', async () => {
  const p = { keys: [key(1)], threshold: 1 };
  const x = await deriveWallet(base.program, base.genesis, key(9), p);
  assert.equal(
    x.wallet.toBase58(),
    (await deriveWallet(base.program, base.genesis, key(9), p)).wallet.toBase58(),
  );
  for (const y of [
    await deriveWallet(base.program, base.genesis, key(8), p),
    await deriveWallet(base.program, base.genesis, key(9), { keys: [key(2)], threshold: 1 }),
    await deriveWallet(base.wallet, base.genesis, key(9), p),
  ])
    assert.notEqual(x.wallet.toBase58(), y.wallet.toBase58());
});
test('proof address binds uploader and signer index', async () => {
  const a = await deriveProof(base.program, base.wallet, key(6), 0, base.genesis);
  const b = await deriveProof(base.program, base.wallet, key(6), 1, base.genesis);
  const c = await deriveProof(base.program, base.wallet, key(6), 0, base.program);
  assert.notEqual(a.proof.toBase58(), b.proof.toBase58());
  assert.notEqual(a.proof.toBase58(), c.proof.toBase58());
});
test('CPI refuses undeclared signers, duplicate accounts and writable wallet delegation', () => {
  const good = {
    ...base,
    action: {
      kind: 'invoke',
      program: new PublicKey(key(6)),
      metas: [{ key: base.wallet, writable: false, signer: true }],
      data: new Uint8Array([1]),
    },
  };
  encodeIntent(good);
  for (const metas of [
    [{ key: base.wallet, writable: true, signer: true }],
    [{ key: base.genesis, writable: false, signer: true }],
    [
      { key: base.genesis, writable: false, signer: false },
      { key: base.genesis, writable: true, signer: false },
    ],
  ]) {
    assert.throws(() => encodeIntent({ ...good, action: { ...good.action, metas } }));
  }
  assert.throws(() => encodeIntent({ ...good, action: { ...good.action, program: base.program } }));
});
test('strict JSON rejects duplicate escaped keys, trailing tokens and deep objects', () => {
  for (const text of [
    '{"a":1,"a":2}',
    '{"a":1,"\\u0061":2}',
    '{"a":1}true',
    '['.repeat(14) + '0' + ']'.repeat(14),
    '{"x":1e999}',
  ])
    assert.throws(() => parseStrictJson(text));
  const object = parseStrictJson('{"__proto__":{"polluted":true}}');
  assert.equal(Object.getPrototypeOf(object), null);
  assert.equal({}.polluted, undefined);
});
test('local research client refuses public or ambiguous RPC hosts', () => {
  requireLocalConnection(new Connection('http://127.0.0.1:18899'));
  for (const url of [
    'https://api.mainnet-beta.solana.com',
    'http://localhost:8899',
    'http://127.0.0.1.example.com',
  ])
    assert.throws(() => requireLocalConnection(new Connection(url)));
});
