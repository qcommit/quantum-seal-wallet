import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  generateKeypair,
  signApproval,
  verifyApproval,
  parseApproval,
  encryptKey,
  decryptKey,
} from '../src/crypto.mjs';
import { fromHex } from '../src/codec.mjs';
const sample = JSON.parse(
  readFileSync(new URL('../../fixtures/sdk-approval.json', import.meta.url), 'utf8'),
);

test('published SDK fixture verifies only against a separately trusted key', () => {
  assert.equal(verifyApproval(sample, { expectedKey: sample.publicKey }).valid, true);
  assert.throws(() => verifyApproval(sample));
  assert.equal(verifyApproval(sample, { expectedKey: new Uint8Array(32) }).valid, false);
});
test('altered signature and intent are rejected', () => {
  const signature = Buffer.from(sample.signature, 'base64');
  signature[17] ^= 1;
  assert.equal(
    verifyApproval(
      { ...sample, signature: signature.toString('base64') },
      { expectedKey: sample.publicKey },
    ).valid,
    false,
  );
  const intent = fromHex(sample.intent);
  intent[150] ^= 1;
  assert.equal(
    verifyApproval(
      { ...sample, intent: Buffer.from(intent).toString('hex') },
      { expectedKey: sample.publicKey },
    ).valid,
    false,
  );
});
test('approval schema rejects unknown fields, duplicate fields and noncanonical encodings', () => {
  assert.throws(() => parseApproval({ ...sample, extra: true }));
  assert.throws(() => parseApproval(JSON.stringify(sample).replace('{', '{"index":0,')));
  assert.throws(() => parseApproval({ ...sample, publicKey: sample.publicKey.toUpperCase() }));
  assert.throws(() => parseApproval({ ...sample, signature: sample.signature + '\n' }));
});
test('one stateless key signs repeated messages with distinct randomized signatures', () => {
  const key = generateKeypair();
  try {
    const one = signApproval(fromHex(sample.intent), key.secretKey),
      two = signApproval(fromHex(sample.intent), key.secretKey);
    assert.notEqual(one.signature, two.signature);
    assert.equal(verifyApproval(one, { expectedKey: key.publicKey }).valid, true);
    assert.equal(verifyApproval(two, { expectedKey: key.publicKey }).valid, true);
  } finally {
    key.secretKey.fill(0);
  }
});
test('encrypted keystore round trips and rejects wrong passphrases or tampering', async () => {
  const key = generateKeypair(),
    password = 'correct example test passphrase';
  try {
    const store = await encryptKey(key.secretKey, password),
      recovered = await decryptKey(store, password);
    assert.deepEqual(recovered, key.secretKey);
    recovered.fill(0);
    await assert.rejects(decryptKey(store, 'incorrect example passphrase'));
    for (const field of ['publicKey', 'salt', 'iv', 'ciphertext', 'tag']) {
      const altered = {
        ...store,
        [field]: (store[field][0] === '0' ? '1' : '0') + store[field].slice(1),
      };
      await assert.rejects(decryptKey(altered, password));
    }
    await assert.rejects(encryptKey(key.secretKey, 'short'));
    await assert.rejects(decryptKey({ ...store, kdf: 'scrypt-N1-r8-p1' }, password));
  } finally {
    key.secretKey.fill(0);
  }
});
