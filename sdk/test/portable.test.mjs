import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { encryptKey as nodeEncrypt, decryptKey as nodeDecrypt } from '../src/crypto.mjs';
import { encryptKey, decryptKey, FEE_KEY_ALGORITHM } from '../src/keystore-web.mjs';
import {
  toBase64,
  fromBase64,
  constantTimeEqual,
  generateKeypair,
  verifyApproval,
} from '../src/approval.mjs';

const sample = JSON.parse(
  readFileSync(new URL('../../fixtures/sdk-approval.json', import.meta.url), 'utf8'),
);
const password = 'correct horse battery staple';

test('portable base64 matches Node for every length and rejects noncanonical input', () => {
  for (let n = 0; n < 70; n++) {
    const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 255);
    const text = Buffer.from(bytes).toString('base64');
    assert.equal(toBase64(bytes), text);
    assert.deepEqual(fromBase64(text, n), bytes);
  }
  assert.throws(() => fromBase64('AB==', 1));
  assert.throws(() => fromBase64('A*==', 1));
});
test('constant-time comparison handles length and content differences', () => {
  assert.equal(constantTimeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2)), true);
  assert.equal(constantTimeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 3)), false);
  assert.equal(constantTimeEqual(Uint8Array.of(1), Uint8Array.of(1, 2)), false);
});
test('the published fixture verifies through the portable module', () => {
  assert.equal(verifyApproval(sample, { expectedKey: sample.publicKey }).valid, true);
});
test('browser and Node keystores are byte-compatible in both directions', async () => {
  const { secretKey, publicKey } = generateKeypair();
  const fromWeb = await encryptKey(secretKey, password);
  assert.deepEqual(await nodeDecrypt(fromWeb, password), secretKey);
  const fromNode = await nodeEncrypt(secretKey, password);
  assert.deepEqual(await decryptKey(fromNode, password), secretKey);
  assert.equal(fromWeb.publicKey, Buffer.from(publicKey).toString('hex'));
  await assert.rejects(decryptKey(fromWeb, password + '!'));
  await assert.rejects(
    decryptKey({ ...fromWeb, publicKey: fromNode.publicKey.replace(/^../, '00') }, password),
  );
});
test('fee-key keystores are bound to their algorithm label', async () => {
  const secret = Uint8Array.from({ length: 64 }, (_, i) => i + 1);
  const sealed = await encryptKey(secret, password, FEE_KEY_ALGORITHM);
  assert.equal(sealed.algorithm, 'Ed25519');
  assert.deepEqual(await decryptKey(sealed, password, FEE_KEY_ALGORITHM), secret);
  await assert.rejects(decryptKey(sealed, password));
  await assert.rejects(decryptKey({ ...sealed, algorithm: 'SLH-DSA-SHA2-128s' }, password));
  await assert.rejects(encryptKey(secret, 'short'));
});
