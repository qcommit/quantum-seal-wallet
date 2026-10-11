// Browser implementation of the quantum-seal/keystore/1 format (scrypt N=2^17, r=8,
// p=1 and AES-256-GCM), byte-compatible with crypto.mjs so backups move between the
// extension and the CLI. Ed25519 fee keys use the same envelope with their own
// algorithm label bound into the associated data.
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { ALGORITHM, raw, hex, fromHex, concat } from './codec.mjs';
import { randomBytes, constantTimeEqual } from './approval.mjs';
import { parseStrictJson } from './strict-json.mjs';

export const STORE = 'quantum-seal/keystore/1';
export const KDF = 'scrypt-N131072-r8-p1';
export const FEE_KEY_ALGORITHM = 'Ed25519';
const ALGORITHMS = [ALGORITHM, FEE_KEY_ALGORITHM];
const utf8 = new TextEncoder();

function associated(algorithm, publicKey) {
  return concat(utf8.encode(`${STORE}/${algorithm}/${KDF}`), publicKey);
}
async function derive(password, salt) {
  if (typeof password !== 'string') throw new Error('Invalid passphrase.');
  const bytes = utf8.encode(password);
  if (bytes.length > 1024) throw new Error('Invalid passphrase.');
  try {
    return await scryptAsync(bytes, salt, { N: 131072, r: 8, p: 1, dkLen: 32, maxmem: 2 ** 28 });
  } finally {
    bytes.fill(0);
  }
}
async function aesKey(bytes, usage) {
  return globalThis.crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, [usage]);
}

export async function encryptKey(secretKey, password, algorithm = ALGORITHM) {
  if (!ALGORITHMS.includes(algorithm)) throw new Error('Unsupported key algorithm.');
  if (typeof password !== 'string' || [...password].length < 12)
    throw new Error('Use a long passphrase of at least 12 characters.');
  const secret = raw(secretKey, 64),
    publicKey = secret.slice(32);
  const salt = randomBytes(32),
    iv = randomBytes(12);
  let key;
  try {
    key = await derive(password, salt);
    const sealed = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: associated(algorithm, publicKey), tagLength: 128 },
        await aesKey(key, 'encrypt'),
        secret,
      ),
    );
    return {
      format: STORE,
      algorithm,
      publicKey: hex(publicKey),
      kdf: KDF,
      salt: hex(salt),
      iv: hex(iv),
      ciphertext: hex(sealed.slice(0, 64)),
      tag: hex(sealed.slice(64)),
    };
  } finally {
    secret.fill(0);
    key?.fill(0);
  }
}

export async function decryptKey(input, password, algorithm = ALGORITHM) {
  const o = typeof input === 'string' ? parseStrictJson(input, 4096) : input;
  const names = ['format', 'algorithm', 'publicKey', 'kdf', 'salt', 'iv', 'ciphertext', 'tag'];
  if (
    !o ||
    typeof o !== 'object' ||
    Array.isArray(o) ||
    Object.keys(o).length !== names.length ||
    names.some((n) => !Object.hasOwn(o, n))
  )
    throw new Error('Missing or unknown fields.');
  if (o.format !== STORE || o.algorithm !== algorithm || o.kdf !== KDF)
    throw new Error('Unsupported keystore format.');
  const publicKey = fromHex(o.publicKey, 32),
    salt = fromHex(o.salt, 32),
    iv = fromHex(o.iv, 12),
    sealed = concat(fromHex(o.ciphertext, 64), fromHex(o.tag, 16));
  let key, plaintext;
  try {
    key = await derive(password, salt);
    plaintext = new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: associated(algorithm, publicKey), tagLength: 128 },
        await aesKey(key, 'decrypt'),
        sealed,
      ),
    );
    if (!constantTimeEqual(plaintext.slice(32), publicKey)) throw new Error('Key mismatch.');
    return plaintext.slice();
  } catch {
    throw new Error('Unable to unlock keystore.');
  } finally {
    key?.fill(0);
    plaintext?.fill(0);
  }
}
