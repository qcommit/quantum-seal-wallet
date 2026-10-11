import {
  randomBytes,
  scrypt,
  createCipheriv,
  createDecipheriv,
  timingSafeEqual,
} from 'node:crypto';
import { promisify } from 'node:util';
import { ALGORITHM, raw, hex, fromHex, concat } from './codec.mjs';
export {
  generateKeypair,
  signApproval,
  parseApproval,
  verifyApproval,
  serializeApproval,
} from './approval.mjs';
import { parseStrictJson } from './strict-json.mjs';

const scryptAsync = promisify(scrypt);
const STORE = 'quantum-seal/keystore/1';
const KDF = 'scrypt-N131072-r8-p1';
const storeContext = new TextEncoder().encode(`${STORE}/${ALGORITHM}/${KDF}`);
function fields(object, names) {
  if (
    !object ||
    typeof object !== 'object' ||
    Array.isArray(object) ||
    Object.keys(object).length !== names.length ||
    names.some((n) => !Object.hasOwn(object, n))
  )
    throw new Error('Missing or unknown fields.');
}
async function derive(password, salt) {
  if (typeof password !== 'string' || Buffer.byteLength(password, 'utf8') > 1024)
    throw new Error('Invalid passphrase.');
  const bytes = Buffer.from(password, 'utf8');
  try {
    return await scryptAsync(bytes, salt, 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
  } finally {
    bytes.fill(0);
  }
}
export async function encryptKey(secretKey, password) {
  if (typeof password !== 'string' || [...password].length < 12)
    throw new Error('Use a long passphrase of at least 12 characters.');
  const secret = raw(secretKey, 64),
    publicKey = secret.slice(32);
  const salt = randomBytes(32),
    iv = randomBytes(12);
  let key;
  try {
    key = await derive(password, salt);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(concat(storeContext, publicKey));
    const ciphertext = Buffer.concat([cipher.update(secret), cipher.final()]);
    return {
      format: STORE,
      algorithm: ALGORITHM,
      publicKey: hex(publicKey),
      kdf: KDF,
      salt: hex(salt),
      iv: hex(iv),
      ciphertext: hex(ciphertext),
      tag: hex(cipher.getAuthTag()),
    };
  } finally {
    secret.fill(0);
    key?.fill(0);
  }
}
export async function decryptKey(input, password) {
  const o = typeof input === 'string' ? parseStrictJson(input, 4096) : input;
  fields(o, ['format', 'algorithm', 'publicKey', 'kdf', 'salt', 'iv', 'ciphertext', 'tag']);
  if (o.format !== STORE || o.algorithm !== ALGORITHM || o.kdf !== KDF)
    throw new Error('Unsupported keystore format.');
  const publicKey = fromHex(o.publicKey, 32),
    salt = fromHex(o.salt, 32),
    iv = fromHex(o.iv, 12);
  const ciphertext = fromHex(o.ciphertext, 64),
    tag = fromHex(o.tag, 16);
  let key, plaintext;
  try {
    key = await derive(password, salt);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(concat(storeContext, publicKey));
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (!timingSafeEqual(plaintext.subarray(32), publicKey)) throw new Error('Key mismatch.');
    return Uint8Array.from(plaintext);
  } catch {
    throw new Error('Unable to unlock keystore.');
  } finally {
    key?.fill(0);
    plaintext?.fill(0);
  }
}
