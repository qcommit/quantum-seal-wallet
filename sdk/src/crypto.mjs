import { slh_dsa_sha2_128s as slh } from '@noble/post-quantum/slh-dsa.js';
import {
  randomBytes,
  scrypt,
  createCipheriv,
  createDecipheriv,
  timingSafeEqual,
} from 'node:crypto';
import { promisify } from 'node:util';
import {
  ALGORITHM,
  CONTEXT,
  SIGNATURE_BYTES,
  raw,
  hex,
  fromHex,
  concat,
  decodeIntent,
  intentDigest,
  address,
} from './codec.mjs';
import { parseStrictJson } from './strict-json.mjs';

const scryptAsync = promisify(scrypt);
const FORMAT = 'quantum-seal/approval/1';
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
function b64(bytes) {
  return Buffer.from(bytes).toString('base64');
}
function unb64(text, length) {
  if (typeof text !== 'string' || text.length !== 4 * Math.ceil(length / 3))
    throw new Error('Invalid base64 length.');
  const bytes = Buffer.from(text, 'base64');
  if (bytes.length !== length || b64(bytes) !== text) throw new Error('Noncanonical base64.');
  return Uint8Array.from(bytes);
}

export function generateKeypair() {
  return slh.keygen();
}
export function signApproval(intentBytes, secretKey, index = 0) {
  if (![0, 1, 2, 255].includes(index)) throw new Error('Invalid signer index.');
  decodeIntent(intentBytes);
  const secret = raw(secretKey, 64),
    publicKey = secret.slice(32);
  const entropy = randomBytes(16);
  try {
    const digest = intentDigest(intentBytes);
    const signature = slh.sign(digest, secret, { context: CONTEXT, extraEntropy: entropy });
    if (!slh.verify(signature, digest, publicKey, { context: CONTEXT }))
      throw new Error('Post-sign verification failed.');
    return {
      format: FORMAT,
      algorithm: ALGORITHM,
      index,
      intent: hex(intentBytes),
      publicKey: hex(publicKey),
      signature: b64(signature),
    };
  } finally {
    secret.fill(0);
    entropy.fill(0);
  }
}
export function parseApproval(input) {
  const object = typeof input === 'string' ? parseStrictJson(input, 32768) : input;
  fields(object, ['format', 'algorithm', 'index', 'intent', 'publicKey', 'signature']);
  if (
    object.format !== FORMAT ||
    object.algorithm !== ALGORITHM ||
    ![0, 1, 2, 255].includes(object.index)
  )
    throw new Error('Unsupported approval format.');
  if (typeof object.intent !== 'string' || object.intent.length > 1700)
    throw new Error('Intent is too large.');
  const intentBytes = fromHex(object.intent),
    intent = decodeIntent(intentBytes);
  return {
    object,
    intent,
    intentBytes,
    publicKey: fromHex(object.publicKey, 32),
    signature: unb64(object.signature, SIGNATURE_BYTES),
  };
}
export function verifyApproval(input, { expectedKey, expectedWallet, expectedProgram } = {}) {
  if (expectedKey === undefined)
    throw new Error('Verification requires a separately trusted post-quantum public key.');
  const p = parseApproval(input),
    trusted = raw(expectedKey);
  if (!timingSafeEqual(p.publicKey, trusted))
    return { valid: false, reason: 'Key does not match the trusted key.' };
  if (expectedWallet !== undefined && !p.intent.wallet.equals(address(expectedWallet)))
    return { valid: false, reason: 'Wrong wallet.' };
  if (expectedProgram !== undefined && !p.intent.program.equals(address(expectedProgram)))
    return { valid: false, reason: 'Wrong program.' };
  const valid = slh.verify(p.signature, intentDigest(p.intentBytes), trusted, { context: CONTEXT });
  return {
    valid,
    reason: valid
      ? 'Signature and pinned key match. Quorum, freshness and execution are not established offline.'
      : 'Invalid signature.',
    intent: p.intent,
  };
}
export function serializeApproval(approval) {
  parseApproval(approval);
  return JSON.stringify(approval, null, 2) + '\n';
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
