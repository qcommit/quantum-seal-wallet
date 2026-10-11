// Portable approval signing and verification: no Node-only APIs, so the same code
// runs in the CLI and in the browser extension.
import { slh_dsa_sha2_128s as slh } from '@noble/post-quantum/slh-dsa.js';
import {
  ALGORITHM,
  CONTEXT,
  SIGNATURE_BYTES,
  raw,
  hex,
  fromHex,
  decodeIntent,
  intentDigest,
  address,
} from './codec.mjs';
import { parseStrictJson } from './strict-json.mjs';

export const APPROVAL_FORMAT = 'quantum-seal/approval/1';

export function randomBytes(length) {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}
export function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
export function toBase64(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
    out += i + 1 < bytes.length ? B64[(n >> 6) & 63] : '=';
    out += i + 2 < bytes.length ? B64[n & 63] : '=';
  }
  return out;
}
export function fromBase64(text, length) {
  if (typeof text !== 'string' || text.length !== 4 * Math.ceil(length / 3))
    throw new Error('Invalid base64 length.');
  const out = new Uint8Array(length);
  let o = 0;
  for (let i = 0; i < text.length; i += 4) {
    const v = [0, 1, 2, 3].map((j) => (text[i + j] === '=' ? 0 : B64.indexOf(text[i + j])));
    if (v.some((x) => x < 0)) throw new Error('Invalid base64.');
    const n = (v[0] << 18) | (v[1] << 12) | (v[2] << 6) | v[3];
    for (const byte of [(n >> 16) & 255, (n >> 8) & 255, n & 255]) if (o < length) out[o++] = byte;
  }
  if (toBase64(out) !== text) throw new Error('Noncanonical base64.');
  return out;
}
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
      format: APPROVAL_FORMAT,
      algorithm: ALGORITHM,
      index,
      intent: hex(intentBytes),
      publicKey: hex(publicKey),
      signature: toBase64(signature),
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
    object.format !== APPROVAL_FORMAT ||
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
    signature: fromBase64(object.signature, SIGNATURE_BYTES),
  };
}
export function verifyApproval(input, { expectedKey, expectedWallet, expectedProgram } = {}) {
  if (expectedKey === undefined)
    throw new Error('Verification requires a separately trusted post-quantum public key.');
  const p = parseApproval(input),
    trusted = raw(expectedKey);
  if (!constantTimeEqual(p.publicKey, trusted))
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
