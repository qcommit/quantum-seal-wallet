import { sha256 } from '@noble/hashes/sha2.js';
import { PublicKey } from '@solana/web3.js';

export const ALGORITHM = 'SLH-DSA-SHA2-128s';
export const CONTEXT = new TextEncoder().encode('QuantumSeal.Wallet.v1');
export const SIGNATURE_BYTES = 7856;
export const MAX_INTENT_BYTES = 850;
export const WALLET_BYTES = 334;
export const PROOF_HEADER_BYTES = 193;
export const PROOF_BYTES = 8049;
export const MAX_CHUNK_BYTES = 768;
export const GUARDIAN_INDEX = 255;
const zero32 = new Uint8Array(32);
const utf8 = new TextEncoder();

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
export function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
export function fromHex(value, length) {
  if (typeof value !== 'string' || value.length % 2 || !/^[0-9a-f]*$/.test(value))
    throw new Error('Expected canonical lowercase hexadecimal.');
  const out = Uint8Array.from(value.match(/../g) ?? [], (s) => Number.parseInt(s, 16));
  if (length !== undefined && out.length !== length) throw new Error(`Expected ${length} bytes.`);
  return out;
}
export function raw(value, length = 32) {
  const b = typeof value === 'string' ? fromHex(value, length) : value;
  if (!(b instanceof Uint8Array) || b.length !== length)
    throw new Error(`Expected ${length} bytes.`);
  return Uint8Array.from(b);
}
export function address(value) {
  return new PublicKey(value);
}
export function u64(value) {
  if (typeof value === 'number' && !Number.isSafeInteger(value))
    throw new Error('Unsafe integer; use bigint or a decimal string.');
  if (typeof value === 'string' && !/^(0|[1-9][0-9]*)$/.test(value))
    throw new Error('Invalid decimal integer.');
  if (!['bigint', 'number', 'string'].includes(typeof value))
    throw new Error('Expected an integer.');
  const n = BigInt(value);
  if (n < 0n || n > 0xffffffffffffffffn) throw new Error('Integer is outside u64 range.');
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
}
export function u16(value) {
  if (!Number.isInteger(value) || value < 0 || value > 65535)
    throw new Error('Integer is outside u16 range.');
  return Uint8Array.of(value & 255, value >>> 8);
}
function nonzero(b) {
  return b.some((v) => v !== 0);
}

export function encodeOwners({ keys, threshold }) {
  if (
    !Array.isArray(keys) ||
    keys.length < 1 ||
    keys.length > 3 ||
    !Number.isInteger(threshold) ||
    threshold < 1 ||
    threshold > keys.length
  )
    throw new Error('Expected 1–3 unique owners and a valid threshold.');
  const parsed = keys.map((k) => raw(k));
  if (parsed.some((k) => !nonzero(k)) || new Set(parsed.map(hex)).size !== parsed.length)
    throw new Error('Owner keys must be nonzero and unique.');
  return concat(
    Uint8Array.of(keys.length, threshold),
    ...parsed,
    new Uint8Array((3 - parsed.length) * 32),
  );
}
export function encodePolicy(policy) {
  const owners = encodeOwners(policy);
  const guardian = policy.guardian ? raw(policy.guardian) : zero32;
  const delayBytes = u64(policy.recoveryDelay ?? 0n);
  const delay = new DataView(delayBytes.buffer).getBigUint64(0, true);
  if (!nonzero(guardian)) {
    if (delay !== 0n) throw new Error('Disabled recovery requires a zero delay.');
  } else if (
    delay < 150n ||
    delay > 2000000n ||
    policy.keys.some((k) => hex(raw(k)) === hex(guardian))
  ) {
    throw new Error('Recovery requires a separate guardian and a delay of 150–2,000,000 slots.');
  }
  return concat(owners, guardian, delayBytes);
}

export class Reader {
  constructor(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new Error('Expected bytes.');
    this.bytes = bytes;
    this.offset = 0;
  }
  take(n) {
    if (!Number.isSafeInteger(n) || n < 0 || this.offset + n > this.bytes.length)
      throw new Error('Truncated data.');
    const out = this.bytes.slice(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }
  byte() {
    return this.take(1)[0];
  }
  u16() {
    const b = this.take(2);
    return b[0] | (b[1] << 8);
  }
  u32() {
    const b = this.take(4);
    return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, true);
  }
  u64() {
    const b = this.take(8);
    return new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, true);
  }
  end() {
    if (this.offset !== this.bytes.length) throw new Error('Trailing bytes.');
  }
}
function readOwners(r, empty = false) {
  const count = r.byte(),
    threshold = r.byte(),
    slots = [r.take(32), r.take(32), r.take(32)];
  if (empty && count === 0 && threshold === 0 && slots.every((k) => !nonzero(k))) return null;
  if (count > 3 || slots.slice(count).some(nonzero)) throw new Error('Noncanonical owner slots.');
  const owners = { keys: slots.slice(0, count), threshold };
  encodeOwners(owners);
  return owners;
}
function readPolicy(r) {
  const owners = readOwners(r),
    guardian = r.take(32),
    recoveryDelay = r.u64();
  const out = { ...owners, guardian: nonzero(guardian) ? guardian : null, recoveryDelay };
  encodePolicy(out);
  return out;
}
export function decodeWallet(bytes) {
  if (bytes.length !== WALLET_BYTES) throw new Error('Wrong wallet account size.');
  const r = new Reader(bytes);
  if (hex(r.take(8)) !== hex(utf8.encode('QSWAL001')))
    throw new Error('Wrong wallet discriminator.');
  const bump = r.byte(),
    id = r.take(32),
    genesis = r.take(32),
    policy = readPolicy(r);
  const epoch = r.u64(),
    nonce = r.u64(),
    recoveryReadyAt = r.u64(),
    recoveryOwners = readOwners(r, true),
    locked = r.byte();
  if (locked > 1 || (recoveryReadyAt === 0n) !== (recoveryOwners === null))
    throw new Error('Invalid wallet state.');
  r.end();
  return {
    bump,
    id,
    genesis,
    policy,
    epoch,
    nonce,
    recoveryReadyAt,
    recoveryOwners,
    locked: !!locked,
  };
}
export function decodeProofHeader(bytes) {
  if (bytes.length !== PROOF_BYTES) throw new Error('Wrong proof account size.');
  const r = new Reader(bytes.slice(0, PROOF_HEADER_BYTES));
  if (hex(r.take(8)) !== hex(utf8.encode('QSPRF001')))
    throw new Error('Wrong proof discriminator.');
  const out = {
    bump: r.byte(),
    wallet: r.take(32),
    uploader: r.take(32),
    digest: r.take(32),
    key: r.take(32),
    epoch: r.u64(),
    nonce: r.u64(),
    expiry: r.u64(),
    index: r.byte(),
    uploaded: r.u16(),
    stage: r.byte(),
    root: r.take(16),
    tree: r.u64(),
    leaf: r.u32(),
  };
  r.end();
  if (out.stage > 9 || out.uploaded > SIGNATURE_BYTES) throw new Error('Invalid proof state.');
  return out;
}

export function encodeIntent(intent) {
  const head = concat(
    Uint8Array.of(1),
    address(intent.genesis).toBytes(),
    address(intent.program).toBytes(),
    address(intent.wallet).toBytes(),
    u64(intent.epoch),
    u64(intent.nonce),
    u64(intent.expiry),
  );
  const a = intent.action;
  let tail;
  switch (a.kind) {
    case 'transfer':
      tail = concat(Uint8Array.of(0), address(a.to).toBytes(), u64(a.lamports));
      break;
    case 'rotate':
      tail = concat(Uint8Array.of(1), encodePolicy(a.policy));
      break;
    case 'recover':
      tail = concat(Uint8Array.of(2), encodeOwners(a.owners));
      break;
    case 'cancelRecovery':
      tail = Uint8Array.of(3);
      break;
    case 'invoke': {
      if (
        !Array.isArray(a.metas) ||
        a.metas.length > 12 ||
        !(a.data instanceof Uint8Array) ||
        a.data.length > 256
      )
        throw new Error('Invocation exceeds protocol limits.');
      const metas = a.metas.map((m) => {
        if (typeof m.writable !== 'boolean' || typeof m.signer !== 'boolean')
          throw new Error('Account flags must be booleans.');
        return concat(
          address(m.key).toBytes(),
          Uint8Array.of(Number(m.writable) | (Number(m.signer) << 1)),
        );
      });
      tail = concat(
        Uint8Array.of(4),
        address(a.program).toBytes(),
        Uint8Array.of(metas.length),
        ...metas,
        u16(a.data.length),
        a.data,
      );
      break;
    }
    default:
      throw new Error('Unknown action.');
  }
  const bytes = concat(head, tail);
  decodeIntent(bytes);
  return bytes;
}
export function decodeIntent(bytes) {
  if (bytes.length > MAX_INTENT_BYTES) throw new Error('Intent is too large.');
  const r = new Reader(bytes);
  if (r.byte() !== 1) throw new Error('Unsupported intent version.');
  const genesis = address(r.take(32)),
    program = address(r.take(32)),
    wallet = address(r.take(32));
  const epoch = r.u64(),
    nonce = r.u64(),
    expiry = r.u64();
  const kind = r.byte();
  let action;
  switch (kind) {
    case 0: {
      const to = address(r.take(32)),
        lamports = r.u64();
      if (lamports === 0n) throw new Error('Zero transfer.');
      action = { kind: 'transfer', to, lamports };
      break;
    }
    case 1:
      action = { kind: 'rotate', policy: readPolicy(r) };
      break;
    case 2:
      action = { kind: 'recover', owners: readOwners(r) };
      break;
    case 3:
      action = { kind: 'cancelRecovery' };
      break;
    case 4: {
      const target = address(r.take(32)),
        count = r.byte(),
        metas = [];
      if (target.equals(program) || count > 12) throw new Error('Unsafe invocation.');
      for (let i = 0; i < count; i++) {
        const key = address(r.take(32)),
          flags = r.byte();
        const writable = !!(flags & 1),
          signer = !!(flags & 2);
        if (
          flags > 3 ||
          metas.some((m) => m.key.equals(key)) ||
          (signer && !key.equals(wallet)) ||
          (key.equals(wallet) && (!signer || writable))
        )
          throw new Error('Unsafe account privileges.');
        metas.push({ key, writable, signer });
      }
      const len = r.u16();
      if (len > 256) throw new Error('Invocation data exceeds protocol limit.');
      action = { kind: 'invoke', program: target, metas, data: r.take(len) };
      break;
    }
    default:
      throw new Error('Unknown action.');
  }
  r.end();
  return { genesis, program, wallet, epoch, nonce, expiry, action };
}
export function intentDigest(bytes) {
  decodeIntent(bytes);
  return sha256(concat(utf8.encode('QuantumSeal/Intent/v1'), bytes));
}
export async function deriveWallet(program, genesis, salt, policy) {
  const id = sha256(
    concat(
      utf8.encode('QuantumSeal/Wallet/v1'),
      address(genesis).toBytes(),
      raw(salt),
      encodePolicy(policy),
    ),
  );
  const [wallet, bump] = await PublicKey.findProgramAddress(
    [utf8.encode('wallet'), id],
    address(program),
  );
  return { wallet, id, bump };
}
export async function deriveProof(program, wallet, digest, index, uploader) {
  if (!Number.isInteger(index) || ![0, 1, 2, 255].includes(index))
    throw new Error('Invalid signer index.');
  const [proof, bump] = await PublicKey.findProgramAddress(
    [
      utf8.encode('proof'),
      address(wallet).toBytes(),
      raw(digest),
      Uint8Array.of(index),
      address(uploader).toBytes(),
    ],
    address(program),
  );
  return { proof, bump };
}
export function displayIntent(intent) {
  return JSON.stringify(
    intent,
    (_, v) => (typeof v === 'bigint' ? v.toString() : v instanceof Uint8Array ? hex(v) : v),
    2,
  );
}
