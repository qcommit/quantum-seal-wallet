#!/usr/bin/env node
// Differential test: the Rust `Intent::decode` (through the `decode_intents` example of
// seal-verify) against the SDK codec in sdk/src/codec.mjs, byte for byte.
//
//   npm run test:differential                     # default seed, 20,000 generated cases
//   node tests/differential.mjs --seed=7 --cases=100000
//   node tests/differential.mjs --write-corpus    # regenerate tests/fixtures/intent-corpus.txt
//
// For every input it checks that Rust accepts iff `decodeIntent` accepts; that when both
// accept, every decoded field and the intent digest agree; and that `encodeIntent(decoded)`
// reproduces the input. For generated intents the SDK can express, it also checks that
// `encodeIntent` succeeds iff Rust accepts, that it produces the same bytes as the
// independent raw encoder below, and that Rust decodes those bytes to the generated fields.
// The corpus file additionally pins Rust's accept/reject result and error variant.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PublicKey } from '@solana/web3.js';
import {
  decodeIntent,
  encodeIntent,
  fromHex,
  hex,
  intentDigest,
  MAINNET_GENESIS,
} from '../sdk/src/codec.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const corpusPath = path.join(root, 'tests/fixtures/intent-corpus.txt');
const options = Object.fromEntries(
  process.argv.slice(2).map((arg) => {
    const m = /^--([a-z-]+)(?:=(.*))?$/.exec(arg);
    if (!m) throw new Error(`Unknown argument: ${arg}`);
    return [m[1], m[2] ?? true];
  }),
);
for (const k of Object.keys(options))
  if (!['seed', 'cases', 'decoder', 'write-corpus'].includes(k))
    throw new Error(`Unknown option --${k}`);
const seed = BigInt(options.seed ?? process.env.QSW_DIFF_SEED ?? 20261011);
const caseTarget = Number(options.cases ?? process.env.QSW_DIFF_CASES ?? 20000);
const decoder =
  options.decoder ??
  process.env.QSW_DECODER ??
  path.join(root, 'target/release/examples/decode_intents');

// ---------------------------------------------------------------- deterministic PRNG
// xoshiro128** seeded through splitmix32; no dependencies, identical on every platform.
function makeRng(seedValue) {
  let x = Number(BigInt.asUintN(32, seedValue ^ (seedValue >> 32n))) >>> 0;
  const split = () => {
    x = (x + 0x9e3779b9) >>> 0;
    let z = x;
    z = Math.imul(z ^ (z >>> 16), 0x85ebca6b) >>> 0;
    z = Math.imul(z ^ (z >>> 13), 0xc2b2ae35) >>> 0;
    return (z ^ (z >>> 16)) >>> 0;
  };
  const s = [split(), split(), split(), split()];
  const rotl = (v, k) => ((v << k) | (v >>> (32 - k))) >>> 0;
  const u32 = () => {
    const result = Math.imul(rotl(Math.imul(s[1], 5) >>> 0, 7), 9) >>> 0;
    const t = (s[1] << 9) >>> 0;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl(s[3], 11);
    return result;
  };
  const int = (n) => Math.floor((u32() / 0x100000000) * n);
  return {
    u32,
    int,
    range: (lo, hi) => lo + int(hi - lo + 1),
    chance: (p) => u32() / 0x100000000 < p,
    pick: (list) => list[int(list.length)],
    bytes: (n) => Uint8Array.from({ length: n }, () => u32() & 255),
    u64: () => (BigInt(u32()) << 32n) | BigInt(u32()),
    bigRange: (lo, hi) => lo + (((BigInt(u32()) << 32n) | BigInt(u32())) % (hi - lo + 1n)),
  };
}

// ---------------------------------------------------------------- raw model encoder
// A model is a loosely typed description of an intent that may be invalid in any way.
const ZERO = new Uint8Array(32);
const U64_MAX = (1n << 64n) - 1n;
const MAX_FEE = 10_000_000n;
const fill = (n) => new Uint8Array(32).fill(n);
const mainnet = new PublicKey(MAINNET_GENESIS).toBytes();
const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const nonzero = (b) => b.some((v) => v !== 0);
function cat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
function le64(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt.asUintN(64, n), true);
  return b;
}
const le16 = (n) => Uint8Array.of(n & 255, (n >>> 8) & 255);
const ownersBytes = (o) => cat(Uint8Array.of(o.count & 255, o.threshold & 255), ...o.slots);

function rawEncode(m) {
  const parts = [
    Uint8Array.of(m.version),
    m.genesis,
    m.program,
    m.wallet,
    le64(m.epoch),
    le64(m.nonce),
    le64(m.expiry),
  ];
  const a = m.action;
  switch (a.kind) {
    case 'transfer':
      parts.push(Uint8Array.of(0), a.to, le64(a.lamports));
      break;
    case 'rotate':
      parts.push(Uint8Array.of(1), ownersBytes(a.owners), a.guardian, le64(a.delay));
      break;
    case 'recover':
      parts.push(Uint8Array.of(2), ownersBytes(a.owners));
      break;
    case 'cancelRecovery':
      parts.push(Uint8Array.of(3));
      break;
    case 'invoke':
      parts.push(Uint8Array.of(4), a.program, Uint8Array.of(a.count ?? a.metas.length));
      for (const meta of a.metas) parts.push(meta.key, Uint8Array.of(meta.flags));
      parts.push(le16(a.len ?? a.data.length), a.data);
      break;
    case 'raw':
      parts.push(Uint8Array.of(a.tag), a.payload);
      break;
    default:
      throw new Error(`model kind ${a.kind}`);
  }
  if (m.fee) parts.push(m.fee.to, le64(m.fee.lamports));
  if (m.trailing) parts.push(m.trailing);
  return cat(...parts);
}

// The SDK-shaped input for a model, or null when the SDK API cannot express it.
function toSdk(m) {
  if (m.trailing || m.version !== (m.fee ? 2 : 1)) return null;
  const pk = (b) => new PublicKey(b);
  const a = m.action;
  let action;
  const ownersOf = (o) => {
    if (o.count > 3 || o.slots.slice(o.count).some(nonzero)) return null;
    return { keys: o.slots.slice(0, o.count), threshold: o.threshold };
  };
  switch (a.kind) {
    case 'transfer':
      action = { kind: 'transfer', to: pk(a.to), lamports: a.lamports };
      break;
    case 'rotate': {
      const owners = ownersOf(a.owners);
      if (!owners) return null;
      action = {
        kind: 'rotate',
        policy: { ...owners, guardian: a.guardian, recoveryDelay: a.delay },
      };
      break;
    }
    case 'recover': {
      const owners = ownersOf(a.owners);
      if (!owners) return null;
      action = { kind: 'recover', owners };
      break;
    }
    case 'cancelRecovery':
      action = { kind: 'cancelRecovery' };
      break;
    case 'invoke':
      if (a.count !== undefined || a.len !== undefined || a.metas.some((x) => x.flags > 3))
        return null;
      action = {
        kind: 'invoke',
        program: pk(a.program),
        metas: a.metas.map((x) => ({
          key: pk(x.key),
          writable: !!(x.flags & 1),
          signer: !!(x.flags & 2),
        })),
        data: a.data,
      };
      break;
    default:
      return null;
  }
  return {
    genesis: pk(m.genesis),
    program: pk(m.program),
    wallet: pk(m.wallet),
    epoch: m.epoch,
    nonce: m.nonce,
    expiry: m.expiry,
    action,
    ...(m.fee ? { fee: { to: pk(m.fee.to), lamports: m.fee.lamports } } : {}),
  };
}

// ---------------------------------------------------------------- canonical descriptions
// Must match crates/seal-verify/examples/decode_intents.rs exactly.
const kb = (k) => hex(k instanceof PublicKey ? k.toBytes() : k);
function describe(version, f, digest) {
  const a = f.action;
  let action;
  switch (a.kind) {
    case 'transfer':
      action = { kind: 'transfer', to: kb(a.to), lamports: String(a.lamports) };
      break;
    case 'rotate':
      action = {
        kind: 'rotate',
        threshold: a.threshold,
        keys: a.keys.map(kb),
        guardian: kb(a.guardian ?? ZERO),
        recoveryDelay: String(a.recoveryDelay),
      };
      break;
    case 'recover':
      action = { kind: 'recover', threshold: a.threshold, keys: a.keys.map(kb) };
      break;
    case 'cancelRecovery':
      action = { kind: 'cancelRecovery' };
      break;
    case 'invoke':
      action = {
        kind: 'invoke',
        program: kb(a.program),
        metas: a.metas.map((x) => ({ key: kb(x.key), writable: x.writable, signer: x.signer })),
        data: hex(a.data),
      };
      break;
    default:
      throw new Error(`describe kind ${a.kind}`);
  }
  return JSON.stringify({
    version,
    genesis: kb(f.genesis),
    program: kb(f.program),
    wallet: kb(f.wallet),
    epoch: String(f.epoch),
    nonce: String(f.nonce),
    expiry: String(f.expiry),
    action,
    fee: f.fee ? { to: kb(f.fee.to), lamports: String(f.fee.lamports) } : null,
    digest: hex(digest),
  });
}
function flattenDecoded(d) {
  const a = d.action;
  if (a.kind === 'rotate')
    return { ...d, action: { kind: 'rotate', ...a.policy, guardian: a.policy.guardian } };
  if (a.kind === 'recover') return { ...d, action: { kind: 'recover', ...a.owners } };
  return d;
}
function flattenModel(m) {
  const a = m.action;
  let action = a;
  if (a.kind === 'rotate')
    action = {
      kind: 'rotate',
      threshold: a.owners.threshold,
      keys: a.owners.slots.slice(0, a.owners.count),
      guardian: a.guardian,
      recoveryDelay: a.delay,
    };
  else if (a.kind === 'recover')
    action = {
      kind: 'recover',
      threshold: a.owners.threshold,
      keys: a.owners.slots.slice(0, a.owners.count),
    };
  else if (a.kind === 'invoke')
    action = {
      ...a,
      metas: a.metas.map((x) => ({
        key: x.key,
        writable: !!(x.flags & 1),
        signer: !!(x.flags & 2),
      })),
    };
  return { ...m, action };
}

// ---------------------------------------------------------------- generators
function generator(rng) {
  const key = () => {
    const k = rng.bytes(32);
    if (!nonzero(k)) k[0] = 1;
    return k;
  };
  const u64 = () =>
    rng.chance(0.25) ? rng.pick([0n, 1n, 2n, 0xffffffffn, 1n << 63n, U64_MAX]) : rng.u64();
  const distinctKeys = (n, avoid) => {
    const out = [];
    while (out.length < n) {
      const k = key();
      if (![...out, ...avoid].some((x) => same(x, k))) out.push(k);
    }
    return out;
  };
  const owners = (avoid) => {
    const count = rng.range(1, 3);
    const keys = distinctKeys(count, avoid);
    return {
      count,
      threshold: rng.range(1, count),
      slots: [0, 1, 2].map((i) => keys[i] ?? ZERO),
    };
  };
  const breakOwners = (o) => {
    const c = Math.min(o.count, 3);
    const choices = [
      () => (o.count = rng.pick([0, 4, 255])),
      () => (o.threshold = 0),
      () => (o.threshold = o.count + 1),
      () => (o.threshold = rng.range(o.count + 1, 255)),
      () => (o.slots[rng.int(c)] = ZERO),
      () => c < 3 && (o.slots[rng.range(c, 2)] = key()),
      () => c >= 2 && (o.slots[1] = o.slots[0]),
      () => c === 3 && (o.slots[2] = o.slots[rng.int(2)]),
    ];
    rng.pick(choices)();
  };
  const policy = (ctx) => {
    const o = owners([]);
    const keys = o.slots.slice(0, o.count);
    if (rng.chance(0.35)) return { owners: o, guardian: ZERO, delay: 0n };
    const guardian = distinctKeys(1, keys)[0];
    const delay = rng.chance(0.4)
      ? rng.pick([150n, 151n, 216000n, 1999999n, 2000000n])
      : rng.bigRange(150n, 2000000n);
    if (ctx.mainnet && rng.chance(0.5)) return { owners: o, guardian, delay: 150n };
    return { owners: o, guardian, delay };
  };
  const breakPolicy = (p) => {
    const keys = p.owners.slots.slice(0, p.owners.count);
    rng.pick([
      () => breakOwners(p.owners),
      () => {
        p.guardian = ZERO;
        p.delay = rng.pick([1n, 150n, U64_MAX]);
      },
      () => {
        p.guardian = rng.pick(keys);
        p.delay = 150n;
      },
      () => {
        p.guardian = key();
        p.delay = rng.pick([0n, 1n, 149n, 2000001n, U64_MAX]);
      },
    ])();
  };
  const invoke = (ctx) => {
    let program = key();
    while (same(program, ctx.program)) program = key();
    const count = rng.chance(0.2) ? rng.pick([0, 12]) : rng.range(0, 12);
    const metas = distinctKeys(count, [ctx.wallet]).map((k) => ({ key: k, flags: rng.int(2) }));
    if (count > 0 && rng.chance(0.4)) metas[rng.int(count)] = { key: ctx.wallet, flags: 2 };
    const len = rng.chance(0.2) ? rng.pick([0, 1, 255, 256]) : rng.range(0, 256);
    return { kind: 'invoke', program, metas, data: rng.bytes(len) };
  };
  const breakInvoke = (a, ctx) => {
    const n = a.metas.length;
    const choices = [
      () => (a.program = ctx.program),
      () => {
        while (a.metas.length < 13) a.metas.push({ key: key(), flags: 0 });
      },
      () => (a.data = rng.bytes(257)),
      () => (a.len = rng.pick([257, 65535, a.data.length + 1])),
      () => (a.count = rng.pick([13, 255, n + 1])),
      () => {
        a.metas.push({ key: key(), flags: rng.range(4, 255) });
      },
      () => a.metas.push({ key: ctx.wallet, flags: rng.pick([0, 1, 3]) }),
      () => a.metas.push({ key: key(), flags: rng.pick([2, 3]) }),
      () => n > 0 && a.metas.push({ ...a.metas[rng.int(n)] }),
      () => a.metas.push({ key: ctx.wallet, flags: 2 }, { key: ctx.wallet, flags: 2 }),
    ];
    rng.pick(choices)();
  };
  const fee = (ctx) => ({
    to: rng.chance(0.1) ? ctx.genesis : key(),
    lamports: rng.chance(0.3)
      ? rng.pick([1n, 2n, MAX_FEE - 1n, MAX_FEE])
      : rng.bigRange(1n, MAX_FEE),
  });
  const breakFee = (f, ctx) =>
    rng.pick([
      () =>
        (f.lamports = rng.pick([0n, MAX_FEE + 1n, U64_MAX, rng.bigRange(MAX_FEE + 1n, U64_MAX)])),
      () => (f.to = rng.pick([ZERO, ctx.wallet, ctx.program])),
    ])();

  // A valid model; `invalid` then applies exactly one semantic corruption.
  return function model(invalid) {
    const isMainnet = rng.chance(0.1);
    const [program, wallet] = distinctKeys(2, []);
    const ctx = { genesis: isMainnet ? mainnet : key(), program, wallet, mainnet: isMainnet };
    const kind = rng.pick(['transfer', 'rotate', 'recover', 'cancelRecovery', 'invoke', 'invoke']);
    let action;
    if (kind === 'transfer')
      action = {
        kind,
        to: rng.chance(0.05) ? rng.pick([wallet, ZERO, program]) : key(),
        lamports: u64() || 1n,
      };
    else if (kind === 'rotate') action = { kind, ...policy(ctx) };
    else if (kind === 'recover') action = { kind, owners: owners([]) };
    else if (kind === 'cancelRecovery') action = { kind };
    else action = invoke(ctx);
    const m = {
      version: 1,
      genesis: ctx.genesis,
      program,
      wallet,
      epoch: u64(),
      nonce: u64(),
      expiry: u64(),
      action,
      fee: null,
    };
    if (rng.chance(0.5)) {
      m.version = 2;
      m.fee = fee(ctx);
    }
    let label = `${kind}/v${m.version}`;
    if (invalid) {
      const options = ['version', 'unknown-action', 'trailing'];
      if (m.fee) options.push('fee', 'fee', 'fee');
      if (kind === 'transfer') options.push('action', 'action');
      if (kind === 'rotate') options.push('action', 'action', 'action');
      if (kind === 'recover') options.push('action', 'action');
      if (kind === 'invoke') options.push('action', 'action', 'action', 'action');
      const what = rng.pick(options);
      label += `/bad-${what}`;
      if (what === 'version') {
        if (rng.chance(0.5)) m.version = m.version === 1 ? 2 : 1;
        else m.version = rng.pick([0, 3, 255]);
      } else if (what === 'unknown-action') {
        m.action = { kind: 'raw', tag: rng.range(5, 255), payload: rng.bytes(rng.range(0, 64)) };
      } else if (what === 'trailing') {
        m.trailing = rng.bytes(rng.range(1, 8));
      } else if (what === 'fee') {
        breakFee(m.fee, ctx);
      } else if (kind === 'transfer') {
        action.lamports = 0n;
      } else if (kind === 'rotate') {
        breakPolicy(action);
      } else if (kind === 'recover') {
        breakOwners(action.owners);
      } else {
        breakInvoke(action, ctx);
      }
    }
    return { label, model: m };
  };
}

function mutateBytes(rng, bytes) {
  const b = Array.from(bytes);
  const what = rng.pick([
    'flip',
    'flip',
    'flip',
    'truncate',
    'extend',
    'version',
    'oversize',
    'splice',
  ]);
  if (what === 'flip') {
    for (let n = rng.range(1, 4); n > 0; n--) b[rng.int(b.length)] ^= 1 << rng.int(8);
  } else if (what === 'truncate') {
    b.length = rng.int(b.length);
  } else if (what === 'extend') {
    b.push(...rng.bytes(rng.range(1, 40)));
  } else if (what === 'version') {
    b[0] = rng.pick([0, 1, 2, 3, rng.int(256)]);
  } else if (what === 'oversize') {
    while (b.length <= 850) b.push(rng.chance(0.5) ? 0 : rng.int(256));
    b.push(...rng.bytes(rng.int(50)));
    b.length = Math.min(b.length, 900);
  } else {
    const at = rng.int(b.length + 1);
    if (rng.chance(0.5)) b.splice(at, rng.range(1, 33));
    else b.splice(at, 0, ...rng.bytes(rng.range(1, 33)));
  }
  return { label: `mutate-${what}`, bytes: Uint8Array.from(b) };
}

// ---------------------------------------------------------------- named edge-case corpus
function corpusCases() {
  const [G, P, W, A, B, C, D, E] = [1, 2, 3, 4, 5, 6, 7, 8].map(fill);
  const base = (action, fee = null) => ({
    version: fee ? 2 : 1,
    genesis: G,
    program: P,
    wallet: W,
    epoch: 4n,
    nonce: 5n,
    expiry: 1000n,
    action,
    fee,
  });
  const own = (count, threshold, ...keys) => ({
    count,
    threshold,
    slots: [0, 1, 2].map((i) => keys[i] ?? ZERO),
  });
  const transfer = { kind: 'transfer', to: A, lamports: 123n };
  const rot = (owners, guardian, delay) => ({ kind: 'rotate', owners, guardian, delay });
  const inv = (metas, data, extra = {}) => ({
    kind: 'invoke',
    program: E,
    metas,
    data,
    ...extra,
  });
  const twelve = Array.from({ length: 11 }, (_, i) => ({ key: fill(16 + i), flags: i & 1 }));
  twelve.push({ key: W, flags: 2 });
  const fee = (lamports, to = D) => ({ to, lamports });
  const out = [];
  const add = (name, m) => out.push({ name, bytes: rawEncode(m), model: m });
  const addBytes = (name, bytes) => out.push({ name, bytes });

  add('transfer-v1', base(transfer));
  add('transfer-u64-max-fields', {
    ...base({ ...transfer, lamports: U64_MAX }),
    epoch: U64_MAX,
    nonce: U64_MAX,
    expiry: U64_MAX,
  });
  add('transfer-zero-lamports', base({ ...transfer, lamports: 0n }));
  add('transfer-one-lamport', base({ ...transfer, lamports: 1n }));
  add('transfer-to-wallet', base({ ...transfer, to: W }));
  add('transfer-to-zero', base({ ...transfer, to: ZERO }));
  add('transfer-v2-fee-1', base(transfer, fee(1n)));
  add('transfer-v2-fee-max', base(transfer, fee(MAX_FEE)));
  add('transfer-v2-fee-0', base(transfer, fee(0n)));
  add('transfer-v2-fee-max-plus-1', base(transfer, fee(MAX_FEE + 1n)));
  add('transfer-v2-fee-u64-max', base(transfer, fee(U64_MAX)));
  add('transfer-v2-fee-to-zero', base(transfer, fee(1n, ZERO)));
  add('transfer-v2-fee-to-wallet', base(transfer, fee(1n, W)));
  add('transfer-v2-fee-to-program', base(transfer, fee(1n, P)));
  add('transfer-v2-fee-to-genesis', base(transfer, fee(1n, G)));
  add('transfer-v2-fee-to-transfer-recipient', base(transfer, fee(1n, A)));
  add('transfer-v2-missing-fee', { ...base(transfer), version: 2 });
  add('transfer-v1-with-fee-block', { ...base(transfer, fee(1n)), version: 1 });
  for (const v of [0, 3, 255]) add(`transfer-version-${v}`, { ...base(transfer), version: v });
  add('transfer-v2-half-fee-block', {
    ...base(transfer),
    version: 2,
    trailing: cat(D, Uint8Array.of(1, 0, 0, 0)),
  });
  add('transfer-trailing-zero-byte', { ...base(transfer), trailing: Uint8Array.of(0) });

  const two = own(2, 2, A, B);
  add('rotate-no-guardian', base(rot(two, ZERO, 0n)));
  add('rotate-guardian-delay-150', base(rot(two, C, 150n)));
  add('rotate-guardian-delay-2000000', base(rot(two, C, 2000000n)));
  add('rotate-guardian-delay-149', base(rot(two, C, 149n)));
  add('rotate-guardian-delay-2000001', base(rot(two, C, 2000001n)));
  add('rotate-guardian-delay-0', base(rot(two, C, 0n)));
  add('rotate-no-guardian-delay-1', base(rot(two, ZERO, 1n)));
  add('rotate-guardian-is-owner', base(rot(two, B, 150n)));
  add('rotate-mainnet-genesis-delay-150', { ...base(rot(two, C, 150n)), genesis: mainnet });
  add('rotate-three-of-three', base(rot(own(3, 3, A, B, C), ZERO, 0n)));
  add('rotate-count-0', base(rot(own(0, 0), ZERO, 0n)));
  add('rotate-count-4', base(rot(own(4, 1, A, B, C), ZERO, 0n)));
  add('rotate-threshold-0', base(rot(own(2, 0, A, B), ZERO, 0n)));
  add('rotate-threshold-above-count', base(rot(own(2, 3, A, B), ZERO, 0n)));
  add('rotate-duplicate-owner', base(rot(own(2, 1, A, A), ZERO, 0n)));
  add('rotate-zero-owner', base(rot(own(2, 1, A, ZERO), ZERO, 0n)));
  add('rotate-nonzero-padding', base(rot(own(1, 1, A, B), ZERO, 0n)));
  add('rotate-v2-fee', base(rot(two, C, 150n), fee(5000n)));

  add('recover-one', base({ kind: 'recover', owners: own(1, 1, A) }));
  add('recover-three-of-three', base({ kind: 'recover', owners: own(3, 2, A, B, C) }));
  add('recover-count-0', base({ kind: 'recover', owners: own(0, 0) }));
  add('recover-threshold-0', base({ kind: 'recover', owners: own(1, 0, A) }));
  add('recover-duplicate', base({ kind: 'recover', owners: own(3, 1, A, B, A) }));
  add('recover-nonzero-padding', base({ kind: 'recover', owners: own(2, 1, A, B, C) }));
  add('recover-v2-fee', base({ kind: 'recover', owners: own(1, 1, A) }, fee(1n)));

  add('cancel-v1', base({ kind: 'cancelRecovery' }));
  add('cancel-v2', base({ kind: 'cancelRecovery' }, fee(1n)));
  add('cancel-trailing', { ...base({ kind: 'cancelRecovery' }), trailing: Uint8Array.of(3) });

  add('invoke-empty', base(inv([], new Uint8Array(0))));
  add('invoke-max-v1', base(inv(twelve, new Uint8Array(256).fill(0xab))));
  add('invoke-max-v2-849-bytes', base(inv(twelve, new Uint8Array(256).fill(0xab)), fee(MAX_FEE)));
  add('invoke-max-v2-plus-trailing-850-bytes', {
    ...base(inv(twelve, new Uint8Array(256)), fee(1n)),
    trailing: Uint8Array.of(0),
  });
  add('invoke-max-v2-plus-2-trailing-851-bytes', {
    ...base(inv(twelve, new Uint8Array(256)), fee(1n)),
    trailing: Uint8Array.of(0, 0),
  });
  add('invoke-13-metas', base(inv([...twelve, { key: fill(40), flags: 0 }], new Uint8Array(0))));
  add('invoke-data-257', base(inv([], new Uint8Array(257))));
  add('invoke-len-65535-truncated', base(inv([], new Uint8Array(0), { len: 65535 })));
  add('invoke-count-255-truncated', base(inv([], new Uint8Array(0), { count: 255 })));
  add('invoke-self', base({ ...inv([], new Uint8Array(0)), program: P }));
  add('invoke-target-wallet', base({ ...inv([], new Uint8Array(0)), program: W }));
  add('invoke-meta-program', base(inv([{ key: P, flags: 1 }], new Uint8Array(1))));
  for (const flags of [0, 1, 2, 3])
    add(`invoke-wallet-flags-${flags}`, base(inv([{ key: W, flags }], new Uint8Array(0))));
  for (const flags of [2, 3])
    add(`invoke-other-signer-flags-${flags}`, base(inv([{ key: A, flags }], new Uint8Array(0))));
  for (const flags of [4, 5, 0x80, 255])
    add(`invoke-flags-${flags}`, base(inv([{ key: A, flags }], new Uint8Array(0))));
  add(
    'invoke-duplicate-meta',
    base(
      inv(
        [
          { key: A, flags: 0 },
          { key: A, flags: 1 },
        ],
        new Uint8Array(0),
      ),
    ),
  );
  add(
    'invoke-duplicate-wallet',
    base(
      inv(
        [
          { key: W, flags: 2 },
          { key: W, flags: 2 },
        ],
        new Uint8Array(0),
      ),
    ),
  );
  add('invoke-zero-meta', base(inv([{ key: ZERO, flags: 1 }], new Uint8Array(0))));
  add('invoke-v2-fee-to-target', base(inv([], new Uint8Array(0)), fee(1n, E)));

  for (const tag of [5, 6, 127, 255])
    add(`action-${tag}`, base({ kind: 'raw', tag, payload: new Uint8Array(0) }));
  addBytes('empty', new Uint8Array(0));
  addBytes('version-1-only', Uint8Array.of(1));
  addBytes('version-2-only', Uint8Array.of(2));
  const t = rawEncode(base(transfer));
  addBytes('header-without-action', t.slice(0, 121));
  addBytes('transfer-truncated-lamports', t.slice(0, t.length - 1));
  addBytes('oversize-851-zero-padded', cat(t, new Uint8Array(851 - t.length)));
  addBytes('oversize-900', cat(t, new Uint8Array(900 - t.length).fill(0xff)));
  addBytes('all-ones-850', new Uint8Array(850).fill(1));
  addBytes('all-ff-900', new Uint8Array(900).fill(255));
  return out;
}

// ---------------------------------------------------------------- the comparison
function runRust(inputs) {
  if (!existsSync(decoder)) {
    console.error(
      `Missing ${decoder}.\nBuild it with: cargo build --locked --release -p seal-verify --example decode_intents`,
    );
    process.exit(2);
  }
  const result = spawnSync(decoder, [], {
    input: inputs.map((c) => hex(c.bytes)).join('\n') + '\n',
    encoding: 'utf8',
    maxBuffer: 1 << 30,
  });
  if (result.status !== 0) throw new Error(`decoder failed: ${result.stderr}`);
  const lines = result.stdout.split('\n');
  lines.pop();
  if (lines.length !== inputs.length)
    throw new Error(`decoder returned ${lines.length} lines for ${inputs.length} inputs`);
  return lines;
}

function jsSide(bytes) {
  try {
    const decoded = decodeIntent(bytes);
    const digest = intentDigest(bytes);
    return { ok: true, decoded, text: describe(bytes[0], flattenDecoded(decoded), digest) };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

function compare(c, rust) {
  const problems = [];
  const js = jsSide(c.bytes);
  const rustOk = rust.startsWith('ok ');
  if (!rustOk && !rust.startsWith('err ')) problems.push(`unexpected decoder output`);
  if (rustOk !== js.ok) problems.push(`acceptance differs`);
  else if (rustOk && rust.slice(3) !== js.text) problems.push(`decoded fields differ`);
  if (js.ok) {
    try {
      const again = encodeIntent(js.decoded);
      if (!same(again, c.bytes)) problems.push('encodeIntent(decodeIntent(bytes)) != bytes');
    } catch (error) {
      problems.push(`encodeIntent(decodeIntent(bytes)) threw: ${error.message}`);
    }
  }
  let sdkEncode = 'n/a';
  if (c.model) {
    const sdk = toSdk(c.model);
    if (sdk) {
      let encoded = null;
      try {
        encoded = encodeIntent(sdk);
        sdkEncode = 'ok';
      } catch (error) {
        sdkEncode = `threw: ${error.message}`;
      }
      if ((encoded !== null) !== rustOk) problems.push('encodeIntent acceptance differs from Rust');
      if (encoded && !same(encoded, c.bytes)) problems.push('encodeIntent bytes != raw encoding');
      if (encoded && rustOk) {
        const expect = describe(c.model.version, flattenModel(c.model), intentDigest(encoded));
        if (rust.slice(3) !== expect) problems.push('Rust fields != generated fields');
      }
    }
  }
  return { problems, js, sdkEncode };
}

function main() {
  const t0 = performance.now();
  const corpus = corpusCases();
  if (options['write-corpus']) {
    const rust = runRust(corpus);
    const lines = corpus.map((c, i) => {
      const { problems } = compare(c, rust[i]);
      if (problems.length) throw new Error(`corpus case ${c.name} disagrees: ${problems}`);
      const expected = rust[i].startsWith('ok ') ? 'ok' : `err:${rust[i].slice(4)}`;
      return `${c.name}\t${hex(c.bytes)}\t${expected}`;
    });
    const header = [
      '# Intent decoder edge cases: name<TAB>hex<TAB>expected (ok | err:<Error variant>).',
      '# Generated by `node tests/differential.mjs --write-corpus`; checked by the',
      '# differential run (Rust vs SDK) and by crates/wallet-core/tests/intent_properties.rs.',
    ];
    writeFileSync(corpusPath, [...header, ...lines].join('\n') + '\n');
    console.log(`Wrote ${lines.length} corpus cases to ${path.relative(root, corpusPath)}.`);
    return;
  }

  const cases = [];
  const recorded = readFileSync(corpusPath, 'utf8')
    .split('\n')
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => l.split('\t'));
  const byName = new Map(corpus.map((c) => [c.name, c]));
  for (const [name, h, expected] of recorded) {
    const bytes = fromHex(h);
    const built = byName.get(name);
    cases.push({
      label: `corpus/${name}`,
      bytes,
      expected,
      model: built && same(built.bytes, bytes) ? built.model : undefined,
    });
  }
  const corpusCount = cases.length;

  const rng = makeRng(seed);
  const model = generator(rng);
  let generated = 0,
    sweeps = 0;
  while (generated < caseTarget) {
    const roll = rng.u32() / 0x100000000;
    if (roll < 0.45) {
      const { label, model: m } = model(false);
      const bytes = rawEncode(m);
      cases.push({ label: `gen/${label}`, bytes, model: m });
      generated++;
      if (rng.chance(0.012)) {
        sweeps++;
        for (let n = 0; n < bytes.length; n++)
          cases.push({ label: `truncate/${label}@${n}`, bytes: bytes.slice(0, n) });
      }
    } else if (roll < 0.75) {
      const { label, model: m } = model(true);
      cases.push({ label: `gen/${label}`, bytes: rawEncode(m), model: m });
      generated++;
    } else if (roll < 0.97) {
      const { label, model: m } = model(false);
      const mutated = mutateBytes(rng, rawEncode(m));
      cases.push({ label: `${mutated.label}/${label}`, bytes: mutated.bytes });
      generated++;
    } else {
      const bytes = rng.bytes(rng.range(0, 900));
      if (bytes.length && rng.chance(0.7)) bytes[0] = rng.range(1, 2);
      cases.push({ label: 'random-bytes', bytes });
      generated++;
    }
  }

  const rust = runRust(cases);
  const failures = [];
  const stats = new Map();
  let accepted = 0;
  cases.forEach((c, i) => {
    const { problems, js, sdkEncode } = compare(c, rust[i]);
    if (c.expected) {
      const got = rust[i].startsWith('ok ') ? 'ok' : `err:${rust[i].slice(4)}`;
      if (got !== c.expected) problems.push(`corpus expects ${c.expected}, Rust gives ${got}`);
    }
    if (rust[i].startsWith('ok ')) accepted++;
    const group = c.label.split(/[/@]/).slice(0, 2).join('/');
    const s = stats.get(group) ?? { n: 0, ok: 0 };
    s.n++;
    if (rust[i].startsWith('ok ')) s.ok++;
    stats.set(group, s);
    if (problems.length)
      failures.push({ label: c.label, hex: hex(c.bytes), problems, rust: rust[i], js, sdkEncode });
  });

  const seconds = ((performance.now() - t0) / 1000).toFixed(1);
  if (process.env.QSW_DIFF_VERBOSE)
    for (const [group, s] of [...stats].sort())
      console.log(`  ${group.padEnd(44)} ${String(s.n).padStart(6)} cases, ${s.ok} accepted`);
  console.log(
    `Differential seed ${seed}: ${cases.length} inputs (${corpusCount} corpus, ${generated} generated, ` +
      `${cases.length - corpusCount - generated} truncations from ${sweeps} sweeps); ` +
      `${accepted} accepted by both, ${cases.length - accepted} rejected; ${failures.length} disagreements; ${seconds}s.`,
  );
  if (failures.length) {
    for (const f of failures.slice(0, 20)) {
      console.error(`\nDISAGREEMENT ${f.label}: ${f.problems.join('; ')}`);
      console.error(`  input ${f.hex}`);
      console.error(`  rust  ${f.rust}`);
      console.error(`  js    ${f.js.ok ? 'ok ' + f.js.text : 'err ' + f.js.error}`);
      console.error(`  encodeIntent ${f.sdkEncode}`);
    }
    process.exit(1);
  }
}

main();
