import test from 'node:test';
import assert from 'node:assert/strict';
import { Keypair, VersionedTransaction, PublicKey, TransactionInstruction } from '@solana/web3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { address, hex, concat, u64, encodePolicy, deriveWallet } from '../src/codec.mjs';
import {
  GENESIS,
  IMMUTABLE_LOADER,
  UPGRADEABLE_LOADER,
  parseNetwork,
  inspectDeployment,
  openNetwork,
  assertNetwork,
  guardConnection,
} from '../src/network.mjs';
import { submitNetwork, SubmissionUncertain, base58, integerAmount } from '../src/transport.mjs';
import {
  createDescriptor,
  parseDescriptor,
  parseUnits,
  walletStatus,
  prepareSolTransfer,
} from '../src/wallet.mjs';

const pub = (n) => address(new Uint8Array(32).fill(n));
const code = Uint8Array.of(0x7f, 0x45, 0x4c, 0x46, 1, 2, 3);
const base = () => ({
  format: 'quantum-seal/network/1',
  cluster: 'mainnet-beta',
  rpc: 'https://rpc.invalid/',
  genesis: GENESIS['mainnet-beta'],
  program: pub(5).toBase58(),
  programSha256: hex(sha256(code)),
  programSize: code.length,
  upgradeAuthority: null,
});
function rpc(config = base()) {
  const accounts = new Map([
    [config.program, { executable: true, owner: IMMUTABLE_LOADER, data: code, lamports: 1000000n }],
  ]);
  const calls = { sends: 0, records: [], simulations: 0, signedWire: null };
  return {
    rpcEndpoint: config.rpc,
    accounts,
    calls,
    getGenesisHash: async () => config.genesis,
    getAccountInfo: async (key) => accounts.get(key.toBase58()) ?? null,
    getMinimumBalanceForRentExemption: async () => 1000n,
    getBalance: async () => 10000000000n,
    getSlot: async () => 50n,
    getLatestBlockhash: async () => ({ blockhash: pub(7).toBase58(), lastValidBlockHeight: 100n }),
    getBlockHeight: async () => 60n,
    getFeeForMessage: async () => ({ value: 5000n }),
    simulateTransaction: async (_, cfg) => {
      assert.equal(cfg.sigVerify, true);
      assert.equal(cfg.replaceRecentBlockhash, false);
      calls.simulations++;
      return { value: { err: null, unitsConsumed: 300n } };
    },
    sendRawTransaction: async (wire) => {
      calls.sends++;
      calls.signedWire = wire;
      assert.equal(calls.records[0]?.phase, 'prepared');
      return base58(VersionedTransaction.deserialize(wire).signatures[0]);
    },
    getSignatureStatuses: async () => ({ value: [{ confirmationStatus: 'finalized', err: null }] }),
    getTransaction: async () => ({
      slot: 70n,
      meta: { err: null, fee: 5000n, computeUnitsConsumed: 100n },
    }),
  };
}
function instruction() {
  return new TransactionInstruction({ programId: pub(5), keys: [], data: Buffer.from([3]) });
}
async function send(connection, extra = {}) {
  const network = await openNetwork(base(), connection),
    payer = await Keypair.generate();
  return submitNetwork(connection, payer, [instruction()], {
    network,
    pollIntervalMs: 0,
    onRecord: (r) => connection.calls.records.push(r),
    ...extra,
  });
}

test('explicit mainnet profile validates only its known genesis and HTTPS', () => {
  assert.equal(parseNetwork(base()).cluster, 'mainnet-beta');
  for (const patch of [
    { genesis: GENESIS.devnet },
    { rpc: 'http://rpc.invalid/' },
    { rpc: 'https://secret@rpc.invalid/' },
    { rpc: 'https://rpc.invalid/#x' },
    { upgradeAuthority: pub(1).toBase58() },
    { programSha256: 'AB'.repeat(32) },
    { programSize: 0 },
    { unknown: 1 },
  ])
    assert.throws(() => parseNetwork({ ...base(), ...patch }));
});
test('RPC reporting another cluster is rejected before inspecting program code', async () => {
  const c = rpc();
  c.getGenesisHash = async () => GENESIS.devnet;
  await assert.rejects(inspectDeployment(c, base()), /another cluster/);
});
test('immutable loader-v2 program bytes are checked including zero padding', async () => {
  const c = rpc();
  c.accounts.get(base().program).data = concat(code, new Uint8Array(20));
  assert.equal((await inspectDeployment(c, base())).immutable, true);
  c.accounts.get(base().program).data = concat(code, Uint8Array.of(1));
  await assert.rejects(inspectDeployment(c, base()), /binary/);
});
test('wrong binary, wrong loader, and missing executable deployment are rejected', async () => {
  for (const patch of [
    { data: new Uint8Array(code.length) },
    { owner: pub(9) },
    { executable: false },
  ]) {
    const c = rpc();
    Object.assign(c.accounts.get(base().program), patch);
    await assert.rejects(inspectDeployment(c, base()));
  }
});
test('loader-v3 checks ProgramData derivation, owner, and immutable authority', async () => {
  const c = rpc(),
    [pd] = await PublicKey.findProgramAddress([pub(5).toBytes()], UPGRADEABLE_LOADER);
  const head = concat(Uint8Array.of(2, 0, 0, 0), pd.toBytes()),
    data = concat(Uint8Array.of(3, 0, 0, 0), u64(12n), new Uint8Array(33), code);
  c.accounts.set(base().program, { executable: true, owner: UPGRADEABLE_LOADER, data: head });
  c.accounts.set(pd.toBase58(), { executable: false, owner: UPGRADEABLE_LOADER, data });
  assert.equal((await inspectDeployment(c, base())).deployedSlot, '12');
  data[12] = 1;
  data.set(pub(8).toBytes(), 13);
  await assert.rejects(inspectDeployment(c, base()), /authority/);
  data[12] = 0;
  c.accounts.get(pd.toBase58()).owner = pub(8);
  await assert.rejects(inspectDeployment(c, base()), /owner/);
});
test('network session binds connection identity and refreshes deployment checks', async () => {
  const c = rpc(),
    session = await openNetwork(base(), c);
  await assert.rejects(assertNetwork(rpc(), session), /mismatched/);
  await assert.rejects(assertNetwork(c, { ...session }), /Unknown/);
  c.accounts.get(base().program).data = new Uint8Array(code.length);
  await assert.rejects(assertNetwork(c, session), /binary/);
});
test('unconfigured remote connection cannot use the legacy local path', async () => {
  await assert.rejects(guardConnection(rpc()), /explicitly validated/);
});
test('simulation and fee ceiling are enforced before any broadcast', async () => {
  let c = rpc();
  c.simulateTransaction = async () => ({
    value: { err: { InstructionError: [0, 'InvalidArgument'] } },
  });
  await assert.rejects(send(c), /Simulation rejected/);
  assert.equal(c.calls.sends, 0);
  c = rpc();
  c.getFeeForMessage = async () => ({ value: 100001n });
  await assert.rejects(send(c), /fee exceeds/);
  assert.equal(c.calls.sends, 0);
  c = rpc();
  c.getFeeForMessage = async () => ({ value: null });
  await assert.rejects(send(c), /quote/);
  assert.equal(c.calls.sends, 0);
});
test('signed signature is journaled before broadcast and success requires finalized metadata', async () => {
  const c = rpc(),
    result = await send(c);
  assert.equal(result.phase, 'confirmed');
  assert.equal(result.commitment, 'finalized');
  assert.equal(c.calls.sends, 1);
  assert.equal(c.calls.records[0].signature, result.signature);
  assert.equal(result.feeLamports, '5000');
});
test('expired preflight blockhash is never broadcast', async () => {
  const c = rpc();
  c.getBlockHeight = async () => 101n;
  await assert.rejects(send(c), /expired before/);
  assert.equal(c.calls.sends, 0);
});
test('ambiguous submission returns its original signature and never re-signs or resends', async () => {
  const c = rpc();
  c.sendRawTransaction = async () => {
    c.calls.sends++;
    throw new Error('connection reset');
  };
  await assert.rejects(
    send(c),
    (e) => e instanceof SubmissionUncertain && e.signature === c.calls.records[0].signature,
  );
  assert.equal(c.calls.sends, 1);
});
test('timeout with no status is unknown rather than reported as successful', async () => {
  const c = rpc();
  c.getSignatureStatuses = async () => ({ value: [null] });
  await assert.rejects(send(c, { confirmationTimeoutMs: 3 }), SubmissionUncertain);
  assert.equal(c.calls.sends, 1);
});
test('confirmed instruction error is not mistaken for a successful transfer', async () => {
  const c = rpc();
  c.getTransaction = async () => ({
    slot: 70n,
    meta: { err: { InstructionError: [0, 'Custom'] }, fee: 5000n },
  });
  await assert.rejects(send(c), /execution error/);
  assert.equal(c.calls.records.at(-1).phase, 'confirmed');
});
test('arbitrary outer program instructions are blocked', async () => {
  const c = rpc(),
    network = await openNetwork(base(), c),
    payer = await Keypair.generate();
  await assert.rejects(
    submitNetwork(
      c,
      payer,
      [new TransactionInstruction({ programId: pub(9), keys: [], data: Buffer.alloc(0) })],
      { network },
    ),
    /pinned wallet program/,
  );
  assert.equal(c.calls.sends, 0);
});
test('exact SOL parsing has no floating-point rounding or implicit truncation', () => {
  assert.equal(parseUnits('0.000000001'), 1n);
  assert.equal(parseUnits('1.25'), 1250000000n);
  assert.equal(parseUnits('18446744073.709551615'), 0xffffffffffffffffn);
  assert.equal(parseUnits('9', 0), 9n);
  for (const s of [
    '0',
    '01',
    '-1',
    '+1',
    '1e9',
    '1.',
    ' 1',
    '1.0000000001',
    '18446744073.709551616',
  ])
    assert.throws(() => parseUnits(s));
  assert.throws(() => integerAmount(Number.MAX_SAFE_INTEGER + 1));
});
test('descriptor validation recomputes the permanent address and initial policy commitment', async () => {
  const d = await createDescriptor({
    program: pub(5),
    genesis: GENESIS['mainnet-beta'],
    salt: new Uint8Array(32).fill(1),
    policy: { keys: [new Uint8Array(32).fill(3)], threshold: 1 },
  });
  assert.deepEqual(await parseDescriptor(JSON.stringify(d)), d);
  for (const patch of [
    { wallet: pub(8).toBase58() },
    { id: '00'.repeat(32) },
    { initialPolicy: { ...d.initialPolicy, keys: ['04'.repeat(32)] } },
    { extra: 1 },
  ])
    await assert.rejects(parseDescriptor({ ...d, ...patch }));
});
test('wallet status and transfer preparation verify state and retain rent', async () => {
  const c = rpc(),
    network = await openNetwork(base(), c);
  const d = await createDescriptor({
    program: pub(5),
    genesis: network.genesis,
    salt: new Uint8Array(32).fill(1),
    policy: { keys: [new Uint8Array(32).fill(3)], threshold: 1 },
  });
  assert.equal((await walletStatus(network, d)).initialized, false);
  const derived = await deriveWallet(
    d.program,
    d.genesis,
    new Uint8Array(32).fill(1),
    d.initialPolicy,
  );
  const data = concat(
    new TextEncoder().encode('QSWAL001'),
    Uint8Array.of(derived.bump),
    derived.id,
    address(d.genesis).toBytes(),
    encodePolicy(d.initialPolicy),
    u64(0n),
    u64(0n),
    u64(0n),
    new Uint8Array(98),
    Uint8Array.of(0),
  );
  c.accounts.set(d.wallet, { owner: pub(5), data, lamports: 1000000000n, executable: false });
  const s = await walletStatus(network, d);
  assert.equal(s.availableLamports, 999999000n);
  const prepared = await prepareSolTransfer(network, d, { to: pub(6), amount: '0.1' });
  assert.equal(prepared.bytes.length, 162);
  await assert.rejects(prepareSolTransfer(network, d, { to: pub(6), amount: '1' }), /rent reserve/);
  await assert.rejects(
    prepareSolTransfer(network, d, { to: pub(6), amount: '0.000000001' }),
    /recipient/,
  );
  await assert.rejects(prepareSolTransfer(network, d, { to: d.wallet, amount: '0.1' }), /Self/);
  assert.equal(c.calls.sends, 0);
});
