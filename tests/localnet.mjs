import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from '@solana/web3.js';
import { generateKeypair, signApproval, parseApproval } from '../sdk/src/crypto.mjs';
import {
  encodeIntent,
  decodeWallet,
  decodeProofHeader,
  deriveWallet,
  concat,
  u64,
  hex,
  MAX_CHUNK_BYTES,
} from '../sdk/src/codec.mjs';
import {
  initializeInstruction,
  executeInstruction,
  beginInstruction,
  appendInstruction,
  sealInstruction,
  stepInstruction,
  closeProofInstruction,
  finalizeRecoveryInstruction,
  tokenTransferAction,
  TOKEN_PROGRAM,
} from '../sdk/src/instructions.mjs';
import { submit, uploadApproval, walletState } from '../sdk/src/client.mjs';

if (process.env.QS_ISOLATED_LOCALNET !== '1')
  throw new Error('Run npm run test:localnet inside the isolated test container.');
const connection = new Connection('http://127.0.0.1:18899', 'confirmed');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const records = [],
  assertions = [];
const report = {
  status: 'running',
  environment: 'network-disabled Docker; local validator; synthetic funds only',
  startedAt: new Date().toISOString(),
  records,
  assertions,
};
const persist = () =>
  writeFileSync(
    'evidence/localnet.json',
    JSON.stringify(
      report,
      (_, value) => (typeof value === 'bigint' ? value.toString() : value),
      2,
    ) + '\n',
  );
const check = (name, fn) => {
  fn();
  assertions.push(name);
  console.log(`PASS ${name}`);
  persist();
};
const onRecord = (r) => {
  records.push(r);
  console.log(`${r.error ? 'REJECT' : 'TX'} ${r.label}: ${r.computeUnits} CU, ${r.bytes} bytes`);
  persist();
};
const send = (ixs, options = {}) => submit(connection, payer, ixs, { onRecord, ...options });
const rejected = async (label, ixs, code, extraSigners = []) => {
  const r = await send(ixs, { label, expectFailure: true, extraSigners });
  if (code !== undefined)
    assert.equal(
      r.error?.InstructionError?.[1]?.Custom,
      code,
      `${label}: ${JSON.stringify(r.error)}`,
    );
  assertions.push(label);
  return r;
};
let payer, program, wallet, genesis;
const keys = [];
try {
  for (let i = 0; i < 180; i++) {
    try {
      genesis = new PublicKey(await connection.getGenesisHash());
      break;
    } catch {
      await sleep(500);
    }
  }
  if (!genesis) throw new Error('Local validator failed to become ready.');
  payer = await Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync('.runtime/relayer.keypair.json'))),
  );
  program = new PublicKey(readFileSync('.runtime/program-id.txt', 'utf8').trim());
  Object.assign(report, {
    genesis: genesis.toBase58(),
    program: program.toBase58(),
    validator: await connection.getVersion(),
  });
  for (let i = 0; i < 4; i++) keys.push(generateKeypair());
  const [a, b, c, guardian] = keys;
  const policy = {
    keys: [a.publicKey, b.publicKey],
    threshold: 2,
    guardian: guardian.publicKey,
    recoveryDelay: 150n,
  };
  const salt = randomBytes(32),
    init = await initializeInstruction({ program, payer: payer.publicKey, genesis, salt, policy });
  wallet = init.wallet;
  report.wallet = wallet.toBase58();
  report.walletRentLamports = (await connection.getMinimumBalanceForRentExemption(334)).toString();
  report.proofRentLamports = (await connection.getMinimumBalanceForRentExemption(8049)).toString();
  await send(
    [SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: wallet, lamports: 1000000n })],
    { label: 'prefund-dust' },
  );
  await send([init.instruction], { label: 'initialize-2-of-2' });
  let state = await walletState(connection, program, wallet);
  check('prefunded PDA initializes with the committed owner policy', () => {
    assert.equal(state.policy.threshold, 2);
    assert.equal(state.nonce, 0n);
  });
  await send(
    [
      SystemProgram.transfer({
        fromPubkey: payer.publicKey,
        toPubkey: wallet,
        lamports: 1000000000n,
      }),
    ],
    { label: 'deposit-sol' },
  );
  const to = (await Keypair.generate()).publicKey;
  // Keep the recipient rent-exempt before testing an ordinary transfer.
  await send(
    [SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: to, lamports: 1000000n })],
    { label: 'fund-recipient' },
  );
  const makeIntent = async (action, fee) => {
    const w = await walletState(connection, program, wallet);
    return encodeIntent({
      genesis,
      program,
      wallet,
      epoch: w.epoch,
      nonce: w.nonce,
      expiry: BigInt(await connection.getSlot('confirmed')) + 20000n,
      action,
      fee,
    });
  };
  const approve = async (bytes, key, index) =>
    uploadApproval(connection, payer, signApproval(bytes, key.secretKey, index), {
      expectedProgram: program,
      expectedWallet: wallet,
      onRecord,
    });
  const bytes = await makeIntent({ kind: 'transfer', to, lamports: 123456n });
  const p0 = await approve(bytes, a, 0),
    p1 = await approve(bytes, b, 1);
  await rejected('single approval cannot satisfy 2-of-2', [executeInstruction(bytes, [p0])], 7011);
  await rejected(
    'duplicate approval cannot satisfy threshold',
    [executeInstruction(bytes, [p0, p0])],
    7012,
  );
  const changed = bytes.slice();
  changed[changed.length - 1] ^= 1;
  await rejected(
    'signed transfer amount cannot be altered',
    [executeInstruction(changed, [p0, p1])],
    7013,
  );
  const before = BigInt(await connection.getBalance(to));
  await send([executeInstruction(bytes, [p0, p1])], { label: 'execute-pq-sol-transfer' });
  check('2-of-2 post-quantum authorization transfers exact SOL amount', () =>
    assert.equal(records.at(-1).error, null),
  );
  assert.equal(BigInt(await connection.getBalance(to)) - before, 123456n);
  await rejected('executed intent cannot be replayed', [executeInstruction(bytes, [p0, p1])], 7009);
  state = await walletState(connection, program, wallet);
  assert.equal(state.nonce, 1n);
  const originalId = hex(state.id);
  const rotated = {
    keys: [c.publicKey],
    threshold: 1,
    guardian: guardian.publicKey,
    recoveryDelay: 150n,
  };
  const rotateBytes = await makeIntent({ kind: 'rotate', policy: rotated });
  const r0 = await approve(rotateBytes, a, 0),
    r1 = await approve(rotateBytes, b, 1);
  await send([executeInstruction(rotateBytes, [r0, r1])], { label: 'rotate-owner-policy' });
  state = await walletState(connection, program, wallet);
  check('key rotation preserves the deposit address and advances epoch', () => {
    assert.equal(hex(state.id), originalId);
    assert.equal(state.epoch, 1n);
    assert.equal(hex(state.policy.keys[0]), hex(c.publicKey));
  });
  await rejected(
    'old epoch signatures remain invalid after rotation',
    [executeInstruction(bytes, [p0, p1])],
    7009,
  );
  const corruptIntent = await makeIntent({ kind: 'transfer', to, lamports: 17n });
  const corrupt = parseApproval(signApproval(corruptIntent, c.secretKey, 0));
  corrupt.signature[7855] ^= 1;
  const started = await beginInstruction(corruptIntent, 0, payer.publicKey);
  const opts = { program, wallet, proof: started.proof, uploader: payer.publicKey };
  await send([started.instruction], { label: 'begin-corrupt-proof' });
  await rejected('incomplete upload cannot be sealed', [sealInstruction(opts)], 7006);
  await rejected(
    'upload offsets cannot skip bytes',
    [appendInstruction({ ...opts, offset: 1, chunk: corrupt.signature.slice(0, 16) })],
    7007,
  );
  const stranger = await Keypair.generate();
  await rejected(
    'another uploader cannot modify proof bytes',
    [
      appendInstruction({
        ...opts,
        uploader: stranger.publicKey,
        offset: 0,
        chunk: corrupt.signature.slice(0, 16),
      }),
    ],
    7022,
    [stranger],
  );
  for (let offset = 0; offset < corrupt.signature.length; offset += MAX_CHUNK_BYTES) {
    await send(
      [
        appendInstruction({
          ...opts,
          offset,
          chunk: corrupt.signature.slice(offset, offset + MAX_CHUNK_BYTES),
        }),
      ],
      { label: 'upload-corrupt-chunk' },
    );
  }
  await send([sealInstruction(opts)], { label: 'seal-corrupt-proof' });
  await rejected(
    'sealed signature bytes cannot be overwritten',
    [appendInstruction({ ...opts, offset: 0, chunk: corrupt.signature.slice(0, 16) })],
    7006,
  );
  await rejected(
    'unverified proof cannot release funds',
    [executeInstruction(corruptIntent, [started.proof])],
    7006,
  );
  for (let i = 0; i < 7; i++)
    await send([stepInstruction(opts)], {
      label: i === 0 ? 'verify-fors' : `verify-xmss-${i - 1}`,
    });
  await rejected(
    'corrupted final signature component fails root comparison',
    [stepInstruction(opts)],
    7010,
  );
  state = await walletState(connection, program, wallet);
  check('failed signature verification does not consume the wallet nonce', () =>
    assert.equal(state.nonce, 2n),
  );
  await rejected(
    'only the original uploader can reclaim proof rent',
    [closeProofInstruction({ program, proof: started.proof, uploader: stranger.publicKey })],
    7022,
    [stranger],
  );
  await send([closeProofInstruction(opts)], { label: 'close-invalid-proof' });
  check('closing a proof reclaims its account', () => assert.equal(records.at(-1).error, null));
  assert.equal(await connection.getAccountInfo(started.proof), null);

  const expired = encodeIntent({
    genesis,
    program,
    wallet,
    epoch: state.epoch,
    nonce: state.nonce,
    expiry: BigInt(await connection.getSlot()) - 1n,
    action: { kind: 'transfer', to, lamports: 1n },
  });
  await rejected(
    'expired authorizations cannot begin uploading',
    [(await beginInstruction(expired, 0, payer.publicKey)).instruction],
    7008,
  );

  const mint = await Keypair.generate(),
    source = await Keypair.generate(),
    destination = await Keypair.generate();
  const mintRent = await connection.getMinimumBalanceForRentExemption(82);
  const accountRent = await connection.getMinimumBalanceForRentExemption(165);
  const tokenIx = (accounts, data) =>
    new TransactionInstruction({
      programId: TOKEN_PROGRAM,
      keys: accounts,
      data: Buffer.from(data),
    });
  const m = (pubkey, isWritable = false, isSigner = false) => ({ pubkey, isWritable, isSigner });
  await send(
    [
      SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: mint.publicKey,
        lamports: mintRent,
        space: 82,
        programId: TOKEN_PROGRAM,
      }),
      tokenIx(
        [m(mint.publicKey, true)],
        concat(Uint8Array.of(20, 6), payer.publicKey.toBytes(), Uint8Array.of(0)),
      ),
    ],
    { label: 'create-test-mint', extraSigners: [mint] },
  );
  for (const [account, owner] of [
    [source, wallet],
    [destination, to],
  ]) {
    await send(
      [
        SystemProgram.createAccount({
          fromPubkey: payer.publicKey,
          newAccountPubkey: account.publicKey,
          lamports: accountRent,
          space: 165,
          programId: TOKEN_PROGRAM,
        }),
        tokenIx(
          [m(account.publicKey, true), m(mint.publicKey)],
          concat(Uint8Array.of(18), owner.toBytes()),
        ),
      ],
      { label: 'create-test-token-account', extraSigners: [account] },
    );
  }
  await send(
    [
      tokenIx(
        [m(mint.publicKey, true), m(source.publicKey, true), m(payer.publicKey, false, true)],
        concat(Uint8Array.of(7), u64(1000000n)),
      ),
    ],
    { label: 'mint-synthetic-test-tokens' },
  );
  const transferAction = tokenTransferAction({
    source: source.publicKey,
    mint: mint.publicKey,
    destination: destination.publicKey,
    wallet,
    amount: 10000n,
    decimals: 6,
  });
  const tokenBytes = await makeIntent(transferAction),
    tokenProof = await approve(tokenBytes, c, 0);
  await send([executeInstruction(tokenBytes, [tokenProof])], { label: 'execute-pq-spl-transfer' });
  const balance = await connection.getTokenAccountBalance(destination.publicKey);
  check('PDA authority transfers classic SPL tokens through signed CPI', () =>
    assert.equal(balance.value.amount.toString(), '10000'),
  );
  const failAction = tokenTransferAction({
    source: source.publicKey,
    mint: mint.publicKey,
    destination: destination.publicKey,
    wallet,
    amount: 10000000n,
    decimals: 6,
  });
  const failBytes = await makeIntent(failAction),
    failProof = await approve(failBytes, c, 0);
  const beforeFailure = await walletState(connection, program, wallet);
  await rejected('failing token CPI rolls back the entire wallet execution', [
    executeInstruction(failBytes, [failProof]),
  ]);
  const afterFailure = await walletState(connection, program, wallet);
  check('failed CPI preserves nonce and clears the transient execution lock', () => {
    assert.equal(afterFailure.nonce, beforeFailure.nonce);
    assert.equal(afterFailure.locked, false);
  });

  const guardianSpendBytes = await makeIntent({ kind: 'transfer', to, lamports: 5n }),
    guardianSpendProof = await approve(guardianSpendBytes, guardian, 255);
  await rejected(
    'a verified guardian approval cannot authorize spending',
    [executeInstruction(guardianSpendBytes, [guardianSpendProof])],
    7011,
  );
  const recoveryAction = { kind: 'recover', owners: { keys: [a.publicKey], threshold: 1 } };
  const refundedRecoveryBytes = await makeIntent(recoveryAction, {
      to: payer.publicKey,
      lamports: 10000000n,
    }),
    refundedRecoveryProof = await approve(refundedRecoveryBytes, guardian, 255);
  await rejected(
    'a guardian recovery proposal cannot carry a fee refund',
    [executeInstruction(refundedRecoveryBytes, [refundedRecoveryProof])],
    7024,
  );
  const recoveryBytes = await makeIntent(recoveryAction),
    recoveryProof = await approve(recoveryBytes, guardian, 255);
  const beforeProposal = await walletState(connection, program, wallet);
  await send([executeInstruction(recoveryBytes, [recoveryProof])], {
    label: 'guardian-proposes-recovery',
  });
  const afterProposal = await walletState(connection, program, wallet);
  check('a guardian proposal does not consume the owners nonce', () => {
    assert.equal(afterProposal.nonce, beforeProposal.nonce);
    assert.notEqual(afterProposal.recoveryReadyAt, 0n);
  });
  await rejected(
    'recovery cannot finalize before its delay',
    [finalizeRecoveryInstruction({ program, wallet })],
    7019,
  );
  const cancelBytes = await makeIntent({ kind: 'cancelRecovery' }),
    cancelProof = await approve(cancelBytes, c, 0);
  await send([executeInstruction(cancelBytes, [cancelProof])], { label: 'owner-vetoes-recovery' });
  await rejected(
    'cancelled recovery cannot be finalized',
    [finalizeRecoveryInstruction({ program, wallet })],
    7018,
  );
  const nextRecovery = await makeIntent(recoveryAction),
    nextProof = await approve(nextRecovery, guardian, 255);
  await send([executeInstruction(nextRecovery, [nextProof])], {
    label: 'guardian-proposes-new-recovery',
  });
  state = await walletState(connection, program, wallet);
  const deadline = Date.now() + 90000;
  while (
    BigInt(await connection.getSlot('confirmed')) < state.recoveryReadyAt &&
    Date.now() < deadline
  )
    await sleep(100);
  await send([finalizeRecoveryInstruction({ program, wallet })], {
    label: 'finalize-delayed-recovery',
  });
  state = await walletState(connection, program, wallet);
  check('delayed PQ recovery changes owners without changing the wallet address', () => {
    assert.equal(hex(state.id), originalId);
    assert.equal(hex(state.policy.keys[0]), hex(a.publicKey));
    assert.equal(state.epoch, 2n);
    assert.equal(state.recoveryReadyAt, 0n);
  });
  const recoveredBytes = await makeIntent({ kind: 'transfer', to, lamports: 31n }),
    recoveredProof = await approve(recoveredBytes, a, 0);
  await send([executeInstruction(recoveredBytes, [recoveredProof])], {
    label: 'recovered-owner-spends',
  });
  for (const proof of [
    p0,
    p1,
    r0,
    r1,
    tokenProof,
    failProof,
    guardianSpendProof,
    refundedRecoveryProof,
    recoveryProof,
    cancelProof,
    nextProof,
    recoveredProof,
  ]) {
    await send([closeProofInstruction({ program, proof, uploader: payer.publicKey })], {
      label: 'reclaim-proof-rent',
    });
  }
  Object.assign(report, {
    status: 'passed',
    finishedAt: new Date().toISOString(),
    transactionCount: records.length,
    rejectedTransactions: records.filter((r) => r.error).length,
    maxWireBytes: Math.max(...records.map((r) => r.bytes)),
    maxComputeUnits: Math.max(...records.map((r) => r.computeUnits)),
  });
  persist();
  console.log('LOCALNET PASSED', report.transactionCount, 'transactions');
} catch (error) {
  Object.assign(report, {
    status: 'failed',
    finishedAt: new Date().toISOString(),
    failure: error.stack,
  });
  persist();
  console.error(error);
  process.exitCode = 1;
} finally {
  for (const key of keys) key.secretKey.fill(0);
}
