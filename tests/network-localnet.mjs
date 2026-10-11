import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { Keypair, PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hex, concat, u64, encodeIntent, decodeIntent } from '../sdk/src/codec.mjs';
import { generateKeypair, signApproval, serializeApproval } from '../sdk/src/crypto.mjs';
import { openNetwork } from '../sdk/src/network.mjs';
import {
  createDescriptor,
  walletStatus,
  initializeWallet,
  prepareSolTransfer,
  prepareTokenTransfer,
  executeApprovals,
} from '../sdk/src/wallet.mjs';
import { TOKEN_PROGRAM, executeInstruction } from '../sdk/src/instructions.mjs';
import { submit, uploadApproval } from '../sdk/src/client.mjs';

if (process.env.QS_ISOLATED_LOCALNET !== '1')
  throw new Error('Run only inside the network-disabled local validator container.');
const events = [],
  assertions = [];
const report = {
  status: 'running',
  environment:
    'network-disabled Docker; real local validator; new network client, synthetic funds only',
  startedAt: new Date().toISOString(),
  events,
  assertions,
};
const persist = () =>
  writeFileSync(
    'evidence/network-localnet.json',
    JSON.stringify(report, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2) + '\n',
  );
const record = (r) => {
  events.push(r);
  persist();
};
const check = (name) => {
  assertions.push(name);
  console.log(`PASS ${name}`);
  persist();
};
const owner = generateKeypair();
try {
  const old = JSON.parse(readFileSync('evidence/localnet.json'));
  assert.equal(old.status, 'passed');
  const binary = readFileSync('target/deploy/seal_wallet.so');
  const config = {
    format: 'quantum-seal/network/1',
    cluster: 'localnet',
    rpc: 'http://127.0.0.1:18899/',
    genesis: old.genesis,
    program: old.program,
    programSha256: hex(sha256(binary)),
    programSize: binary.length,
    upgradeAuthority: null,
  };
  const network = await openNetwork(config);
  Object.assign(report, {
    genesis: network.genesis,
    program: network.program,
    programSha256: network.programSha256,
    immutable: network.immutable,
  });
  check('deployed SBF binary and immutable loader match pinned artifact');
  const payer = await Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync('.runtime/relayer.keypair.json'))),
  );
  const descriptor = await createDescriptor({
    program: network.program,
    genesis: network.genesis,
    policy: { keys: [owner.publicKey], threshold: 1 },
  });
  report.wallet = descriptor.wallet;
  assert.equal((await walletStatus(network, descriptor)).initialized, false);
  const init = await initializeWallet(network, payer, descriptor, {
    onRecord: record,
    computeUnitPrice: 1n,
  });
  assert.equal(init.receipt.error, null);
  const again = await initializeWallet(network, payer, descriptor, { onRecord: record });
  assert.equal(again.alreadyInitialized, true);
  check('creation initializes the PDA; repeated initialization does not spend again');
  const recipient = (await Keypair.generate()).publicKey;
  await submit(
    network.connection,
    payer,
    [
      SystemProgram.transfer({
        fromPubkey: payer.publicKey,
        toPubkey: new PublicKey(descriptor.wallet),
        lamports: 1000000000n,
      }),
    ],
    { label: 'synthetic-deposit', onRecord: record },
  );
  const prepared = await prepareSolTransfer(network, descriptor, {
    to: recipient,
    amount: '0.01',
    expiresInSlots: 20000n,
  });
  const approval = serializeApproval(signApproval(prepared.bytes, owner.secretKey, 0));
  writeFileSync('.runtime/network-approval.json', approval, { mode: 0o600 });
  const verify = spawnSync(
    'target/release/seal-verify',
    ['--proof', '.runtime/network-approval.json', '--key', hex(owner.publicKey)],
    { encoding: 'utf8' },
  );
  assert.equal(verify.status, 0, verify.stderr);
  check('independent Rust CLI verifies the new network-client approval');
  let chunks = 0;
  await assert.rejects(
    executeApprovals(network, payer, descriptor, [approval], {
      onRecord: (r) => {
        record(r);
        if (r.phase === 'confirmed' && r.label === 'upload-chunk' && ++chunks === 4)
          throw new Error('injected interruption');
      },
    }),
    /injected interruption/,
  );
  const sent = await executeApprovals(network, payer, descriptor, [approval], {
    onRecord: record,
    computeUnitPrice: 1n,
  });
  assert.equal(sent.executed, true);
  assert.equal(sent.cleanupErrors.length, 0);
  assert.equal(await network.connection.getBalance(recipient, 'confirmed'), 10000000n);
  assert.equal((await walletStatus(network, descriptor)).state.nonce, 1n);
  assert.equal(
    events.filter((e) => e.phase === 'confirmed' && e.label.includes('upload-chunk')).length,
    11,
  );
  check('interrupted proof upload resumes with exactly eleven total chunks');
  check('1-of-1 SLH-DSA authorization transfers exact SOL and advances nonce once');
  check('successful execution reclaims temporary proof rent');
  const before = events.length;
  await assert.rejects(
    executeApprovals(network, payer, descriptor, [approval], { onRecord: record }),
    /replayed/,
  );
  assert.equal(events.length, before);
  check('replayed approval is rejected before spending additional fees');

  // Fee refund (version-2 intent): the wallet reimburses the fee payer it names.
  const refund = 90000n;
  const refunded = await prepareSolTransfer(network, descriptor, {
    to: recipient,
    amount: '0.003',
    expiresInSlots: 20000n,
    feeRefund: { to: payer.publicKey, lamports: refund },
  });
  assert.equal(refunded.bytes[0], 2);
  const refundApproval = serializeApproval(signApproval(refunded.bytes, owner.secretKey, 0));
  const refundProof = await uploadApproval(network.connection, payer, refundApproval, {
    network,
    expectedProgram: network.program,
    expectedWallet: descriptor.wallet,
    onRecord: record,
  });
  // Pointing the refund at any other account must fail even with a valid proof.
  const tampered = executeInstruction(refunded.bytes, [refundProof]);
  tampered.keys[tampered.keys.length - 1] = {
    pubkey: recipient,
    isWritable: true,
    isSigner: false,
  };
  await assert.rejects(
    submit(network.connection, payer, [tampered], {
      network,
      label: 'tampered-refund',
      onRecord: record,
    }),
    /Simulation rejected/,
  );
  check('execution rejects a fee-refund account other than the signed one');
  const walletBefore = (await walletStatus(network, descriptor)).balanceLamports;
  const recipientBefore = BigInt(await network.connection.getBalance(recipient, 'confirmed'));
  let executeFee = 0n,
    payerBeforeExecute = null;
  const refundedSend = await executeApprovals(network, payer, descriptor, [refundApproval], {
    onRecord: async (r) => {
      if (r.label.startsWith('execute-wallet-transfer') && r.phase === 'prepared')
        payerBeforeExecute = BigInt(
          await network.connection.getBalance(payer.publicKey, 'confirmed'),
        );
      if (r.label.startsWith('execute-wallet-transfer') && r.phase === 'confirmed')
        executeFee = BigInt(r.feeLamports);
      record(r);
    },
  });
  assert.equal(refundedSend.executed, true);
  const walletAfter = (await walletStatus(network, descriptor)).balanceLamports;
  assert.equal(walletBefore - walletAfter, 3000000n + refund);
  assert.equal(
    BigInt(await network.connection.getBalance(recipient, 'confirmed')) - recipientBefore,
    3000000n,
  );
  const executeRecord = events.findLast(
    (e) => e.label.startsWith('execute-wallet-transfer') && e.phase === 'confirmed',
  );
  const executeTx = await network.connection.getTransaction(executeRecord.signature, {
    commitment: 'confirmed',
    maxSupportedTransactionVersion: 0,
  });
  const payerIndex = executeTx.transaction.message.staticAccountKeys.findIndex((k) =>
    k.equals(payer.publicKey),
  );
  assert.equal(
    BigInt(executeTx.meta.postBalances[payerIndex]) -
      BigInt(executeTx.meta.preBalances[payerIndex]),
    // The same transaction also closes the proof account, returning its deposit.
    refund + BigInt(await network.connection.getMinimumBalanceForRentExemption(8049)) - executeFee,
  );
  assert.ok(payerBeforeExecute !== null);
  check('a version-2 transfer pays the exact signed fee refund from the wallet');

  // Adversarial proofs: a proof verified for another wallet, and the same owner's
  // approval uploaded twice by different uploaders, must not authorize anything.
  const otherOwner = generateKeypair();
  const other = await createDescriptor({
    program: network.program,
    genesis: network.genesis,
    policy: { keys: [otherOwner.publicKey], threshold: 1 },
  });
  await initializeWallet(network, payer, other, { onRecord: record });
  await submit(
    network.connection,
    payer,
    [
      SystemProgram.transfer({
        fromPubkey: payer.publicKey,
        toPubkey: new PublicKey(other.wallet),
        lamports: 100000000n,
      }),
    ],
    { label: 'synthetic-deposit', onRecord: record },
  );
  const otherIntent = await prepareSolTransfer(network, other, {
    to: recipient,
    amount: '0.001',
    expiresInSlots: 20000n,
  });
  const otherProof = await uploadApproval(
    network.connection,
    payer,
    serializeApproval(signApproval(otherIntent.bytes, otherOwner.secretKey, 0)),
    { network, expectedProgram: network.program, expectedWallet: other.wallet, onRecord: record },
  );
  const mine = await prepareSolTransfer(network, descriptor, {
    to: recipient,
    amount: '0.001',
    expiresInSlots: 20000n,
  });
  await assert.rejects(
    submit(network.connection, payer, [executeInstruction(mine.bytes, [otherProof])], {
      network,
      label: 'foreign-wallet-proof',
      onRecord: record,
    }),
    /"Custom":"?7013"?/,
  );
  check('a proof verified for another wallet cannot authorize this wallet');
  const mineApproval = serializeApproval(signApproval(mine.bytes, owner.secretKey, 0));
  const secondUploader = await Keypair.generate();
  await submit(
    network.connection,
    payer,
    [
      SystemProgram.transfer({
        fromPubkey: payer.publicKey,
        toPubkey: secondUploader.publicKey,
        lamports: 200000000n,
      }),
    ],
    { label: 'fund-second-uploader', onRecord: record },
  );
  const upload = (who) =>
    uploadApproval(network.connection, who, mineApproval, {
      network,
      expectedProgram: network.program,
      expectedWallet: descriptor.wallet,
      onRecord: record,
    });
  const firstCopy = await upload(payer),
    secondCopy = await upload(secondUploader);
  assert.ok(!firstCopy.equals(secondCopy));
  const nonceBefore = (await walletStatus(network, descriptor)).state.nonce;
  await assert.rejects(
    submit(network.connection, payer, [executeInstruction(mine.bytes, [firstCopy, secondCopy])], {
      network,
      label: 'duplicate-owner-approval',
      onRecord: record,
    }),
    /"Custom":"?7012"?/,
  );
  assert.equal((await walletStatus(network, descriptor)).state.nonce, nonceBefore);
  check('one owner approval uploaded twice by different uploaders counts once');
  otherOwner.secretKey.fill(0);

  // Account-layout edge cases around the fee refund.
  const edge = await prepareSolTransfer(network, descriptor, {
    to: recipient,
    amount: '0.001',
    expiresInSlots: 20000n,
    // An account that appears nowhere else in the transaction: the fee payer and the
    // transfer target are writable at the transaction level, which overrides a read-only meta.
    feeRefund: { to: secondUploader.publicKey, lamports: refund },
  });
  const edgeProof = await uploadApproval(
    network.connection,
    payer,
    serializeApproval(signApproval(edge.bytes, owner.secretKey, 0)),
    {
      network,
      expectedProgram: network.program,
      expectedWallet: descriptor.wallet,
      onRecord: record,
    },
  );
  const readOnlyFee = executeInstruction(edge.bytes, [edgeProof]);
  readOnlyFee.keys[readOnlyFee.keys.length - 1] = { ...readOnlyFee.keys.at(-1), isWritable: false };
  await assert.rejects(
    submit(network.connection, payer, [readOnlyFee], {
      network,
      label: 'read-only-refund',
      onRecord: record,
    }),
    /"Custom":"?7005"?/,
  );
  check('a read-only fee-refund account is rejected');
  const v1 = await prepareSolTransfer(network, descriptor, {
    to: recipient,
    amount: '0.001',
    expiresInSlots: 20000n,
  });
  const v1Proof = await uploadApproval(
    network.connection,
    payer,
    serializeApproval(signApproval(v1.bytes, owner.secretKey, 0)),
    {
      network,
      expectedProgram: network.program,
      expectedWallet: descriptor.wallet,
      onRecord: record,
    },
  );
  const extra = executeInstruction(v1.bytes, [v1Proof]);
  extra.keys.push({ pubkey: payer.publicKey, isWritable: true, isSigner: false });
  await assert.rejects(
    submit(network.connection, payer, [extra], {
      network,
      label: 'v1-extra-account',
      onRecord: record,
    }),
    /"Custom":"?7022"?/,
  );
  check('a version-1 intent with an extra trailing account is rejected');
  // Refund recipient equal to the transfer target: both amounts arrive.
  const same = await prepareSolTransfer(network, descriptor, {
    to: recipient,
    amount: '0.002',
    expiresInSlots: 20000n,
    feeRefund: { to: recipient, lamports: refund },
  });
  const sameBefore = BigInt(await network.connection.getBalance(recipient, 'confirmed'));
  const sameSent = await executeApprovals(
    network,
    payer,
    descriptor,
    [serializeApproval(signApproval(same.bytes, owner.secretKey, 0))],
    { onRecord: record },
  );
  assert.equal(sameSent.executed, true);
  assert.equal(
    BigInt(await network.connection.getBalance(recipient, 'confirmed')) - sameBefore,
    2000000n + refund,
  );
  check('a fee refund to the transfer recipient pays both amounts');

  // The program itself refuses approvals that expire beyond the one-day horizon.
  const state = (await walletStatus(network, descriptor)).state;
  const far = encodeIntent({
    genesis: new PublicKey(network.genesis),
    program: new PublicKey(network.program),
    wallet: new PublicKey(descriptor.wallet),
    epoch: state.epoch,
    nonce: state.nonce,
    expiry: BigInt(await network.connection.getSlot('confirmed')) + 300000n,
    action: { kind: 'transfer', to: recipient, lamports: 1000n },
  });
  assert.equal(decodeIntent(far).fee, null);
  await assert.rejects(
    uploadApproval(
      network.connection,
      payer,
      serializeApproval(signApproval(far, owner.secretKey, 0)),
      {
        network,
        expectedProgram: network.program,
        expectedWallet: descriptor.wallet,
        onRecord: record,
      },
    ),
    /Simulation rejected/,
  );
  check('the program refuses approvals that expire beyond the horizon');
  // Create synthetic classic SPL accounts only inside the isolated validator.
  const mint = await Keypair.generate(),
    source = await Keypair.generate(),
    destination = await Keypair.generate();
  const m = (pubkey, isWritable = false, isSigner = false) => ({ pubkey, isWritable, isSigner });
  const ix = (keys, data) =>
    new TransactionInstruction({ programId: TOKEN_PROGRAM, keys, data: Buffer.from(data) });
  const local = (instructions, extraSigners = []) =>
    submit(network.connection, payer, instructions, {
      extraSigners,
      onRecord: record,
      label: 'synthetic-token-setup',
    });
  await local(
    [
      SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: mint.publicKey,
        lamports: await network.connection.getMinimumBalanceForRentExemption(82),
        space: 82,
        programId: TOKEN_PROGRAM,
      }),
      ix(
        [m(mint.publicKey, true)],
        concat(Uint8Array.of(20, 6), payer.publicKey.toBytes(), Uint8Array.of(0)),
      ),
    ],
    [mint],
  );
  for (const [account, authority] of [
    [source, new PublicKey(descriptor.wallet)],
    [destination, recipient],
  ])
    await local(
      [
        SystemProgram.createAccount({
          fromPubkey: payer.publicKey,
          newAccountPubkey: account.publicKey,
          lamports: await network.connection.getMinimumBalanceForRentExemption(165),
          space: 165,
          programId: TOKEN_PROGRAM,
        }),
        ix(
          [m(account.publicKey, true), m(mint.publicKey)],
          concat(Uint8Array.of(18), authority.toBytes()),
        ),
      ],
      [account],
    );
  await local([
    ix(
      [m(mint.publicKey, true), m(source.publicKey, true), m(payer.publicKey, false, true)],
      concat(Uint8Array.of(7), u64(10000000n)),
    ),
  ]);
  const token = await prepareTokenTransfer(network, descriptor, {
    source: source.publicKey,
    mint: mint.publicKey,
    destination: destination.publicKey,
    amount: '1.25',
    expiresInSlots: 20000n,
    feeRefund: { to: payer.publicKey, lamports: 50000n },
  });
  const tokenWalletBefore = (await walletStatus(network, descriptor)).balanceLamports;
  const tokenApproval = serializeApproval(signApproval(token.bytes, owner.secretKey, 0));
  const tokenSent = await executeApprovals(network, payer, descriptor, [tokenApproval], {
    onRecord: record,
  });
  assert.equal(tokenSent.executed, true);
  assert.equal(tokenSent.cleanupErrors.length, 0);
  assert.equal(
    String((await network.connection.getTokenAccountBalance(destination.publicKey)).value.amount),
    '1250000',
  );
  assert.equal(
    tokenWalletBefore - (await walletStatus(network, descriptor)).balanceLamports,
    50000n,
  );
  check('classic SPL amount is read from mint decimals and transferred exactly');
  check('a token transfer through the CPI path also pays its signed fee refund');
  writeFileSync('.runtime/network-test.network.json', JSON.stringify(config));
  writeFileSync('.runtime/network-wallet.json', JSON.stringify(descriptor));
  const cli = (args) =>
    spawnSync(process.execPath, ['sdk/src/network-cli.mjs', ...args], {
      encoding: 'utf8',
      env: process.env,
    });
  let run = cli(['check-network', '--config', '.runtime/network-test.network.json']);
  assert.equal(run.status, 0, run.stderr);
  run = cli([
    'initialize',
    '--config',
    '.runtime/network-test.network.json',
    '--wallet',
    '.runtime/network-wallet.json',
    '--payer',
    payer.publicKey.toBase58(),
    '--fee-payer',
    '/nonexistent/never-read',
  ]);
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /PLAN ONLY/);
  check('network CLI checks deployment and plans without loading a fee-payer key');
  run = cli([
    'initialize',
    '--config',
    '.runtime/network-test.network.json',
    '--wallet',
    '.runtime/network-wallet.json',
    '--payer',
    payer.publicKey.toBase58(),
    '--broadcast',
    '--fee-payer',
    '/nonexistent/never-read',
    '--receipt',
    '.runtime/no-broadcast.receipt.jsonl',
  ]);
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /interactive terminal/);
  check('noninteractive broadcast is rejected before reading fee-payer keys');
  if (existsSync('.runtime/network-cli-intent.bin')) unlinkSync('.runtime/network-cli-intent.bin');
  run = cli([
    'prepare-sol',
    '--config',
    '.runtime/network-test.network.json',
    '--wallet',
    '.runtime/network-wallet.json',
    '--to',
    recipient.toBase58(),
    '--amount',
    '0.002',
    '--out',
    '.runtime/network-cli-intent.bin',
  ]);
  assert.equal(run.status, 0, run.stderr);
  assert.equal(readFileSync('.runtime/network-cli-intent.bin').length, 162);
  check('CLI prepares an unsigned SOL intent against current live wallet state');
  const tx = events.filter((e) => e.phase === 'confirmed' || !e.phase);
  Object.assign(report, {
    status: 'passed',
    finishedAt: new Date().toISOString(),
    transactionCount: tx.length,
    maxWireBytes: Math.max(...tx.map((x) => x.bytes)),
    maxComputeUnits: Math.max(...tx.map((x) => Number(x.computeUnits ?? 0))),
    publicTransactions: 0,
  });
  persist();
  console.log('NETWORK CLIENT LOCALNET PASSED', tx.length, 'transactions');
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
  owner.secretKey.fill(0);
}
