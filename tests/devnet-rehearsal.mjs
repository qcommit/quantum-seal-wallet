// Devnet rehearsal: real create → SOL transfer → classic SPL transfer against the
// deployed program, under public-network conditions. Records every transaction's
// timing and fee in evidence/devnet-rehearsal.json.
//
// Requires QS_DEVNET_FUNDER (path to a funded devnet keypair JSON kept OUTSIDE this
// repository) and .runtime/devnet.network.json from `network-config`/`check-network`.
// Devnet SOL only; never point this at mainnet.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import {
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  Transaction,
} from '@solana/web3.js';
import { concat, u64 } from '../sdk/src/codec.mjs';
import { generateKeypair, signApproval, serializeApproval } from '../sdk/src/approval.mjs';
import { openNetwork, parseNetwork } from '../sdk/src/network.mjs';
import {
  createDescriptor,
  walletStatus,
  initializeWallet,
  prepareSolTransfer,
  prepareTokenTransfer,
  executeApprovals,
} from '../sdk/src/wallet.mjs';
import { TOKEN_PROGRAM } from '../sdk/src/instructions.mjs';

const config = parseNetwork(readFileSync('.runtime/devnet.network.json', 'utf8'));
assert.equal(config.cluster, 'devnet', 'This rehearsal runs on devnet only.');
const funder = await Keypair.fromSecretKey(
  Uint8Array.from(JSON.parse(readFileSync(process.env.QS_DEVNET_FUNDER, 'utf8'))),
);
const report = {
  status: 'running',
  cluster: 'devnet',
  startedAt: new Date().toISOString(),
  program: config.program,
  programSha256: config.programSha256,
  phases: [],
  transactions: [],
};
const persist = () =>
  writeFileSync(
    'evidence/devnet-rehearsal.json',
    JSON.stringify(report, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 2) + '\n',
  );
const pending = new Map();
const onRecord = (r) => {
  if (r.phase === 'prepared') pending.set(r.signature, Date.now());
  if (r.phase === 'confirmed') {
    report.transactions.push({
      label: r.label,
      signature: r.signature,
      fee: r.feeLamports,
      computeUnits: r.computeUnits,
      bytes: r.bytes,
      seconds: (Date.now() - (pending.get(r.signature) ?? Date.now())) / 1000,
      error: r.error,
    });
    persist();
  }
};
async function phase(name, fn) {
  const started = Date.now(),
    first = report.transactions.length;
  const result = await fn();
  const txs = report.transactions.slice(first);
  report.phases.push({
    name,
    seconds: (Date.now() - started) / 1000,
    transactions: txs.length,
    feeLamports: txs.reduce((n, t) => n + BigInt(t.fee), 0n).toString(),
  });
  persist();
  console.log(
    `${name}: ${txs.length} transactions in ${((Date.now() - started) / 1000).toFixed(1)} s`,
  );
  return result;
}

const owner = generateKeypair();
try {
  const network = await openNetwork(config);
  const { connection } = network;
  const payer = await Keypair.generate();
  report.feePayer = payer.publicKey.toBase58();
  const plain = async (instructions, signers) => {
    const latest = await connection.getLatestBlockhash('confirmed');
    const tx = new Transaction({
      feePayer: signers[0].publicKey,
      recentBlockhash: latest.blockhash,
    });
    tx.add(...instructions);
    await tx.sign(...signers);
    const sig = await connection.sendRawTransaction(await tx.serialize());
    await connection.confirmTransaction({ signature: sig, ...latest }, 'finalized');
    return sig;
  };
  await plain(
    [
      SystemProgram.transfer({
        fromPubkey: funder.publicKey,
        toPubkey: payer.publicKey,
        lamports: 400000000n,
      }),
    ],
    [funder],
  );
  const descriptor = await createDescriptor({
    program: network.program,
    genesis: network.genesis,
    policy: { keys: [owner.publicKey], threshold: 1 },
  });
  report.wallet = descriptor.wallet;
  await phase('create wallet', () => initializeWallet(network, payer, descriptor, { onRecord }));
  await plain(
    [
      SystemProgram.transfer({
        fromPubkey: funder.publicKey,
        toPubkey: new PublicKey(descriptor.wallet),
        lamports: 100000000n,
      }),
    ],
    [funder],
  );
  const recipient = (await Keypair.generate()).publicKey;
  const refund = 100000n;
  const payerBefore = BigInt(await connection.getBalance(payer.publicKey, 'finalized'));
  const sol = await prepareSolTransfer(network, descriptor, {
    to: recipient,
    amount: '0.01',
    feeRefund: { to: payer.publicKey, lamports: refund },
  });
  const signStart = performance.now();
  const solApproval = serializeApproval(signApproval(sol.bytes, owner.secretKey, 0));
  report.signMilliseconds = Math.round(performance.now() - signStart);
  const sent = await phase('SOL transfer (0.01 SOL, with fee refund)', () =>
    executeApprovals(network, payer, descriptor, [solApproval], { onRecord }),
  );
  assert.equal(sent.cleanupErrors.length, 0);
  assert.equal(BigInt(await connection.getBalance(recipient, 'finalized')), 10000000n);
  const payerAfter = BigInt(await connection.getBalance(payer.publicKey, 'finalized'));
  report.solTransfer = {
    recipientReceivedLamports: '10000000',
    feePayerNetLamports: (payerAfter - payerBefore).toString(),
    refundLamports: refund.toString(),
  };
  // Synthetic classic SPL token for the CPI path (devnet only).
  const mint = await Keypair.generate(),
    source = await Keypair.generate(),
    destination = await Keypair.generate();
  const m = (pubkey, isWritable = false, isSigner = false) => ({ pubkey, isWritable, isSigner });
  const tix = (keys, data) =>
    new TransactionInstruction({ programId: TOKEN_PROGRAM, keys, data: Buffer.from(data) });
  const rent82 = BigInt(await connection.getMinimumBalanceForRentExemption(82)),
    rent165 = BigInt(await connection.getMinimumBalanceForRentExemption(165));
  await plain(
    [
      SystemProgram.createAccount({
        fromPubkey: funder.publicKey,
        newAccountPubkey: mint.publicKey,
        lamports: rent82,
        space: 82,
        programId: TOKEN_PROGRAM,
      }),
      tix(
        [m(mint.publicKey, true)],
        concat(Uint8Array.of(20, 6), funder.publicKey.toBytes(), Uint8Array.of(0)),
      ),
      SystemProgram.createAccount({
        fromPubkey: funder.publicKey,
        newAccountPubkey: source.publicKey,
        lamports: rent165,
        space: 165,
        programId: TOKEN_PROGRAM,
      }),
      tix(
        [m(source.publicKey, true), m(mint.publicKey)],
        concat(Uint8Array.of(18), new PublicKey(descriptor.wallet).toBytes()),
      ),
      SystemProgram.createAccount({
        fromPubkey: funder.publicKey,
        newAccountPubkey: destination.publicKey,
        lamports: rent165,
        space: 165,
        programId: TOKEN_PROGRAM,
      }),
      tix(
        [m(destination.publicKey, true), m(mint.publicKey)],
        concat(Uint8Array.of(18), recipient.toBytes()),
      ),
      tix(
        [m(mint.publicKey, true), m(source.publicKey, true), m(funder.publicKey, false, true)],
        concat(Uint8Array.of(7), u64(5000000n)),
      ),
    ],
    [funder, mint, source, destination],
  );
  const token = await prepareTokenTransfer(network, descriptor, {
    source: source.publicKey,
    mint: mint.publicKey,
    destination: destination.publicKey,
    amount: '1.25',
    feeRefund: { to: payer.publicKey, lamports: refund },
  });
  const tokenApproval = serializeApproval(signApproval(token.bytes, owner.secretKey, 0));
  const tokenSent = await phase('SPL token transfer (1.25 tokens, with fee refund)', () =>
    executeApprovals(network, payer, descriptor, [tokenApproval], { onRecord }),
  );
  assert.equal(tokenSent.cleanupErrors.length, 0);
  assert.equal(
    String(
      (await connection.getTokenAccountBalance(destination.publicKey, 'finalized')).value.amount,
    ),
    '1250000',
  );
  const status = await walletStatus(network, descriptor);
  assert.equal(status.state.nonce, 2n);
  Object.assign(report, {
    status: 'passed',
    finishedAt: new Date().toISOString(),
    transactionCount: report.transactions.length,
    totalFeeLamports: report.transactions.reduce((n, t) => n + BigInt(t.fee), 0n).toString(),
    medianConfirmSeconds: (() => {
      const s = report.transactions.map((t) => t.seconds).sort((a, b) => a - b);
      return s[Math.floor(s.length / 2)];
    })(),
  });
  persist();
  console.log('DEVNET REHEARSAL PASSED', report.transactionCount, 'transactions');
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
