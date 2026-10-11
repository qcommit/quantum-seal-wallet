import { Transaction, VersionedTransaction, ComputeBudgetProgram } from '@solana/web3.js';
import { assertNetwork } from './network.mjs';

export function integerAmount(value, label = 'amount') {
  if (typeof value === 'number' && !Number.isSafeInteger(value))
    throw new Error(`${label} must be an exact integer.`);
  if (
    !['number', 'bigint', 'string'].includes(typeof value) ||
    !/^(0|[1-9][0-9]*)$/.test(String(value))
  )
    throw new Error(`${label} must be a canonical unsigned integer.`);
  const result = BigInt(value);
  if (result > 0xffffffffffffffffn) throw new Error(`${label} exceeds u64.`);
  return result;
}

export function base58(bytes) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = 0n,
    out = '',
    zeroes = 0;
  for (const byte of bytes) n = (n << 8n) | BigInt(byte);
  for (const byte of bytes) {
    if (byte !== 0) break;
    zeroes++;
  }
  while (n) {
    out = alphabet[Number(n % 58n)] + out;
    n /= 58n;
  }
  return '1'.repeat(zeroes) + out;
}

export class SubmissionUncertain extends Error {
  constructor(signature, reason) {
    super(
      `${reason} Signature: ${signature}. Check its history and wallet nonce before retrying; no replacement transaction was signed.`,
    );
    this.name = 'SubmissionUncertain';
    this.signature = signature;
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function submitNetwork(connection, payer, instructions, options = {}) {
  const {
    network,
    label = 'transaction',
    onRecord = () => {},
    extraSigners = [],
    expectFailure = false,
    computeUnitPrice = 0n,
    maxFeeLamports = 100000n,
    confirmationTimeoutMs = 120000,
    pollIntervalMs = network?.cluster === 'localnet' ? 500 : 1500,
  } = options;
  const deployment = await assertNetwork(connection, network);
  const { commitment } = deployment;
  if (expectFailure || extraSigners.length)
    throw new Error(
      'Network submission does not accept expected-failure transactions or extra signers.',
    );
  if (
    !Array.isArray(instructions) ||
    !instructions.length ||
    instructions.some((ix) => ix.programId.toBase58() !== deployment.program)
  )
    throw new Error('Only instructions to the pinned wallet program may be submitted.');
  if (
    !Number.isInteger(confirmationTimeoutMs) ||
    confirmationTimeoutMs < 1 ||
    confirmationTimeoutMs > 300000 ||
    !Number.isInteger(pollIntervalMs) ||
    pollIntervalMs < 0 ||
    pollIntervalMs > 10000
  )
    throw new Error('Invalid confirmation deadline.');
  const price = integerAmount(computeUnitPrice, 'compute-unit price'),
    feeLimit = integerAmount(maxFeeLamports, 'fee limit');
  if (price > 1000000n || feeLimit === 0n || feeLimit > 10000000n)
    throw new Error('Fee configuration exceeds the client safety limits.');
  const latest = await connection.getLatestBlockhash(commitment);
  const transaction = new Transaction({
    feePayer: payer.publicKey,
    recentBlockhash: latest.blockhash,
  });
  transaction.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 1200000 }));
  if (price) transaction.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: price }));
  transaction.add(...instructions);
  await transaction.sign(payer);
  const wire = await transaction.serialize();
  if (wire.length > 1232)
    throw new Error(`Transaction exceeds the legacy wire limit: ${wire.length} bytes.`);
  const versioned = VersionedTransaction.deserialize(wire);
  const signature = base58(versioned.signatures[0]);
  const estimatedFee = await connection.getFeeForMessage(versioned.message, commitment);
  if (estimatedFee.value === null)
    throw new Error('RPC could not quote this transaction fee. Nothing was submitted.');
  if (integerAmount(estimatedFee.value, 'RPC fee') > feeLimit)
    throw new Error('Transaction fee exceeds the configured limit. Nothing was submitted.');
  const simulation = await connection.simulateTransaction(versioned, {
    commitment,
    sigVerify: true,
    replaceRecentBlockhash: false,
  });
  if (simulation.value.err)
    throw new Error(
      `Simulation rejected ${label}: ${JSON.stringify(simulation.value.err, (_, v) => (typeof v === 'bigint' ? v.toString() : v))}`,
    );
  if (
    integerAmount(await connection.getBlockHeight(commitment), 'block height') >
    integerAmount(latest.lastValidBlockHeight)
  )
    throw new Error('Blockhash expired before submission. Nothing was submitted.');
  // Persist the locally derived signature before the RPC can accept the transaction.
  await onRecord({
    phase: 'prepared',
    label,
    signature,
    cluster: deployment.cluster,
    genesis: deployment.genesis,
    blockhash: latest.blockhash,
    lastValidBlockHeight: String(latest.lastValidBlockHeight),
    bytes: wire.length,
    quotedFeeLamports: String(estimatedFee.value),
  });
  try {
    const returned = await connection.sendRawTransaction(wire, {
      skipPreflight: false,
      preflightCommitment: commitment,
      maxRetries: 3,
    });
    if (returned !== signature) throw new Error('RPC returned a different transaction signature.');
  } catch {
    throw new SubmissionUncertain(
      signature,
      'RPC submission did not return a trustworthy acknowledgement.',
    );
  }
  const deadline = Date.now() + confirmationTimeoutMs;
  let status;
  while (Date.now() < deadline) {
    try {
      status = (
        await connection.getSignatureStatuses([signature], { searchTransactionHistory: true })
      ).value[0];
    } catch {
      throw new SubmissionUncertain(signature, 'RPC confirmation failed.');
    }
    const ready =
      status &&
      (status.confirmationStatus === 'finalized' ||
        (commitment === 'confirmed' && status.confirmationStatus === 'confirmed'));
    if (ready) break;
    // A processed transaction may still finalize after its blockhash expires.
    if (!status) {
      let height;
      try {
        height = await connection.getBlockHeight(commitment);
      } catch {
        throw new SubmissionUncertain(signature, 'RPC block-height check failed.');
      }
      if (integerAmount(height) > integerAmount(latest.lastValidBlockHeight))
        throw new SubmissionUncertain(
          signature,
          'Blockhash expired without a confirmed history result.',
        );
    }
    await sleep(pollIntervalMs);
  }
  if (
    !status ||
    (status.confirmationStatus !== 'finalized' &&
      !(commitment === 'confirmed' && status.confirmationStatus === 'confirmed'))
  )
    throw new SubmissionUncertain(signature, 'Confirmation deadline exceeded.');
  let tx;
  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      tx = await connection.getTransaction(signature, {
        commitment,
        maxSupportedTransactionVersion: 0,
      });
    } catch {
      throw new SubmissionUncertain(signature, 'Confirmed transaction metadata is unavailable.');
    }
    if (tx?.meta) break;
    await sleep(pollIntervalMs);
  }
  if (!tx?.meta)
    throw new SubmissionUncertain(signature, 'Confirmed transaction metadata is unavailable.');
  const record = {
    phase: 'confirmed',
    label,
    signature,
    cluster: deployment.cluster,
    commitment,
    bytes: wire.length,
    computeUnits:
      tx.meta.computeUnitsConsumed === undefined ? null : String(tx.meta.computeUnitsConsumed),
    feeLamports: String(tx.meta.fee),
    slot: String(tx.slot),
    error: tx.meta.err ?? null,
  };
  await onRecord(record);
  if (record.error || status.err)
    throw new Error(`${label} was confirmed with an execution error. Signature: ${signature}`);
  return record;
}
