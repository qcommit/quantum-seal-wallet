import { guardConnection, requireLoopback } from './network.mjs';
import { submitNetwork } from './transport.mjs';
import { Transaction, ComputeBudgetProgram } from '@solana/web3.js';
import { decodeWallet, decodeProofHeader, hex, MAX_CHUNK_BYTES, address } from './codec.mjs';
import { parseApproval, verifyApproval } from './approval.mjs';
import {
  beginInstruction,
  appendInstruction,
  sealInstruction,
  stepInstruction,
} from './instructions.mjs';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export function requireLocalConnection(connection) {
  requireLoopback(connection);
}
export async function walletState(connection, program, wallet, { network } = {}) {
  const { commitment } = await guardConnection(connection, network, program);
  const account = await connection.getAccountInfo(address(wallet), commitment);
  if (!account || !account.owner.equals(address(program)))
    throw new Error('Wallet account is missing or has the wrong owner.');
  return decodeWallet(Uint8Array.from(account.data));
}
export async function submit(connection, payer, instructions, options = {}) {
  if (options.network) return submitNetwork(connection, payer, instructions, options);
  const {
    label = 'transaction',
    extraSigners = [],
    expectFailure = false,
    onRecord = () => {},
  } = options;
  requireLocalConnection(connection);
  const { blockhash } = await connection.getLatestBlockhash('confirmed');
  const transaction = new Transaction({ feePayer: payer.publicKey, recentBlockhash: blockhash });
  transaction.add(ComputeBudgetProgram.setComputeUnitLimit({ units: 1200000 }), ...instructions);
  await transaction.sign(payer, ...extraSigners);
  const wire = await transaction.serialize();
  if (wire.length > 1232)
    throw new Error(`Legacy transaction exceeds 1,232 bytes: ${wire.length}.`);
  const signature = await connection.sendRawTransaction(wire, {
    skipPreflight: expectFailure,
    preflightCommitment: 'confirmed',
    maxRetries: 3,
  });
  const deadline = Date.now() + 90000;
  let status;
  while (Date.now() < deadline) {
    status = (await connection.getSignatureStatuses([signature])).value[0];
    if (status && ['confirmed', 'finalized'].includes(status.confirmationStatus)) break;
    await sleep(80);
  }
  if (!status || !['confirmed', 'finalized'].includes(status.confirmationStatus))
    throw new Error(`Confirmation timed out: ${signature}`);
  let tx;
  for (let attempt = 0; attempt < 20; attempt++) {
    tx = await connection.getTransaction(signature, {
      commitment: 'confirmed',
      maxSupportedTransactionVersion: 0,
    });
    if (tx) break;
    await sleep(80);
  }
  if (!tx?.meta) throw new Error(`Confirmed transaction metadata unavailable: ${signature}`);
  const record = {
    label,
    signature,
    bytes: wire.length,
    computeUnits: Number(tx.meta.computeUnitsConsumed ?? 0),
    feeLamports: Number(tx.meta.fee),
    error: JSON.parse(
      JSON.stringify(tx.meta.err, (_, value) =>
        typeof value === 'bigint' ? Number(value) : value,
      ),
    ),
    slot: Number(tx.slot),
  };
  onRecord(record);
  if (record.error && !expectFailure)
    throw new Error(
      `${label} failed: ${JSON.stringify(record.error)}\n${(tx.meta.logMessages ?? []).join('\n')}`,
    );
  if (!record.error && expectFailure)
    throw new Error(`${label}: expected a rejected transaction, but it succeeded.`);
  return record;
}

export async function uploadApproval(
  connection,
  payer,
  approval,
  {
    expectedProgram,
    expectedWallet,
    verificationBatchSize = 8,
    onRecord = () => {},
    network,
    ...transport
  } = {},
) {
  const { commitment } = await guardConnection(connection, network, expectedProgram);
  const sendOptions = { ...transport, network, onRecord };
  if (![1, 2, 4, 8].includes(verificationBatchSize))
    throw new Error('Verification batch size must be 1, 2, 4 or 8.');
  if (!expectedProgram || !expectedWallet)
    throw new Error('Pin the program and wallet before uploading an approval.');
  const p = parseApproval(approval),
    intent = p.intent;
  if (
    !intent.program.equals(address(expectedProgram)) ||
    !intent.wallet.equals(address(expectedWallet))
  )
    throw new Error('Approval is for another program or wallet.');
  if ((await connection.getGenesisHash()) !== intent.genesis.toBase58())
    throw new Error('Approval is for another cluster.');
  const w = await walletState(connection, expectedProgram, expectedWallet, { network });
  if (
    w.epoch !== intent.epoch ||
    w.nonce !== intent.nonce ||
    intent.expiry < BigInt(await connection.getSlot(commitment))
  )
    throw new Error('Approval is stale or expired.');
  const trusted = p.object.index === 255 ? w.policy.guardian : w.policy.keys[p.object.index];
  if (
    !trusted ||
    !verifyApproval(p.object, { expectedKey: trusted, expectedProgram, expectedWallet }).valid
  )
    throw new Error('Approval does not match the active owner policy.');
  const started = await beginInstruction(p.intentBytes, p.object.index, payer.publicKey);
  const options = {
    program: intent.program,
    wallet: intent.wallet,
    proof: started.proof,
    uploader: payer.publicKey,
  };
  // Steps are combined where one atomic transaction can hold them: opening the proof
  // account with the first chunk, and the final chunk with sealing and the full
  // eight-step verification. A resumed upload continues from the on-chain state.
  const combineFinal = verificationBatchSize === 8;
  const verifyAll = () => Array.from({ length: 8 }, () => stepInstruction(options));
  let account = await connection.getAccountInfo(started.proof, commitment);
  if (!account) {
    const first = p.signature.slice(0, MAX_CHUNK_BYTES);
    await submit(
      connection,
      payer,
      [started.instruction, appendInstruction({ ...options, offset: 0, chunk: first })],
      { ...sendOptions, label: 'begin-proof+upload-chunk' },
    );
    account = await connection.getAccountInfo(started.proof, commitment);
  }
  if (!account || !account.owner.equals(intent.program))
    throw new Error('Invalid proof account owner.');
  let header = decodeProofHeader(Uint8Array.from(account.data));
  if (
    hex(Uint8Array.from(account.data).slice(193, 193 + header.uploaded)) !==
    hex(p.signature.slice(0, header.uploaded))
  )
    throw new Error('Existing upload contains different signature bytes.');
  if (header.stage === 0) {
    let sealed = false;
    for (let offset = header.uploaded; offset < p.signature.length; offset += MAX_CHUNK_BYTES) {
      const chunk = p.signature.slice(offset, offset + MAX_CHUNK_BYTES);
      const append = appendInstruction({ ...options, offset, chunk });
      if (combineFinal && offset + chunk.length === p.signature.length) {
        await submit(connection, payer, [append, sealInstruction(options), ...verifyAll()], {
          ...sendOptions,
          label: 'upload-chunk+seal-proof+verify-batch-1-8',
        });
        sealed = true;
      } else {
        await submit(connection, payer, [append], { ...sendOptions, label: 'upload-chunk' });
      }
    }
    if (!sealed)
      await submit(
        connection,
        payer,
        combineFinal ? [sealInstruction(options), ...verifyAll()] : [sealInstruction(options)],
        { ...sendOptions, label: combineFinal ? 'seal-proof+verify-batch-1-8' : 'seal-proof' },
      );
  }
  account = await connection.getAccountInfo(started.proof, commitment);
  header = decodeProofHeader(Uint8Array.from(account.data));
  for (let stage = header.stage; stage < 9; stage += verificationBatchSize) {
    const count = Math.min(verificationBatchSize, 9 - stage);
    const steps = Array.from({ length: count }, () => stepInstruction(options));
    await submit(connection, payer, steps, {
      ...sendOptions,
      label: `verify-batch-${stage}-${stage + count - 1}`,
    });
  }
  return started.proof;
}
