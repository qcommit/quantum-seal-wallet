import { TransactionInstruction, SystemProgram } from '@solana/web3.js';
import {
  address,
  raw,
  concat,
  u64,
  u16,
  encodePolicy,
  decodeIntent,
  intentDigest,
  deriveWallet,
  deriveProof,
  MAX_CHUNK_BYTES,
} from './codec.mjs';

const meta = (key, writable = false, signer = false) => ({
  pubkey: address(key),
  isWritable: writable,
  isSigner: signer,
});
const ix = (program, keys, ...parts) =>
  new TransactionInstruction({
    programId: address(program),
    keys,
    data: Buffer.from(concat(...parts)),
  });

export async function initializeInstruction({ program, payer, genesis, salt, policy }) {
  const { wallet, id, bump } = await deriveWallet(program, genesis, salt, policy);
  const instruction = ix(
    program,
    [meta(payer, true, true), meta(wallet, true), meta(SystemProgram.programId)],
    Uint8Array.of(0),
    address(genesis).toBytes(),
    raw(salt),
    encodePolicy(policy),
  );
  return { wallet, id, bump, instruction };
}
export async function beginInstruction(intentBytes, index, uploader) {
  const intent = decodeIntent(intentBytes),
    digest = intentDigest(intentBytes);
  const { proof, bump } = await deriveProof(intent.program, intent.wallet, digest, index, uploader);
  const instruction = ix(
    intent.program,
    [
      meta(intent.wallet),
      meta(proof, true),
      meta(uploader, true, true),
      meta(SystemProgram.programId),
    ],
    Uint8Array.of(1, index),
    u64(intent.epoch),
    u64(intent.nonce),
    u64(intent.expiry),
    digest,
  );
  return { proof, bump, instruction };
}
export function appendInstruction({ program, wallet, proof, uploader, offset, chunk }) {
  if (!(chunk instanceof Uint8Array) || chunk.length < 1 || chunk.length > MAX_CHUNK_BYTES)
    throw new Error('Invalid upload chunk.');
  return ix(
    program,
    [meta(wallet), meta(proof, true), meta(uploader, false, true)],
    Uint8Array.of(2),
    u16(offset),
    chunk,
  );
}
export function sealInstruction({ program, wallet, proof }) {
  return ix(program, [meta(wallet), meta(proof, true)], Uint8Array.of(3));
}
export function stepInstruction({ program, wallet, proof }) {
  return ix(program, [meta(wallet), meta(proof, true)], Uint8Array.of(4));
}
export function executeInstruction(intentBytes, proofs) {
  if (!Array.isArray(proofs) || proofs.length < 1 || proofs.length > 3)
    throw new Error('Expected 1–3 verified proof accounts.');
  const intent = decodeIntent(intentBytes),
    keys = [meta(intent.wallet, true), ...proofs.map((p) => meta(p))];
  const a = intent.action;
  if (a.kind === 'transfer') keys.push(meta(a.to, true));
  if (a.kind === 'invoke') {
    keys.push(meta(a.program));
    // The PDA is signed only by invoke_signed inside the wallet program.
    for (const m of a.metas) keys.push(meta(m.key, m.writable));
  }
  return ix(intent.program, keys, Uint8Array.of(5, proofs.length), intentBytes);
}
export function finalizeRecoveryInstruction({ program, wallet }) {
  return ix(program, [meta(wallet, true)], Uint8Array.of(6));
}
export function closeProofInstruction({ program, proof, uploader }) {
  return ix(program, [meta(proof, true), meta(uploader, true, true)], Uint8Array.of(7));
}
export const TOKEN_PROGRAM = address('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
export function tokenTransferAction({ source, mint, destination, wallet, amount, decimals }) {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255 || BigInt(amount) <= 0n)
    throw new Error('Invalid token transfer.');
  return {
    kind: 'invoke',
    program: TOKEN_PROGRAM,
    metas: [
      { key: address(source), writable: true, signer: false },
      { key: address(mint), writable: false, signer: false },
      { key: address(destination), writable: true, signer: false },
      { key: address(wallet), writable: false, signer: true },
    ],
    data: concat(Uint8Array.of(12), u64(amount), Uint8Array.of(decimals)),
  };
}
