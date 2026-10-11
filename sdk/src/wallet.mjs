import { randomBytes } from 'node:crypto';
import { SystemProgram } from '@solana/web3.js';
import {
  address,
  raw,
  hex,
  fromHex,
  encodePolicy,
  deriveWallet,
  decodeWallet,
  encodeIntent,
  decodeIntent,
  displayIntent,
  WALLET_BYTES,
  PROOF_BYTES,
} from './codec.mjs';
import { parseStrictJson } from './strict-json.mjs';
import { parseApproval, verifyApproval } from './crypto.mjs';
import { assertNetwork } from './network.mjs';
import { integerAmount } from './transport.mjs';
import {
  initializeInstruction,
  executeInstruction,
  closeProofInstruction,
  tokenTransferAction,
  TOKEN_PROGRAM,
} from './instructions.mjs';
import { submit, uploadApproval } from './client.mjs';

export function parseUnits(text, decimals = 9) {
  if (
    typeof text !== 'string' ||
    text.length > 300 ||
    !/^(0|[1-9][0-9]*)(\.[0-9]+)?$/.test(text) ||
    !Number.isInteger(decimals) ||
    decimals < 0 ||
    decimals > 255
  )
    throw new Error('Use a positive decimal amount without signs or exponent notation.');
  const [whole, fraction = ''] = text.split('.');
  if (fraction.length > decimals)
    throw new Error(`Amount has more than ${decimals} decimal places.`);
  const amount = integerAmount(
    (whole + fraction.padEnd(decimals, '0')).replace(/^0+(?=\d)/, ''),
    'amount',
  );
  if (!amount) throw new Error('Amount must be greater than zero.');
  return amount;
}

function normalizedPolicy(policy) {
  const known = ['keys', 'threshold', 'guardian', 'recoveryDelay'];
  if (!policy || typeof policy !== 'object' || Object.keys(policy).some((k) => !known.includes(k)))
    throw new Error('Unknown policy field.');
  encodePolicy(policy);
  return {
    keys: policy.keys.map((key) => hex(raw(key))),
    threshold: policy.threshold,
    guardian: policy.guardian ? hex(raw(policy.guardian)) : null,
    recoveryDelay: integerAmount(policy.recoveryDelay ?? 0n).toString(),
  };
}

export async function createDescriptor({ program, genesis, policy, salt = randomBytes(32) }) {
  policy = normalizedPolicy(policy);
  const result = await deriveWallet(program, genesis, salt, policy);
  return {
    format: 'quantum-seal/wallet-descriptor/1',
    program: address(program).toBase58(),
    genesis: address(genesis).toBase58(),
    wallet: result.wallet.toBase58(),
    id: hex(result.id),
    salt: hex(raw(salt)),
    initialPolicy: policy,
  };
}

export async function parseDescriptor(input) {
  const value = typeof input === 'string' ? parseStrictJson(input, 8192) : input;
  const keys = ['format', 'program', 'genesis', 'wallet', 'id', 'salt', 'initialPolicy'];
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    keys.some((k) => !Object.hasOwn(value, k)) ||
    value.format !== 'quantum-seal/wallet-descriptor/1'
  )
    throw new Error('Invalid public wallet descriptor.');
  const canonical = await createDescriptor({
    program: value.program,
    genesis: value.genesis,
    policy: value.initialPolicy,
    salt: fromHex(value.salt, 32),
  });
  if (canonical.wallet !== value.wallet || canonical.id !== value.id)
    throw new Error('Descriptor address does not match its initial policy commitment.');
  return canonical;
}

async function pinnedDescriptor(network, input) {
  const descriptor = await parseDescriptor(input);
  if (descriptor.program !== network.program || descriptor.genesis !== network.genesis)
    throw new Error('Descriptor is for another deployment or cluster.');
  return descriptor;
}

export async function walletStatus(network, input) {
  const descriptor = await pinnedDescriptor(network, input);
  await assertNetwork(network.connection, network, descriptor.program);
  const account = await network.connection.getAccountInfo(
    address(descriptor.wallet),
    network.commitment,
  );
  const lamports = integerAmount(account?.lamports ?? 0n);
  const reserve = integerAmount(
    await network.connection.getMinimumBalanceForRentExemption(WALLET_BYTES),
  );
  if (!account || (account.owner.equals(SystemProgram.programId) && account.data.length === 0))
    return {
      descriptor,
      initialized: false,
      balanceLamports: lamports,
      reserveLamports: reserve,
      availableLamports: 0n,
      state: null,
    };
  if (!account.owner.equals(address(descriptor.program)) || account.executable)
    throw new Error('Wallet account has the wrong owner or flags.');
  const state = decodeWallet(Uint8Array.from(account.data));
  const expected = await deriveWallet(
    descriptor.program,
    descriptor.genesis,
    fromHex(descriptor.salt, 32),
    descriptor.initialPolicy,
  );
  if (
    hex(state.id) !== descriptor.id ||
    state.bump !== expected.bump ||
    !address(state.genesis).equals(address(descriptor.genesis))
  )
    throw new Error('Wallet state does not match the descriptor.');
  if (state.locked) throw new Error('Wallet execution lock is set.');
  return {
    descriptor,
    initialized: true,
    balanceLamports: lamports,
    reserveLamports: reserve,
    availableLamports: lamports > reserve ? lamports - reserve : 0n,
    state,
  };
}

export async function initializeWallet(network, payer, input, options = {}) {
  const current = await walletStatus(network, input);
  if (current.initialized)
    return { alreadyInitialized: true, wallet: current.descriptor.wallet, receipt: null };
  const d = current.descriptor;
  const { instruction } = await initializeInstruction({
    program: d.program,
    payer: payer.publicKey,
    genesis: d.genesis,
    salt: fromHex(d.salt, 32),
    policy: d.initialPolicy,
  });
  const receipt = await submit(network.connection, payer, [instruction], {
    ...options,
    network,
    label: 'initialize-wallet',
  });
  if (!(await walletStatus(network, d)).initialized)
    throw new Error(
      `Initialization receipt exists but state is unavailable. Inspect ${receipt.signature}; do not retry blindly.`,
    );
  return { alreadyInitialized: false, wallet: d.wallet, receipt };
}

async function liveIntent(network, input, action, expiresInSlots) {
  const current = await walletStatus(network, input);
  if (!current.initialized) throw new Error('Initialize the wallet before preparing a transfer.');
  const horizon = integerAmount(expiresInSlots ?? 3000n, 'expiry horizon');
  if (horizon < 150n || horizon > 216000n)
    throw new Error('Expiry horizon must be 150–216,000 slots.');
  const now = integerAmount(await network.connection.getSlot(network.commitment));
  const { descriptor: d, state } = current;
  const bytes = encodeIntent({
    genesis: address(d.genesis),
    program: address(d.program),
    wallet: address(d.wallet),
    epoch: state.epoch,
    nonce: state.nonce,
    expiry: now + horizon,
    action,
  });
  return { current, bytes, summary: displayIntent(decodeIntent(bytes)) };
}

export async function prepareSolTransfer(network, descriptor, { to, amount, expiresInSlots } = {}) {
  const lamports = parseUnits(amount, 9);
  const destination = address(to);
  const result = await liveIntent(
    network,
    descriptor,
    { kind: 'transfer', to: destination, lamports },
    expiresInSlots,
  );
  if (destination.toBase58() === result.current.descriptor.wallet)
    throw new Error('Self-transfers are not supported.');
  if (lamports > result.current.availableLamports)
    throw new Error('Insufficient wallet balance after retaining the rent reserve.');
  const target = await network.connection.getAccountInfo(destination, network.commitment);
  if (target?.executable) throw new Error('SOL recipient is an executable program.');
  const targetRent = integerAmount(
    await network.connection.getMinimumBalanceForRentExemption(target?.data.length ?? 0),
  );
  if (integerAmount(target?.lamports ?? 0n) + lamports < targetRent)
    throw new Error('Transfer would leave the recipient below its rent-exempt minimum.');
  return { bytes: result.bytes, summary: result.summary };
}

export async function prepareTokenTransfer(
  network,
  descriptor,
  { source, mint, destination, amount, expiresInSlots } = {},
) {
  await assertNetwork(network.connection, network);
  const d = await pinnedDescriptor(network, descriptor);
  const accounts = await Promise.all(
    [source, mint, destination].map((key) =>
      network.connection.getAccountInfo(address(key), network.commitment),
    ),
  );
  if (accounts.some((a) => !a || a.executable || !a.owner.equals(TOKEN_PROGRAM)))
    throw new Error('Expected existing classic SPL Token accounts and mint.');
  const [from, token, to] = accounts.map((a) => new Uint8Array(a.data));
  if (
    from.length !== 165 ||
    to.length !== 165 ||
    token.length !== 82 ||
    from[108] !== 1 ||
    to[108] !== 1 ||
    token[45] !== 1
  )
    throw new Error('Uninitialized, frozen, or unsupported token account layout.');
  if (
    !address(from.slice(0, 32)).equals(address(mint)) ||
    !address(to.slice(0, 32)).equals(address(mint)) ||
    !address(from.slice(32, 64)).equals(address(d.wallet))
  )
    throw new Error('Token mint or source wallet authority mismatch.');
  if (address(source).equals(address(destination)))
    throw new Error('Source and destination must differ.');
  const quantity = parseUnits(amount, token[44]);
  if (new DataView(from.buffer, from.byteOffset).getBigUint64(64, true) < quantity)
    throw new Error('Insufficient token balance.');
  const action = tokenTransferAction({
    source,
    mint,
    destination,
    wallet: d.wallet,
    amount: quantity,
    decimals: token[44],
  });
  const result = await liveIntent(network, d, action, expiresInSlots);
  return {
    bytes: result.bytes,
    summary: result.summary,
    decimals: token[44],
    atomicAmount: quantity.toString(),
  };
}

export async function validateApprovals(network, input, approvals) {
  const current = await walletStatus(network, input);
  if (!current.initialized) throw new Error('Wallet is not initialized.');
  if (!Array.isArray(approvals) || approvals.length < 1 || approvals.length > 3)
    throw new Error('Supply one to three approvals.');
  const parsed = approvals.map(parseApproval),
    first = parsed[0];
  const indices = new Set();
  for (const proof of parsed) {
    const index = proof.object.index,
      trusted = current.state.policy.keys[index];
    if (index === 255 || indices.has(index) || !trusted)
      throw new Error('Approval owner is absent, duplicated, or a recovery guardian.');
    indices.add(index);
    if (
      proof.object.intent !== first.object.intent ||
      !verifyApproval(proof.object, {
        expectedKey: trusted,
        expectedWallet: current.descriptor.wallet,
        expectedProgram: current.descriptor.program,
      }).valid
    )
      throw new Error(
        'Approval signature or exact intent does not match the current wallet policy.',
      );
  }
  if (indices.size < current.state.policy.threshold)
    throw new Error('Not enough distinct owner approvals.');
  const i = first.intent,
    slot = integerAmount(await network.connection.getSlot(network.commitment));
  if (
    i.genesis.toBase58() !== network.genesis ||
    i.epoch !== current.state.epoch ||
    i.nonce !== current.state.nonce ||
    i.expiry < slot
  )
    throw new Error('Approval is expired, replayed, or for another cluster/policy epoch.');
  if (i.action.kind === 'transfer') {
    if (
      i.action.lamports > current.availableLamports ||
      i.action.to.toBase58() === current.descriptor.wallet
    )
      throw new Error('Invalid recipient or insufficient spendable SOL.');
  } else if (
    i.action.kind !== 'invoke' ||
    !i.action.program.equals(TOKEN_PROGRAM) ||
    i.action.data.length !== 10 ||
    i.action.data[0] !== 12 ||
    i.action.metas.length !== 4 ||
    !i.action.metas[3].key.equals(address(current.descriptor.wallet))
  ) {
    throw new Error(
      'This transaction client accepts SOL and classic SPL TransferChecked only. Use the low-level SDK for separately reviewed policy operations.',
    );
  }
  return { current, parsed, bytes: first.intentBytes, summary: displayIntent(i) };
}

export async function executionCost(network, approvals = 1, maxFeeLamports = 100000n) {
  if (!Number.isInteger(approvals) || approvals < 1 || approvals > 3)
    throw new Error('Invalid approval count.');
  const proofRent = integerAmount(
    await network.connection.getMinimumBalanceForRentExemption(PROOF_BYTES),
  );
  const transactionsUpperBound = approvals * 15 + 1;
  const feesUpperBound = integerAmount(maxFeeLamports) * BigInt(transactionsUpperBound);
  return {
    transactionsUpperBound,
    refundableProofRentLamports: proofRent * BigInt(approvals),
    feesUpperBoundLamports: feesUpperBound,
    requiredPayerLamports: proofRent * BigInt(approvals) + feesUpperBound,
  };
}

export async function executeApprovals(network, payer, descriptor, approvals, options = {}) {
  const ready = await validateApprovals(network, descriptor, approvals);
  const cost = await executionCost(network, approvals.length, options.maxFeeLamports);
  if (
    integerAmount(await network.connection.getBalance(payer.publicKey, network.commitment)) <
    cost.requiredPayerLamports
  )
    throw new Error('Fee payer cannot cover the conservative proof-rent and fee budget.');
  const proofs = [];
  for (const approval of approvals)
    proofs.push(
      await uploadApproval(network.connection, payer, approval, {
        ...options,
        network,
        expectedProgram: network.program,
        expectedWallet: ready.current.descriptor.wallet,
      }),
    );
  const receipt = await submit(
    network.connection,
    payer,
    [executeInstruction(ready.bytes, proofs)],
    { ...options, network, label: 'execute-wallet-transfer' },
  );
  const cleanupErrors = [];
  for (const proof of proofs) {
    try {
      await submit(
        network.connection,
        payer,
        [closeProofInstruction({ program: network.program, proof, uploader: payer.publicKey })],
        { ...options, network, label: 'reclaim-proof-rent' },
      );
    } catch (error) {
      cleanupErrors.push({ proof: proof.toBase58(), error: error.message });
    }
  }
  return { executed: true, receipt, cleanupErrors };
}
