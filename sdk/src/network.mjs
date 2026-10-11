import { Connection, PublicKey } from '@solana/web3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { address, hex } from './codec.mjs';
import { parseStrictJson } from './strict-json.mjs';

export const GENESIS = Object.freeze({
  'mainnet-beta': '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
  devnet: 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG',
});
export const UPGRADEABLE_LOADER = address('BPFLoaderUpgradeab1e11111111111111111111111');
export const IMMUTABLE_LOADER = address('BPFLoader2111111111111111111111111111111111');
const sessions = new WeakMap();
const fields = [
  'format',
  'cluster',
  'rpc',
  'genesis',
  'program',
  'programSha256',
  'programSize',
  'upgradeAuthority',
];

export function parseNetwork(input) {
  const value = typeof input === 'string' ? parseStrictJson(input, 8192) : input;
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).length !== fields.length ||
    fields.some((k) => !Object.hasOwn(value, k))
  )
    throw new Error('Network configuration has missing or unknown fields.');
  if (
    value.format !== 'quantum-seal/network/1' ||
    !['localnet', 'devnet', 'mainnet-beta'].includes(value.cluster)
  )
    throw new Error('Unsupported network configuration.');
  const url = new URL(value.rpc);
  if (url.username || url.password || url.hash)
    throw new Error('RPC URL cannot contain credentials or a fragment.');
  const loopback = ['127.0.0.1', '[::1]'].includes(url.hostname);
  if (
    value.cluster === 'localnet'
      ? !(loopback && url.protocol === 'http:')
      : url.protocol !== 'https:'
  )
    throw new Error('Public clusters require HTTPS; localnet requires literal HTTP loopback.');
  const genesis = address(value.genesis).toBase58(),
    program = address(value.program).toBase58();
  if (GENESIS[value.cluster] && genesis !== GENESIS[value.cluster])
    throw new Error('Genesis hash does not identify the selected cluster.');
  if (
    !/^[0-9a-f]{64}$/.test(value.programSha256) ||
    !Number.isSafeInteger(value.programSize) ||
    value.programSize < 1 ||
    value.programSize > 10485760
  )
    throw new Error('Pin the exact program binary SHA-256 and byte length.');
  const authority =
    value.upgradeAuthority === null ? null : address(value.upgradeAuthority).toBase58();
  if (value.cluster === 'mainnet-beta' && authority !== null)
    throw new Error(
      'Mainnet mode requires an immutable wallet program; upgrade authority must be null.',
    );
  return Object.freeze({ ...value, rpc: url.href, genesis, program, upgradeAuthority: authority });
}

export function requireLoopback(connection) {
  const url = new URL(connection.rpcEndpoint);
  if (
    url.protocol !== 'http:' ||
    !['127.0.0.1', '[::1]'].includes(url.hostname) ||
    url.username ||
    url.password
  )
    throw new Error('Public RPC requires an explicitly validated network session.');
}

function dataBytes(account) {
  if (!account || !(account.data instanceof Uint8Array))
    throw new Error('Missing program account data.');
  return Uint8Array.from(account.data);
}
function u32(bytes, offset = 0) {
  if (offset + 4 > bytes.length) throw new Error('Truncated loader account.');
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, true);
}

export async function inspectDeployment(connection, configuration) {
  const config = parseNetwork(configuration);
  if (new URL(connection.rpcEndpoint).href !== config.rpc)
    throw new Error('RPC endpoint does not match the network configuration.');
  if ((await connection.getGenesisHash()) !== config.genesis)
    throw new Error('RPC returned another cluster genesis hash.');
  const commitment = config.cluster === 'localnet' ? 'confirmed' : 'finalized';
  const programId = address(config.program);
  const program = await connection.getAccountInfo(programId, commitment);
  if (!program?.executable)
    throw new Error('Pinned wallet program is not deployed and executable.');
  let code,
    authority = null,
    programData = null,
    deployedSlot = null;
  if (program.owner.equals(IMMUTABLE_LOADER)) {
    code = dataBytes(program);
  } else if (program.owner.equals(UPGRADEABLE_LOADER)) {
    const header = dataBytes(program);
    if (header.length !== 36 || u32(header) !== 2)
      throw new Error('Invalid upgradeable program header.');
    programData = address(header.slice(4));
    const [derived] = await PublicKey.findProgramAddress([programId.toBytes()], UPGRADEABLE_LOADER);
    if (!derived.equals(programData)) throw new Error('ProgramData address is not canonical.');
    const account = await connection.getAccountInfo(programData, commitment);
    if (!account || account.executable || !account.owner.equals(UPGRADEABLE_LOADER))
      throw new Error('ProgramData has the wrong owner or flags.');
    const bytes = dataBytes(account);
    if (bytes.length < 45 || u32(bytes) !== 3 || bytes[12] > 1)
      throw new Error('Invalid ProgramData header.');
    authority = bytes[12] === 1 ? address(bytes.slice(13, 45)).toBase58() : null;
    deployedSlot = new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(4, true).toString();
    code = bytes.slice(45);
  } else {
    throw new Error('Unsupported program loader. Only loader-v2 and loader-v3 are accepted.');
  }
  if (authority !== config.upgradeAuthority)
    throw new Error('Program upgrade authority does not match the pinned policy.');
  if (
    code.length < config.programSize ||
    code.subarray(config.programSize).some((byte) => byte !== 0) ||
    hex(sha256(code.subarray(0, config.programSize))) !== config.programSha256
  )
    throw new Error('Deployed program binary does not match the reviewed artifact.');
  return Object.freeze({
    cluster: config.cluster,
    genesis: config.genesis,
    program: config.program,
    programSha256: config.programSha256,
    programSize: config.programSize,
    programData: programData?.toBase58() ?? null,
    deployedSlot,
    upgradeAuthority: authority,
    immutable: authority === null,
    commitment,
  });
}

// Public RPC endpoints throttle with HTTP 429, and connections occasionally fail or
// time out. The identical request is retried after a backoff in both cases: reads are
// idempotent, and a retried sendTransaction carries the same signed bytes, which the
// cluster deduplicates by signature. Nothing is re-signed.
export function rateLimitedFetch(
  fetchImpl = globalThis.fetch,
  { attempts = 8, baseMs = 500 } = {},
) {
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, Math.min(ms, 15000)));
  return async (url, init) => {
    for (let attempt = 0; ; attempt++) {
      let response;
      try {
        response = await fetchImpl(url, {
          ...init,
          redirect: 'error',
          signal: AbortSignal.timeout(15000),
        });
      } catch (error) {
        if (attempt + 1 >= attempts) throw error;
        await pause(baseMs * 2 ** attempt);
        continue;
      }
      if (response.status !== 429 || attempt + 1 >= attempts) return response;
      const header = Number(response.headers.get('retry-after'));
      await pause(Number.isFinite(header) && header > 0 ? header * 1000 : baseMs * 2 ** attempt);
    }
  };
}

export async function openNetwork(input, connection) {
  const config = parseNetwork(input);
  connection ??= new Connection(config.rpc, {
    commitment: config.cluster === 'localnet' ? 'confirmed' : 'finalized',
    disableRetryOnRateLimit: true,
    fetch: rateLimitedFetch(),
  });
  const deployment = await inspectDeployment(connection, config);
  const session = Object.freeze({ connection, ...deployment });
  sessions.set(session, { connection, config, verified: deployment });
  return session;
}

export async function assertNetwork(connection, session, program) {
  const internal = sessions.get(session);
  if (!internal || internal.connection !== connection)
    throw new Error('Unknown network session or mismatched connection.');
  if (program && address(program).toBase58() !== internal.config.program)
    throw new Error('Instruction targets a different wallet program.');
  // An immutable program's bytes cannot change on-chain, so after one full byte check
  // each transaction re-checks only the cluster and that the program is still the
  // executable account the loader installed. Upgradeable deployments (test clusters)
  // are re-verified in full every time, because their bytes can be replaced.
  const verified = internal.verified;
  if (verified?.immutable) {
    const [genesis, account] = await Promise.all([
      connection.getGenesisHash(),
      connection.getAccountInfo(address(internal.config.program), verified.commitment),
    ]);
    if (genesis !== internal.config.genesis)
      throw new Error('RPC returned another cluster genesis hash.');
    const loader = verified.programData ? UPGRADEABLE_LOADER : IMMUTABLE_LOADER;
    if (!account?.executable || !account.owner.equals(loader))
      throw new Error('Pinned wallet program is no longer the verified deployment.');
    return verified;
  }
  internal.verified = await inspectDeployment(connection, internal.config);
  return internal.verified;
}

export async function guardConnection(connection, session, program) {
  if (session) return assertNetwork(connection, session, program);
  requireLoopback(connection);
  return { cluster: 'localnet', commitment: 'confirmed' };
}
