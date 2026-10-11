import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import {
  generateKeypair,
  signApproval,
  verifyApproval,
  serializeApproval,
} from '../sdk/src/crypto.mjs';
import { fromHex, hex } from '../sdk/src/codec.mjs';
const samples = Number(process.env.QS_BENCH_SAMPLES ?? 10),
  warmups = 2;
if (!Number.isInteger(samples) || samples < 1 || samples > 100)
  throw new Error('Use 1–100 samples.');
mkdirSync('.runtime', { recursive: true });
const fixture = JSON.parse(readFileSync('fixtures/sdk-approval.json', 'utf8'));
const intent = fromHex(fixture.intent),
  keys = generateKeypair();
const measure = (fn) => {
  const start = performance.now();
  fn();
  return performance.now() - start;
};
const summary = (values) => {
  const s = [...values].sort((a, b) => a - b),
    n = s.length;
  return {
    min: s[0],
    median: n % 2 ? s[n >> 1] : (s[n / 2 - 1] + s[n / 2]) / 2,
    max: s[n - 1],
    samples: values,
  };
};
try {
  const approval = signApproval(intent, keys.secretKey);
  writeFileSync('.runtime/benchmark-approval.json', serializeApproval(approval));
  const operations = {
    sdkSignIncludingSelfCheck: () => signApproval(intent, keys.secretKey),
    sdkVerifyIncludingParsing: () => {
      if (!verifyApproval(approval, { expectedKey: keys.publicKey }).valid)
        throw new Error('Verification failed.');
    },
    independentRustCliIncludingStartup: () =>
      execFileSync(
        'target/release/seal-verify',
        ['--proof', '.runtime/benchmark-approval.json', '--key', hex(keys.publicKey)],
        { timeout: 10000, stdio: 'pipe' },
      ),
  };
  const results = {};
  for (const [name, operation] of Object.entries(operations)) {
    for (let i = 0; i < warmups; i++) operation();
    results[name] = summary(Array.from({ length: samples }, () => measure(operation)));
  }
  const report = {
    recordedAt: new Date().toISOString(),
    algorithm: 'SLH-DSA-SHA2-128s',
    environment: {
      platform: os.platform(),
      architecture: os.arch(),
      cpu: os.cpus()[0]?.model,
      node: process.version,
    },
    samples,
    warmups,
    units: 'milliseconds',
    payloadBytes: intent.length,
    signatureBytes: 7856,
    approvalJsonBytes: Buffer.byteLength(serializeApproval(approval)),
    results,
    scope:
      'Local CPU measurements. No network, public-cluster latency, security audit, or GPU acceleration claim.',
  };
  writeFileSync('evidence/benchmark.json', JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
} finally {
  keys.secretKey.fill(0);
}
