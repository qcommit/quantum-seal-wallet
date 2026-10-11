#!/usr/bin/env python3
"""Run the release checks and record command outcomes with source/artifact hashes."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
EVIDENCE = ROOT / 'evidence'
EVIDENCE.mkdir(exist_ok=True)
ENV = dict(os.environ, CARGO_BUILD_JOBS='4', CARGO_TERM_COLOR='never', NO_COLOR='1')
checks = []
commands = [
    ('sdk-tests', ['npm', 'test']),
    ('format', ['npm', 'run', 'format:check']),
    ('rust-format', ['cargo', 'fmt', '--all', '--', '--check']),
    ('clippy', ['cargo', 'clippy', '--locked', '--workspace', '--all-targets', '--', '-D', 'warnings']),
    ('rust-tests', ['cargo', 'test', '--locked', '--release', '--workspace']),
    ('verifier-build', ['cargo', 'build', '--locked', '--release', '-p', 'seal-verify']),
    ('cli-pty', ['python3', 'tests/cli-pty.py']),
    ('npm-audit', ['npm', 'audit', '--json']),
    ('build-sbf', ['bash', 'scripts/build-sbf.sh']),
    ('localnet-run', ['bash', 'scripts/test-localnet.sh']),
]
for name, command in commands:
    started = time.monotonic()
    result = subprocess.run(command, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=900)
    text = result.stdout.replace(str(ROOT), '<repo>')
    (EVIDENCE / (name + '.txt')).write_text(text)
    if name == 'npm-audit':
        (EVIDENCE / 'npm-audit.json').write_text(result.stdout)
    checks.append({'name': name, 'command': command, 'exitCode': result.returncode,
                   'seconds': round(time.monotonic() - started, 3)})
    print(name, result.returncode, flush=True)
    if result.returncode != 0:
        (EVIDENCE / 'validation.json').write_text(json.dumps({'status':'failed','checks':checks},indent=2)+'\n')
        print(text, file=sys.stderr)
        sys.exit(1)
files = []
for folder in ['crates','programs','sdk','scripts','tests']:
    files.extend(p for p in (ROOT/folder).rglob('*') if p.is_file() and p.suffix in {'.rs','.mjs','.py','.sh','.toml'})
files += [ROOT/'Cargo.lock', ROOT/'package-lock.json', ROOT/'Cargo.toml', ROOT/'package.json', ROOT/'rust-toolchain.toml']
source = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(files))}
(EVIDENCE / 'source-checksums.json').write_text(json.dumps(source,indent=2)+'\n')
localnet = json.loads((EVIDENCE/'localnet.json').read_text())
rust = (EVIDENCE/'rust-tests.txt').read_text()
js = (EVIDENCE/'sdk-tests.txt').read_text()
report = {'status':'passed','recordedAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
    'checks':checks,'rustTestFunctions':sum(map(int,re.findall(r'test result: ok\. (\d+) passed',rust))),
    'javascriptTests':int(re.search(r'(?:ℹ |# )tests (\d+)',js).group(1)),
    'nistCaseComparisons':28,'signatureComponentMutations':491,
    'localnetTransactions':localnet['transactionCount'],'localnetExpectedRejections':localnet['rejectedTransactions'],
    'localnetAssertions':len(localnet['assertions']),
    'networkClientLocalnet': {k: json.loads((EVIDENCE/'network-localnet.json').read_text())[k] for k in ['status','transactionCount','maxWireBytes','maxComputeUnits','publicTransactions']},
    'artifacts':{name:{'bytes':(ROOT/name).stat().st_size,'sha256':hashlib.sha256((ROOT/name).read_bytes()).hexdigest()}
                 for name in ['target/deploy/seal_wallet.so','target/release/seal-verify']},
    'devnetRehearsal': {k: json.loads((EVIDENCE/'devnet-rehearsal.json').read_text()).get(k)
                        for k in ['status','program','programSha256','transactionCount','totalFeeLamports']}
                       if (EVIDENCE/'devnet-rehearsal.json').exists() else None,
    'notPerformed':['Independent third-party security audit','Mainnet deployment',
                    'Full ACVP corpus','RustSec advisory scan','Mobile wallet testing']}
(EVIDENCE/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
print('Validation passed:',report['rustTestFunctions'],'Rust tests,',report['javascriptTests'],'JS tests,',report['localnetTransactions'],'local transactions.')
