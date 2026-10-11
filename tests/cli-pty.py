#!/usr/bin/env python3
"""Exercise interactive key creation and signing with synthetic, disposable keys."""
import json
import os
from pathlib import Path
import pty
import select
import shutil
import stat
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which('node')
PASSWORD = 'disposable CLI test passphrase only'

def terminal(args, responses):
    master, slave = pty.openpty()
    process = subprocess.Popen([NODE, 'sdk/src/cli.mjs', *args], cwd=ROOT,
                               stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    transcript = bytearray()
    consumed = 0
    try:
        for prompt, reply in responses:
            deadline = time.monotonic() + 30
            while prompt.encode() not in transcript[consumed:]:
                if time.monotonic() > deadline or process.poll() is not None:
                    raise AssertionError(f'CLI did not reach prompt: {prompt}')
                if select.select([master], [], [], 0.2)[0]:
                    transcript.extend(os.read(master, 8192))
            consumed = len(transcript)
            os.write(master, (reply + '\r').encode())
        deadline = time.monotonic() + 30
        while process.poll() is None and time.monotonic() < deadline:
            if select.select([master], [], [], 0.2)[0]:
                try:
                    transcript.extend(os.read(master, 8192))
                except OSError:
                    break
        code = process.wait(timeout=5)
        assert PASSWORD.encode() not in transcript, 'Passphrase appeared in terminal output'
        assert code == 0, f'CLI exit code {code}: {transcript.decode(errors="replace")}'
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        os.close(master)

def base58(data):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    number, result = int.from_bytes(data, 'big'), ''
    while number:
        number, remainder = divmod(number, 58)
        result = alphabet[remainder] + result
    return '1' * (len(data) - len(data.lstrip(b'\0'))) + result

(ROOT / '.runtime').mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='cli-qa-', dir=ROOT / '.runtime') as directory:
    directory = Path(directory)
    store, intent_file, proof = directory / 'test.keystore.json', directory / 'intent.bin', directory / 'approval.json'
    terminal(['keygen', '--out', str(store)], [('New passphrase: ', PASSWORD), ('Repeat passphrase: ', PASSWORD)])
    assert stat.S_IMODE(store.stat().st_mode) == 0o600
    public_key = json.loads(store.read_text())['publicKey']
    fixture = json.loads((ROOT / 'fixtures/sdk-approval.json').read_text())
    intent = bytes.fromhex(fixture['intent'])
    intent_file.write_bytes(intent)
    terminal(['sign', '--intent', str(intent_file), '--keystore', str(store), '--wallet', base58(intent[65:97]),
              '--program', base58(intent[33:65]), '--index', '0', '--out', str(proof)],
             [('Type SIGN to authorize exactly these bytes: ', 'SIGN'), ('Keystore passphrase: ', PASSWORD)])
    output = subprocess.check_output([str(ROOT / 'target/release/seal-verify'), '--proof', str(proof), '--key', public_key], text=True)
    assert json.loads(output)['signature_valid'] is True
    missing_pin = subprocess.run([NODE, 'sdk/src/cli.mjs', 'verify', '--proof', str(proof)], cwd=ROOT, capture_output=True)
    assert missing_pin.returncode != 0
    assert stat.S_IMODE(proof.stat().st_mode) == 0o600
report = {'status':'passed', 'checks':['TTY key generation', 'TTY transaction review and signing',
    'passphrase not echoed', 'keystore permissions 0600', 'approval permissions 0600',
    'independent Rust verification of CLI output', 'missing trusted key rejected'],
    'scope':'Synthetic temporary keys only; files removed after the test.'}
(ROOT / 'evidence/cli-pty.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
