#!/usr/bin/env python3
"""Check committed and publishable source paths without opening private runtime files."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
raw = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root)
files = sorted(set(p.decode() for p in raw.split(b'\0') if p))
errors = []
for name in files:
    path = PurePosixPath(name)
    if path.parts[0] in {'.runtime', 'node_modules', 'target', 'dist', '.git'} or '..' in path.parts:
        errors.append(f'Private or generated path included: {name}')
    if name.endswith(('.keypair.json', '.keystore.json', '.pem', '.key', '.env')) or path.name.startswith('.env.'):
        errors.append(f'Potential private-key/configuration file included: {name}')
    if (root / name).is_symlink():
        errors.append(f'Symlink requires manual release review: {name}')
for required in ['README.md', 'LICENSE', 'SECURITY.md', 'Cargo.lock', 'package-lock.json', 'docs/PROTOCOL.md',
                 'docs/RELEASE.md', 'fixtures/NIST-LICENSE.txt', 'licenses/moby-profiles.txt']:
    if not (root / required).is_file(): errors.append(f'Missing release document: {required}')
manifest = json.loads((root / 'fixtures/PROVENANCE.json').read_text())
for entry in manifest['nistSources']:
    if entry['mode'] not in {'sigGen', 'sigVer'}: continue
    data = (root / 'fixtures' / (entry['mode'] + '.json')).read_bytes()
    if hashlib.sha256(data).hexdigest() != entry['subsetSha256']:
        errors.append(f"NIST subset checksum mismatch: {entry['mode']}")
if errors:
    print('\n'.join(errors), file=sys.stderr)
    sys.exit(1)
print(f'Checked {len(files)} publishable files and both NIST subset checksums.')
print('This is a path/integrity check, not a complete secret scanner or security audit.')
