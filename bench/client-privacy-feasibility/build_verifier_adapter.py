"""Build a +1 mutation adapter using the preserved original verifier libraries."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

HERE = Path(__file__).resolve().parent
ORIGINAL = Path('/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test')
DEPS = ORIGINAL / 'rust-target/release/deps'
OUT = HERE / 'results/verifier-adapter-build'
OUT.mkdir(exist_ok=False)
binary = HERE.parents[1] / 'target/client-privacy-feasibility/bin/verifier-plus-one'
assert not binary.exists()
source = HERE / 'verify_saved_plus_one.rs'
original_source = (ORIGINAL / 'verify_saved.rs').read_text()
assert source.read_text() == original_source.replace(
    'let x = changed[index]; changed[index] += x;',
    'let old = changed[index]; changed[index] = "0x1".parse().unwrap(); changed[index] += old;')
cmd = ['/home/broody/.cargo/bin/rustup', 'run', 'nightly-2026-01-15', 'rustc',
       '--edition=2021', '-C', 'linker=/usr/bin/cc', '-C', 'target-cpu=native',
       '-C', 'opt-level=2', '-L', 'dependency=' + str(DEPS), str(source), '-o', str(binary)]
selected = {}
for name in ['starknet_api', 'starknet_proof_verifier']:
    path = max(DEPS.glob('lib' + name + '-*.rlib'), key=lambda p: p.stat().st_mtime)
    selected[name] = str(path)
    cmd.extend(['--extern', name + '=' + str(path)])
for path in sorted((ORIGINAL / 'rust-target/release/build').glob('*/out')):
    cmd.extend(['-L', 'native=' + str(path)])

def digest(path):
    return hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()

identities = {str(p): digest(p) for p in sorted(DEPS.glob('*.rlib'))}
meta = {'command': cmd, 'selected': selected, 'original_rlib_sha256': identities,
        'adapter_source_sha256': digest(source), 'verifier_library_modified': False}
env = os.environ | {'RUSTUP_HOME': '/tmp/templar-stwo-privacy-dtgn6e8l/rustup',
                    'PATH': '/usr/bin:/home/broody/.cargo/bin:/bin'}
with (OUT / 'build.log').open('w') as log:
    run = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT)
meta['exit_code'] = run.returncode
if run.returncode == 0:
    meta['binary'] = str(binary)
    meta['binary_sha256'] = digest(binary)
(OUT / 'metadata.json').write_text(json.dumps(meta, indent=2) + '\n')
print(json.dumps({k: v for k, v in meta.items() if k != 'original_rlib_sha256'}, indent=2))
raise SystemExit(run.returncode)
