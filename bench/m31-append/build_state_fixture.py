"""Link fixture glue against preserved sequencer libraries, without modifying them."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BASE = Path('/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test')
DEPS = BASE / 'rust-target/release/deps'
OUT = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else ROOT / 'target/m31-append/state-fixture-build'
OUT.mkdir(parents=True, exist_ok=False)
fingerprints = BASE / 'rust-target/release/.fingerprint'
owner = max(DEPS.glob('libblockifier_reexecution-*.rlib'), key=lambda p: p.stat().st_mtime)
owner_id = owner.stem.removeprefix('lib')
owner_deps = json.loads((fingerprints / owner_id / 'lib-blockifier_reexecution.json').read_text())['deps']
expected_deps = {dep[1]: dep[-1].to_bytes(8, 'little').hex() for dep in owner_deps}
command = ['/home/broody/.cargo/bin/rustup', 'run', 'nightly-2026-01-15', 'rustc',
           '--edition=2021', '-C', 'linker=/usr/bin/cc', '-C', 'target-cpu=native',
           '-C', 'opt-level=2', '-L', 'dependency=' + str(DEPS),
           str(HERE / 'state_fixture.rs'), '-o', str(OUT / 'state-fixture')]
selected = {}
for name in ['serde_json', 'blockifier_reexecution', 'starknet_api',
             'starknet_committer', 'starknet_patricia', 'starknet_types_core',
             'starknet_core', 'starknet_rust_core', 'tokio']:
    candidates = list(DEPS.glob('lib' + name + '-*.rlib'))
    if name in expected_deps:
        candidates = [p for p in candidates if
            any((d / ('lib-' + name)).is_file() and
                (d / ('lib-' + name)).read_text().strip() == expected_deps[name]
                for d in fingerprints.glob('*-' + p.stem.rsplit('-', 1)[1]))]
    assert candidates, f'no preserved library matches pinned dependency fingerprint: {name}'
    path = max(candidates, key=lambda p: p.stat().st_mtime)
    selected[name] = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    command += ['--extern', name + '=' + str(path)]
for path in sorted((BASE / 'rust-target/release/build').glob('*/out')):
    command += ['-L', 'native=' + str(path)]
env = os.environ.copy()
env.update(RUSTUP_HOME='/tmp/templar-stwo-privacy-dtgn6e8l/rustup', PATH='/usr/bin:/home/broody/.cargo/bin:/bin')
(OUT / 'inputs.json').write_text(json.dumps({'libraries': selected, 'command': command,
    'source_sha256': hashlib.sha256((HERE / 'state_fixture.rs').read_bytes()).hexdigest()}, indent=2))
with (OUT / 'build.log').open('w') as log:
    result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
print(json.dumps({'exit_code': result.returncode, 'log': str(OUT / 'build.log')}))
raise SystemExit(result.returncode)
