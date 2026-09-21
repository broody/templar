"""Build/test the isolated fixed-wrapper harness; never run proof measurements."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
WORK = REPO / 'target/client-privacy-feasibility'
RESULTS = HERE.parent / 'results/build'
RESULTS.mkdir(parents=True, exist_ok=False)
ENV = os.environ | {
    'RUSTUP_HOME': '/tmp/templar-stwo-privacy-dtgn6e8l/rustup',
    'PATH': '/usr/bin:/home/broody/.cargo/bin:/bin',
    'RUSTC_WRAPPER': '',
    'RUSTFLAGS': '-Ctarget-cpu=native',
    'CARGO_TARGET_DIR': str(WORK / 'client-target'),
    'CARGO_BUILD_JOBS': '8',
}

def snapshot():
    files = []
    for name in ['stwo', 'stwo-cairo', 'stwo-circuits', 'proving-utils']:
        files.extend(p for p in (WORK / name).rglob('*')
                     if p.is_file() and p.suffix in {'.rs', '.toml', '.json'})
    files.extend(p for p in HERE.rglob('*') if p.is_file() and p.suffix in {'.rs', '.toml'})
    return {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(files)}

before = snapshot()
meta = {'environment': {k: ENV[k] for k in ['RUSTUP_HOME', 'PATH', 'RUSTFLAGS',
        'RUSTC_WRAPPER', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS']}, 'steps': []}
base = ['/usr/bin/taskset', '-c', '0-7', '/home/broody/.cargo/bin/rustup',
        'run', 'nightly-2026-01-15', 'cargo']
for label, args in [('build', ['build', '--offline', '--release']),
                    ('test', ['test', '--offline', '--release'])]:
    command = base + args + ['--manifest-path', str(HERE / 'Cargo.toml')]
    start = time.time()
    with (RESULTS / (label + '.log')).open('w') as log:
        result = subprocess.run(command, env=ENV, cwd=REPO, stdout=log, stderr=subprocess.STDOUT)
    meta['steps'].append({'command': command, 'exit_code': result.returncode,
                          'elapsed_seconds': time.time() - start})
    (RESULTS / 'metadata.json').write_text(json.dumps(meta, indent=2) + '\n')
    if result.returncode:
        print((RESULTS / (label + '.log')).read_text()[-10000:])
        raise SystemExit(result.returncode)
assert before == snapshot(), 'Sources changed during compilation; rebuild before measurements'
binary = WORK / 'client-target/release/templar-client-privacy-feasibility'
(WORK / 'bin').mkdir(exist_ok=True)
frozen = WORK / 'bin/fixed-cairo-wrapper'
if frozen.exists():
    raise SystemExit('Refusing to replace frozen binary')
shutil.copy2(binary, frozen)
meta.update(binary=str(frozen), binary_sha256=hashlib.sha256(frozen.read_bytes()).hexdigest(),
            source_hashes=before, cargo_lock_sha256=hashlib.sha256((HERE / 'Cargo.lock').read_bytes()).hexdigest())
compiler = subprocess.run(['/home/broody/.cargo/bin/rustup', 'run', 'nightly-2026-01-15',
                           'rustc', '-vV'], env=ENV, text=True, capture_output=True, check=True)
meta['rustc'] = compiler.stdout
(RESULTS / 'metadata.json').write_text(json.dumps(meta, indent=2) + '\n')
shutil.copy2(HERE / 'Cargo.lock', RESULTS / 'Cargo.lock')
print(json.dumps({k: meta[k] for k in ['binary', 'binary_sha256', 'cargo_lock_sha256']}, indent=2))
