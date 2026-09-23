"""Link attribution.rs against exact preserved dependencies; do not mutate them.

Same fingerprint-resolution as build.py. Only the source file differs.
"""
from pathlib import Path
import hashlib, json, os, subprocess
HERE = Path(__file__).resolve().parent
BASE = Path('/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test')
DEPS = BASE / 'rust-target/release/deps'
FP = BASE / 'rust-target/release/.fingerprint'


def main():
    out = Path(os.environ.get('ATTR_OUT', str(HERE.parents[2] / 'target' / 'm31-private-wrapper' / 'attribution-build')))
    out.mkdir(parents=True, exist_ok=False)
    owners = ['starknet_transaction_prover', 'privacy_prove', 'privacy_circuit_verify', 'circuit_prover', 'circuit_cairo_verifier']
    expected = {}
    selected = {}
    for name in owners:
        lib = max(DEPS.glob('lib' + name + '-*.rlib'), key=lambda p: p.stat().st_mtime)
        fp = next(FP.glob('*-' + lib.stem.rsplit('-', 1)[1]))
        info = json.loads((fp / ('lib-' + name + '.json')).read_text())
        for dep in info['deps']:
            value = dep[-1].to_bytes(8, 'little').hex()
            if dep[1] in expected:
                assert expected[dep[1]] == value, dep[1]
            expected[dep[1]] = value
        selected[name] = lib
    for name, value in expected.items():
        candidates = []
        for p in DEPS.glob('lib' + name + '-*'):
            if p.suffix not in ('.rlib', '.so'):
                continue
            for d in FP.glob('*-' + p.stem.rsplit('-', 1)[1]):
                fingerprint = d / ('lib-' + name)
                if fingerprint.is_file() and fingerprint.read_text().strip() == value:
                    candidates.append(p)
        assert candidates, name
        selected[name] = max(candidates, key=lambda p: p.stat().st_mtime)
    cmd = ['/home/broody/.cargo/bin/rustup', 'run', 'nightly-2026-01-15', 'rustc', '--edition=2021',
           '-C', 'linker=/usr/bin/cc', '-C', 'target-cpu=native', '-C', 'opt-level=2',
           '-L', 'dependency=' + str(DEPS), str(HERE / 'blake_sites.rs'), '-o', str(out / 'blake_sites')]
    for name, p in sorted(selected.items()):
        cmd += ['--extern', name + '=' + str(p)]
    for p in sorted((BASE / 'rust-target/release/build').glob('*/out')):
        cmd += ['-L', 'native=' + str(p)]
    env = dict(os.environ, RUSTUP_HOME='/tmp/templar-stwo-privacy-dtgn6e8l/rustup', PATH='/usr/bin:/home/broody/.cargo/bin:/bin')
    metadata = {
        'source_sha256': hashlib.sha256((HERE / 'blake_sites.rs').read_bytes()).hexdigest(),
        'command': cmd,
        'libraries': {n: {'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for n, p in selected.items()},
    }
    (out / 'inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')
    with (out / 'build.log').open('w') as log:
        r = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT)
    print(json.dumps({'exit_code': r.returncode, 'log': str(out / 'build.log')}))
    raise SystemExit(r.returncode)


if __name__ == '__main__':
    main()
