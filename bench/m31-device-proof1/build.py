"""Phase 0: rebuild the stock V1 transaction prover and its local verifier from pinned sources.

The stock prover is `starknet_transaction_prover` at sequencer e6b6fd2e (tag PRIVACY-0.14.3-RC.2)
with `--features stwo_proving`, the original lockfile, nightly-2026-01-15, release,
-Ctarget-cpu=native: the build ADR-0018 V1 recorded. The source is `git archive` of the pinned
commit from ~/development/sequencer-pin, unmodified. The verifier is `verify_saved.rs`, the
original local verifier reconstructed from `bench/client-privacy-feasibility/verify_saved_plus_one.rs`
(the one-line difference that script asserts is undone) and checked against the archived source
hash, linked against this build's own `starknet_proof_verifier`.

`prove-small` (V2 small path) is built from `prove-small/` against `target/proving-server` with
nightly-2026-01-15 and -Ctarget-cpu=native, its lockfile seeded from that worktree's.

Usage: build.py [prover|verifier|prove-small|all]. Builds use 12 physical cores (6-17), a 32 GiB
cap, no swap. Never run while a timed benchmark is running.
"""
from pathlib import Path
import hashlib, json, os, re, subprocess, sys, time

H = Path(__file__).resolve().parent
ROOT = H.parents[1]
W = ROOT / 'target/m31-device-proof1'
SRC = W / 'src/sequencer-e6b6fd2e'
TARGET = W / 'v1-target'
BIN = W / 'bin'
REV = 'e6b6fd2e9932909107833579e5b6efd6c75fa0af'
LOCK_SHA = '2d47ff1cc07040e820dca7a0946b0ffebff82f30d75efabc67a25e7f2e96af60'  # ADR-0018 v1 source-pins.json
VERIFY_SAVED_SHA = 'eef9af4a1d9f2266566b6e5604405dd92758b711d0d5f367374c75d310d38694'  # same file
VENV = Path.home() / '.local/share/templar/venvs/cairo-lang-0.14.3a3/bin'
RUSTUP = '/home/broody/.cargo/bin/rustup'
TOOLCHAIN = 'nightly-2026-01-15'
PATH = f'{VENV}:/usr/bin:/home/broody/.cargo/bin:/bin'
RESULTS = H / 'results/phase0'


def sha(p):
    with open(p, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def export_source():
    if not SRC.exists():
        SRC.mkdir(parents=True)
        archive = subprocess.run(['git', '-C', str(Path.home() / 'development/sequencer-pin'), 'archive', REV],
                                 check=True, capture_output=True).stdout
        subprocess.run(['tar', '-x', '-C', str(SRC)], input=archive, check=True)
    assert sha(SRC / 'Cargo.lock') == LOCK_SHA, 'lockfile differs from the ADR-0018 V1 pin'


def build_prover():
    export_source()
    RESULTS.mkdir(parents=True, exist_ok=True)
    log = RESULTS / 'v1-prover-build.log'
    unit = 'templar-dp1-build-v1-' + str(time.time_ns())
    env = {'PATH': PATH, 'RUSTC_WRAPPER': '', 'RUSTFLAGS': '-Ctarget-cpu=native',
           'CARGO_TARGET_DIR': str(TARGET), 'CARGO_BUILD_JOBS': '12'}
    cmd = ['systemd-run', '--user', '--wait', '--pipe', '--unit=' + unit,
           '-p', f'WorkingDirectory={SRC}', '-p', 'MemoryMax=32G', '-p', 'MemorySwapMax=0',
           '-p', 'CPUQuota=1200%', '-p', 'CPUAffinity=6-17', '-p', 'RuntimeMaxSec=5400']
    cmd += ['--setenv=' + k + '=' + v for k, v in env.items()]
    cmd += [RUSTUP, 'run', TOOLCHAIN, 'cargo', 'build', '--offline', '--locked', '--release',
            '-p', 'starknet_transaction_prover', '--features', 'stwo_proving']
    start = time.time()
    with log.open('w') as f:
        r = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)
    text = log.read_text()
    ok = r.returncode == 0 and re.search(r'Finished .release. profile', text)
    record = {'what': 'stock V1 starknet_transaction_prover', 'sequencer_revision': REV,
              'cargo_lock_sha256': LOCK_SHA, 'toolchain': TOOLCHAIN, 'rustflags': '-Ctarget-cpu=native',
              'features': 'stwo_proving', 'command': cmd, 'exit_code': r.returncode,
              'wall_seconds': time.time() - start, 'unmodified_source': True}
    if ok:
        BIN.mkdir(parents=True, exist_ok=True)
        out = BIN / 'v1-stock-prover'
        subprocess.run(['cp', str(TARGET / 'release/starknet_transaction_prover'), str(out)], check=True)
        record['binary'] = str(out)
        record['binary_sha256'] = sha(out)
    (RESULTS / 'v1-prover-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: record.get(k) for k in ('exit_code', 'wall_seconds', 'binary_sha256')}))
    if not ok:
        print(text[-4000:])
        raise SystemExit(1)


def pinned_rlib(name):
    """The rlib of `name` that starknet_transaction_prover itself links (by fingerprint)."""
    deps, fps = TARGET / 'release/deps', TARGET / 'release/.fingerprint'
    owner = max(deps.glob('libstarknet_transaction_prover-*.rlib'), key=lambda p: p.stat().st_mtime)
    owner_id = owner.stem.removeprefix('lib')
    owner_deps = json.loads((fps / owner_id / 'lib-starknet_transaction_prover.json').read_text())['deps']
    wanted = {d[1]: d[-1].to_bytes(8, 'little').hex() for d in owner_deps}
    cands = list(deps.glob('lib' + name + '-*.rlib'))
    if name in wanted:
        cands = [p for p in cands if any((d / ('lib-' + name)).is_file() and
                                         (d / ('lib-' + name)).read_text().strip() == wanted[name]
                                         for d in fps.glob('*-' + p.stem.rsplit('-', 1)[1]))]
    assert len(cands) == 1, (name, cands)
    return cands[0]


def build_verifier():
    RESULTS.mkdir(parents=True, exist_ok=True)
    plus_one = (ROOT / 'bench/client-privacy-feasibility/verify_saved_plus_one.rs').read_text()
    changed = 'let old = changed[index]; changed[index] = "0x1".parse().unwrap(); changed[index] += old;'
    original = 'let x = changed[index]; changed[index] += x;'
    assert plus_one.count(changed) == 1
    source = plus_one.replace(changed, original)
    src_path = H / 'verify_saved.rs'
    src_path.write_text(source)
    assert sha(src_path) == VERIFY_SAVED_SHA, 'reconstructed verifier differs from the archived verify_saved.rs'
    BIN.mkdir(parents=True, exist_ok=True)
    out = BIN / 'v1-local-verifier'
    cmd = [RUSTUP, 'run', TOOLCHAIN, 'rustc', '--edition=2021', '-C', 'linker=/usr/bin/cc',
           '-C', 'target-cpu=native', '-C', 'opt-level=2', '-L', 'dependency=' + str(TARGET / 'release/deps'),
           str(src_path), '-o', str(out)]
    selected = {}
    for name in ['starknet_api', 'starknet_proof_verifier']:
        p = pinned_rlib(name)
        selected[name] = {'path': str(p), 'sha256': sha(p)}
        cmd += ['--extern', f'{name}={p}']
    for p in sorted((TARGET / 'release/build').glob('*/out')):
        cmd += ['-L', 'native=' + str(p)]
    env = os.environ | {'PATH': PATH}
    with (RESULTS / 'v1-verifier-build.log').open('w') as f:
        r = subprocess.run(cmd, env=env, stdout=f, stderr=subprocess.STDOUT)
    record = {'what': 'original V1 local verifier (verify_saved.rs), reconstructed', 'source_sha256': sha(src_path),
              'matches_archived_source': True, 'libraries': selected, 'exit_code': r.returncode}
    if r.returncode == 0:
        record['binary'] = str(out)
        record['binary_sha256'] = sha(out)
    (RESULTS / 'v1-verifier-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: record.get(k) for k in ('exit_code', 'binary_sha256')}))
    raise SystemExit(r.returncode)


def build_prove_small():
    RESULTS.mkdir(parents=True, exist_ok=True)
    crate = H / 'prove-small'
    seed = ROOT / 'target/proving-server/Cargo.lock'
    if not (crate / 'Cargo.lock').exists():
        (crate / 'Cargo.lock').write_bytes(seed.read_bytes())
    proving_rev = subprocess.run(['git', '-C', str(ROOT / 'target/proving-server'), 'rev-parse', 'HEAD'],
                                 capture_output=True, text=True, check=True).stdout.strip()
    dirty = subprocess.run(['git', '-C', str(ROOT / 'target/proving-server'), 'status', '--porcelain'],
                           capture_output=True, text=True, check=True).stdout.strip()
    log = RESULTS / 'prove-small-build.log'
    unit = 'templar-dp1-build-prove-small-' + str(time.time_ns())
    target = W / 'prove-small-target'
    env = {'PATH': '/usr/bin:/home/broody/.cargo/bin:/bin', 'RUSTC_WRAPPER': '', 'RUSTFLAGS': '-Ctarget-cpu=native',
           'CARGO_TARGET_DIR': str(target), 'CARGO_BUILD_JOBS': '12'}
    cmd = ['systemd-run', '--user', '--wait', '--pipe', '--unit=' + unit,
           '-p', f'WorkingDirectory={crate}', '-p', 'MemoryMax=32G', '-p', 'MemorySwapMax=0',
           '-p', 'CPUQuota=1200%', '-p', 'CPUAffinity=6-17', '-p', 'RuntimeMaxSec=5400']
    cmd += ['--setenv=' + k + '=' + v for k, v in env.items()]
    cmd += [RUSTUP, 'run', TOOLCHAIN, 'cargo', 'build', '--offline', '--release']
    start = time.time()
    with log.open('w') as f:
        r = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)
    ok = r.returncode == 0 and re.search(r'Finished .release. profile', log.read_text())
    record = {'what': 'prove-small (V2 small path driver)', 'proving_worktree': str(ROOT / 'target/proving-server'),
              'proving_revision': proving_rev, 'proving_worktree_clean': not dirty,
              'toolchain': TOOLCHAIN, 'rustflags': '-Ctarget-cpu=native', 'command': cmd,
              'exit_code': r.returncode, 'wall_seconds': time.time() - start,
              'cargo_lock_seed_sha256': sha(seed), 'cargo_lock_sha256': sha(crate / 'Cargo.lock'),
              'main_rs_sha256': sha(crate / 'src/main.rs')}
    if ok:
        BIN.mkdir(parents=True, exist_ok=True)
        out = BIN / 'prove-small'
        subprocess.run(['cp', str(target / 'release/prove-small'), str(out)], check=True)
        record['binary'] = str(out)
        record['binary_sha256'] = sha(out)
    (RESULTS / 'prove-small-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: record.get(k) for k in ('exit_code', 'wall_seconds', 'binary_sha256')}))
    if not ok:
        print(log.read_text()[-4000:])
        raise SystemExit(1)


if __name__ == '__main__':
    what = sys.argv[1] if len(sys.argv) > 1 else 'all'
    if what in ('prover', 'all'):
        build_prover()
    if what in ('prove-small', 'all'):
        build_prove_small()
    if what in ('verifier', 'all'):
        build_verifier()
