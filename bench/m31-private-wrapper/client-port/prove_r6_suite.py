"""R0 V6 real proofs (docs/pool-v3-spec.md §4.4): every shape on the pool's compress tree, the
`valid_until` extremes 1 and 2^56 − 1, and every forgery the circuit admits but the bridge must
reject. Honest proofs come from the production build, forgeries from the `tamper` build (the
circuit is the same: `record` only writes debug info). Proofs go to RUN_DIR/<name>/; the summary
to results/stwo-client-r6/proofs/proofs.json and the manifest to results/stwo-client-r6/.

    python3 prove_r6_suite.py [RUN_DIR]     # default ~/.local/share/templar/runs/r6-p1/proofs
"""
import json, os, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUN = Path(sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser('~/.local/share/templar/runs/r6-p1/proofs'))
RESULTS = HERE / 'results/stwo-client-r6'
TOOLCHAIN = '+nightly-2026-01-15'
SHAPES = ['transfer', 'single', 'one-out', 'partial', 'full', 'invoke', 'shadow', 'nft']
FORGERIES = [
    ('voluntary-reveal', 'transfer'), ('zero-delivery', 'transfer'), ('recipient-only', 'transfer'),
    ('identity-no-intent', 'transfer'), ('duplicate-nullifier', 'transfer'), ('asset-range', 'partial'),
    ('recipient-range', 'partial'), ('zero-chain', 'transfer'), ('valid-until-zero', 'partial'),
    ('valid-until-limb-range', 'partial'), ('valid-until-hi-limb-range', 'partial'),
]


def build(tamper):
    cmd = ['cargo', TOOLCHAIN, 'build', '--release', '--example', 'prove_payment_r6']
    if tamper:
        cmd += ['--features', 'tamper']
    subprocess.run(cmd, cwd=HERE, check=True)
    return HERE / 'target/release/examples/prove_payment_r6'


def prove(binary, name, args):
    out = RUN / name
    if out.exists():
        shutil.rmtree(out)
    r = subprocess.run([str(binary), str(out), '16', '--compress-nodes', *args], cwd=HERE, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f'{name}: {r.stderr[-2000:]}')
    report = json.loads((out / 'report.json').read_text())
    manifest = json.loads((out / 'trusted-config.json').read_text())
    report['circuit_hash_u32_le'] = manifest['circuit_hash_u32_le']
    report['statement_tag_u32'] = manifest.get('statement_tag_u32')
    for k in ('build_seconds', 'scope', 'blinding_rule', 'max_fri_columns', 'tree_nodes'):
        report.pop(k, None)
    print(name, report['trace_log_size'], report['proof_felts'], flush=True)
    return report


RUN.mkdir(parents=True, exist_ok=True)
summary = {}
honest = build(False)
for s in SHAPES:
    summary[s] = prove(honest, s, ['--shape', s])
summary['valid-until-1'] = prove(honest, 'valid-until-1', ['--shape', 'partial', '--valid-until', '1'])
summary['valid-until-max'] = prove(honest, 'valid-until-max', ['--shape', 'partial', '--valid-until', str((1 << 56) - 1)])
summary['transfer-repeat'] = prove(honest, 'transfer-repeat', ['--shape', 'transfer'])
tampered = build(True)
for kind, shape in FORGERIES:
    summary[f'forge-{kind}'] = prove(tampered, f'forge-{kind}', ['--shape', shape, '--forge', kind])
build(False)  # leave the production build in place

hashes = {tuple(r['circuit_hash_u32_le']) for r in summary.values()}
assert len(hashes) == 1, f'{len(hashes)} circuit hashes'
assert {r['trace_log_size'] for r in summary.values()} == {18}, 'every V6 proof at trace 2^18 (spec §4.5)'
(RESULTS / 'proofs').mkdir(parents=True, exist_ok=True)
(RESULTS / 'proofs/proofs.json').write_text(json.dumps(summary, indent=1, sort_keys=True) + '\n')
shutil.copy(RUN / 'transfer/trusted-config.json', RESULTS / 'trusted-config.json')
print(json.dumps({'proofs': len(summary), 'circuit_hash': list(hashes.pop()),
                  'trace_log_sizes': sorted({r['trace_log_size'] for r in summary.values()}),
                  'proof_felts': [min(r['proof_felts'] for r in summary.values()), max(r['proof_felts'] for r in summary.values())]}))
