"""P0b spike (throwaway): build the BASELINE (unmodified R4) and SPIKE (R4 + Stark owner
signature over SNIP-12) statement accounts in one generated workspace.

The workspace is a copy of the built R4 bridge workspace (target/bridge-r4: account, bridge with
its generated pin, vendored fork verifier) plus two members: `account_sig`
(bench/wallet-sig-spike/e2e/account) and `snip12` (bench/wallet-sig-spike/snip12/src/lib.cairo
with a minimal manifest, no snforge). Nothing outside target/wallet-sig-spike/e2e is written.

Usage: build_e2e.py [WORK]   (default target/wallet-sig-spike/e2e/work; must not exist)
"""
from pathlib import Path
import hashlib, json, shutil, subprocess, sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SRC = ROOT / 'target/bridge-r4'
SNIP12 = ROOT / 'bench/wallet-sig-spike/snip12/src/lib.cairo'
SCARB = '/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb'
CASM_LIMIT = 80 * 1024


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def class_sizes(work, stem):
    sierra = work / f'target/contract/{stem}.contract_class.json'
    casm = work / f'target/contract/{stem}.compiled_contract_class.json'
    s, c = json.loads(sierra.read_text()), json.loads(casm.read_text())
    segs = c.get('bytecode_segment_lengths')
    return {'sierra_path': str(sierra), 'casm_path': str(casm), 'sierra_sha256': sha(sierra), 'casm_sha256': sha(casm),
            'sierra_felts': len(s['sierra_program']), 'casm_felts': len(c['bytecode']),
            'casm_limit': CASM_LIMIT, 'within_limit': len(c['bytecode']) <= CASM_LIMIT,
            'bytecode_segments': len(segs) if isinstance(segs, list) else None}


def main():
    work = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / 'target/wallet-sig-spike/e2e/work'
    assert not work.exists(), 'fresh work directory required'
    assert (SRC / 'bridge/src/pinned.cairo').exists(), 'build target/bridge-r4 first (build_bridge_arith.py)'
    shutil.copytree(SRC, work, ignore=shutil.ignore_patterns('target'))
    shutil.copytree(HERE / 'account', work / 'account_sig', ignore=shutil.ignore_patterns('target'))
    (work / 'snip12/src').mkdir(parents=True)
    (work / 'snip12/Scarb.toml').write_text(
        '[package]\nname = "templar_wallet_sig_snip12"\nversion = "0.1.0"\nedition = "2024_07"\n\n'
        '[dependencies]\nstarknet = "2.18.0"\n')
    shutil.copyfile(SNIP12, work / 'snip12/src/lib.cairo')
    manifest = work / 'Scarb.toml'
    text = manifest.read_text()
    assert text.count('    "account",\n') == 1
    manifest.write_text(text.replace('    "account",\n', '    "account",\n    "account_sig",\n    "snip12",\n'))
    for pkg in ('templar_membership_account', 'templar_wallet_sig_account'):
        subprocess.run([SCARB, '--profile', 'contract', '--manifest-path', str(manifest), 'build', '-p', pkg], check=True)
    base = class_sizes(work, 'templar_membership_account_PaymentVerifierAccount')
    spike = class_sizes(work, 'templar_wallet_sig_account_WalletSigSpikeAccount')
    # The copied workspace recompiles the same account: CASM must be identical (a few Sierra
    # debug-type felts differ with the workspace path).
    ref = SRC / 'target/contract/templar_membership_account_PaymentVerifierAccount.compiled_contract_class.json'
    same = None
    if ref.exists():
        same = json.loads(ref.read_text())['bytecode'] == json.loads(Path(base['casm_path']).read_text())['bytecode']
    record = {
        'scope': 'P0b spike (throwaway); local build only',
        'source_workspace': str(SRC),
        'source_build_record_sha256': sha(SRC / 'build-record.json'),
        'pinned_sha256': sha(SRC / 'bridge/src/pinned.cairo'),
        'baseline_casm_equals_target_bridge_r4': same,
        'sources': {str(p.relative_to(ROOT)): sha(p) for p in [SNIP12, *sorted((HERE / 'account').rglob('*'))] if p.is_file()},
        'baseline': base,
        'spike': spike,
        'casm_delta_felts': spike['casm_felts'] - base['casm_felts'],
        'sierra_delta_felts': spike['sierra_felts'] - base['sierra_felts'],
    }
    (work / 'e2e-build-record.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: record[k] for k in ('baseline_casm_equals_target_bridge_r4', 'casm_delta_felts', 'sierra_delta_felts')}
                     | {'baseline_casm': base['casm_felts'], 'spike_casm': spike['casm_felts']}))


if __name__ == '__main__':
    main()
