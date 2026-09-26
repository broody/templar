"""Phase 0 report: binary hash checks against archived build records, and the calibration table
(measured, reference, deviation) from the phase-0 result files. Writes
results/phase0/binary-hashes.json and results/phase0/calibration.json.
"""
from pathlib import Path
import hashlib, json, re

H = Path(__file__).resolve().parent
ROOT = H.parents[1]
R0 = H / 'results/phase0'
RUNS = Path.home() / '.local/share/templar/runs/m31-device-proof1'
ARCH = ROOT / 'bench/m31-private-wrapper/results/outer-blake-v1-cap32'


def sha(p):
    with open(p, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def load(p):
    return json.loads(Path(p).read_text())


def hashes():
    checks = []

    def check(path, expected, record, note=''):
        p = ROOT / path
        actual = sha(p) if p.exists() else None
        checks.append({'binary': path, 'sha256': actual, 'archived_sha256': expected, 'record': record,
                       'match': actual == expected if expected else None, 'note': note})
    check('target/bounded-memory/bin/baseline-prover', 'd45f739393d497087381fc179391897445d36e983b00278b68c301460896bd7d',
          'bench/cairo-memory/results/summary.json', 'cairo-memory low-memory build, not stock')
    check('target/bounded-memory/bin/low-memory-prover', '8eaa1763abd7216f43fff2a935a3646e5643f55763236b41885ee77f5286d471',
          'bench/bounded-memory/results/low-memory-prover-build.json', 'bounded build used for V1 bounded runs')
    check('target/m31-private-wrapper/capacity-capture-build-v3/capture', '9920dedb496508ae1245ab8261dca7c76641dd11ff9a79d3709010e39e8b722b',
          'bench/m31-private-wrapper/results/bridge-capacity/os-capture/execution.json', 'V1 virtual-OS capture tool')
    check('target/m31-private-wrapper/capacity-build-original-v3/capacity', '27cf06db20a3b7b887ae47bb9640992acaf7fef8e2da4e1a2aab187b41713726',
          'bench/m31-private-wrapper/results/server-circuit/capacity-boot-optimized/summary.json',
          'V1 component trace tool; capacity.rs was edited after this build (source hash differs from its inputs.json)')
    check('target/m31-append/state-fixture-build-v4/state-fixture', 'f04d0f3bfad252db20220a545cd3dbd717d0d8451824986f77cc66dbeaba291c',
          'bench/m31-append/results/state-fixture/anchor.json', 'synthetic state fixture tool')
    check('target/m31-private-wrapper/attribution-build/blake_sites', None, 'none (binary unrecorded)',
          'source blake_sites.rs matches the build record inputs.json source_sha256 0f9d7457…')
    check('server/os-runner/target/release/templar-os-runner', None, 'none', 'V2 os-runner, not used (V1 capture still runs)')
    # The archived stock V1 prover and verifier lived in /tmp and were wiped by the 2026-09-24 reboot.
    stock = load(R0 / 'v1-prover-build.json')
    verifier = load(R0 / 'v1-verifier-build.json')
    checks.append({'binary': 'target/m31-device-proof1/bin/v1-stock-prover', 'sha256': stock['binary_sha256'],
                   'archived_sha256': '31fb582d5ec8cfcb028ae7c144f0152acc432f68d5cbfeb4c10e881a00f18db5',
                   'record': 'bench/m31-private-wrapper/results/outer-blake-v1-cap32/anchor.json', 'match': False,
                   'note': 'rebuilt from the same pinned source and lockfile; the archived binary is gone and '
                           'embeds different build paths; functional identity shown by a byte-identical proof'})
    checks.append({'binary': 'target/m31-device-proof1/bin/v1-local-verifier', 'sha256': verifier['binary_sha256'],
                   'archived_sha256': '492e2ea2b2bbc9eef05239407e9f3cbcc39199934b3f3bb02172aba3fd198934',
                   'record': 'bench/m31-private-wrapper/results/outer-blake-v1-cap32/anchor.json', 'match': False,
                   'note': 'source reconstructed and matches the archived verify_saved.rs hash; linked against the rebuilt libraries'})
    (R0 / 'binary-hashes.json').write_text(json.dumps(checks, indent=2) + '\n')
    return checks


def dev(measured, reference):
    return None if reference in (None, 0) or measured is None else (measured - reference) / reference


def calibration():
    arch = load(ARCH / 'report.json')
    arch_verify = int(re.search(r'verification_ms=(\d+)', (ARCH / 'local-verification.log').read_text())[1])
    stock = [load(R0 / f'blake589k-v1-stock-32g{s}/summary.json') for s in ('', '-r2', '-r3')]
    bounded = load(R0 / 'blake589k-v1-bounded-32g/summary.json')
    v2_blake = [load(R0 / f'blake589k-v2-small-64g{s}.json') for s in ('', '-final')]
    v2_sample = [load(R0 / f'starkware-sample-v2-small-64g{s}.json') for s in ('', '-final')]
    verify_ms = lambda n: int(re.search(r'verification_ms=(\d+)', (R0 / n / 'local-verification.log').read_text())[1])
    adr = load(ROOT / 'docs/adr/evidence/0018/summary.json')
    rows = []

    def row(metric, values, reference, ref_source, note=''):
        vals = [v for v in values if v is not None]
        m = sum(vals) / len(vals) if vals else None
        rows.append({'metric': metric, 'measured': values, 'measured_mean': m, 'reference': reference,
                     'reference_source': ref_source, 'deviation': dev(m, reference), 'note': note})
    src = 'bench/m31-private-wrapper/results/outer-blake-v1-cap32 (2026-09-22)'
    row('V1 stock, 589,958-step fixture: virtual-OS steps', [s['virtual_os']['n_steps'] for s in stock], 589958, src)
    row('V1 stock: OS stage seconds', [s['os_seconds'] for s in stock], arch['os_seconds'], src)
    row('V1 stock: proving stage seconds', [s['prove_seconds'] for s in stock], arch['prove_seconds'], src)
    row('V1 stock: request seconds', [s['request_seconds'] for s in stock], arch['request_seconds'], src)
    row('V1 stock: peak RSS GiB (VmHWM)', [s['peak_rss_gib'] for s in stock], arch['peak_rss_gib'], src)
    row('V1 stock: cgroup peak GiB', [s['cgroup_peak_gib'] for s in stock], arch['cgroup_peak_bytes'] / 2**30, src)
    row('V1 stock: proof bytes', [s['proof_bytes'] for s in stock], arch['proof_bytes'], src)
    row('V1 stock: proof byte-identical to archive', [s['matches_archived']['proof_bytes_identical'] for s in stock], True, src)
    row('V1 stock: local verification ms', [verify_ms(n) for n in ('blake589k-v1-stock-32g', 'blake589k-v1-stock-32g-r2',
                                                                  'blake589k-v1-stock-32g-r3')], arch_verify, src)
    row('V1 bounded (16/16 columns), same fixture: peak RSS GiB', [bounded['peak_rss_gib']], None, 'no archived bounded run of this fixture',
        f"ratio to stock mean {bounded['peak_rss_gib'] / (sum(s['peak_rss_gib'] for s in stock) / 3):.3f}; plan expects 0.43-0.63; "
        'ordinary spend reference 5.69/9.00 = 0.63 (bench/bounded-memory)')
    row('V1 bounded: proving stage seconds', [bounded['prove_seconds']], None, 'no archived bounded run of this fixture',
        f"ratio to stock mean {bounded['prove_seconds'] / (sum(s['prove_seconds'] for s in stock) / 3):.3f}; ordinary spend reference 23.07/16.74 = 1.38")
    row('V1 bounded: proof byte-identical to archive', [bounded['matches_archived']['proof_bytes_identical']], True, src)
    row('V2 small, same 589,958-step PIE: proving seconds', [r['prove_seconds'] for r in v2_blake],
        sum(s['prove_seconds'] for s in stock) / 3, 'V1 stock on the same workload (this phase)')
    row('V2 small, same PIE: peak RSS GiB', [r['peak_rss_gib'] for r in v2_blake],
        sum(s['peak_rss_gib'] for s in stock) / 3, 'V1 stock on the same workload (this phase)')
    row('V2 small, same PIE: proof bytes', [r['proof_bytes'] for r in v2_blake], None, '', 'verified, 3 rejections; deterministic across runs')
    row('V2 small, StarkWare sample tx (275,933 steps): proving seconds', [r['prove_seconds'] for r in v2_sample],
        adr['recursive_prove_seconds'], 'ADR-0018 V2 ordinary 2/2/1 (103,294 OS steps, older proving revision)',
        'different workload: the 2/2/1 private request lived in /tmp and was wiped')
    row('V2 small, StarkWare sample: peak RSS GiB', [r['peak_rss_gib'] for r in v2_sample], adr['prover_peak_rss_kib'] / 2**20,
        'ADR-0018 V2 ordinary 2/2/1', 'different workload (see above)')
    row('V2 small, StarkWare sample: proof bytes', [r['proof_bytes'] for r in v2_sample], adr['proof_bytes'],
        'ADR-0018 V2 ordinary 2/2/1', 'different workload')
    (R0 / 'calibration.json').write_text(json.dumps(rows, indent=2) + '\n')
    return rows


if __name__ == '__main__':
    for c in hashes():
        print(c['binary'], c['match'], c['note'][:60])
    for r in calibration():
        d = r['deviation']
        print(f"{r['metric']}: {r['measured_mean']} vs {r['reference']} ({'' if d is None else f'{100 * d:+.1f}%'})")
