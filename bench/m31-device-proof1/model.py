"""Phase 2 analysis: the result tables, the memory model and the tier verdicts.

Memory is fitted against the Cairo base-trace cells (every committed base column's rows, from
`prove-small trace` on the same PIE), not steps. V1 runs are fitted against the same V2 trace
cells as a proxy (the V1 AIR is close but not identical). Writes results/phase2/model.json.
"""
from pathlib import Path
import json, re

H = Path(__file__).resolve().parent
RUNS = Path.home() / '.local/share/templar/runs/m31-device-proof1'
P2 = H / 'results/phase2'
LIMITS = {'16 GiB desktop': 12, '32 GiB desktop': 26, 'browser (wasm32)': 3.5, 'phone': 2}


def load(p):
    return json.loads(Path(p).read_text())


def trace_of(pie_dir):
    """(base cells, padded rows, total steps) for a PIE's analysis directory."""
    sp = load(pie_dir / 'trace-v2/small-path.json')
    boot = load(pie_dir / 'trace-v2/boot.json')
    claim = load(pie_dir / 'trace-v2/claim.json')
    rows = 0
    for name, c in claim.items():
        if name == 'public_data' or not isinstance(c, dict):
            continue
        for key, v in c.items():
            if key == 'log_size':
                rows += 2 ** v
            elif key == 'big_log_sizes':
                rows += sum(2 ** x for x in v)
    return {'base_cells': sp['base_trace_cells'], 'padded_rows': rows, 'total_steps': boot['n_steps']}


def analysis_dir(variant, k):
    if variant == 'blake589k':
        return RUNS / 'phase0/blake589k-analysis'
    if variant == 'sample':
        return RUNS / 'phase0/starkware-sample-analysis'
    return RUNS / 'phase1' / variant / f'k{k}' / 'analysis'


def runs():
    """Every passing phase-2 run as a row: prover, variant, k, peak, time."""
    rows = []
    for f in sorted((P2 / 'v2').glob('*.json')):
        d = load(f)
        m = re.match(r'(?:scaling-)?(compact|qm31_compact|qm31)-k(\d+)-', d['name'])
        if not m:
            continue
        variant, k, mode = m[1], int(m[2]), d['mode']
        rows.append({'name': d['name'], 'prover': {'recursive': 'v2-small', 'cairo-only': 'v2-cairo-stage',
                                                   'recursion': 'v2-recursion-stage'}[mode],
                     'variant': variant, 'k': k, 'status': d['status'], 'cap': d['cap_gib'], 'threads': d['threads'],
                     'peak_rss_gib': d['peak_rss_gib'], 'prove_seconds': d.get('prove_seconds'),
                     'wall_seconds': d['wall_seconds'], 'proof_bytes': d.get('proof_bytes'),
                     'stages': d.get('stages'), 'verified': (d.get('verify') or {}).get('passed'),
                     'message_ok': d.get('message_matches_capture'), 'scaling': d['name'].startswith('scaling-'),
                     'native_verify': d.get('native_verify'), 'error': d.get('error_lines')})
    for f in sorted(P2.glob('compact-k*-v1-*/summary.json')):
        d = load(f)
        m = re.match(r'compact-k(\d+)-v1-(stock|bounded)', d['name'])
        rows.append({'name': d['name'], 'prover': 'v1-' + m[2], 'variant': 'compact', 'k': int(m[1]),
                     'status': d['status'], 'cap': d['cap_gib'], 'threads': d['threads'], 'peak_rss_gib': d['peak_rss_gib'],
                     'prove_seconds': d.get('prove_seconds'), 'request_seconds': d.get('request_seconds'),
                     'proof_bytes': d.get('proof_bytes'), 'verified': d.get('verifier_passed_with_three_rejections'),
                     'message_ok': d.get('message_matches_capture'), 'scaling': False,
                     'os_steps': (d.get('virtual_os') or {}).get('n_steps')})
    return rows


def fit(points):
    n = len(points)
    mx = sum(x for x, _ in points) / n
    my = sum(y for _, y in points) / n
    sxx = sum((x - mx) ** 2 for x, _ in points)
    b = sum((x - mx) * (y - my) for x, y in points) / sxx
    a = my - b * mx
    resid = [y - (a + b * x) for x, y in points]
    ss = sum(r * r for r in resid)
    st = sum((y - my) ** 2 for _, y in points)
    return {'intercept': a, 'slope': b, 'max_abs_residual': max(abs(r) for r in resid), 'r2': 1 - ss / st if st else None,
            'n': n}


def main():
    rows = runs()
    # Extra calibration points on other workloads, same provers.
    calib = []
    for name, variant, prover in [('calib-blake589k-v2-small', 'blake589k', 'v2-small'),
                                  ('calib-blake589k-v2-cairo-only', 'blake589k', 'v2-cairo-stage')]:
        d = load(P2 / 'calibration' / f'{name}.json')
        calib.append({'prover': prover, 'variant': variant, 'k': None, 'peak_rss_gib': d['peak_rss_gib'],
                      'prove_seconds': d['prove_seconds'], 'threads': 4, 'status': d['status'], 'scaling': False})
    v1c = load(P2 / 'calib-blake589k-v1-stock/summary.json')
    calib.append({'prover': 'v1-stock', 'variant': 'blake589k', 'k': None, 'peak_rss_gib': v1c['peak_rss_gib'],
                  'prove_seconds': v1c['prove_seconds'], 'threads': 4, 'status': v1c['status'], 'scaling': False})
    b0 = load(H / 'results/phase0/blake589k-v1-bounded-32g/summary.json')
    calib.append({'prover': 'v1-bounded', 'variant': 'blake589k', 'k': None, 'peak_rss_gib': b0['peak_rss_gib'],
                  'prove_seconds': b0['prove_seconds'], 'threads': 4, 'status': b0['status'], 'scaling': False})
    for s in ('starkware-sample-v2-small-64g', 'starkware-sample-v2-small-64g-final'):
        d = load(H / 'results/phase0' / f'{s}.json')
        calib.append({'prover': 'v2-small', 'variant': 'sample', 'k': None, 'peak_rss_gib': d['peak_rss_gib'],
                      'prove_seconds': d['prove_seconds'], 'threads': 4, 'status': 'passed', 'scaling': False})
    points = [r for r in rows + calib if r['status'] == 'passed' and r['threads'] == 4 and r['prover'] != 'v2-recursion-stage']
    for r in points:
        r.update(trace_of(analysis_dir(r['variant'], r['k'])))
    models = {}
    for prover in ('v2-small', 'v2-cairo-stage', 'v1-stock', 'v1-bounded'):
        ps = [r for r in points if r['prover'] == prover]
        if len({r['base_cells'] for r in ps}) < 2:
            continue
        models[prover] = {
            'peak_gib_vs_base_cells_1e8': fit([(r['base_cells'] / 1e8, r['peak_rss_gib']) for r in ps]),
            'peak_gib_vs_padded_rows_1e6': fit([(r['padded_rows'] / 1e6, r['peak_rss_gib']) for r in ps]),
            'peak_gib_vs_steps_1e6': fit([(r['total_steps'] / 1e6, r['peak_rss_gib']) for r in ps]),
            'seconds_vs_base_cells_1e8': fit([(r['base_cells'] / 1e8, r['prove_seconds']) for r in ps]),
            'points': [(r['variant'], r['k'], r['base_cells'], r['peak_rss_gib'], r['prove_seconds']) for r in ps],
        }
    # The statement family only (the cost-model account): the Blake fixture has a different
    # composition (many big-felt memory values) and sits above the family line.
    family = {}
    for prover in ('v2-small', 'v2-cairo-stage', 'v1-stock', 'v1-bounded'):
        ps = [r for r in points if r['prover'] == prover and r['variant'] in ('compact', 'qm31', 'qm31_compact')]
        if len({r['base_cells'] for r in ps}) >= 2:
            family[prover] = fit([(r['base_cells'] / 1e8, r['peak_rss_gib']) for r in ps])
            family[prover]['seconds'] = fit([(r['base_cells'] / 1e8, r['prove_seconds']) for r in ps])
    # Projection for a faithful R0 V6 statement: k = 102 plus 5-15% more account steps for the
    # relation's selects and range checks, at the compact family's cells per account step.
    p1 = H / 'results/phase1'
    proj = {}
    for variant in ('compact', 'qm31_compact', 'qm31'):
        a, b = load(p1 / f'{variant}-k64.json'), load(p1 / f'{variant}-k106.json')
        ca = trace_of(analysis_dir(variant, 64))['base_cells']
        cb = trace_of(analysis_dir(variant, 106))['base_cells']
        per_step = (cb - ca) / (b['steps_by_pc_segment']['account'] - a['steps_by_pc_segment']['account'])
        c102 = ca + (cb - ca) * (102 - 64) / (106 - 64)
        steps102 = a['steps_by_pc_segment']['account'] + (b['steps_by_pc_segment']['account'] - a['steps_by_pc_segment']['account']) * 38 / 42
        lo, hi = c102 + 0.05 * steps102 * per_step, c102 + 0.15 * steps102 * per_step
        e = lambda m, c: m['intercept'] + m['slope'] * c / 1e8
        entry = {'cells_k102': c102, 'cells_faithful': [lo, hi], 'cells_per_account_step': per_step}
        for prover in ('v2-small', 'v2-cairo-stage', 'v1-stock', 'v1-bounded'):
            if prover in family:
                entry[prover + '_peak_gib'] = [e(family[prover], lo), e(family[prover], hi)]
                entry[prover + '_seconds'] = [e(family[prover]['seconds'], lo), e(family[prover]['seconds'], hi)]
        proj[variant] = entry
    out = {'rows': rows, 'calibration_points': calib, 'models': models, 'family_models': family,
           'r0v6_projection': proj}
    (P2 / 'model.json').write_text(json.dumps(out, indent=2) + '\n')
    for prover, m in models.items():
        c = m['peak_gib_vs_base_cells_1e8']
        s = m['peak_gib_vs_steps_1e6']
        print(f"{prover}: peak = {c['intercept']:.2f} + {c['slope']:.2f} GiB per 1e8 cells (r2 {c['r2']:.4f}, max resid "
              f"{c['max_abs_residual']:.2f}); vs steps r2 {s['r2']:.4f} resid {s['max_abs_residual']:.2f}; n={c['n']}")
    for prover, c in family.items():
        print(f"family {prover}: peak = {c['intercept']:.2f} + {c['slope']:.2f}/1e8 cells (r2 {c['r2']:.4f}, max resid "
              f"{c['max_abs_residual']:.2f}, n={c['n']}); seconds = {c['seconds']['intercept']:.1f} + {c['seconds']['slope']:.2f}/1e8")
    for v, e in proj.items():
        print(v, {k: ([round(x, 1) for x in val] if isinstance(val, list) and k != 'cells_faithful' else val)
                  for k, val in e.items()})


if __name__ == '__main__':
    main()
