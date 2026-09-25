"""P0b spike (throwaway): component trace sizes and Blake attribution for the captured PIEs,
with the server-log20 tools (`capacity trace`, `blake_sites`), as in
bench/m31-private-wrapper/server-log20/sweep.py. Resource counts only; no proof, no timing.

Usage: analyze_pies.py E2E_DIR NAME...   (E2E_DIR/captures/NAME/os.pie.zip -> E2E_DIR/analysis/NAME)
"""
from pathlib import Path
import json, subprocess, sys

ROOT = Path(__file__).resolve().parents[3]
CAPACITY = ROOT / 'target/m31-private-wrapper/capacity-build-original-v3/capacity'
BLAKE_SITES = ROOT / 'target/m31-private-wrapper/attribution-build/blake_sites'
LIMIT = 20


def maxrss_kib(log):
    for line in log.read_text().splitlines():
        if 'Maximum resident set size' in line:
            return int(line.split(':')[-1])
    return None


def analyze(e2e, name):
    cap = e2e / 'captures' / name
    out = e2e / 'analysis' / name
    out.mkdir(parents=True, exist_ok=True)
    pie = cap / 'os.pie.zip'
    if not (out / 'trace/claim.json').exists():
        with (out / 'trace.log').open('w') as log:
            subprocess.run(['/usr/bin/time', '-v', str(CAPACITY), 'trace', str(pie), str(out / 'trace')], check=True, stdout=log, stderr=subprocess.STDOUT)
    if not (out / 'blake/blake-sites.json').exists():
        with (out / 'blake.log').open('w') as log:
            subprocess.run(['/usr/bin/time', '-v', str(BLAKE_SITES), str(pie), str(out / 'blake')], check=True, stdout=log, stderr=subprocess.STDOUT)
    boot = json.loads((out / 'trace/boot.json').read_text())
    claim = json.loads((out / 'trace/claim.json').read_text())
    sizes = {}

    def walk(x, path):
        if isinstance(x, dict):
            for k, v in x.items():
                walk(v, path + [k])
        elif isinstance(x, list):
            for i, v in enumerate(x):
                walk(v, path + [str(i)])
        elif isinstance(x, int) and path and path[-1] == 'log_size':
            sizes['/'.join(path[:-1])] = x
    walk(claim, [])
    b = json.loads((out / 'blake/blake-sites.json').read_text())
    seg = {k: sum(v) for k, v in b['blake_by_pc_segment_[compress,finalize]'].items()}
    capture = json.loads((cap / 'capture.json').read_text())
    poseidon = boot['builtin_segments']['poseidon_builtin']
    r = {
        'pie': str(pie),
        'os_resources': capture['resources'],
        'bootloader_total_steps': b['total_steps'],
        'steps_by_pc_segment': b['steps_by_pc_segment'],
        'account_code_steps_seg19': b['steps_by_pc_segment'].get('19'),
        'account_code_visited_pcs_seg19': len(b['visited_seg19']),
        'segment_sizes': {str(i): n for i, n in enumerate(b['segment_sizes'])},
        'blake_total': b['blake_total'],
        'blake_total_boot_json': boot['blake_compressions'],
        'blake_by_pc_segment': seg,
        'blake_by_role': {'bootloader': seg.get('0'), 'os': seg.get('14'), 'account': seg.get('19')},
        'poseidon_instances_boot': (poseidon['stop_ptr'] - poseidon['begin_addr']) // 6,
        'builtin_segments': boot['builtin_segments'],
        'component_log_sizes': sizes,
        'max_log': max(sizes.values()),
        'over_log20': {k: v for k, v in sizes.items() if v > LIMIT},
        'tool_max_rss_kib': {'capacity_trace': maxrss_kib(out / 'trace.log'), 'blake_sites': maxrss_kib(out / 'blake.log')},
    }
    (out / 'result.json').write_text(json.dumps(r, indent=1) + '\n')
    return r


BYTECODE_OFFSET = 27  # the class bytecode starts at offset 27 of PC segment 19 in the bootloader replay


def hashed_bytecode(e2e, name, casm_path):
    """Felts of the class's leaf bytecode segments that contain an executed PC: what the OS
    Blake-hashes (inferred from the segment tree; unvisited leaves enter by their hash)."""
    c = json.loads(Path(casm_path).read_text())
    b = json.loads((e2e / 'analysis' / name / 'blake/blake-sites.json').read_text())
    bc = [int(x, 16) for x in c['bytecode']]
    visited = {p - BYTECODE_OFFSET for p in b['visited_seg19'] if p >= BYTECODE_OFFSET}
    leaves = []

    def flat(segs, off):
        for x in segs:
            if isinstance(x, int):
                leaves.append((off, x))
                off += x
            else:
                off = flat(x, off)
        return off
    assert flat(c['bytecode_segment_lengths'], 0) == len(bc)
    vis = [(o, n) for o, n in leaves if any(p in visited for p in range(o, o + n))]
    felts = sum(n for _, n in vis)
    big = sum(1 for o, n in vis for i in range(o, o + n) if bc[i] >= 2**63)
    return {'casm_felts': len(bc), 'leaf_segments': len(leaves), 'visited_leaf_segments': len(vis),
            'visited_pcs': len(visited & set(range(len(bc)))), 'hashed_felts': felts, 'hashed_big_felts': big}


def summary(e2e):
    build = json.loads((e2e / 'work/e2e-build-record.json').read_text())
    rows = {}
    for name, cls in (('baseline', 'baseline'), ('spike', 'spike')):
        r = json.loads((e2e / 'analysis' / name / 'result.json').read_text())
        ex = json.loads((e2e / 'captures' / name / 'execution.json').read_text())
        bi = r['os_resources']['builtin_instance_counter']
        seg = r['steps_by_pc_segment']
        rows[name] = {
            'pie': r['pie'], 'pie_sha256': ex['pie_sha256'], 'payload': ex['payload'], 'calldata_felts': ex['calldata_felts'],
            'os_n_steps': r['os_resources']['n_steps'], 'os_memory_holes': r['os_resources']['n_memory_holes'],
            'ec_op': bi['ec_op_builtin'], 'poseidon': bi['poseidon_builtin'], 'range_check': bi['range_check_builtin'],
            'pedersen': bi['pedersen_builtin'], 'bitwise': bi['bitwise_builtin'], 'ecdsa': bi['ecdsa_builtin'], 'output': bi['output_builtin'],
            'replay_total_steps': r['bootloader_total_steps'], 'steps_bootloader_seg0': seg.get('0'),
            'steps_os_seg14': seg.get('14'), 'steps_account_seg19': seg.get('19'),
            'blake_total': r['blake_total'], 'blake_bootloader': r['blake_by_role']['bootloader'],
            'blake_os': r['blake_by_role']['os'], 'blake_account': r['blake_by_role']['account'],
            'max_component_log': r['max_log'], 'over_log20': r['over_log20'], 'component_log_sizes': r['component_log_sizes'],
            'sierra_felts': build[cls]['sierra_felts'], 'casm_felts': build[cls]['casm_felts'],
            'os_hashed_bytecode': hashed_bytecode(e2e, name, build[cls]['casm_path']),
            'capture_max_rss_kib': maxrss_kib(e2e / 'captures' / name / 'capture.log'),
            'tool_max_rss_kib': r['tool_max_rss_kib'],
        }
    a, b = rows['baseline'], rows['spike']
    delta = {k: b[k] - a[k] for k in a if isinstance(a[k], int) and isinstance(b[k], int) and not k.endswith('_kib')}
    delta['os_hashed_felts'] = b['os_hashed_bytecode']['hashed_felts'] - a['os_hashed_bytecode']['hashed_felts']
    changed = {k: [a['component_log_sizes'].get(k), v] for k, v in b['component_log_sizes'].items() if a['component_log_sizes'].get(k) != v}
    neg = json.loads((e2e / 'captures/negative/execution.json').read_text()) if (e2e / 'captures/negative/execution.json').exists() else None
    out = {'scope': 'P0b spike (throwaway): virtual-OS PIEs over the synthetic fixture; resource counts, no proof',
           'rows': rows, 'delta_spike_minus_baseline': delta, 'component_log_size_changes': changed,
           'negative': neg and {k: neg.get(k) for k in ('rejected', 'exit_code', 'n_messages', 'pie_exists', 'reason')}}
    (e2e / 'summary.json').write_text(json.dumps(out, indent=1) + '\n')
    return out


def main():
    e2e = Path(sys.argv[1]).resolve()
    for name in sys.argv[2:]:
        r = analyze(e2e, name)
        print(json.dumps({'name': name, 'blake': r['blake_total'], 'by_role': r['blake_by_role'], 'max_log': r['max_log'],
                          'over_log20': r['over_log20'], 'account_steps': r['account_code_steps_seg19']}), flush=True)
    if (e2e / 'analysis/baseline/result.json').exists() and (e2e / 'analysis/spike/result.json').exists():
        s = summary(e2e)
        print(json.dumps({'delta': s['delta_spike_minus_baseline'], 'component_log_size_changes': s['component_log_size_changes']}))


if __name__ == '__main__':
    main()
