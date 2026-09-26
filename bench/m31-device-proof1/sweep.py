"""Phase 1: capture sweep of the cost-model statement account. No proving, no chain.

For each permutation variant (compact, unrolled, qm31) this builds the account with Scarb 2.18.0,
makes and checks a synthetic authenticated state fixture with the preserved `state-fixture` tool
(pinned sequencer libraries: class hash, CASM compilation, Patricia nodes, block hash), then for
each `k` builds the INVOKE request, captures it in the virtual OS on loopback (`capture.py`),
checks the emitted message shape, and runs the shape tools. `summarize` writes one JSON per
capture and `results/phase1/summary.json`.

Usage: sweep.py prepare VARIANT... | run VARIANT K... | summarize
"""
from pathlib import Path
import hashlib, json, math, os, random, re, subprocess, sys

H = Path(__file__).resolve().parent
sys.path.insert(0, str(H))
import capture  # noqa: E402

ROOT = H.parents[1]
W = ROOT / 'target/m31-device-proof1'
RUNS = Path.home() / '.local/share/templar/runs/m31-device-proof1/phase1'
RESULTS = H / 'results/phase1'
SCARB = Path.home() / '.asdf/installs/scarb/2.18.0/bin'
STATE_FIXTURE = ROOT / 'target/m31-append/state-fixture-build-v4/state-fixture'
STATE_FIXTURE_PIN = 'f04d0f3bfad252db20220a545cd3dbd717d0d8451824986f77cc66dbeaba291c'  # bench/m31-append/results/state-fixture/anchor.json
TEMPLATE = ROOT / 'bench/m31-private-wrapper/results/bridge-capacity/optimized/public-request.json'
FEATURES = {'compact': ['--features', 'compact_perm'], 'unrolled': [], 'qm31': ['--features', 'qm31_perm'],
            'qm31_compact': ['--features', 'qm31_compact_perm']}
P = 2**31 - 1
CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')
TAG = int.from_bytes(b'TMPZDP1_COST_V1', 'big')
ASSET = 0x5678EF
# The schedule's permutations per job (statement.cairo): jobs 1-19.
JOB_PERMS = [1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4, 4, 4, 4, 2, 2]
assert sum(JOB_PERMS) == 42
W_LEN, SIB = 1000, 190
LIMIT_LOG = 20
HASH_COMPONENTS = {'blake_g', 'blake_round', 'blake_round_sigma', 'triple_xor_32', 'verify_bitwise_xor_12',
                   'blake_compress_opcode', 'poseidon_3_partial_rounds_chain', 'poseidon_full_round_chain',
                   'cube_252', 'range_check_252_width_27', 'poseidon_aggregator', 'poseidon_builtin',
                   'poseidon_round_keys'}


def sha(p):
    with open(p, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def jobs_nodes(k):
    """The longest schedule prefix with at most min(k, 42) permutations, then nodes."""
    jobs, perms = 0, 0
    while jobs < len(JOB_PERMS) and perms + JOB_PERMS[jobs] <= min(k, 42):
        perms += JOB_PERMS[jobs]
        jobs += 1
    return jobs, perms, k - perms


def prepare(variant):
    out = RUNS / variant
    out.mkdir(parents=True, exist_ok=True)
    target = W / f'cairo-{variant}'
    env = os.environ | {'PATH': f'{SCARB}:' + os.environ['PATH']}
    with (out / 'scarb-build.log').open('w') as log:
        subprocess.run([str(SCARB / 'scarb'), '--target-dir', str(target), 'build', *FEATURES[variant]],
                       cwd=H / 'cairo', env=env, check=True, stdout=log, stderr=subprocess.STDOUT)
    sierra = target / 'dev/device_cost_CostStatementAccount.contract_class.json'
    casm = target / 'dev/device_cost_CostStatementAccount.compiled_contract_class.json'
    assert sha(STATE_FIXTURE) == STATE_FIXTURE_PIN
    fixture = out / 'state-fixture.json'
    for p in (fixture, out / 'state-validation.json'):
        if p.exists():
            p.unlink()
    subprocess.run([str(STATE_FIXTURE), 'make', str(sierra), str(fixture)], check=True)
    subprocess.run([str(STATE_FIXTURE), 'check', str(fixture), str(out / 'state-validation.json')], check=True)
    fx = json.loads(fixture.read_text())
    (cls,) = fx['classes'].values()
    record = {'variant': variant, 'scarb_features': FEATURES[variant], 'sierra_sha256': sha(sierra),
              'scarb_casm_felts': len(json.loads(casm.read_text())['bytecode']),
              'fixture_sha256': sha(fixture), 'authority': fx['authority'],
              'sequencer_casm_felts': len(cls['casm']['bytecode']),
              'state_fixture_binary_sha256': STATE_FIXTURE_PIN,
              'cairo_sources_sha256': {p.name: sha(p) for p in sorted((H / 'cairo/src').glob('*.cairo'))}}
    (out / 'prepare.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: record[k] for k in ('variant', 'scarb_casm_felts', 'sequencer_casm_felts', 'fixture_sha256')}))


def words(rng, n):
    return [rng.randrange(1, P) for _ in range(n)]


def calldata(jobs, nodes):
    rng = random.Random(0xD1)  # the same public data and witness for every variant and k
    root, nullifiers, identity = words(rng, 9), words(rng, 18), words(rng, 9)
    cms = [words(rng, 9), words(rng, 9)]
    cts = [[rng.randrange(2**248) for _ in range(9)] + [rng.randrange(2**200)] for _ in range(2)]
    spend = [CHAIN, 0x456, ASSET, 9, *root, 18, *nullifiers, 2]
    for cm, ct in zip(cms, cts):
        spend += [9, *cm, 10, *ct]
    spend += [0, 0, 0, 9, *identity, 123456, 0]  # withdrawal (recipient, amount), intent, identity, valid_until, binding
    w = words(rng, W_LEN)
    w[90], w[91] = 1, 0  # ordinary key mode; input 1 disabled (its root equality is not exercised)
    w[92:96] = [600, 400, 700, 300]
    for i in range(104, 190):
        w[i] = rng.randrange(2)
    return spend + [W_LEN, *w, jobs, nodes]


def run(variant, k):
    prep = json.loads((RUNS / variant / 'prepare.json').read_text())
    fixture = RUNS / variant / 'state-fixture.json'
    out = RUNS / variant / f'k{k}'
    jobs, sponge, nodes = jobs_nodes(k)
    request = json.loads(TEMPLATE.read_text())
    request['transaction']['sender_address'] = prep['authority']['statement']
    request['transaction']['calldata'] = [hex(x) for x in calldata(jobs, nodes)]
    out.mkdir(parents=True, exist_ok=False)
    (out / 'request.json').write_text(json.dumps(request))
    cap = capture.capture(fixture, prep['fixture_sha256'], out / 'request.json', out / 'os')
    msgs = cap['l2_to_l1_messages']
    num = lambda v: int(v, 16) if isinstance(v, str) else int(v)
    payload = [num(x) for x in msgs[0]['payload']] if len(msgs) == 1 else []
    shape = {'n_messages': len(msgs), 'from_statement': len(msgs) == 1 and num(msgs[0]['from_address']) == num(prep['authority']['statement']),
             'to_zero': len(msgs) == 1 and num(msgs[0]['to_address']) == 0, 'payload_len': len(payload),
             'class_tag_chain_pool': payload[:4] == [num(prep['authority']['statement_class']), TAG, CHAIN, 0x456],
             'binding': hex(payload[4]) if len(payload) == 5 else None}
    shape['ok'] = shape['n_messages'] == 1 and shape['from_statement'] and shape['to_zero'] and shape['payload_len'] == 5 \
        and shape['class_tag_chain_pool'] and payload[4] != 0
    (out / 'message.json').write_text(json.dumps(shape, indent=2) + '\n')
    assert shape['ok'], shape
    capture.analyze(out / 'os/os.pie.zip', out / 'analysis')
    print(json.dumps({'variant': variant, 'k': k, 'jobs': jobs, 'nodes': nodes, 'n_steps': cap['resources']['n_steps'],
                      'binding': shape['binding']}), flush=True)


def log_sizes(claim):
    """Component -> list of log sizes (memory_id_to_big has one per big component)."""
    sizes = {}
    for name, c in claim.items():
        if name == 'public_data' or c is None:
            continue
        if isinstance(c, dict):
            if 'log_size' in c:
                sizes[name] = [c['log_size']]
            elif 'big_log_sizes' in c:
                sizes[name] = list(c['big_log_sizes'])
            elif 'log_sizes' in c:
                sizes[name] = list(c['log_sizes'])
            else:
                vals = [v for kk, v in c.items() if 'log_size' in kk and isinstance(v, int)]
                sizes[name] = vals or [None]
    return sizes


def segment_leaves(lengths, start=0):
    """Leaves of the bytecode segment tree as (start, length)."""
    leaves = []
    for item in lengths:
        if isinstance(item, int):
            leaves.append((start, item))
            start += item
        else:
            sub = segment_leaves(item, start)
            leaves += sub
            start = sub[-1][0] + sub[-1][1] if sub else start
    return leaves


def casm_felts(casm, visited):
    code = [int(x, 16) if isinstance(x, str) else int(x) for x in casm['bytecode']]
    bsl = casm.get('bytecode_segment_lengths', [len(code)])
    leaves = segment_leaves(bsl if isinstance(bsl, list) else [bsl])
    assert sum(l for _, l in leaves) == len(code)
    loaded = [(s, l) for s, l in leaves if s in visited]
    hashed = sum(l for _, l in loaded)
    blake_model = 0
    for s, l in loaded:
        n_words = sum(2 if x < 2**63 else 8 for x in code[s:s + l])
        blake_model += max(1, math.ceil(n_words / 16))
    executed_felts = sum(2 if (code[pc] >> 48) & 4 else 1 for pc in visited if pc < len(code))
    return {'casm_felts': len(code), 'segment_leaves': len(leaves), 'loaded_leaves': len(loaded),
            'hashed_felts': hashed, 'executed_instructions': len(visited), 'executed_felts': executed_felts,
            'class_hash_blake_model': blake_model}


def summarize_one(variant, k):
    base = RUNS / variant / f'k{k}'
    a = base / 'analysis'
    cap = json.loads((base / 'os/capture.json').read_text())
    v2boot = json.loads((a / 'trace-v2/boot.json').read_text())
    v1boot = json.loads((a / 'trace-v1/boot.json').read_text())
    small = json.loads((a / 'trace-v2/small-path.json').read_text())
    v1 = log_sizes(json.loads((a / 'trace-v1/claim.json').read_text()))
    v2 = log_sizes(json.loads((a / 'trace-v2/claim.json').read_text()))
    blake = json.loads((a / 'blake/blake-sites.json').read_text())
    fx = json.loads((RUNS / variant / 'state-fixture.json').read_text())
    (cls,) = fx['classes'].values()
    # blake_sites records segment 19's visited PCs; segment 19 holds the compiled-class struct and
    # then the bytecode. Locate the bytecode by its first eight felts in the recorded head.
    code = [int(x, 16) if isinstance(x, str) else int(x) for x in cls['casm']['bytecode']]
    head = [int(m[1]) if (m := re.match(r'Some\(Int\((\d+)\)\)', x)) else None for x in blake['seg19_head']]
    offsets = [o for o in range(len(head) - 8) if head[o:o + 8] == code[:8]]
    assert len(offsets) == 1, offsets
    off = offsets[0]
    visited = {pc - off for pc in blake['visited_seg19'] if off <= pc < off + len(code)}
    # The OS runs one instruction just past the bytecode (offset len), outside the class hash.
    outside = sorted(pc - off for pc in blake['visited_seg19'] if not off <= pc < off + len(code))
    assert len(outside) <= 1, outside
    felts = casm_felts(cls['casm'], visited)
    by_seg = {s: sum(v) for s, v in blake['blake_by_pc_segment_[compress,finalize]'].items()}
    steps_seg = {int(s): v for s, v in blake['steps_by_pc_segment'].items()}
    os_seg = max(steps_seg, key=lambda s: steps_seg[s] if s not in (0, 19) else -1)
    request = json.loads((base / 'request.json').read_text())
    jobs, sponge, nodes = jobs_nodes(k)
    enabled_v2 = {n for n, s in v2.items() if any(x for x in s if x)}
    over_v2 = {n: max(s) for n, s in v2.items() if max(x or 0 for x in s) > LIMIT_LOG}
    over_v1 = {n: max(s) for n, s in v1.items() if max(x or 0 for x in s) > LIMIT_LOG}
    not_in_small = sorted(enabled_v2 - set(small['privacy_transaction_components']))
    poseidon = cap['resources']['builtin_instance_counter']['poseidon_builtin']
    poseidon_total = v2boot['builtin_instance_counter'].get('poseidon_builtin')
    blake_total = v2boot['opcode_rows']['blake_compress_opcode']
    nonhash_over = {n: s for n, s in over_v2.items() if n not in HASH_COMPONENTS}
    s1 = {'nonhash_components_over_2^20': nonhash_over, 'blake_total': blake_total, 'blake_ok': blake_total <= 8192,
          'poseidon_total': poseidon_total, 'poseidon_ok': poseidon_total <= 8192,
          'components_not_in_small_path': not_in_small, 'all_components_le_2^20': not over_v2}
    s1['pass'] = not nonhash_over and s1['blake_ok'] and s1['poseidon_ok'] and not not_in_small and not over_v2
    # The plan's 8,192 is V1's Blake capacity (blake_g 128 rows per compression). V2's blake_g has
    # 80 rows per compression (10 rounds), so at log 20 it holds about 13,107.
    s1['blake_g_log'] = {'v1': max(v1.get('blake_g', [0])), 'v2': max(v2.get('blake_g', [0]))}
    s1['v1_all_components_le_2^20'] = not over_v1
    s1['blake_le_7000_margin'] = blake_total <= 7000
    if variant.startswith('qm31'):
        s1['qm31_steps_le_1.2M'] = cap['resources']['n_steps'] <= 1_200_000
        s1['pass'] = s1['pass'] and s1['qm31_steps_le_1.2M']
    record = {
        'variant': variant, 'k': k, 'jobs': jobs, 'sponge_permutations': sponge, 'nodes': nodes,
        'virtual_os': cap['resources'], 'os_seconds': cap['os_seconds'],
        'bootloader_run_total_steps': v2boot['n_steps'], 'steps_by_pc_segment': {
            'bootloader': steps_seg.get(0), 'os': steps_seg.get(os_seg), 'account': steps_seg.get(19),
            'os_segment_index': os_seg, 'all': blake['steps_by_pc_segment']},
        'builtins_total': v2boot['builtin_instance_counter'], 'opcode_rows_v2': v2boot['opcode_rows'],
        'memory_rows_v2': v2boot['memory'],
        'blake': {'total': blake_total, 'bootloader': by_seg.get('0', 0), 'os': by_seg.get(str(os_seg), 0),
                  'account': by_seg.get('19', 0), 'by_segment_[compress,finalize]': blake['blake_by_pc_segment_[compress,finalize]']},
        'poseidon': {'virtual_os': poseidon, 'total': poseidon_total},
        'casm': felts | {'bytecode_offset_in_segment_19': off, 'visited_outside_bytecode': outside}, 'calldata_felts': len(request['transaction']['calldata']),
        'component_log_sizes_v2': v2, 'component_log_sizes_v1': v1,
        'max_log_v2': max(max(x or 0 for x in s) for s in v2.values()),
        'max_log_v1': max(max(x or 0 for x in s) for s in v1.values()),
        'over_2^20_v2': over_v2, 'over_2^20_v1': over_v1,
        'v1_boot': {'blake_compressions': v1boot['blake_compressions'], 'qm31_opcodes': v1boot['qm31_opcodes'],
                    'generic_opcodes': v1boot['generic_opcodes']},
        'small_path': {'cairo_trace_log_size': small['cairo_trace_log_size'],
                       'enabled_components': sorted(enabled_v2), 'not_in_fixed_list': not_in_small,
                       'accepted_by_fixed_recursion': not not_in_small and not over_v2},
        'S1': s1, 'message': json.loads((base / 'message.json').read_text()),
        'pie_sha256': sha(base / 'os/os.pie.zip'), 'fixture_sha256': sha(RUNS / variant / 'state-fixture.json'),
        'tools': {n: {kk: r[kk] for kk in ('wall_seconds', 'max_rss_gib')} for n, r in
                  json.loads((a / 'tools.json').read_text()).items()},
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f'{variant}-k{k}.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def fit(points):
    """Least-squares slope and intercept of (x, y)."""
    n = len(points)
    mx = sum(x for x, _ in points) / n
    my = sum(y for _, y in points) / n
    sxx = sum((x - mx) ** 2 for x, _ in points)
    b = sum((x - mx) * (y - my) for x, y in points) / sxx
    return b, my - b * mx


def summarize():
    rows = []
    for variant in FEATURES:
        for d in sorted((RUNS / variant).glob('k*'), key=lambda p: int(p.name[1:])):
            if (d / 'analysis/tools.json').exists():
                rows.append(summarize_one(variant, int(d.name[1:])))
    table = []
    for r in rows:
        top = sorted(((max(x or 0 for x in s), n) for n, s in r['component_log_sizes_v2'].items()), reverse=True)[:4]
        table.append({'variant': r['variant'], 'k': r['k'], 'jobs': r['jobs'], 'nodes': r['nodes'],
                      'os_steps': r['virtual_os']['n_steps'], 'total_steps': r['bootloader_run_total_steps'],
                      'account_steps': r['steps_by_pc_segment']['account'], 'blake': r['blake']['total'],
                      'blake_os': r['blake']['os'], 'poseidon': r['poseidon']['total'],
                      'hashed_felts': r['casm']['hashed_felts'], 'executed_felts': r['casm']['executed_felts'],
                      'casm_felts': r['casm']['casm_felts'], 'calldata': r['calldata_felts'],
                      'largest_v2': [f'{n}:{s}' for s, n in top], 'max_log_v2': r['max_log_v2'],
                      'max_log_v1': r['max_log_v1'], 'blake_g_log': r['S1']['blake_g_log'],
                      'add_opcode_rows': r['opcode_rows_v2']['add_opcode'], 'mul_opcode_rows': r['opcode_rows_v2']['mul_opcode'],
                      'memory_rows': r['memory_rows_v2'], 'not_in_small_path': r['S1']['components_not_in_small_path'],
                      'S1_pass': r['S1']['pass'], 'binding': r['message']['binding']})
    fits = {}
    for variant in FEATURES:
        rs = {r['k']: r for r in rows if r['variant'] == variant}
        # Sponge-only captures (k <= 16: nodes = 0) and node-only increments (k >= 64: jobs = 19).
        sponge = [(r['sponge_permutations'], r['steps_by_pc_segment']['account']) for r in rs.values() if r['nodes'] == 0]
        nodes = [(r['nodes'], r['steps_by_pc_segment']['account']) for r in rs.values() if r['jobs'] == 19]
        os_all = [(k, r['virtual_os']['n_steps']) for k, r in rs.items()]
        f = {}
        if len(sponge) >= 2:
            f['account_steps_per_sponge_permutation'] = fit(sponge)[0]
        if len(nodes) >= 2:
            f['account_steps_per_node_permutation'] = fit(nodes)[0]
        if len(os_all) >= 2:
            f['os_steps_per_k_all_points'], f['os_steps_intercept'] = fit(os_all)
        fits[variant] = f
    bindings = {}
    for r in rows:
        bindings.setdefault(str(r['k']), {})[r['variant']] = r['message']['binding']
    consistent = {k: len(set(v.values())) == 1 for k, v in bindings.items() if len(v) > 1}
    summary = {'rows': table, 'fits': fits, 'bindings_by_k': bindings, 'bindings_agree_across_variants': consistent}
    (RESULTS / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    for t in table:
        print(json.dumps(t))
    print(json.dumps(fits, indent=1))
    print(json.dumps(consistent))


if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'prepare':
        for v in sys.argv[2:]:
            prepare(v)
    elif cmd == 'run':
        for k in sys.argv[3:]:
            run(sys.argv[2], int(k))
    elif cmd == 'summarize':
        summarize()
    else:
        raise SystemExit(__doc__)
