#!/usr/bin/env python3
"""R0 V6 in the server's pinned virtual OS on live Sepolia state (docs/pool-v3-spec.md §9.3, §15 C):
the deployed V6 statement account runs each shape's real proof; the run's resources set the caps,
the bucket check measures the PROOF2 leaf margin, and one PROOF2 checks the facts against the
routing adapter's formula (PV6-C7).

  measure_v6.py os [CASE...]       virtual-OS runs at the latest block (nothing is sent)
  measure_v6.py bucket [CASE...]   templar-prove bucket on each run's PIE
  measure_v6.py prove CASE         PROOF2 (templar-prove, bounded; ~30 GiB) and the facts check
  measure_v6.py gas [CASE...]      the virtual transaction's L2 gas from the local node's estimate
                                   (refused while the proof's calldata exceeds the node's cap)
  measure_v6.py l2 [CASE...]       the smallest L2 gas bound the virtual OS run succeeds with,
                                   by bisection (±2M): the gas the virtual transaction uses
  measure_v6.py report             results/measure-v6.json

CASE is a proof directory in ~/.local/share/templar/runs/r6-p1/proofs (default: the eight shapes and
the valid_until extremes). The job is built as server/prover/src/pipeline.rs builds an r6 job: an
INVOKE_V3 from the statement account, calldata `(proof_data)`, zero tip and prices, the 450M L2 gas
bound, the nonce at the base block. The run must emit exactly one message, `[statement class,
'TMPZR0_PAYMENT_V6', chain, pool, binding]`, the binding recomputed with starknet.js
(cairo-r6/kat/v6.cjs). Nothing is signed or sent.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNTIME = Path(os.environ.get('TEMPLAR_ADR27_RUN', Path.home() / '.local/share/templar/runs/adr27-d'))
PROOFS = Path.home() / '.local/share/templar/runs/r6-p1/proofs'
JOBS = RUNTIME / 'measure'
RPC = 'http://127.0.0.1:9545/rpc/v0_10'
OS_RUNNER = ROOT / 'server/os-runner/target/release/templar-os-runner'
PROVE = ROOT / 'server/prove/target/release/templar-prove'
V6 = ROOT / 'bench/m31-private-wrapper/client-port/cairo-r6/kat/v6.cjs'
POSEIDON = ROOT / 'sdk/ts/node_modules/starknet'
L2_GAS = 450_000_000
TAG = int.from_bytes(b'TMPZR0_PAYMENT_V6', 'big')
CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')
CASES = ['transfer', 'single', 'one-out', 'partial', 'full', 'invoke', 'shadow', 'nft', 'valid-until-1', 'valid-until-max']


def rpc(method, params):
    req = urllib.request.Request(RPC, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=300) as r:
        v = json.load(r)
    if 'error' in v:
        raise RuntimeError(json.dumps(v['error'])[:1500])
    return v['result']


def load(p, default=None):
    p = Path(p)
    return json.loads(p.read_text()) if p.exists() else default


D = load(HERE / 'results/deployment.json') or sys.exit('deploy first (deploy.py)')
STATEMENT, CLASS = D['r0_route']['statement'], D['statement_class']


def timed(cmd, log, env=None):
    t = time.time()
    with open(log, 'w') as f:
        p = subprocess.run(['/usr/bin/time', '-v', *map(str, cmd)], stdout=f, stderr=subprocess.STDOUT, env=env)
    text = Path(log).read_text()
    rss = next((int(line.split()[-1]) for line in text.splitlines() if 'Maximum resident set size' in line), None)
    return p.returncode, time.time() - t, rss


def binding(proof_dir):
    js = f"const v=require({json.dumps(str(V6))});console.log(v.hex(v.binding(v.readPublic({json.dumps(str(proof_dir))}))))"
    return int(subprocess.check_output(['node', '-e', js], text=True).strip(), 16)


def tx_for(case, block, l2_gas=L2_GAS):
    proof = load(PROOFS / case / 'cairo-arguments.json')
    assert int(proof[0], 16) == len(proof) - 1
    nonce = rpc('starknet_getNonce', [{'block_number': block}, STATEMENT])
    zero = {'max_amount': '0x0', 'max_price_per_unit': '0x0'}
    return {'type': 'INVOKE', 'version': '0x3', 'sender_address': STATEMENT, 'calldata': proof, 'signature': [], 'nonce': nonce,
            'resource_bounds': {'l1_gas': zero, 'l2_gas': {'max_amount': hex(l2_gas), 'max_price_per_unit': '0x0'}, 'l1_data_gas': zero},
            'tip': '0x0', 'paymaster_data': [], 'account_deployment_data': [],
            'nonce_data_availability_mode': 'L1', 'fee_data_availability_mode': 'L1'}


def os_run(case):
    pub = load(PROOFS / case / 'public.json')
    assert 'account' not in pub and int(pub['chain'], 16) == CHAIN
    block = int(rpc('starknet_blockNumber', []))
    job = JOBS / case
    job.mkdir(parents=True, exist_ok=True)
    (job / 'os-job.json').write_text(json.dumps({'rpc_url': RPC, 'chain_id': 'SN_SEPOLIA', 'block_number': block,
                                                 'transaction': tx_for(case, block)}, indent=1))
    code, secs, rss = timed([OS_RUNNER, 'run', job], job / 'os.log')
    out = {'case': case, 'block': block, 'os_exit': code, 'os_wall_seconds': round(secs, 1), 'os_max_rss_kib': rss}
    if code == 0:
        res = load(job / 'os-result.json')
        msgs = res['l2_to_l1_messages']
        num = lambda v: int(v, 16) if isinstance(v, str) else int(v)  # noqa: E731
        expected = [int(CLASS, 16), TAG, CHAIN, int(pub['pool'], 16), binding(PROOFS / case)]
        out.update(resources=res['resources'], os_seconds=res['os_seconds'], messages=len(msgs),
                   message_ok=len(msgs) == 1 and num(msgs[0]['from_address']) == int(STATEMENT, 16)
                   and [num(x) for x in msgs[0]['payload']] == expected, payload=[hex(x) for x in expected])
    else:
        out['log_tail'] = (job / 'os.log').read_text()[-600:]
    (job / 'measure-os.json').write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items() if k not in ('resources', 'payload')} | {'n_steps': out.get('resources', {}).get('n_steps')}), flush=True)


def bucket(case):
    job = JOBS / case
    code, secs, rss = timed([PROVE, 'bucket', job], job / 'bucket.log', env=dict(os.environ, RAYON_NUM_THREADS='16'))
    out = {'case': case, 'exit': code, 'wall_seconds': round(secs, 1), 'max_rss_kib': rss, **(load(job / 'bucket.json', {}) if code == 0 else {})}
    (job / 'measure-bucket.json').write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items() if k not in ('component_log_sizes', 'component_enable_bits')}), flush=True)


def prove(case):
    job = JOBS / case
    (job / 'prove-job.json').write_text(json.dumps({'cairo_fri_columns': 16, 'circuit_fri_columns': 16, 'stream_commitments': False}))
    code, secs, rss = timed([PROVE, 'prove', job], job / 'prove.log', env=dict(os.environ, RAYON_NUM_THREADS='16'))
    out = {'case': case, 'prove_exit': code, 'wall_seconds': round(secs, 1), 'max_rss_kib': rss}
    if code == 0:
        out.update(load(job / 'prove-result.json'))
        pre = load(job / 'output-preimage.json')
        os_out = load(job / 'measure-os.json')
        facts = [int.from_bytes(b'PROOF2', 'big'), int.from_bytes(b'VIRTUAL_SNOS', 'big'), *[int(x, 16) for x in pre]]
        # The routing adapter's message hash: Poseidon(statement, 0, 5, payload) (§6.2).
        js = (f"const {{hash}}=require({json.dumps(str(POSEIDON))});"
              f"console.log(hash.computePoseidonHashOnElements({json.dumps([STATEMENT, '0x0', '0x5', *os_out['payload']])}))")
        want = int(subprocess.check_output(['node', '-e', js], text=True).strip(), 16)
        route = D['r0_route']
        out['facts'] = [hex(x) for x in facts]
        out['facts_check'] = {
            'n_facts': len(facts) == 9,
            'os_program': facts[2] == int(route['os_program'], 16),
            'output_version': facts[3] == int.from_bytes(b'VIRTUAL_SNOS0', 'big'),
            'base_block': facts[4] == os_out['block'],
            'one_message': facts[7] == 1,
            'message_hash': facts[8] == want,
        }
    (job / 'measure-prove.json').write_text(json.dumps(out, indent=1))
    print(json.dumps(out), flush=True)


def gas(case):
    block = int(rpc('starknet_blockNumber', []))
    tx = tx_for(case, block)
    try:
        est = rpc('starknet_estimateFee', [[tx], ['SKIP_VALIDATE'], {'block_number': block}])
        out = {'case': case, 'l2_gas_consumed': int(est[0]['l2_gas_consumed'], 16), 'estimate': est[0]}
    except RuntimeError as e:
        out = {'case': case, 'error': str(e)[:600]}
    (JOBS / case).mkdir(parents=True, exist_ok=True)
    (JOBS / case / 'measure-gas.json').write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items() if k != 'estimate'}), flush=True)


def l2(case):
    """Bisects the virtual transaction's L2 gas bound: the run succeeds with at least the gas it
    uses (§9.3: `os_l2_gas` measured again). One block for every run."""
    block = int(rpc('starknet_blockNumber', []))
    job = JOBS / case / 'l2'
    job.mkdir(parents=True, exist_ok=True)
    runs = []

    def ok(bound):
        (job / 'os-job.json').write_text(json.dumps({'rpc_url': RPC, 'chain_id': 'SN_SEPOLIA', 'block_number': block,
                                                     'transaction': tx_for(case, block, bound)}, indent=1))
        code, secs, _ = timed([OS_RUNNER, 'run', job], job / 'os.log')
        good = code == 0 and len(load(job / 'os-result.json', {}).get('l2_to_l1_messages', [])) == 1
        runs.append({'bound': bound, 'ok': good, 'seconds': round(secs, 1)})
        print(json.dumps(runs[-1]), flush=True)
        return good

    lo, hi = 0, L2_GAS
    assert ok(hi), 'the run fails at the server bound'
    while hi - lo > 2_000_000:
        mid = (lo + hi) // 2
        if ok(mid):
            hi = mid
        else:
            lo = mid
    out = {'case': case, 'block': block, 'l2_gas_used_at_most': hi, 'l2_gas_used_above': lo, 'runs': runs}
    (JOBS / case / 'measure-l2.json').write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items() if k != 'runs'}), flush=True)


def report():
    rows = {}
    for case in CASES:
        o, b, g, p, l = (load(JOBS / case / f'measure-{k}.json', {}) for k in ('os', 'bucket', 'gas', 'prove', 'l2'))
        if not o:
            continue
        rows[case] = {
            'os': {'exit': o.get('os_exit'), 'message_ok': o.get('message_ok'), 'n_steps': o.get('resources', {}).get('n_steps'),
                   'builtins': {k: v for k, v in o.get('resources', {}).get('builtin_instance_counter', {}).items() if v},
                   'seconds': o.get('os_seconds')},
            'bucket': {k: b.get(k) for k in ('trace_log_size', 'largest_component_log_size', 'leaf_bootloader_steps', 'wall_seconds', 'max_rss_kib')},
            'l2_gas': g.get('l2_gas_consumed'),
            'l2_gas_bisected': l.get('l2_gas_used_at_most'),
            'prove': {k: p.get(k) for k in ('prove_seconds', 'proof_bytes', 'leaf_trace_log_size', 'max_rss_kib', 'facts_check')} if p else None,
        }
    steps = [r['os']['n_steps'] for r in rows.values() if r['os']['n_steps']]
    summary = {'statement': STATEMENT, 'statement_class': CLASS, 'cases': rows,
               'max_os_steps': max(steps) if steps else None,
               'max_builtins': {k: max(r['os']['builtins'].get(k, 0) for r in rows.values()) for r in rows.values() for k in r['os']['builtins']},
               'max_largest_component_log_size': max((r['bucket']['largest_component_log_size'] or 0) for r in rows.values()),
               # None when nothing was measured (not zero).
               'max_l2_gas': max((r['l2_gas'] for r in rows.values() if r['l2_gas'] is not None), default=None),
               'max_l2_gas_bisected': max((r['l2_gas_bisected'] for r in rows.values() if r['l2_gas_bisected'] is not None), default=None)}
    (HERE / 'results').mkdir(exist_ok=True)
    (HERE / 'results/measure-v6.json').write_text(json.dumps(summary, indent=1) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k != 'cases'}, indent=1))


cmd, args = (sys.argv[1] if len(sys.argv) > 1 else 'report'), sys.argv[2:]
JOBS.mkdir(parents=True, exist_ok=True)
if cmd == 'report':
    report()
else:
    for case in (args or CASES):
        {'os': os_run, 'bucket': bucket, 'prove': prove, 'gas': gas, 'l2': l2}[cmd](case)
