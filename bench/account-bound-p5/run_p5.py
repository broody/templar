#!/usr/bin/env python3
"""P5 runs (docs/account-bound-note-spec.md §15 P5): R0 V5 spends through the deployed statement
account in the server's pinned virtual OS on live Sepolia state, then PROOF2, then the resource
analysis for the caps and the uniformity gate (§12).

  run_p5.py os CASE [--tamper]  the virtual-OS run at the latest block (nothing is sent); --tamper
                           flips the last signature felt's low bit: the run must be rejected
  run_p5.py prove CASE     PROOF2 of that run (templar-prove, bounded; ~28 GiB, minutes)
  run_p5.py analyze CASE   component log sizes and Blake from the PIE (capacity trace, blake_sites)
  run_p5.py report         results.json and the uniformity table
  run_p5.py summary        results/summary.json (committed: accounts truncated, no salts or signatures)
  run_p5.py cases          the known cases and what they need

CASE is a proof in RUN/proofs (`ordinary-<shape>`, `ready-<shape>`, `braavos-<shape>`) or a P3
real-wallet withdrawal (`p3-ready-partial`, `p3-braavos-partial`). A bound case needs the wallet's
signature: RUN/sign-results (this phase's signing page) or P3's sign results.

The job is built exactly like server/prover/src/pipeline.rs: an INVOKE_V3 from the statement
account, calldata `(proof_data, salt, signature)`, zero tip and prices, the L2 gas bound 450M, the
nonce at the base block. The run must emit exactly one message, `[statement class,
'TMPZR0_PAYMENT_V5', chain, pool, binding]`, with the binding recomputed here from the statement.
Nothing is signed or sent; no private key is read.
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
RUN = Path(os.environ.get('TEMPLAR_P5_RUN', Path.home() / '.local/share/templar/runs/account-bound-p5'))
P3 = Path.home() / '.local/share/templar/runs/r5-p3'
RPC = 'http://127.0.0.1:9545/rpc/v0_10'
OS_RUNNER = ROOT / 'server/os-runner/target/release/templar-os-runner'
PROVE = ROOT / 'server/prove/target/release/templar-prove'
CAPACITY = ROOT / 'target/m31-private-wrapper/capacity-build-original-v3/capacity'
BLAKE_SITES = ROOT / 'target/m31-private-wrapper/attribution-build/blake_sites'
V5 = ROOT / 'bench/m31-private-wrapper/client-port/cairo-r5/kat/v5.cjs'
L2_GAS = 450_000_000  # server/prover: os_l2_gas
TAG = int.from_bytes(b'TMPZR0_PAYMENT_V5', 'big')
CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')


def rpc(method, params):
    req = urllib.request.Request(RPC, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=300) as r:
        v = json.load(r)
    if 'error' in v:
        raise RuntimeError(json.dumps(v['error'])[:1500])
    return v['result']


def load(p):
    return json.loads(Path(p).read_text())


def deployment():
    d = RUN / 'sepolia' / 'deployment.json'
    if not d.exists():
        sys.exit('the statement account is not deployed yet: run deploy_statement.py')
    return load(d)


def case_dirs(case):
    """(proof directory, signature source) for a case."""
    if case.startswith('p3-'):
        wallet = case.split('-')[1]
        return P3 / 'proofs' / f'wallet-{wallet}', ('p3', wallet)
    return RUN / 'proofs' / case, (None if case.startswith('ordinary-') else ('p5', case))


def authorization(pub, source):
    """(salt, signature) for a bound case, from the signing results; (0, []) for an ordinary one."""
    if source is None:
        assert int(pub['account'], 16) == 0
        return 0, []
    kind, name = source
    account = int(pub['account'], 16)
    if kind == 'p3':
        requests = load(P3 / 'sign-requests.json')
        results = [load(f) for f in sorted((P3 / 'final2' / 'sign-results').glob('*.json'))]
        req = next(v for k, v in requests.items() if int(k, 16) == account)
        res = next(r for r in results if int(r['account'], 16) == account)
        assert res['request']['salt'] == req['salt']
        return int(req['salt'], 16), [int(x, 16) for x in res['signature']]
    for f in sorted((RUN / 'sign-results').glob('*.json')) if (RUN / 'sign-results').exists() else []:
        r = load(f)
        if int(r['account'], 16) != account:
            continue
        for x in r.get('results', [r]):
            if x['request']['proof'] == name:
                assert x['isValidSignature']['valid'], f'{name}: the signature did not verify when signed'
                return int(x['request']['salt'], 16), [int(s, 16) for s in x['signature']]
    sys.exit(f'{name}: no signature yet (sign it on the signing page)')


def binding(proof_dir):
    js = f"const v=require({json.dumps(str(V5))});console.log(v.hex(v.binding(v.readPublic({json.dumps(str(proof_dir))}))))"
    return int(subprocess.check_output(['node', '-e', js], text=True).strip(), 16)


def timed(cmd, log, env=None):
    t = time.time()
    with open(log, 'w') as f:
        p = subprocess.run(['/usr/bin/time', '-v', *map(str, cmd)], stdout=f, stderr=subprocess.STDOUT, env=env)
    text = Path(log).read_text()
    rss = next((int(line.split()[-1]) for line in text.splitlines() if 'Maximum resident set size' in line), None)
    return p.returncode, time.time() - t, rss


def os_run(case, tamper=False):
    d = deployment()
    proof_dir, source = case_dirs(case)
    pub = load(proof_dir / 'public.json')
    salt, signature = authorization(pub, source)
    if tamper:
        assert signature, 'only a bound case has a signature to tamper with'
        signature = [*signature[:-1], signature[-1] ^ 1]
        case += '-tampered'
    proof = load(proof_dir / 'cairo-arguments.json')
    calldata = [*proof, hex(salt), hex(len(signature)), *map(hex, signature)]
    block = int(rpc('starknet_blockNumber', []))
    nonce = rpc('starknet_getNonce', [{'block_number': block}, d['statement']])
    job = RUN / 'jobs' / case
    job.mkdir(parents=True, exist_ok=True)
    zero = {'max_amount': '0x0', 'max_price_per_unit': '0x0'}
    tx = {'type': 'INVOKE', 'version': '0x3', 'sender_address': d['statement'], 'calldata': calldata, 'signature': [], 'nonce': nonce,
          'resource_bounds': {'l1_gas': zero, 'l2_gas': {'max_amount': hex(L2_GAS), 'max_price_per_unit': '0x0'}, 'l1_data_gas': zero},
          'tip': '0x0', 'paymaster_data': [], 'account_deployment_data': [],
          'nonce_data_availability_mode': 'L1', 'fee_data_availability_mode': 'L1'}
    (job / 'os-job.json').write_text(json.dumps({'rpc_url': RPC, 'chain_id': 'SN_SEPOLIA', 'block_number': block, 'transaction': tx}, indent=1))
    code, secs, rss = timed([OS_RUNNER, 'run', job], job / 'os.log')
    out = {'case': case, 'block': block, 'account': pub['account'], 'intent': pub['intent'], 'bound': source is not None,
           'os_exit': code, 'os_wall_seconds': round(secs, 1), 'os_max_rss_kib': rss}
    if code != 0:
        log = (job / 'os.log').read_text()
        out['rejection'] = next((line.strip()[:300] for line in log.splitlines() if 'virtual OS:' in line or 'Error' in line), log[-300:])
    if code == 0:
        res = load(job / 'os-result.json')
        msgs = res['l2_to_l1_messages']
        expected = [int(d['class_hash'], 16), TAG, CHAIN, int(pub['pool'], 16), binding(proof_dir)]
        num = lambda v: int(v, 16) if isinstance(v, str) else int(v)  # noqa: E731
        out.update(resources=res['resources'], os_seconds=res['os_seconds'], messages=len(msgs),
                   message_ok=len(msgs) == 1 and num(msgs[0]['from_address']) == int(d['statement'], 16) and [num(x) for x in msgs[0]['payload']] == expected)
    (job / 'p5-os.json').write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items() if k != 'resources'} | {'n_steps': out.get('resources', {}).get('n_steps')}))
    return out


def prove(case):
    job = RUN / 'jobs' / case
    assert (job / 'os.pie.zip').exists(), 'run the OS first'
    (job / 'prove-job.json').write_text(json.dumps({'cairo_fri_columns': 16, 'circuit_fri_columns': 16, 'stream_commitments': False}))
    code, secs, rss = timed([PROVE, 'prove', job], job / 'prove.log', env=dict(os.environ, RAYON_NUM_THREADS='16'))
    out = {'case': case, 'prove_exit': code, 'wall_seconds': round(secs, 1), 'max_rss_kib': rss}
    if code == 0:
        out.update(load(job / 'prove-result.json'))
        out['output_preimage'] = load(job / 'output-preimage.json')
    (job / 'p5-prove.json').write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items() if k != 'output_preimage'}))


def analyze(case):
    job = RUN / 'jobs' / case
    out = job / 'analysis'
    out.mkdir(exist_ok=True)
    pie = job / 'os.pie.zip'
    if not (out / 'trace/claim.json').exists():
        timed([CAPACITY, 'trace', pie, out / 'trace'], out / 'trace.log')
    if not (out / 'blake/blake-sites.json').exists():
        timed([BLAKE_SITES, pie, out / 'blake'], out / 'blake.log')
    claim, boot, blake = load(out / 'trace/claim.json'), load(out / 'trace/boot.json'), load(out / 'blake/blake-sites.json')
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
    seg = {k: sum(v) for k, v in blake['blake_by_pc_segment_[compress,finalize]'].items()}
    r = {'case': case, 'component_log_sizes': sizes, 'max_log': max(sizes.values()), 'blake_total': blake['blake_total'],
         'blake_by_role': {'bootloader': seg.get('0'), 'os': seg.get('14'), 'account': seg.get('19')},
         'bootloader_total_steps': blake['total_steps'], 'builtin_segments': boot['builtin_segments']}
    (job / 'p5-analysis.json').write_text(json.dumps(r, indent=1))
    print(json.dumps({k: v for k, v in r.items() if k not in ('component_log_sizes', 'builtin_segments')}))


def report():
    rows = {}
    for job in sorted((RUN / 'jobs').iterdir()) if (RUN / 'jobs').exists() else []:
        row = {}
        for part in ('os', 'prove', 'analysis'):
            f = job / f'p5-{part}.json'
            if f.exists():
                row[part] = load(f)
        rows[job.name] = row
    analyzed = {k: v['analysis'] for k, v in rows.items() if 'analysis' in v}
    sizes = {k: v['component_log_sizes'] for k, v in analyzed.items()}
    gate = None
    if sizes:
        first = next(iter(sizes.values()))
        diff = {k: {c: (first.get(c), s.get(c)) for c in set(first) | set(s) if first.get(c) != s.get(c)} for k, s in sizes.items()}
        gate = {'same_component_log_sizes': all(not d for d in diff.values()), 'differences_from_first': {k: d for k, d in diff.items() if d},
                'max_log': {k: a['max_log'] for k, a in analyzed.items()}}
    result = {'cases': rows, 'uniformity_gate': gate}
    (RUN / 'results.json').write_text(json.dumps(result, indent=1))
    for k, v in rows.items():
        o, p, a = v.get('os', {}), v.get('prove', {}), v.get('analysis', {})
        print(f"{k:22} steps={o.get('resources', {}).get('n_steps')} msg_ok={o.get('message_ok')} "
              f"prove={p.get('prove_seconds')}s rss={p.get('max_rss_kib')} max_log={a.get('max_log')} blake={a.get('blake_total')}")
    print(json.dumps(gate, indent=1))


def summary():
    """The committed summary (results/summary.json): accounts truncated, no salts or signatures."""
    r = load(RUN / 'results.json')
    short = lambda a: a if int(a, 16) == 0 else a[:12] + '…'  # noqa: E731
    out = {'statement_account': deployment()['statement'], 'class_hash': deployment()['class_hash'], 'cases': {}}
    for k, v in r['cases'].items():
        o, p, a = v.get('os', {}), v.get('prove', {}), v.get('analysis', {})
        out['cases'][k] = {
            'account': short(o.get('account', '0x0')), 'bound': o.get('bound'), 'intent': o.get('intent', '0x0') != '0x0', 'block': o.get('block'),
            'os': {'exit': o.get('os_exit'), 'message_ok': o.get('message_ok'), 'n_steps': o.get('resources', {}).get('n_steps'),
                   'builtins': {b: n for b, n in o.get('resources', {}).get('builtin_instance_counter', {}).items() if n}, 'seconds': o.get('os_seconds'),
                   'rejection': (o.get('rejection') or '')[:120] or None},
            'proof2': {'verified': p.get('verified'), 'prove_seconds': p.get('prove_seconds'), 'max_rss_kib': p.get('max_rss_kib'), 'proof_bytes': p.get('proof_bytes')} if p else None,
            'trace': {'max_log': a.get('max_log'), 'blake_total': a.get('blake_total'), 'blake_by_role': a.get('blake_by_role'),
                      'component_log_sizes': a.get('component_log_sizes')} if a else None,
        }
    out['uniformity_gate'] = r['uniformity_gate']
    for m in ('v4', 'v5-bound'):
        f = RUN / f'wasm-{m}.json'
        if f.exists():
            w = load(f)
            out.setdefault('wasm', {})[m] = {'browser': w['browser'], 'prove_ms': [round(x['prove_ms']) for x in w['runs']],
                                            'linear_memory_mib': w['runs'][0]['linear_memory_mib']}
    dst = HERE / 'results' / 'summary.json'
    dst.parent.mkdir(exist_ok=True)
    dst.write_text(json.dumps(out, indent=1) + '\n')
    print(dst)


def cases():
    for d in sorted((RUN / 'proofs').iterdir()) if (RUN / 'proofs').exists() else []:
        if d.is_dir():
            print(d.name, 'ordinary' if d.name.startswith('ordinary-') else 'needs a signature')
    print('p3-ready-partial p3-braavos-partial (P3 signatures)')


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'cases'
    {'os': lambda: os_run(sys.argv[2], '--tamper' in sys.argv), 'prove': lambda: prove(sys.argv[2]), 'analyze': lambda: analyze(sys.argv[2]),
     'report': report, 'summary': summary, 'cases': cases}[cmd]()
