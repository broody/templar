#!/usr/bin/env python3
"""P0b spike runner (throwaway): run one prove-only account transaction in the server's pinned
virtual OS on LIVE Sepolia state, without sending anything, and record the outcome.

Modes:
  probe --probe ADDR --target ADDR --hash FELT --sig FELT[,FELT...]
        SigProbe.__execute__(target, hash, signature); accepted iff the OS run succeeds and emits
        exactly [probe_class, 'SPIKE_SIG_V1', target, hash] from the probe.
  r4    [--job DIR] [--tamper INDEX]
        Wiring check against the deployed R4 statement account, reusing a finished prover-server
        job's client proof (calldata). --tamper flips one calldata felt (expected: reject).
  raw   --sender ADDR --calldata-file JSON [--expect-payload JSON]

What it does, per run (in --out, default target/wallet-sig-spike/probe/runs/<mode>-<time>):
  1. builds os-job.json exactly like server/prover/src/pipeline.rs (INVOKE_V3, zero prices,
     l2_gas bound 1e9, nonce at the base block, empty signature);
  2. runs `templar-os-runner run DIR` (the server's binary, unmodified) under /usr/bin/time -v;
     the OS run fails (reject) if the transaction reverts, since the virtual block executor
     refuses reverted transactions;
  3. READ-ONLY starknet_simulateTransactions of the same transaction at the same block
     (SKIP_FEE_CHARGE, validation on) for Sierra gas per call (the node's versioned constants; the
     virtual OS additionally forces Sierra-gas accounting for every Cairo 1 class);
  4. recon.mjs on the sender and the target: class, Sierra version, is_valid_signature entry point,
     and whether the compiled class hash in the classes trie is the Blake (v2) hash;
  5. writes result.json.
Nothing is signed or sent. No private key is read.
"""
import argparse, json, os, re, subprocess, sys, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT_ROOT = ROOT / 'target/wallet-sig-spike/probe/runs'
OS_RUNNER = ROOT / 'server/os-runner/target/release/templar-os-runner'
DEFAULT_RPC = 'http://127.0.0.1:9545/rpc/v0_10'
DEFAULT_JOB = Path.home() / '.local/share/templar/runs/prover-server/jobs/9080ac4b7f9bb20fb60dde6c7896d23e'
R4_ACCOUNT = '0x0349eba5bab782fec0997d0fc1c516848ac2c9e070d5fda0c1046727f6209ee4'
L2_GAS_BOUND = '0x3b9aca00'  # server/prover/src/pipeline.rs


def rpc(url, method, params):
    req = urllib.request.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=300) as r:
        v = json.load(r)
    if 'error' in v:
        raise RuntimeError(json.dumps(v['error'])[:2000])
    return v['result']


def felt(x):
    return int(x, 16) if isinstance(x, str) and x.startswith('0x') else int(x)


def h(x):
    return hex(felt(x) if isinstance(x, str) else x)


def short(s):
    return int.from_bytes(s.encode(), 'big')


def invoke_tx(sender, calldata, nonce):
    # Identical in shape to the prover server's statement transaction (pipeline.rs).
    return {
        'type': 'INVOKE', 'version': '0x3', 'sender_address': h(sender), 'calldata': [h(x) for x in calldata],
        'signature': [], 'nonce': nonce,
        'resource_bounds': {'l1_gas': {'max_amount': '0x0', 'max_price_per_unit': '0x0'},
                            'l2_gas': {'max_amount': L2_GAS_BOUND, 'max_price_per_unit': '0x0'},
                            'l1_data_gas': {'max_amount': '0x0', 'max_price_per_unit': '0x0'}},
        'tip': '0x0', 'paymaster_data': [], 'account_deployment_data': [],
        'nonce_data_availability_mode': 'L1', 'fee_data_availability_mode': 'L1',
    }


def run_os(out, url, chain, block, tx):
    (out / 'os-job.json').write_text(json.dumps({'rpc_url': url, 'chain_id': chain, 'block_number': block, 'transaction': tx}, indent=1))
    t0 = time.time()
    p = subprocess.run(['/usr/bin/time', '-v', str(OS_RUNNER), 'run', str(out)], capture_output=True, text=True)
    wall = time.time() - t0
    (out / 'os.log').write_text(p.stdout + p.stderr)
    rss = re.search(r'Maximum resident set size \(kbytes\): (\d+)', p.stderr)
    r = {'exit_code': p.returncode, 'wall_seconds': round(wall, 2), 'max_rss_kib': int(rss.group(1)) if rss else None}
    if p.returncode == 0:
        res = json.loads((out / 'os-result.json').read_text())
        r.update(os_seconds=res['os_seconds'], n_steps=res['resources']['n_steps'],
                 n_memory_holes=res['resources']['n_memory_holes'],
                 builtins={k: v for k, v in res['resources']['builtin_instance_counter'].items() if v},
                 l2_to_l1_messages=res['l2_to_l1_messages'])
    else:
        log = (p.stdout + p.stderr).split('Command exited with non-zero status')[0].split('\tCommand being timed')[0]
        r['error_tail'] = log.strip()[-2500:]
        # The innermost failure reason: the last quoted string or decoded short string in the log.
        quoted = re.findall(r'"([^"\n]{1,300})"', log)
        shorts = re.findall(r"\('([^'\n]{1,31})'\)", log)
        r['reason'] = (quoted or shorts or [None])[-1]
    return r


def walk_calls(inv, depth=0, rows=None):
    rows = [] if rows is None else rows
    if not inv or 'contract_address' not in inv:
        return rows
    er = inv.get('execution_resources') or {}
    rows.append({'depth': depth, 'contract': inv['contract_address'], 'class_hash': inv.get('class_hash'),
                 'selector': inv.get('entry_point_selector'), 'l2_gas': er.get('l2_gas'), 'l1_gas': er.get('l1_gas'),
                 'is_reverted': inv.get('is_reverted'), 'result': inv.get('result')[:4] if inv.get('result') else inv.get('result')})
    for c in inv.get('calls', []):
        walk_calls(c, depth + 1, rows)
    return rows


def simulate(url, block, tx):
    try:
        sim = rpc(url, 'starknet_simulateTransactions', [{'block_number': block}, [tx], ['SKIP_FEE_CHARGE']])[0]
    except RuntimeError as e:
        return {'error': str(e)[:2000]}
    tr = sim['transaction_trace']
    ex = tr.get('execute_invocation') or {}
    out = {'execution_resources': tr.get('execution_resources'), 'fee_estimation': sim.get('fee_estimation'),
           'validate_calls': walk_calls(tr.get('validate_invocation')),
           'reverted': 'revert_reason' in ex, 'revert_reason': ex.get('revert_reason', '')[:3000] or None,
           'execute_calls': walk_calls(ex) if 'revert_reason' not in ex else []}
    return out


def recon(url, *addrs):
    p = subprocess.run(['node', str(HERE / 'recon.mjs'), '--rpc', url, *addrs], capture_output=True, text=True, timeout=900)
    if p.returncode:
        return {'error': p.stderr[-1000:]}
    rep = json.loads(p.stdout)
    return {t['input']: {k: t.get(k) for k in ['class_hash', 'known_as', 'sierra_version', 'compiler_version', 'sierra_gas_accounting',
                                                  'is_valid_signature', 'isValidSignature', 'abi_vendor_strings', 'migration', 'get_name',
                                                  'get_version', 'cairo', 'note']} for t in rep['targets']}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('mode', choices=['probe', 'r4', 'raw'])
    ap.add_argument('--rpc', default=DEFAULT_RPC)
    ap.add_argument('--block', default='latest', help='base block number (default: latest)')
    ap.add_argument('--out')
    ap.add_argument('--probe')
    ap.add_argument('--target')
    ap.add_argument('--hash')
    ap.add_argument('--sig', help='comma-separated signature felts')
    ap.add_argument('--job', default=str(DEFAULT_JOB))
    ap.add_argument('--tamper', type=int)
    ap.add_argument('--sender')
    ap.add_argument('--calldata-file')
    ap.add_argument('--expect-payload')
    ap.add_argument('--no-os', action='store_true', help='skip the virtual OS run (simulate and recon only)')
    ap.add_argument('--no-recon', action='store_true')
    a = ap.parse_args()

    url = a.rpc
    chain_felt = felt(rpc(url, 'starknet_chainId', []))
    chain = chain_felt.to_bytes(32, 'big').lstrip(b'\0').decode()
    block = rpc(url, 'starknet_blockNumber', []) if a.block == 'latest' else int(a.block)

    if a.mode == 'probe':
        assert a.probe and a.target and a.hash is not None and a.sig is not None, 'probe needs --probe --target --hash --sig'
        sig = [felt(x) for x in a.sig.split(',') if x]
        sender = a.probe
        calldata = [felt(a.target), felt(a.hash), len(sig), *sig]
        probe_class = rpc(url, 'starknet_getClassHashAt', [{'block_number': block}, sender])
        expected = [felt(probe_class), short('SPIKE_SIG_V1'), felt(a.target), felt(a.hash)]
        recon_addrs = [sender, a.target]
    elif a.mode == 'r4':
        job = json.loads((Path(a.job) / 'os-job.json').read_text())
        prev = json.loads((Path(a.job) / 'os-result.json').read_text())
        sender = job['transaction']['sender_address']
        assert felt(sender) == felt(R4_ACCOUNT)
        calldata = [felt(x) for x in job['transaction']['calldata']]
        if a.tamper is not None:
            calldata[a.tamper] ^= 1
        expected = [felt(x) for x in prev['l2_to_l1_messages'][0]['payload']]
        recon_addrs = [sender]
    else:
        assert a.sender and a.calldata_file, 'raw needs --sender --calldata-file'
        sender = a.sender
        calldata = [felt(x) for x in json.loads(Path(a.calldata_file).read_text())]
        expected = [felt(x) for x in json.loads(a.expect_payload)] if a.expect_payload else None
        recon_addrs = [sender]

    out = Path(a.out) if a.out else OUT_ROOT / f'{a.mode}-{time.strftime("%Y%m%dT%H%M%S")}'
    out.mkdir(parents=True, exist_ok=True)
    nonce = rpc(url, 'starknet_getNonce', [{'block_number': block}, sender])
    tx = invoke_tx(sender, calldata, nonce)
    result = {'mode': a.mode, 'rpc': url, 'chain': chain, 'block': block, 'sender': h(sender), 'nonce': nonce,
              'calldata_felts': len(calldata), 'tamper': a.tamper, 'expected_payload': [h(x) for x in expected] if expected else None}
    if a.mode == 'probe':
        result.update(target=h(a.target), hash=h(a.hash), signature=[h(x) for x in sig])

    if not a.no_os:
        os_r = run_os(out, url, chain, block, tx)
        msgs = os_r.get('l2_to_l1_messages') or []
        payload_ok = None
        if os_r['exit_code'] == 0:
            payload_ok = (len(msgs) == 1 and felt(msgs[0]['from_address']) == felt(sender)
                          and (expected is None or [felt(x) for x in msgs[0]['payload']] == expected))
        os_r['payload_matches_expected'] = payload_ok
        result['os'] = os_r
        result['accept'] = bool(os_r['exit_code'] == 0 and payload_ok)
    result['simulate'] = simulate(url, block, tx)
    if not a.no_recon:
        result['classes'] = recon(url, *recon_addrs)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    summary = {k: result.get(k) for k in ['mode', 'block', 'accept', 'tamper']}
    if 'os' in result:
        summary.update({k: result['os'].get(k) for k in ['exit_code', 'n_steps', 'builtins', 'os_seconds', 'max_rss_kib', 'reason']})
    summary['sim_l2_gas'] = (result['simulate'].get('execution_resources') or {}).get('l2_gas')
    summary['sim_reverted'] = result['simulate'].get('reverted')
    summary['out'] = str(out)
    print(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()
