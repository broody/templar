#!/usr/bin/env python3
"""P6: collect the public record of the end to end into results/e2e.json.

Reads the run directory's `e2e/progress.json` (written by sdk/ts/bench/sepolia-v3-e2e.mjs) and the
receipts; keeps public data only (transaction hashes, fees, timings, relay answers, the gateway's
reason), never seeds, keys, openings or job bodies. Usage: collect.py
"""
import json
import os
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNTIME = Path(os.environ.get('TEMPLAR_P6_RUN', Path.home() / '.local/share/templar/runs/account-bound-p6'))
RPC = 'http://127.0.0.1:9545/rpc/v0_10'


def rpc(method, params):
    req = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    out = subprocess.run(['curl', '-s', '-X', 'POST', '-H', 'content-type: application/json', '--data-binary', '@-', RPC],
                         input=req, capture_output=True, check=True)
    return json.loads(out.stdout)


def fee(tx):
    r = rpc('starknet_getTransactionReceipt', [tx]).get('result')
    return r and {'block': r['block_number'], 'status': r['execution_status'], 'fee_STRK': int(r['actual_fee']['amount'], 16) / 1e18}


progress = json.loads((RUNTIME / 'e2e/progress.json').read_text())
stages = {e['stage']: e for e in progress['log']}
gateway = subprocess.run(['journalctl', '--user', '-u', 'templar-relayer-p6', '--no-pager', '-o', 'cat'], capture_output=True, text=True).stdout
reasons = sorted({line.split('An unexpected error occurred: ')[1].split('");')[0].strip('"') for line in gateway.splitlines() if 'An unexpected error occurred' in line})
out = {
    'deployment': json.loads((HERE / 'results/deployment.json').read_text()),
    'relayer_account': json.loads((RUNTIME / 'sepolia/relayer.json').read_text())['address'],
    'bound_setup_check': {k: stages['bound-checked'][k] for k in ('at', 'account', 'vendor', 'version')},
    'deposits': {k: {'tx': stages['deposited'][k]['transactionHash'], 'receipt': fee(stages['deposited'][k]['transactionHash'])}
                 for k in ('ordinary', 'bound')},
    'synced': {k: {'complete': v['complete'], 'balances': v['balances']} for k, v in stages['synced'].items() if k in ('alice', 'bound')},
    'spends': {},
    'gateway_reasons': reasons,
}
for name in ('bound-transfer', 'ordinary-withdraw'):
    e = stages.get(name)
    if e:
        out['spends'][name] = {'at': e['at'], 'prove_ms': e['prove_ms'], 'wrap_ms': e['wrap_ms'], 'plan': e['plan'], 'window': e['window'],
                               'authorization_hash': (e.get('authorization') or {}).get('hash'), 'relay': e['relay'],
                               'relay_tx_known_to_node': 'error' not in (e.get('relay_tx_status') or {'error': 1}),
                               'job_id': (e.get('job') or {}).get('jobId')}
if 'fallback' in stages:
    f = stages['fallback']
    out['fallback'] = {'at': f['at'], 'deadline': f['deadline'], 'from_block': f['from_block'],
                       'outcome': {k: v for k, v in f['outcome'].items() if k in ('sent', 'maxFee', 'expectedFee', 'warnings', 'error', 'code', 'record_stage')}}
(HERE / 'results').mkdir(exist_ok=True)
(HERE / 'results/e2e.json').write_text(json.dumps(out, indent=1) + '\n')
print(json.dumps({k: out[k] for k in ('deposits', 'gateway_reasons')}, indent=1))
print(json.dumps({k: {kk: v[kk] for kk in ('prove_ms', 'wrap_ms', 'relay')} for k, v in out['spends'].items()}, indent=1))
print(json.dumps(out.get('fallback'), indent=1)[:1500])
