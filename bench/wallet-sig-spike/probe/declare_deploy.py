#!/usr/bin/env python3
"""P0b spike (throwaway): declare SigProbe and deploy one instance on Sepolia with sncast.

NOT EXECUTED by the spike. Sends two transactions (declare, deploy) from the account named in the
accounts file; sncast reads the key, this script never does. Without
--i-approve-onchain-transactions it only prints the plan and the read-only checks.

  python3 declare_deploy.py --accounts-file FILE --account NAME [--declare-url URL]
                            [--i-approve-onchain-transactions]

Expected cost (estimate_fee.mjs, 2026-09-25, block 15,610,398, L2 gas 22.03 gwei-fri): about
1.62 STRK (declaration ~72.4M L2 gas by the 40,960 gas/felt rule, ~1.60 STRK; UDC deploy ~1.32M
L2 gas, ~0.03 STRK; plus the sender's validation, ~0.3M L2 gas). The bounds below cap it at
~3.2 STRK.

The local node cannot simulate declarations of Sierra 1.8 classes (bench/m31-sepolia/README.md),
and sncast estimates by simulation, so the declaration needs an RPC that can (--declare-url; the
Sepolia runs used a public v0_10 endpoint). The deploy goes through the local node.

Checkpointed in --out (default target/wallet-sig-spike/probe/deploy): a recorded step is reused, an
incomplete one stops the script for manual inspection. Writes deployment.json {probe, class_hash,
declare_tx, deploy_tx}.
"""
import argparse, json, os, subprocess, sys, time, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CRATE = HERE / 'sigprobe'
SNCAST = '/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin/sncast'
SCARB_BIN = '/home/broody/.asdf/installs/scarb/2.18.0/bin'
RPC = 'http://127.0.0.1:9545/rpc/v0_10'
CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')
EXPECTED_CLASS = 0x07df5178c3f270bf75c40d1c2da4d2062ea43a01dbb9a082bfcddc69f8f41195
SALT = '0x5349475f50524f42455f5350494b45'  # 'SIG_PROBE_SPIKE'
L2_PRICE_BOUND = 40_000_000_000       # fri per L2 gas (block price 2026-09-25: ~22e9)
DECLARE_L2_GAS = 95_000_000           # sncast --dry-run 2026-09-25: 81.7M consumed
DEPLOY_L2_GAS = 5_000_000             # ~3.8x the 1.32M estimate
L1_DATA_PRICE_BOUND = 4_000_000_000_000  # fri per L1 data gas (dry run: 1.55e12)
MAX_FEE_FRI = 4 * 10**18              # hard ceiling per transaction

ENV = dict(os.environ, PATH=SCARB_BIN + ':' + os.environ['PATH'],
           SCARB_TARGET_DIR=str(ROOT / 'target/wallet-sig-spike/probe/scarb-target'))


def rpc(method, params, url=RPC):
    req = urllib.request.Request(url, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as r:
        v = json.load(r)
    if 'error' in v:
        raise RuntimeError(json.dumps(v['error']))
    return v['result']


def bounds(l2):
    b = [('l2-gas', l2), ('l2-gas-price', L2_PRICE_BOUND), ('l1-gas', 1), ('l1-gas-price', 200_000_000_000_000),
         ('l1-data-gas', 10_000), ('l1-data-gas-price', L1_DATA_PRICE_BOUND)]
    total = l2 * L2_PRICE_BOUND + 200_000_000_000_000 + 10_000 * L1_DATA_PRICE_BOUND
    assert total <= MAX_FEE_FRI, f'fee bound {total / 1e18} STRK exceeds the ceiling'
    return [a for k, v in b for a in (f'--{k}', str(v))]


def class_hash():
    out = subprocess.check_output([SNCAST, '--json', 'utils', 'class-hash', '--contract-name', 'SigProbe'], cwd=CRATE, env=ENV, text=True)
    return int(json.loads(out.strip().splitlines()[-1])['class_hash'], 16)


def step(out, name, cmd):
    d = out / name
    if (d / 'response.json').exists():
        return json.loads((d / 'response.json').read_text())
    if (d / 'stdout.jsonl').exists():
        sys.exit(f'{name}: an earlier attempt is incomplete; inspect {d} before retrying')
    d.mkdir(parents=True, exist_ok=True)
    (d / 'command.json').write_text(json.dumps(cmd))
    with (d / 'stdout.jsonl').open('w') as so, (d / 'stderr.log').open('w') as se:
        p = subprocess.run(cmd, cwd=CRATE, env=ENV, stdout=so, stderr=se)
    rows = [json.loads(l) for l in (d / 'stdout.jsonl').read_text().splitlines() if l.startswith('{')]
    if p.returncode:
        sys.exit(f'{name} failed: ' + (d / 'stderr.log').read_text()[-1500:] + str(rows)[-1500:])
    v = next(x for x in rows if 'transaction_hash' in x)
    (d / 'response.json').write_text(json.dumps(v, indent=2))
    return v


def wait_receipt(tx):
    for _ in range(200):
        try:
            v = rpc('starknet_getTransactionReceipt', [tx])
            if v.get('finality_status') in ('ACCEPTED_ON_L2', 'ACCEPTED_ON_L1'):
                assert v['execution_status'] == 'SUCCEEDED', v
                return v
        except RuntimeError as e:
            if 'not found' not in str(e).lower():
                raise
        time.sleep(3)
    sys.exit(f'receipt pending for {tx}; inspect before resubmitting')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--accounts-file', required=True)
    ap.add_argument('--account', required=True)
    ap.add_argument('--declare-url', default=RPC, help='RPC used for the declaration (must be able to simulate Sierra 1.8)')
    ap.add_argument('--out', default=str(ROOT / 'target/wallet-sig-spike/probe/deploy'))
    ap.add_argument('--i-approve-onchain-transactions', action='store_true')
    a = ap.parse_args()

    assert int(rpc('starknet_chainId', []), 16) == CHAIN, 'not Sepolia'
    ch = class_hash()
    assert ch == EXPECTED_CLASS, f'class hash {hex(ch)} differs from the recorded build {hex(EXPECTED_CLASS)}'
    try:
        rpc('starknet_getClass', ['latest', hex(ch)])
        declared = True
    except RuntimeError:
        declared = False
    base = [SNCAST, '--account', a.account, '--accounts-file', a.accounts_file, '--json']
    declare_cmd = base + ['declare', '--url', a.declare_url, '--contract-name', 'SigProbe', *bounds(DECLARE_L2_GAS)]
    deploy_cmd = base + ['deploy', '--url', RPC, '--class-hash', hex(ch), '--salt', SALT, *bounds(DEPLOY_L2_GAS)]
    plan = {'class_hash': hex(ch), 'already_declared': declared, 'declare': None if declared else declare_cmd, 'deploy': deploy_cmd}
    if not a.i_approve_onchain_transactions:
        print(json.dumps({'plan_only': True, **plan}, indent=1))
        print('not sending: pass --i-approve-onchain-transactions to declare and deploy', file=sys.stderr)
        return
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    dep = {'class_hash': hex(ch)}
    if not declared:
        v = step(out, 'declare', declare_cmd)
        assert int(v['class_hash'], 16) == ch
        dep['declare_tx'] = v['transaction_hash']
        dep['declare_receipt_block'] = wait_receipt(v['transaction_hash']).get('block_number')
    v = step(out, 'deploy', deploy_cmd)
    dep['probe'] = v['contract_address']
    dep['deploy_tx'] = v['transaction_hash']
    dep['deploy_receipt_block'] = wait_receipt(v['transaction_hash']).get('block_number')
    assert int(rpc('starknet_getClassHashAt', ['latest', dep['probe']]), 16) == ch
    (out / 'deployment.json').write_text(json.dumps(dep, indent=2) + '\n')
    print(json.dumps(dep, indent=1))


if __name__ == '__main__':
    main()
