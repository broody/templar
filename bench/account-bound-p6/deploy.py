#!/usr/bin/env python3
"""P6: deploy M31 pool V3 on Sepolia (docs/account-bound-note-spec.md §15 P6).

  python3 deploy.py --check                           # read-only: classes, reused contracts, fee estimate
  python3 deploy.py                                   # prints the plan, sends nothing
  python3 deploy.py --i-approve-onchain-transactions  # declare, deploy, initialize

Transactions, all from `account-1` through sncast (sncast reads the key; this script never does):
1. declare `M31PoolV3` (the only new class);
2. deploy pool V3: owner `account-1`, frontier storage, `E`, `Q`, `W`, `T` below;
3. deploy the R0 V5 adapter: a new instance of the declared `Proof2Adapter` class, bound to the P5
   statement account, `account_tag = 'TMPZR0_PAYMENT_V5'`, `max_proof_age = 1,024` (§8.4);
4. deploy the P1 adapter: the same class, bound to pool V2's P1 statement account (its circuit has
   the H2 fix), `account_tag = 'TMPZP1_POLICY_V1'`, the same age (the server has one age setting);
5. `initialize(r0_adapter, p1_adapter, [])`: no shadow classes yet, so no `COMPUTE` route until one
   is reviewed and proposed through the timelock.

Checkpointed in the run directory; bounded fees.
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNTIME = Path(os.environ.get('TEMPLAR_P6_RUN', Path.home() / '.local/share/templar/runs/account-bound-p6'))
os.environ['TEMPLAR_SEPOLIA_RUN'] = str(RUNTIME / 'sepolia')
(RUNTIME / 'sepolia' / 'steps').mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / 'bench/m31-sepolia'))
from sepolia import (ACCOUNT, ACCOUNT_NAME, ACCOUNTS_FILE, CHAIN, DECLARE_RPC, ENV, MAX_DECLARE_FEE_FRI, RUN,  # noqa: E402
                     SCARB, SNCAST, call, h, load, normal_tx, rpc, save)

POOL_CRATE = ROOT / 'bench/m31-pool/cairo'
P5 = load(Path.home() / '.local/share/templar/runs/account-bound-p5/sepolia/deployment.json')
V2 = load(ROOT / 'bench/m31-sepolia/results/v4-hidden-asset/deployment.json')

# §8.2–8.4. E and Q from P5's measured pipeline; W with a sync margin above E + Q; T in seconds,
# shorter on Sepolia than mainnet's 7-day floor but above E + Q (about 45 minutes) with margin.
E, Q, W, T = 1500, 100, 4096, 7200
MAX_PROOF_AGE = 1024
OS_PROGRAM = V2['os_program']
ADAPTER_CLASS = V2['classes']['adapter']
R0_TAG = hex(int.from_bytes(b'TMPZR0_PAYMENT_V5', 'big'))
P1_TAG = hex(int.from_bytes(b'TMPZP1_POLICY_V1', 'big'))
DECLARE_L2_GAS = 5_900_000_000               # --check 2026-09-26: 5,357M (about 1.1x)
DECLARE_L2_PRICE_BOUND = 30_000_000_000      # fri per L2 gas for the declaration (block price ~21.5e9)
DEPLOY_L2_GAS = 60_000_000
INVOKE_L2_GAS = 20_000_000
L2_PRICE_BOUND = 40_000_000_000              # fri per L2 gas
L1_DATA_PRICE_BOUND = 4_000_000_000_000      # fri per L1 data gas (2026-09-26: ~1.38e12)


def bounds(l2, ceiling, l2_price=L2_PRICE_BOUND):
    """Explicit resource bounds: `l2` L2 gas at up to `l2_price`, small L1 and L1 data caps."""
    b = [('l2-gas', l2), ('l2-gas-price', l2_price), ('l1-gas', 1), ('l1-gas-price', 200_000_000_000_000),
         ('l1-data-gas', 10_000), ('l1-data-gas-price', L1_DATA_PRICE_BOUND)]
    total = l2 * l2_price + 200_000_000_000_000 + 10_000 * L1_DATA_PRICE_BOUND
    assert total <= ceiling, f'fee bound {total / 1e18} STRK exceeds the ceiling'
    return [a for k, v in b for a in (f'--{k}', str(v))]


def class_hash(contract):
    out = subprocess.check_output([SNCAST, '--json', 'utils', 'class-hash', '--contract-name', contract], cwd=POOL_CRATE, env=ENV, text=True)
    return json.loads(out.strip().splitlines()[-1])['class_hash']


def declared(hash_):
    try:
        rpc('starknet_getClass', ['latest', hash_])
        return True
    except RuntimeError as e:
        assert 'not found' in str(e).lower(), e
        return False


def class_at(address):
    return int(rpc('starknet_getClassHashAt', ['latest', address]), 16)


assert int(rpc('starknet_chainId', []), 16) == CHAIN, 'the local node is not on Sepolia'
subprocess.run([SCARB, '--release', 'build'], cwd=POOL_CRATE, env=ENV, check=True, capture_output=True)
casm = load(POOL_CRATE / 'target/release/m31_pool_M31PoolV3.compiled_contract_class.json')['bytecode']
assert len(casm) <= 81_920, len(casm)
pool_class = class_hash('M31PoolV3')
assert int(class_hash('Proof2Adapter'), 16) == int(ADAPTER_CLASS, 16), 'the adapter source no longer hashes to the declared class'
assert declared(ADAPTER_CLASS)
# The reused statement accounts are the builds recorded at their deployment.
assert P5['build']['message_tag'] == 'TMPZR0_PAYMENT_V5' and class_at(P5['statement']) == int(P5['class_hash'], 16)
assert class_at(V2['statement1']) == int(V2['classes']['statement1'], 16)
assert W >= E + Q and 0 < Q <= 2**32 and E <= 2**32 and T > 0

plan = {
    'pool_class': pool_class, 'pool_class_declared': declared(pool_class), 'pool_casm_felts': len(casm),
    'owner': ACCOUNT, 'parameters': {'E_blocks': E, 'Q_blocks': Q, 'W_blocks': W, 'T_seconds': T},
    'r0_adapter': {'class': ADAPTER_CLASS, 'statement': P5['statement'], 'statement_class': P5['class_hash'],
                   'os_program': OS_PROGRAM, 'max_proof_age': MAX_PROOF_AGE, 'account_tag': 'TMPZR0_PAYMENT_V5'},
    'p1_adapter': {'class': ADAPTER_CLASS, 'statement': V2['statement1'], 'statement_class': V2['classes']['statement1'],
                   'os_program': OS_PROGRAM, 'max_proof_age': MAX_PROOF_AGE, 'account_tag': 'TMPZP1_POLICY_V1'},
    'shadow_classes': [],
}

if '--check' in sys.argv:
    if not plan['pool_class_declared']:
        r = subprocess.run([SNCAST, '--account', ACCOUNT_NAME, '--accounts-file', ACCOUNTS_FILE, '--json', 'declare', '--url', DECLARE_RPC,
                            '--contract-name', 'M31PoolV3', '--dry-run'], cwd=POOL_CRATE, env=ENV, capture_output=True, text=True)
        est = [json.loads(line) for line in r.stdout.splitlines() if line.startswith('{')]
        plan['declare_estimate'] = est[-1] if est else r.stderr[-800:]
    plan['account_1_strk'] = int(call('0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d', 'balance_of', [ACCOUNT])[0]) / 1e18
    print(json.dumps(plan, indent=2))
    sys.exit(0)

d = load(RUN / 'deployment.json', {})
if d.get('initialized'):
    print(json.dumps(d, indent=2))
    sys.exit(0)
if '--i-approve-onchain-transactions' not in sys.argv:
    print('Plan (nothing sent; pass --i-approve-onchain-transactions to send):')
    print(json.dumps({**plan, 'transactions': ([] if plan['pool_class_declared'] else ['declare M31PoolV3']) +
                      ['deploy pool V3', 'deploy R0 V5 adapter', 'deploy P1 adapter', 'initialize']}, indent=2))
    sys.exit(0)


def salt(name):
    return hex(int.from_bytes(hashlib.sha256(b'TEMPLAR_P6_' + name.encode()).digest(), 'big') % 2**250)


def deploy(name, class_, data):
    v = normal_tx('deploy-' + name, ['deploy', '--class-hash', class_, '--salt', salt(name),
                                     '--constructor-calldata', *[h(x) for x in data], *bounds(DEPLOY_L2_GAS, 25 * 10**18)], HERE)
    return v['contract_address']


if not plan['pool_class_declared']:
    v = normal_tx('declare-pool-v3', ['declare', '--contract-name', 'M31PoolV3', *bounds(DECLARE_L2_GAS, MAX_DECLARE_FEE_FRI, DECLARE_L2_PRICE_BOUND)],
                  POOL_CRATE, url=DECLARE_RPC)
    assert int(v['class_hash'], 16) == int(pool_class, 16)
if 'pool' not in d:
    d['pool'] = deploy('pool-v3', pool_class, [ACCOUNT, 0, E, Q, W, T])
    save(RUN / 'deployment.json', d)
if 'r0_adapter' not in d:
    d['r0_adapter'] = deploy('r0-v5-adapter', ADAPTER_CLASS, [d['pool'], P5['statement'], P5['class_hash'], OS_PROGRAM, MAX_PROOF_AGE, R0_TAG])
    save(RUN / 'deployment.json', d)
if 'p1_adapter' not in d:
    d['p1_adapter'] = deploy('p1-adapter', ADAPTER_CLASS, [d['pool'], V2['statement1'], V2['classes']['statement1'], OS_PROGRAM, MAX_PROOF_AGE, P1_TAG])
    save(RUN / 'deployment.json', d)
normal_tx('initialize', ['invoke', '--contract-address', d['pool'], '--function', 'initialize',
                         '--calldata', d['r0_adapter'], d['p1_adapter'], '0x0', *bounds(INVOKE_L2_GAS, 25 * 10**18)], HERE)

# Read back what the SDK and the server pin.
r0, p1 = (hex(call(d['pool'], 'get_verifier', [k])[0]) for k in (int.from_bytes(b'R0', 'big'), int.from_bytes(b'P1', 'big')))
assert int(r0, 16) == int(d['r0_adapter'], 16) and int(p1, 16) == int(d['p1_adapter'], 16)
assert call(d['pool'], 'get_parameters') == [E, Q, W, T]
assert call(d['pool'], 'get_owner') == [int(ACCOUNT, 16)]
assert class_at(d['pool']) == int(pool_class, 16)
d.update(initialized=True, pool_class=pool_class, adapter_class=ADAPTER_CLASS, owner=ACCOUNT,
         parameters={'E_blocks': E, 'Q_blocks': Q, 'W_blocks': W, 'T_seconds': T},
         floors={'W >= E + Q': W >= E + Q, 'mainnet T >= 7 days': 'not applied on Sepolia', 'T > E + Q (~45 min)': T > 45 * 60},
         r0=plan['r0_adapter'], p1=plan['p1_adapter'], shadow_classes=[], token=V2['token'],
         start_block=load(RUN / 'steps/deploy-pool-v3/receipt.json')['block_number'],
         steps={n: load(RUN / 'steps' / n / 'receipt.json', {}).get('actual_fee') for n in
                ('declare-pool-v3', 'deploy-pool-v3', 'deploy-r0-v5-adapter', 'deploy-p1-adapter', 'initialize')})
save(RUN / 'deployment.json', d)
(HERE / 'results').mkdir(exist_ok=True)
save(HERE / 'results/deployment.json', d)
print(json.dumps(d, indent=2))
