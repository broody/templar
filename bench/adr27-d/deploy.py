#!/usr/bin/env python3
"""ADR-0027 phase D: deploy R0 V6 and the routing adapters on Sepolia (docs/pool-v3-spec.md §11.1).

  python3 deploy.py --check                           # read-only: classes, balances, fee estimates
  python3 deploy.py                                   # prints the plan, sends nothing
  python3 deploy.py --i-approve-onchain-transactions  # declare, deploy, read back

Transactions, all from `account-1` through sncast (sncast reads the key; this script never does):
1. declare the V6 statement account (`PaymentVerifierAccount`, the phase C build in
   `~/.local/share/templar/runs/r6-p1/bridge`; the declaration copy enables gas and must compile to
   the audited `contract`-profile CASM);
2. deploy it (no constructor arguments), and a second instance under another salt: the planned
   route of the §11.4 drill, pinned in the release;
3. declare `RoutingAdapter` (bench/m31-pool/cairo);
4. deploy the R0 routing adapter on pool V3 with the V6 route;
5. deploy the P1 routing adapter with the P1 route: the pool V2 P1 statement account P6's P1
   adapter pins, checked against §6.5 (bench/adr27-d/README.md).

Then it reads back both adapters through their views (§11.1 step 2): pool, kind, routes, no pending
proposals, the adapter class and each route's class on chain. Nothing here touches pool V3's
verifiers: the swap is phase E. Checkpointed in the run directory; bounded fees.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNTIME = Path(os.environ.get('TEMPLAR_ADR27_RUN', Path.home() / '.local/share/templar/runs/adr27-d'))
os.environ['TEMPLAR_SEPOLIA_RUN'] = str(RUNTIME / 'sepolia')
(RUNTIME / 'sepolia' / 'steps').mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / 'bench/m31-sepolia'))
from sepolia import (ACCOUNT, ACCOUNT_NAME, ACCOUNTS_FILE, CHAIN, DECLARE_RPC, ENV, MAX_DECLARE_FEE_FRI, RUN,  # noqa: E402
                     SCARB, SNCAST, call, h, load, normal_tx, rpc, save)

P6 = load(ROOT / 'bench/account-bound-p6/results/deployment.json')
POOL = P6['pool']
POOL_CRATE = ROOT / 'bench/m31-pool/cairo'
AUDITED = Path.home() / '.local/share/templar/runs/r6-p1/bridge'
DECLARE_BUILD = RUNTIME / 'statement-declare'
PACKAGE, CONTRACT = 'templar_membership_account', 'PaymentVerifierAccount'
ARTIFACT = f'{PACKAGE}_{CONTRACT}.compiled_contract_class.json'
R6_CIRCUIT = [2010035999, 4123906337, 3936982050, 2269257694, 3115244238, 1536739351, 29337086, 2871661834]
OS_PROGRAM = P6['r0']['os_program']
MAX_PROOF_AGE = 1024                         # §6.4
R0_KIND, P1_KIND = int.from_bytes(b'R0', 'big'), int.from_bytes(b'P1', 'big')
SALTS = {name: hex(int.from_bytes(hashlib.sha256(b'TEMPLAR_ADR27_' + name.encode()).digest(), 'big') % 2**250)
         for name in ('r6-statement', 'r6-statement-planned', 'r0-routing-adapter', 'p1-routing-adapter')}
# Declarations cost 40,960 L2 gas per class felt; the bounds are refreshed from --check.
STATEMENT_DECLARE_L2_GAS = 4_700_000_000
ADAPTER_DECLARE_L2_GAS = 1_200_000_000
DECLARE_L2_PRICE_BOUND = 30_000_000_000      # fri per L2 gas for declarations
DEPLOY_L2_GAS = 60_000_000
L2_PRICE_BOUND = 40_000_000_000
L1_DATA_PRICE_BOUND = 4_000_000_000_000
BUDGET_STRK = 1000                           # the owner's preapproval for phases D and E


def bounds(l2, ceiling, l2_price=L2_PRICE_BOUND):
    b = [('l2-gas', l2), ('l2-gas-price', l2_price), ('l1-gas', 1), ('l1-gas-price', 200_000_000_000_000),
         ('l1-data-gas', 10_000), ('l1-data-gas-price', L1_DATA_PRICE_BOUND)]
    total = l2 * l2_price + 200_000_000_000_000 + 10_000 * L1_DATA_PRICE_BOUND
    assert total <= ceiling, f'fee bound {total / 1e18} STRK exceeds the ceiling'
    return [a for k, v in b for a in (f'--{k}', str(v))]


def max_fee(l2, l2_price=L2_PRICE_BOUND):
    return l2 * l2_price + 200_000_000_000_000 + 10_000 * L1_DATA_PRICE_BOUND


def short(s):
    return int.from_bytes(s.encode(), 'big')


def route(statement, statement_class, tag):
    """A `Route` in its Serde order (sdk/vectors/routing.json)."""
    return [int(statement, 16), int(statement_class, 16), short(tag), int(OS_PROGRAM, 16), short('PROOF2'),
            short('VIRTUAL_SNOS'), short('VIRTUAL_SNOS0'), MAX_PROOF_AGE]


def class_hash(cwd, contract, package=None):
    args = [SNCAST, '--json', 'utils', 'class-hash', '--contract-name', contract] + (['--package', package] if package else [])
    return json.loads(subprocess.check_output(args, cwd=cwd, env=ENV, text=True).strip().splitlines()[-1])['class_hash']


def declared(hash_):
    try:
        rpc('starknet_getClass', ['latest', hash_])
        return True
    except RuntimeError as e:
        assert 'not found' in str(e).lower(), e
        return False


def class_at(address):
    return int(rpc('starknet_getClassHashAt', ['latest', address]), 16)


def udc_address(class_hash_, salt, calldata):
    """The address sncast's deploy gives: the UDC, not unique (deployer 0, the salt as given);
    checked against P6's pool address."""
    out = subprocess.check_output(
        ['node', '-e', "const {hash}=require(process.argv[1]);const [c,s,d]=JSON.parse(process.argv[2]);"
         "console.log(hash.calculateContractAddressFromHash(s,c,d,0))",
         str(ROOT / 'sdk/ts/node_modules/starknet'), json.dumps([class_hash_, salt, [h(x) for x in calldata]])], text=True)
    return hex(int(out.strip(), 16))


assert int(rpc('starknet_chainId', []), 16) == CHAIN, 'the local node is not on Sepolia'
assert int(udc_address(P6['pool_class'], hex(int.from_bytes(hashlib.sha256(b'TEMPLAR_P6_pool-v3').digest(), 'big') % 2**250),
                       [ACCOUNT, 0, 1500, 100, 4096, 7200]), 16) == int(POOL, 16), 'the address derivation'
# The pool is P6's, still on its V5 adapters (phase E swaps them).
assert call(POOL, 'get_owner') == [int(ACCOUNT, 16)]
assert call(POOL, 'get_parameters') == [1500, 100, 4096, 7200]
assert call(POOL, 'get_verifier', [R0_KIND]) == [int(P6['r0_adapter'], 16)]
assert call(POOL, 'get_verifier', [P1_KIND]) == [int(P6['p1_adapter'], 16)]

# 1. The V6 statement account: the audited phase C build, declared from a gas-enabled copy.
record = json.loads((AUDITED / 'build-record.json').read_text())
assert record['message_tag'] == 'TMPZR0_PAYMENT_V6' and record['n_outputs'] == 33 and record['circuit_hash_u32_le'] == R6_CIRCUIT, 'not the phase C build'
if not DECLARE_BUILD.exists():
    DECLARE_BUILD.mkdir(parents=True)
    for part in ['Scarb.lock', 'bridge', 'account', 'vendor']:
        src = AUDITED / part
        (shutil.copytree(src, DECLARE_BUILD / part, ignore=shutil.ignore_patterns('target')) if src.is_dir() else shutil.copy2(src, DECLARE_BUILD / part))
    toml = (AUDITED / 'Scarb.toml').read_text()
    for member in ('    "pool_e2e",\n', '    "m31_pool",\n', '    "account_tests",\n'):
        toml = toml.replace(member, '')
    assert '[cairo]\nenable-gas = false\n' in toml
    (DECLARE_BUILD / 'Scarb.toml').write_text(toml.replace('[cairo]\nenable-gas = false\n', '[cairo]\n', 1))
subprocess.run([SCARB, '--release', 'build', '-p', PACKAGE], cwd=DECLARE_BUILD, env=ENV, check=True, capture_output=True)
statement_casm = json.loads((DECLARE_BUILD / 'target/release' / ARTIFACT).read_text())['bytecode']
assert statement_casm == json.loads((AUDITED / 'target/contract' / ARTIFACT).read_text())['bytecode'], 'the declaration build differs from the audited build'
assert len(statement_casm) <= 81_920
statement_class = class_hash(DECLARE_BUILD, CONTRACT, PACKAGE)

# 3. The routing adapter class: the phase C source.
subprocess.run([SCARB, '--release', 'build'], cwd=POOL_CRATE, env=ENV, check=True, capture_output=True)
adapter_casm = load(POOL_CRATE / 'target/release/m31_pool_RoutingAdapter.compiled_contract_class.json')['bytecode']
adapter_sierra = load(POOL_CRATE / 'target/release/m31_pool_RoutingAdapter.contract_class.json')['sierra_program']
adapter_class = class_hash(POOL_CRATE, 'RoutingAdapter')
# The pool's class is unchanged by phase C (the adapter is a new class).
assert int(class_hash(POOL_CRATE, 'M31PoolV3'), 16) == int(P6['pool_class'], 16) == class_at(POOL)

# 5. The P1 route: the statement account P6's P1 adapter pins.
p1_statement, p1_class = P6['p1']['statement'], P6['p1']['statement_class']
assert class_at(p1_statement) == int(p1_class, 16)

statements = {name: udc_address(statement_class, SALTS[name], []) for name in ('r6-statement', 'r6-statement-planned')}
r0_routes = [route(statements['r6-statement'], statement_class, 'TMPZR0_PAYMENT_V6')]
p1_routes = [route(p1_statement, p1_class, 'TMPZP1_POLICY_V1')]
r0_args = [int(POOL, 16), R0_KIND, 1, *r0_routes[0]]
p1_args = [int(POOL, 16), P1_KIND, 1, *p1_routes[0]]
adapters = {'r0-routing-adapter': udc_address(adapter_class, SALTS['r0-routing-adapter'], r0_args),
            'p1-routing-adapter': udc_address(adapter_class, SALTS['p1-routing-adapter'], p1_args)}
fees = {'declare-statement': max_fee(STATEMENT_DECLARE_L2_GAS, DECLARE_L2_PRICE_BOUND),
        'declare-routing-adapter': max_fee(ADAPTER_DECLARE_L2_GAS, DECLARE_L2_PRICE_BOUND),
        **{f'deploy-{n}': max_fee(DEPLOY_L2_GAS) for n in SALTS}}
plan = {
    'pool': POOL, 'owner': ACCOUNT,
    'statement': {'class': statement_class, 'declared': declared(statement_class), 'casm_felts': len(statement_casm),
                  'addresses': statements, 'circuit_hash_u32_le': R6_CIRCUIT, 'fork_commit': record['fork_commit']},
    'routing_adapter': {'class': adapter_class, 'declared': declared(adapter_class), 'casm_felts': len(adapter_casm),
                        'sierra_felts': len(adapter_sierra), 'addresses': adapters},
    'r0_route': {'statement': statements['r6-statement'], 'statement_class': statement_class, 'account_tag': 'TMPZR0_PAYMENT_V6',
                 'os_program': OS_PROGRAM, 'max_proof_age': MAX_PROOF_AGE},
    'p1_route': {'statement': p1_statement, 'statement_class': p1_class, 'account_tag': 'TMPZP1_POLICY_V1',
                 'os_program': OS_PROGRAM, 'max_proof_age': MAX_PROOF_AGE},
    'planned_route': {'statement': statements['r6-statement-planned'], 'statement_class': statement_class},
    'max_fee_STRK': {k: v / 1e18 for k, v in fees.items()},
}
assert sum(fees.values()) <= BUDGET_STRK * 10**18, 'the fee bounds exceed the preapproved budget'

if '--check' in sys.argv:
    for name, (cwd, contract, package, hash_) in {'statement': (DECLARE_BUILD, CONTRACT, PACKAGE, statement_class),
                                                  'routing_adapter': (POOL_CRATE, 'RoutingAdapter', None, adapter_class)}.items():
        if declared(hash_):
            continue
        r = subprocess.run([SNCAST, '--account', ACCOUNT_NAME, '--accounts-file', ACCOUNTS_FILE, '--json', 'declare', '--url', DECLARE_RPC,
                            '--contract-name', contract, *(['--package', package] if package else []), '--dry-run'],
                           cwd=cwd, env=ENV, capture_output=True, text=True)
        est = [json.loads(line) for line in r.stdout.splitlines() if line.startswith('{')]
        plan[name]['declare_estimate'] = est[-1] if est else r.stderr[-800:]
    plan['account_1_strk'] = int(call('0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d', 'balance_of', [ACCOUNT])[0]) / 1e18
    print(json.dumps(plan, indent=2))
    sys.exit(0)

d = load(RUN / 'deployment.json', {})
if d.get('read_back'):
    print(json.dumps(d, indent=2))
    sys.exit(0)
if '--i-approve-onchain-transactions' not in sys.argv:
    print('Plan (nothing sent; pass --i-approve-onchain-transactions to send):')
    print(json.dumps(plan, indent=2))
    sys.exit(0)


def deploy(name, class_, data):
    v = normal_tx('deploy-' + name, ['deploy', '--class-hash', class_, '--salt', SALTS[name],
                                     *(['--constructor-calldata', *[h(x) for x in data]] if data else []),
                                     *bounds(DEPLOY_L2_GAS, 25 * 10**18)], HERE)
    assert int(v['contract_address'], 16) == int((statements | adapters)[name], 16), (name, v['contract_address'])
    return hex(int(v['contract_address'], 16))


if not declared(statement_class):
    v = normal_tx('declare-statement', ['declare', '--contract-name', CONTRACT, '--package', PACKAGE,
                                        *bounds(STATEMENT_DECLARE_L2_GAS, MAX_DECLARE_FEE_FRI, DECLARE_L2_PRICE_BOUND)],
                  DECLARE_BUILD, url=DECLARE_RPC)
    assert int(v['class_hash'], 16) == int(statement_class, 16)
for name in ('r6-statement', 'r6-statement-planned'):
    if name not in d:
        d[name] = deploy(name, statement_class, [])
        save(RUN / 'deployment.json', d)
if not declared(adapter_class):
    v = normal_tx('declare-routing-adapter', ['declare', '--contract-name', 'RoutingAdapter',
                                              *bounds(ADAPTER_DECLARE_L2_GAS, MAX_DECLARE_FEE_FRI, DECLARE_L2_PRICE_BOUND)],
                  POOL_CRATE, url=DECLARE_RPC)
    assert int(v['class_hash'], 16) == int(adapter_class, 16)
for name, args in (('r0-routing-adapter', r0_args), ('p1-routing-adapter', p1_args)):
    if name not in d:
        d[name] = deploy(name, adapter_class, args)
        save(RUN / 'deployment.json', d)

# Read back (§11.1 step 2).
back = {}
for name, kind, routes in (('r0-routing-adapter', R0_KIND, r0_routes), ('p1-routing-adapter', P1_KIND, p1_routes)):
    a = d[name]
    assert class_at(a) == int(adapter_class, 16)
    assert call(a, 'get_pool') == [int(POOL, 16)] and call(a, 'get_kind') == [kind]
    assert call(a, 'get_routes') == [len(routes)] + [x for r in routes for x in r]
    assert call(a, 'get_route_proposals') == [0]
    for r in routes:
        assert call(a, 'get_route', [r[0]]) == [0, *r]
        assert class_at(hex(r[0])) == r[1]
    back[name] = {'class': hex(class_at(a)), 'routes': [hex(r[0]) for r in routes], 'proposals': 0}
for name in ('r6-statement', 'r6-statement-planned'):
    assert class_at(d[name]) == int(statement_class, 16)
# The pool still serves V5 until phase E.
assert call(POOL, 'get_verifier', [R0_KIND]) == [int(P6['r0_adapter'], 16)]
d.update(read_back=back, statement_class=statement_class, adapter_class=adapter_class, pool=POOL, owner=ACCOUNT,
         r0_route=plan['r0_route'], p1_route=plan['p1_route'], planned_route=plan['planned_route'], salts=SALTS,
         build={k: record[k] for k in ('message_tag', 'n_outputs', 'circuit_hash_u32_le', 'fork_commit')},
         casm_felts={'statement': len(statement_casm), 'routing_adapter': len(adapter_casm)},
         steps={p.name: load(p / 'receipt.json', {}).get('actual_fee') for p in sorted((RUN / 'steps').iterdir()) if (p / 'receipt.json').exists()})
save(RUN / 'deployment.json', d)
(HERE / 'results').mkdir(exist_ok=True)
save(HERE / 'results/deployment.json', d)
print(json.dumps(d, indent=2))
