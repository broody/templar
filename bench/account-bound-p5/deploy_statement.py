#!/usr/bin/env python3
"""P5: declare and deploy the R0 V5 statement account on Sepolia (docs/account-bound-note-spec.md
§15 P5), so the pinned virtual OS can run it on live state with the real Ready and Braavos
accounts. P6 reuses this deployment for the adapter.

  python3 deploy_statement.py --check                          # read-only: class hash, fee estimate
  python3 deploy_statement.py                                  # prints the plan, sends nothing
  python3 deploy_statement.py --i-approve-onchain-transactions # declare (if needed) and deploy

The class is the audited P3 build (`~/.local/share/templar/runs/r5-p3b/bridge`, the one the prover
config tests and pool_e2e pin). The declaration builds a copy with gas enabled, whose CASM must equal
the audited `contract`-profile build. Transactions are sent with sncast from `account-1`; sncast
reads the key, this script never does. Checkpointed in the run directory; bounded fees.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNTIME = Path(os.environ.get('TEMPLAR_P5_RUN', Path.home() / '.local/share/templar/runs/account-bound-p5'))
os.environ['TEMPLAR_SEPOLIA_RUN'] = str(RUNTIME / 'sepolia')
(RUNTIME / 'sepolia' / 'steps').mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(HERE.parent / 'm31-sepolia'))
from sepolia import (ACCOUNT, ACCOUNT_NAME, ACCOUNTS_FILE, CHAIN, DECLARE_RPC, ENV, MAX_DECLARE_FEE_FRI, RUN,  # noqa: E402
                     SCARB, SNCAST, load, normal_tx, rpc, save)

AUDITED = Path.home() / '.local/share/templar/runs/r5-p3b/bridge'
DECLARE_BUILD = RUNTIME / 'statement-declare'
PACKAGE, CONTRACT = 'templar_membership_account', 'PaymentVerifierAccount'
ARTIFACT = f'{PACKAGE}_{CONTRACT}.compiled_contract_class.json'
R5_CIRCUIT = [1903585510, 1708577544, 3915427995, 3101166941, 461832048, 2805149134, 1077751030, 1205594117]
# The public endpoint's estimate for the R4 account was 4,099M L2 gas (bench/m31-sepolia); R5's class
# is about 3% larger. The bound is refreshed from --check before sending.
DECLARE_L2_GAS = 4_700_000_000
DEPLOY_L2_GAS = 60_000_000
SALT = hex(int.from_bytes(b'TEMPLAR_R5_STATEMENT', 'big'))
L2_PRICE_BOUND = 40_000_000_000              # fri per L2 gas (block price 2026-09-26: ~21.6e9)
L1_DATA_PRICE_BOUND = 4_000_000_000_000      # fri per L1 data gas (2026-09-26: ~1.38e12)


def bounds(l2, ceiling):
    """Explicit resource bounds: `l2` L2 gas at up to 40 gwei-fri, small L1 and L1 data caps."""
    b = [('l2-gas', l2), ('l2-gas-price', L2_PRICE_BOUND), ('l1-gas', 1), ('l1-gas-price', 200_000_000_000_000),
         ('l1-data-gas', 10_000), ('l1-data-gas-price', L1_DATA_PRICE_BOUND)]
    total = l2 * L2_PRICE_BOUND + 200_000_000_000_000 + 10_000 * L1_DATA_PRICE_BOUND
    assert total <= ceiling, f'fee bound {total / 1e18} STRK exceeds the ceiling'
    return [a for k, v in b for a in (f'--{k}', str(v))]

assert int(rpc('starknet_chainId', []), 16) == CHAIN, 'the local node is not on Sepolia'
record = json.loads((AUDITED / 'build-record.json').read_text())
assert record['message_tag'] == 'TMPZR0_PAYMENT_V5' and record['n_outputs'] == 35 and record['circuit_hash_u32_le'] == R5_CIRCUIT, 'not the audited R5 build'

# The declaration copy: the bridge, the account and the vendored verifier, with gas enabled.
if not DECLARE_BUILD.exists():
    DECLARE_BUILD.mkdir(parents=True)
    for part in ['Scarb.lock', 'bridge', 'account', 'vendor']:
        (shutil.copytree if (AUDITED / part).is_dir() else shutil.copy2)(AUDITED / part, DECLARE_BUILD / part, **({'ignore': shutil.ignore_patterns('target')} if (AUDITED / part).is_dir() else {}))
    toml = (AUDITED / 'Scarb.toml').read_text()
    for member in ('    "pool_e2e",\n', '    "m31_pool",\n', '    "account_tests",\n'):
        toml = toml.replace(member, '')
    assert '[cairo]\nenable-gas = false\n' in toml
    (DECLARE_BUILD / 'Scarb.toml').write_text(toml.replace('[cairo]\nenable-gas = false\n', '[cairo]\n', 1))
subprocess.run([SCARB, '--release', 'build', '-p', PACKAGE], cwd=DECLARE_BUILD, env=ENV, check=True, capture_output=True)
declared = json.loads((DECLARE_BUILD / 'target/release' / ARTIFACT).read_text())['bytecode']
assert declared == json.loads((AUDITED / 'target/contract' / ARTIFACT).read_text())['bytecode'], 'the declaration build differs from the audited build'
assert len(declared) <= 81_920
out = subprocess.check_output([SNCAST, '--json', 'utils', 'class-hash', '--contract-name', CONTRACT, '--package', PACKAGE], cwd=DECLARE_BUILD, env=ENV, text=True)
class_hash = json.loads(out.strip().splitlines()[-1])['class_hash']


def is_declared(h):
    try:
        rpc('starknet_getClass', ['latest', h])
        return True
    except RuntimeError as e:
        assert 'not found' in str(e).lower(), e
        return False


declared_now = is_declared(class_hash)
plan = {'class_hash': class_hash, 'casm_felts': len(declared), 'declared': declared_now, 'deployer': ACCOUNT,
        'salt': SALT, 'declare_rpc': DECLARE_RPC, 'declare_l2_gas_bound': DECLARE_L2_GAS, 'max_declare_fee_fri': MAX_DECLARE_FEE_FRI}

if '--check' in sys.argv:
    if not declared_now:
        r = subprocess.run([SNCAST, '--account', ACCOUNT_NAME, '--accounts-file', ACCOUNTS_FILE, '--json', 'declare', '--url', DECLARE_RPC,
                            '--contract-name', CONTRACT, '--package', PACKAGE, '--dry-run'], cwd=DECLARE_BUILD, env=ENV, capture_output=True, text=True)
        est = [json.loads(line) for line in r.stdout.splitlines() if line.startswith('{')]
        plan['declare_estimate'] = est[-1] if est else r.stderr[-800:]
    print(json.dumps(plan, indent=2))
    sys.exit(0)

d = load(RUN / 'deployment.json', {})
if d.get('statement'):
    print(json.dumps(d, indent=2))
    sys.exit(0)
if '--i-approve-onchain-transactions' not in sys.argv:
    print('Plan (nothing sent; pass --i-approve-onchain-transactions to send):')
    print(json.dumps({**plan, 'transactions': ([] if declared_now else ['declare']) + ['deploy (UDC, no constructor arguments)']}, indent=2))
    sys.exit(0)

if not declared_now:
    v = normal_tx('declare-statement', ['declare', '--contract-name', CONTRACT, '--package', PACKAGE, *bounds(DECLARE_L2_GAS, MAX_DECLARE_FEE_FRI)],
                  DECLARE_BUILD, url=DECLARE_RPC)
    assert int(v['class_hash'], 16) == int(class_hash, 16)
v = normal_tx('deploy-statement', ['deploy', '--class-hash', class_hash, '--salt', SALT, *bounds(DEPLOY_L2_GAS, 25 * 10**18)], HERE)
address = v['contract_address']
assert int(rpc('starknet_getClassHashAt', ['latest', address]), 16) == int(class_hash, 16)
d = {'statement': address, 'class_hash': class_hash, 'salt': SALT, 'deployer': ACCOUNT,
     'build': {k: record[k] for k in ('message_tag', 'n_outputs', 'circuit_hash_u32_le', 'fork_commit')},
     'steps': {n: load(RUN / 'steps' / n / 'response.json') for n in ('declare-statement', 'deploy-statement') if (RUN / 'steps' / n / 'response.json').exists()}}
save(RUN / 'deployment.json', d)
print(json.dumps(d, indent=2))
