#!/usr/bin/env python3
"""P6 end to end: the relayer's own account on Sepolia, with a fresh key.

  python3 relayer_account.py --check                           # read-only: address, balances
  python3 relayer_account.py                                   # prints the plan, sends nothing
  python3 relayer_account.py --i-approve-onchain-transactions  # fund and deploy it

The key is generated here, in the run directory (0600), and is only ever this test relayer's:
`account-1`'s key stays with sncast. Transactions:
1. `account-1` sends the relayer STRK for fees (sncast);
2. `account-1` sends it token A for the test deposits (sncast);
3. the relayer's account deploys itself (sncast, from the run directory's accounts file).
"""
import json
import os
import secrets
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNTIME = Path(os.environ.get('TEMPLAR_P6_RUN', Path.home() / '.local/share/templar/runs/account-bound-p6'))
os.environ['TEMPLAR_SEPOLIA_RUN'] = str(RUNTIME / 'sepolia')
sys.path.insert(0, str(ROOT / 'bench/m31-sepolia'))
from sepolia import ACCOUNT, ENV, RPC, RUN, SNCAST, call, h, load, normal_tx, receipt, rpc, save  # noqa: E402
import subprocess  # noqa: E402

STRK = '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d'
TOKEN_A = load(RUN / 'deployment.json')['token']
KEY = RUNTIME / 'relayer.key'
ACCOUNTS = RUNTIME / 'relayer-accounts.json'
NAME = 'relayer-p6'
FUND_STRK = 40 * 10**18
FUND_A = 3000
N = 0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f  # the Stark curve's order


def bounds(l2):
    b = [('l2-gas', l2), ('l2-gas-price', 40_000_000_000), ('l1-gas', 1), ('l1-gas-price', 200_000_000_000_000),
         ('l1-data-gas', 10_000), ('l1-data-gas-price', 4_000_000_000_000)]
    return [a for k, v in b for a in (f'--{k}', str(v))]


def balance(token, who):
    lo, hi = call(token, 'balance_of', [who])[:2]
    return lo + (hi << 128)


if not KEY.exists():
    KEY.write_text(hex(1 + secrets.randbelow(N - 1)))  # sncast refuses a trailing newline
    KEY.chmod(0o600)
if not ACCOUNTS.exists():
    subprocess.run([SNCAST, '--accounts-file', str(ACCOUNTS), '--json', 'account', 'create', '--name', NAME,
                    '--private-key-file', str(KEY), '--url', RPC], env=ENV, check=True, capture_output=True)
    ACCOUNTS.chmod(0o600)
acct = json.loads(ACCOUNTS.read_text())
entry = next(v[NAME] for v in acct.values() if isinstance(v, dict) and NAME in v)
address = entry['address']


def deployed():
    try:
        rpc('starknet_getClassHashAt', ['latest', address])
        return True
    except RuntimeError as e:
        assert 'not found' in str(e).lower(), e
        return False


state = {'relayer': address, 'class_hash': entry.get('class_hash'), 'deployed': deployed(),
         'strk': balance(STRK, address) / 1e18, 'token_a': balance(TOKEN_A, address),
         'account_1_token_a': balance(TOKEN_A, ACCOUNT)}
if '--check' in sys.argv or '--i-approve-onchain-transactions' not in sys.argv:
    if '--check' not in sys.argv:
        print('Plan (nothing sent; pass --i-approve-onchain-transactions to send):')
        state['transactions'] = [f'account-1 -> relayer: {FUND_STRK / 1e18:.0f} STRK', f'account-1 -> relayer: {FUND_A} token A', 'deploy the relayer account']
    print(json.dumps(state, indent=2))
    sys.exit(0)

assert state['account_1_token_a'] >= FUND_A or state['token_a'] >= FUND_A
if state['strk'] < FUND_STRK / 1e18 / 2:
    normal_tx('fund-relayer-strk', ['invoke', '--contract-address', STRK, '--function', 'transfer',
                                    '--calldata', address, h(FUND_STRK), '0x0', *bounds(20_000_000)], HERE)
if state['token_a'] < FUND_A:
    normal_tx('fund-relayer-token-a', ['invoke', '--contract-address', TOKEN_A, '--function', 'transfer',
                                       '--calldata', address, h(FUND_A), '0x0', *bounds(20_000_000)], HERE)
if not deployed():
    path = RUN / 'steps/deploy-relayer/response.json'
    v = load(path)
    if v is None:
        out = subprocess.run([SNCAST, '--accounts-file', str(ACCOUNTS), '--account', NAME, '--json', 'account', 'deploy', '--name', NAME,
                              '--url', RPC, *bounds(20_000_000)], env=ENV, capture_output=True, text=True)
        rows = [json.loads(line) for line in out.stdout.splitlines() if line.startswith('{')]
        v = next((r for r in rows if 'transaction_hash' in r), None)
        assert v, out.stderr[-1200:]
        save(path, v)
    receipt(v['transaction_hash'], path.parent / 'receipt.json')
state.update(deployed=deployed(), strk=balance(STRK, address) / 1e18, token_a=balance(TOKEN_A, address))
save(RUN / 'relayer.json', {'address': address, 'class_hash': entry.get('class_hash'), 'key_file': str(KEY)})
print(json.dumps(state, indent=2))
