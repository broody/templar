#!/usr/bin/env python3
"""§11.4 step 1 of the Sepolia drill (docs/pool-v3-spec.md): a V5 proof against the routing adapter
must get `NO_ROUTE`.

The spend is fresh (a `valid_until` on the grid ahead, a binding recomputed over it), so pool V3's
checks before its verifier pass: chain, pool, expiry, withdrawal and exit rules, binding. Its proof
facts are the ones a PROOF2 of the retired V5 statement account would carry: `[PROOF2,
VIRTUAL_SNOS, os_program, VIRTUAL_SNOS0, base, base hash, config hash, 1, Poseidon(V5 statement,
0, 5, [V5 class, 'TMPZR0_PAYMENT_V5', chain, pool, binding])]`. The transaction is simulated at the
latest block, unsigned (SKIP_VALIDATE, SKIP_FEE_CHARGE) from the relayer's address; the proof field
carries a real V5 PROOF2 from P6. Nothing is signed or sent.

Before the swap the pool's verifier is the V5 adapter: the facts match, and the pool reverts later
(`UNKNOWN_ROOT`, the spend's root is random). After the swap the verifier is the R0 routing adapter,
whose only route is V6: `NO_ROUTE`. A positive control runs the same spend with the facts of the V6
route's statement account: the routing adapter accepts them (the pool then reverts at
`UNKNOWN_ROOT`), so `NO_ROUTE` comes from the V5 identity, not from an adapter refusing everything.

    python3 bench/adr27-d/drill_v5.py
"""
import base64
import json
import os
import secrets
import subprocess
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'bench/m31-pool'))
from gen_binding_v5_kat import delivery, ref  # noqa: E402

RPC = 'http://127.0.0.1:9545/rpc/v0_10'
P6 = json.loads((ROOT / 'bench/account-bound-p6/results/deployment.json').read_text())
P6_RUN = Path.home() / '.local/share/templar/runs/account-bound-p6'
RELAYER = json.loads((P6_RUN / 'sepolia/relayer.json').read_text())['address']
V5_PROOF = P6_RUN / 'prover/jobs/8f60059045ec6f3262a08ee051bb406a/proof.bin'
CONFIG_HASH = 0x57ed4d5e20d617d8cc087a5882eae4f71d005172326be6439b2e1fd8b4dc57
P = 2**31 - 1
CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')
POOL = int(P6['pool'], 16)
short = lambda s: int.from_bytes(s.encode(), 'big')  # noqa: E731


def rpc(method, params):
    req = urllib.request.Request(RPC, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=300) as r:
        v = json.load(r)
    if 'error' in v:
        raise RuntimeError(json.dumps(v['error'])[:2000])
    return v['result']


def selector(name):
    js = "const {hash}=require(process.argv[1]);console.log(hash.getSelectorFromName(process.argv[2]))"
    return int(subprocess.check_output(['node', '-e', js, str(ROOT / 'sdk/ts/node_modules/starknet'), name], text=True).strip(), 16)


def call(address, fn, data=()):
    return [int(x, 16) for x in rpc('starknet_call', [{'contract_address': hex(address), 'entry_point_selector': hex(selector(fn)),
                                                       'calldata': [hex(x) for x in data]}, 'latest'])]


digest = lambda: [secrets.randbelow(P - 1) + 1 for _ in range(9)]  # noqa: E731
latest = rpc('starknet_getBlockWithTxHashes', ['latest'])
b = latest['block_number']
E, Q, W, T = call(POOL, 'get_parameters')
valid_until = (b + E) // Q * Q
cts = [[secrets.randbelow(2**248) for _ in range(9)] + [secrets.randbelow(2**200)] for _ in range(2)]
pub = {'chain': hex(CHAIN), 'pool': hex(POOL), 'token_out': '0x0', 'root': digest(), 'nullifiers': [digest(), digest()],
       'commitments': [digest(), digest()], 'deliveries': [hex(delivery(ct)) for ct in cts], 'withdrawal_recipient': '0x0',
       'withdrawal_amount': '0', 'intent': '0x0', 'identity': [0] * 9, 'valid_until': str(valid_until)}
b5 = [short('TMR0_BIND_V5'), CHAIN, POOL, 0, *pub['root'], *pub['nullifiers'][0], *pub['nullifiers'][1],
      *pub['commitments'][0], delivery(cts[0]), *pub['commitments'][1], delivery(cts[1]), 0, 0, 0, *pub['identity'], valid_until]
binding = ref.poseidon_hash_span(b5)
spend = [CHAIN, POOL, 0, 9, *pub['root'], 18, *pub['nullifiers'][0], *pub['nullifiers'][1], 2]
for j in range(2):
    spend += [9, *pub['commitments'][j], 10, *cts[j]]
spend += [0, 0, 0, 9, *pub['identity'], valid_until, binding]

base = b - 11
base_hash = int(rpc('starknet_getBlockWithTxHashes', [{'block_number': base}])['block_hash'], 16)


def facts_of(statement, cls, tag):
    message = ref.poseidon_hash_span([statement, 0, 5, cls, short(tag), CHAIN, POOL, binding])
    return [short('PROOF2'), short('VIRTUAL_SNOS'), int(P6['r0']['os_program'], 16), short('VIRTUAL_SNOS0'), base, base_hash, CONFIG_HASH, 1, message]


D6 = json.loads((HERE / 'results/deployment.json').read_text())
cases = {
    'v5': facts_of(int(P6['r0']['statement'], 16), int(P6['r0']['statement_class'], 16), 'TMPZR0_PAYMENT_V5'),
    'v6_control': facts_of(int(D6['r0_route']['statement'], 16), int(D6['r0_route']['statement_class'], 16), 'TMPZR0_PAYMENT_V6'),
}

calldata = [1, POOL, selector('apply_spend'), len(spend) + 1, *spend, 0]
zero = {'max_amount': '0x0', 'max_price_per_unit': '0x0'}
tx0 = {'type': 'INVOKE', 'version': '0x3', 'sender_address': RELAYER, 'calldata': [hex(x) for x in calldata], 'signature': [],
      'nonce': rpc('starknet_getNonce', ['latest', RELAYER]),
      'resource_bounds': {'l1_gas': zero, 'l2_gas': {'max_amount': hex(1_000_000_000), 'max_price_per_unit': '0x0'}, 'l1_data_gas': zero},
      'tip': '0x0', 'paymaster_data': [], 'account_deployment_data': [], 'nonce_data_availability_mode': 'L1',
      'fee_data_availability_mode': 'L1', 'proof': base64.b64encode(V5_PROOF.read_bytes()).decode()}
verifier = call(POOL, 'get_verifier', [short('R0')])[0]
known = {int(P6['r0_adapter'], 16): 'the V5 adapter', int(D6['r0-routing-adapter'], 16): 'the R0 routing adapter'}
out = {'block': b, 'valid_until': valid_until, 'binding': hex(binding), 'r0_verifier': hex(verifier),
       'r0_verifier_is': known.get(verifier, 'an unknown adapter')}
assert verifier in known, 'the pool\'s R0 verifier is neither the V5 adapter nor the R0 routing adapter'


def reason_of(r):
    for code in ('NO_ROUTE', 'UNKNOWN_ROOT', 'PROOF_BINDING', 'ROUTE_CLASS', 'PROOF_AGE', 'SPEND_EXPIRED', 'BAD_BINDING'):
        if code in r or '0x' + code.encode().hex() in r:
            return code
    return r[-300:]


for label, facts in cases.items():
    try:
        trace = rpc('starknet_simulateTransactions', ['latest', [{**tx0, 'proof_facts': [hex(x) for x in facts]}], ['SKIP_VALIDATE', 'SKIP_FEE_CHARGE']])[0]['transaction_trace']
        reason = trace.get('execute_invocation', {}).get('revert_reason')
        out[label] = {'reverted': reason is not None, 'reason': reason_of(reason) if reason else None}
    except RuntimeError as e:
        out[label] = {'error': str(e)[:1500]}
# After the swap: the V5 message gets NO_ROUTE, and the V6 control passes the adapter.
out['no_route'] = out['v5'].get('reason') == 'NO_ROUTE'
out['control_passes_verifier'] = out['v6_control'].get('reason') == 'UNKNOWN_ROOT'
runs = HERE / 'results/drill-v5.json'
prior = json.loads(runs.read_text()) if runs.exists() else []
runs.write_text(json.dumps(prior + [out], indent=1) + '\n')
print(json.dumps(out, indent=1))
