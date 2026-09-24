"""Local rehearsal of the Sepolia wallet flow, nothing on chain: two deposits predicted as the
pool computes them, a transfer proved from that leaf list, and the proof checked against the
statement-account build (circuit hash pin and bridge acceptance)."""
from pathlib import Path
import json, subprocess, sys, tempfile
import wallet

CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')
POOL, TOKEN = 0x1234abcd, 0x5678ef
BRIDGE = Path(sys.argv[1])  # a build_bridge_arith.py output directory for the R0 V2 compress circuit
out = Path(tempfile.mkdtemp(prefix='templar-rehearse-'))

alice, bob = wallet.random_digest(), wallet.random_digest()
a, b = wallet.keys(alice), wallet.keys(bob)
notes = []
for amount in (600, 400):
    rho = wallet.random_digest()
    inn = wallet.inner(a['receiver'], rho)
    notes.append({'sk': alice, 'rho': rho, 'amount': str(amount), 'cm': wallet.commitment(CHAIN, POOL, TOKEN, amount, inn)})
leaves = [n['cm'] for n in notes]
ct = [wallet.ciphertext('bob'), wallet.ciphertext('change')]
spend = {
    'chain': hex(CHAIN), 'pool': hex(POOL), 'token': hex(TOKEN), 'leaves': leaves,
    'inputs': [{'sk': n['sk'], 'rho': n['rho'], 'amount': n['amount'], 'position': i} for i, n in enumerate(notes)],
    'outputs': [
        {'active': True, 'receiver': b['receiver'], 'rho': wallet.random_digest(), 'amount': '700', 'delivery': hex(wallet.delivery_digest(ct[0]))},
        {'active': True, 'receiver': a['receiver'], 'rho': wallet.random_digest(), 'amount': '300', 'delivery': hex(wallet.delivery_digest(ct[1]))},
    ],
    'withdrawal': {'recipient': '0x0', 'amount': '0'},
}
report = wallet.prove(spend, out / 'transfer')
pin = json.loads((BRIDGE / 'build-record.json').read_text())['circuit_hash_u32_le']
mine = json.loads((out / 'transfer/trusted-config.json').read_text())['circuit_hash_u32_le']
print(json.dumps({'report': {k: report[k] for k in ('trace_log_size', 'blinding_rows', 'proving_seconds', 'native_negatives')},
                  'circuit_hash_matches_statement_account': pin == mine}, indent=1))
assert pin == mine, 'wallet circuit differs from the statement account build'
v = subprocess.run([sys.executable, str(wallet.CLIENT / 'validate_bridge_r0.py'), str(BRIDGE), str(out / 'transfer'), str(out / 'bridge')],
                   capture_output=True, text=True, cwd=wallet.CLIENT)
lines = [json.loads(l) for l in v.stdout.splitlines() if l.startswith('{')]
print('bridge', sum(l['passed'] for l in lines), '/', len(lines), 'valid steps', lines[0]['steps'] if lines else None)
assert v.returncode == 0
print('rehearsal dir', out)
