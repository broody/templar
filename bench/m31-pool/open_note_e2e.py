"""Local end-to-end open-note execution with a real client proof, nothing synthetic between the
wallet and the pool:

  wallet (keys, deposits, change, open-note destination, execution intent)
    -> R0 V3 client proof (Rust `wallet` example) binding that intent
    -> bridge validation (`target/bridge-r0v3`) -> virtual-OS capture (local fixture) -> PROOF2
    -> Cairo vectors for `tests/test_open_note_e2e.cairo`, which deploys the pool, tokens, swap
       adapter and PROOF2 adapter at the addresses the proof commits to, replays the deposits,
       injects the real PROOF2 facts and settles `apply_spend_with_invoke`.

Wallet secrets stay in a private run directory outside the repository; the vectors carry only
public data. Usage: open_note_e2e.py [RUN_DIR]"""
from pathlib import Path
import json, os, subprocess, sys, time
import open_note as on

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CLIENT = ROOT / 'bench/m31-private-wrapper/client-port'
BRIDGE = ROOT / 'target/bridge-r0v3'
sys.path.insert(0, str(ROOT / 'bench/m31-sepolia'))
sys.path.insert(0, str(CLIENT))
os.environ.setdefault('TEMPLAR_SEPOLIA_RUN', '/nonexistent')
import wallet  # noqa: E402
import validate_bridge_r0  # noqa: E402

CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')
POOL, TOKEN_A, TOKEN_B, ADAPTER, PROOF2_ADAPTER = 0x7e57a001, 0x7e57a0a1, 0x7e57a0b1, 0x7e57a0ad, 0x7e57a0f2
BUDGET, PROCEEDS, MINIMUM, NOTE_ID, EXPIRY = 300, 290, 280, 77, 1000


def run(cmd, log, **kw):
    with open(log, 'w') as f:
        r = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, **kw)
    assert r.returncode == 0, Path(log).read_text()[-3000:]


def main():
    run_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / '.local/share/templar/runs' / f'open-note-e2e-{int(time.time())}'
    run_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(run_dir, 0o700)
    t = {}
    # Wallet: Alice's key, two deposits, a change output and one open-note destination.
    alice = wallet.random_digest()
    a = wallet.keys(alice)
    notes = []
    for amount in (600, 400):
        rho = wallet.random_digest()
        inner = wallet.inner(a['receiver'], rho)
        notes.append({'rho': rho, 'amount': amount, 'inner': inner, 'ciphertext': wallet.ciphertext('deposit'),
                      'cm': wallet.commitment(CHAIN, POOL, TOKEN_A, amount, inner)})
    change_ct = wallet.ciphertext('change')
    dest_rho = wallet.random_digest()
    dest = {'note_id': NOTE_ID, 'token': TOKEN_B, 'minimum': MINIMUM, 'inner': wallet.inner(a['receiver'], dest_rho),
            'ciphertext': wallet.ciphertext('open-note')}
    intent = {'kind': on.INVOKE, 'adapter': ADAPTER, 'nonce': 0, 'expiry': EXPIRY,
              'calldata': on.swap_calldata(TOKEN_A, BUDGET, [{'note_id': NOTE_ID, 'token': TOKEN_B, 'amount': PROCEEDS}]),
              'destinations': [dest]}
    intent_felt = on.hash_intent(CHAIN, POOL, TOKEN_A, ADAPTER, BUDGET, intent)
    spend = {
        'chain': hex(CHAIN), 'pool': hex(POOL), 'token': hex(TOKEN_A), 'leaves': [n['cm'] for n in notes],
        'inputs': [{'sk': alice, 'rho': n['rho'], 'amount': str(n['amount']), 'position': i} for i, n in enumerate(notes)],
        'outputs': [
            {'active': True, 'receiver': a['receiver'], 'rho': wallet.random_digest(), 'amount': str(1000 - BUDGET),
             'delivery': hex(wallet.delivery_digest(change_ct))},
            {'active': False, 'receiver': [0] * 9, 'rho': [0] * 9, 'amount': '0', 'delivery': '0x0'},
        ],
        'withdrawal': {'recipient': hex(ADAPTER), 'amount': str(BUDGET)},
        'intent': hex(intent_felt),
    }
    # Client proof.
    t0 = time.time()
    client = wallet.prove(spend, run_dir / 'client')
    t['client'] = {k: client[k] for k in ('trace_log_size', 'blinding_rows', 'proving_seconds', 'max_rss_gib', 'proof_felts')}
    public = json.loads((run_dir / 'client/public.json').read_text())
    assert int(public['intent'], 16) == intent_felt and public['identity'] == [0] * 9
    pin = json.loads((BRIDGE / 'build-record.json').read_text())['circuit_hash_u32_le']
    assert json.loads((run_dir / 'client/trusted-config.json').read_text())['circuit_hash_u32_le'] == pin, 'bridge-r0v3 circuit'
    # Server: bridge, virtual OS, PROOF2.
    run([sys.executable, str(CLIENT / 'validate_bridge_r0.py'), str(BRIDGE), str(run_dir / 'client'), str(run_dir / 'bridge')],
        run_dir / 'bridge.log', cwd=CLIENT)
    rows = [json.loads(l) for l in (run_dir / 'bridge.log').read_text().splitlines() if l.startswith('{')]
    t['bridge'] = {'passed': sum(r['passed'] for r in rows), 'cases': len(rows), 'steps': rows[0].get('steps')}
    sierra = next((BRIDGE / 'target/contract').glob('*PaymentVerifierAccount.contract_class.json'))
    run([sys.executable, str(CLIENT / 'capture_os.py'), '--sierra', str(sierra), '--proof-dir', str(run_dir / 'client'),
         '--public', str(run_dir / 'client/public.json'), '--output', str(run_dir / 'os'), '--tag-version', 'R0'],
        run_dir / 'capture.log', cwd=CLIENT)
    capture = json.loads((run_dir / 'os/execution.json').read_text())
    t['os'] = {'steps': json.loads((run_dir / 'os/capture.json').read_text())['resources']['n_steps'],
               'seconds': capture['elapsed_seconds'], 'exact_message': capture.get('exact_message_verified')}
    run(['bash', str(ROOT / 'bench/m31-private-wrapper/proof2-large/run.sh'), str(run_dir / 'os/os.pie.zip'), str(run_dir / 'proof2'), '115G'],
        run_dir / 'proof2.log')
    p2 = json.loads((run_dir / 'proof2/summary.json').read_text())
    assert p2['verified']
    t['proof2'] = {k: p2[k] for k in ('prove_seconds', 'proof_bytes', 'verified')}
    rss = [l for l in (run_dir / 'proof2/run.log').read_text().splitlines() if 'Maximum resident' in l]
    t['proof2']['max_rss_gib'] = int(rss[-1].split()[-1]) / 2**20 if rss else None
    preimage = json.loads((run_dir / 'proof2/output-preimage.json').read_text())
    facts = [int.from_bytes(b'PROOF2', 'big'), int.from_bytes(b'VIRTUAL_SNOS', 'big'), *[int(x, 16) for x in preimage]]
    fixture = json.loads((run_dir / 'os/state-fixture.json').read_text())
    statement, statement_class = int(fixture['authority']['statement'], 16), int(fixture['authority']['statement_class'], 16)
    binding = validate_bridge_r0.binding(public)
    message = on.ref.poseidon_hash_span([statement, 0, 5, statement_class, int.from_bytes(b'TMPZR0_PAYMENT_V3', 'big'),
                                         CHAIN, POOL, binding])
    assert facts[8] == message, 'facts carry the statement account message for this binding'
    # Cairo vectors (public data only).
    spend_felts = on.encode_spend(public, [change_ct, None], binding)
    intent_felts = on.encode_intent(intent)
    arr = lambda xs: 'array![' + ', '.join(hex(x) for x in xs) + ']'
    lines = ['// Generated by bench/m31-pool/open_note_e2e.py: a real R0 V3 open-note spend (public data only).',
             f'pub const POOL: felt252 = {hex(POOL)};', f'pub const TOKEN_A: felt252 = {hex(TOKEN_A)};',
             f'pub const TOKEN_B: felt252 = {hex(TOKEN_B)};', f'pub const ADAPTER: felt252 = {hex(ADAPTER)};',
             f'pub const PROOF2_ADAPTER: felt252 = {hex(PROOF2_ADAPTER)};', f'pub const STATEMENT: felt252 = {hex(statement)};',
             f'pub const STATEMENT_CLASS: felt252 = {hex(statement_class)};', f'pub const OS_PROGRAM: felt252 = {hex(facts[2])};',
             f'pub const BASE_BLOCK: u64 = {facts[4]};', f'pub const PROCEEDS: u128 = {PROCEEDS};', f'pub const BUDGET: u128 = {BUDGET};']
    for i, n in enumerate(notes):
        lines += [f'pub const DEPOSIT{i}_AMOUNT: u128 = {n["amount"]};',
                  f'pub fn deposit{i}_inner() -> Array<felt252> {{ {arr(n["inner"])} }}',
                  f'pub fn deposit{i}_ciphertext() -> Array<felt252> {{ {arr(n["ciphertext"])} }}']
    lines += [f'pub fn facts() -> Array<felt252> {{ {arr(facts)} }}',
              f'pub fn spend_felts() -> Array<felt252> {{ {arr(spend_felts)} }}',
              f'pub fn intent_felts() -> Array<felt252> {{ {arr(intent_felts)} }}',
              f'pub fn identity_check() -> (felt252, felt252, felt252) {{ ({hex(on.partial_commitment(list(range(1, 10))))}, 5, '
              f'{hex(on.identity_commitment(on.partial_commitment(list(range(1, 10))), 5))}) }}']
    (HERE / 'cairo/src/tests/e2e_vectors.cairo').write_text('\n'.join(lines) + '\n')
    t['binding'] = hex(binding)
    t['intent'] = hex(intent_felt)
    (HERE / 'results').mkdir(exist_ok=True)
    (HERE / 'results/open-note-e2e.json').write_text(json.dumps(t, indent=1) + '\n')
    print(json.dumps(t, indent=1))
    print('run dir (private):', run_dir)


if __name__ == '__main__':
    main()
