"""Local end-to-end policy-note escrow with real client proofs (`docs/policy-note-spec.md` §1, §10):

  depositor wallet (seed) creates two policy notes by deposit, each with a PB01 backup
    note A: escrow, settle outcome pays the beneficiary two notes (600 + 400); far deadline
    note B: escrow, deadline already passed
  executor, holding only note A's opening (no wallet secret), proves the settlement (P1)
  depositor, from the seed alone, recovers note B and proves its refund (P1, outcome 0)
    -> bridge validation (`target/bridge-p1`) -> virtual-OS capture -> PROOF2, for each proof
    -> Cairo vectors for `tests/test_policy_e2e.cairo`, which deploys the pool, token, escrow and
       P1 PROOF2 adapter at the committed addresses, replays the deposits, has the arbiter
       approve, and settles both through `apply_policy_spend` with the real PROOF2 facts
  beneficiary finds its two notes by trial decryption and proves an ordinary R0 spend of them;
  the depositor finds the refund note.

Secrets stay in a private run directory outside the repository; the vectors carry public data
only. Usage: policy_e2e.py [RUN_DIR]"""
from pathlib import Path
import json, os, secrets, subprocess, sys, time
import policy_note as pn
import policy_wallet as pw

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CLIENT = ROOT / 'bench/m31-private-wrapper/client-port'
BRIDGE = ROOT / 'target/bridge-p1'
SNFORGE_ENV = dict(os.environ, ASDF_SCARB_VERSION='2.18.0', ASDF_STARKNET_FOUNDRY_VERSION='0.63.0')
sys.path.insert(0, str(ROOT / 'bench/m31-sepolia'))
os.environ.setdefault('TEMPLAR_SEPOLIA_RUN', '/nonexistent')
import wallet  # noqa: E402

CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')
POOL, TOKEN, ESCROW, P1_ADAPTER, ARBITER = 0x7e57b001, 0x7e57b0a1, 0x7e57b0e5, 0x7e57b0f1, 0xa4b1
AMOUNT_A, AMOUNT_B, DEADLINE_A, DEADLINE_B = 1000, 700, 10**7, 1


def run(cmd, log, **kw):
    with open(log, 'w') as f:
        r = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, **kw)
    assert r.returncode == 0, Path(log).read_text()[-3000:]


def escrow_class():
    out = subprocess.run(['snforge', 'test', 'print_policy_escrow_class'], cwd=HERE / 'cairo', env=SNFORGE_ENV,
                         capture_output=True, text=True, check=True).stdout
    return int(next(l for l in out.splitlines() if 'POLICY_ESCROW_CLASS' in l).split()[-1])


def prove_client(cmd, spend, out):
    """A P1 client proof through the Rust wallet, with its resource usage."""
    out.mkdir(parents=True, exist_ok=True)
    (out / 'spend.json').write_text(json.dumps(spend))
    env = dict(os.environ, RAYON_NUM_THREADS='4')
    r = subprocess.run(['/usr/bin/time', '-v', 'taskset', '-c', '0-3', str(wallet.WALLET), cmd, str(out / 'spend.json'), str(out), '16'],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr[-3000:]
    report = json.loads((out / 'report.json').read_text())
    rss = [l for l in r.stderr.splitlines() if 'Maximum resident' in l]
    report['max_rss_gib'] = int(rss[-1].split()[-1]) / 2**20
    return {k: report[k] for k in ('trace_log_size', 'blinding_rows', 'proving_seconds', 'proof_felts', 'max_rss_gib')}


def serve(client_dir, out, t, name):
    """Server side for one P1 proof: bridge validation, OS capture, PROOF2; returns the facts."""
    pin = json.loads((BRIDGE / 'build-record.json').read_text())['circuit_hash_u32_le']
    assert json.loads((client_dir / 'trusted-config.json').read_text())['circuit_hash_u32_le'] == pin, 'bridge-p1 circuit'
    run([sys.executable, str(CLIENT / 'validate_bridge_p1.py'), str(BRIDGE), str(client_dir), str(out / 'bridge')],
        out / 'bridge.log', cwd=CLIENT)
    rows = [json.loads(l) for l in (out / 'bridge.log').read_text().splitlines() if l.startswith('{')]
    t[name]['bridge'] = {'passed': sum(r['passed'] for r in rows), 'cases': len(rows), 'steps': rows[0].get('steps')}
    sierra = next((BRIDGE / 'target/contract').glob('*PolicyVerifierAccount.contract_class.json'))
    run([sys.executable, str(CLIENT / 'capture_os.py'), '--sierra', str(sierra), '--proof-dir', str(client_dir),
         '--public', str(client_dir / 'public.json'), '--output', str(out / 'os'), '--tag-version', 'P1'],
        out / 'capture.log', cwd=CLIENT)
    capture = json.loads((out / 'os/execution.json').read_text())
    t[name]['os'] = {'steps': json.loads((out / 'os/capture.json').read_text())['resources']['n_steps'],
                     'seconds': capture['elapsed_seconds'], 'exact_message': capture.get('exact_message_verified')}
    run(['bash', str(ROOT / 'bench/m31-private-wrapper/proof2-large/run.sh'), str(out / 'os/os.pie.zip'), str(out / 'proof2'), '115G'],
        out / 'proof2.log')
    p2 = json.loads((out / 'proof2/summary.json').read_text())
    assert p2['verified']
    t[name]['proof2'] = {k: p2[k] for k in ('prove_seconds', 'proof_bytes', 'verified')}
    rss = [l for l in (out / 'proof2/run.log').read_text().splitlines() if 'Maximum resident' in l]
    t[name]['proof2']['max_rss_gib'] = int(rss[-1].split()[-1]) / 2**20 if rss else None
    preimage = json.loads((out / 'proof2/output-preimage.json').read_text())
    facts = [int.from_bytes(b'PROOF2', 'big'), int.from_bytes(b'VIRTUAL_SNOS', 'big'), *[int(x, 16) for x in preimage]]
    fixture = json.loads((out / 'os/state-fixture.json').read_text())
    statement, statement_class = int(fixture['authority']['statement'], 16), int(fixture['authority']['statement_class'], 16)
    public = json.loads((client_dir / 'public.json').read_text())
    message = pn.ref.poseidon_hash_span([statement, 0, 5, statement_class, int.from_bytes(b'TMPZP1_POLICY_V1', 'big'),
                                         CHAIN, POOL, pn.binding(public)])
    assert facts[8] == message, 'facts carry the P1 statement account message for this binding'
    return facts, statement, statement_class, public


def main():
    run_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / '.local/share/templar/runs' / f'policy-e2e-{int(time.time())}'
    run_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(run_dir, 0o700)
    t = {'a': {}, 'b': {}}
    klass = escrow_class()
    # Wallets from seeds (kept in the private run directory only).
    seeds = {'depositor': secrets.token_bytes(32), 'beneficiary': secrets.token_bytes(32)}
    (run_dir / 'seeds.json').write_text(json.dumps({k: v.hex() for k, v in seeds.items()}))
    dep, ben = pw.Wallet(seeds['depositor']), pw.Wallet(seeds['beneficiary'])
    # Note A's settlement pays the beneficiary two notes (sealed to its incoming keys); note B's
    # settlement is never approved.
    def pay(w, i, amount):
        rho = pn.random_digest()
        receiver = w.receiver(i)
        words = pw.to_words(pw.seal(w.incoming(i).public_key, pw.m301(TOKEN, receiver, rho, amount)))
        return pn.out(receiver, rho, amount, pn.data_felt_delivery(words)), words
    out0, ct0 = pay(ben, 0, 600)
    out1, ct1 = pay(ben, 1, 400)
    settle_a = pn.fixed([out0, out1])
    note_a = pw.new_policy_note(dep, CHAIN, POOL, TOKEN, AMOUNT_A, ESCROW, klass, ARBITER, DEADLINE_A, [settle_a])
    out_b, _ = pay(ben, 0, AMOUNT_B)
    note_b = pw.new_policy_note(dep, CHAIN, POOL, TOKEN, AMOUNT_B, ESCROW, klass, ARBITER, DEADLINE_B, [pn.fixed([out_b])])
    # Creation by deposit: the pool computes each commitment from `inner`.
    leaves, deposits = [], []
    for n in (note_a, note_b):
        inner = wallet.inner(n['info']['receiver'], n['rho'])
        leaves.append(wallet.commitment(CHAIN, POOL, TOKEN, n['amount'], inner))
        deposits.append({'amount': n['amount'], 'inner': inner, 'ciphertext': n['creation_ciphertext']})
    data = pn.data_felt([])
    # The executor: note A's opening only (no wallet secret).
    opening = {'policy': note_a['policy'], 'cap': note_a['cap'], 'rho': note_a['rho'], 'amount': AMOUNT_A, 'position': 0,
               'ciphertexts': {'1': [ct0, ct1]}}
    (run_dir / 'executor-opening.json').write_text(json.dumps(opening))
    spend_a = pn.spend_request(CHAIN, POOL, TOKEN, leaves, opening['cap'], opening['rho'], AMOUNT_A, 0, opening['policy'], 1, 0, data)
    t['a']['client'] = prove_client('prove-policy', spend_a, run_dir / 'a/client')
    # The depositor, from the seed alone: recover note B and prove its refund.
    published = [(i, leaves[i], deposits[i]['ciphertext']) for i in range(2)]
    found = {r['index']: r for r in pw.recover(dep, CHAIN, POOL, published)}
    assert set(found) == {0, 1}, 'both notes recovered from the seed'
    r = found[1]
    assert r['policy_id'] == note_b['info']['policy_id']
    spend_b = {'chain': hex(CHAIN), 'pool': hex(POOL), 'token': hex(TOKEN), 'leaves': leaves,
               'note': {'cap': r['cap'], 'rho': r['rho'], 'amount': str(r['amount']), 'position': 1},
               'header': r['header'], 'refund': r['refund'], 'rest': r['rest'], 'data': hex(data)}
    t['b']['client'] = prove_client('prove-refund', spend_b, run_dir / 'b/client')
    # Server, per proof.
    facts_a, statement, statement_class, pub_a = serve(run_dir / 'a/client', run_dir / 'a', t, 'a')
    facts_b, statement_b, class_b, pub_b = serve(run_dir / 'b/client', run_dir / 'b', t, 'b')
    assert (statement_b, class_b) == (statement, statement_class)
    assert pub_a['index'] == 1 and pub_b['index'] == 0 and pub_b['deadline'] == DEADLINE_B
    # After both settlements: deposits (0, 1), A's two notes (2, 3), B's refund (4).
    after = leaves + [pub_a['commitments'][0], pub_a['commitments'][1], pub_b['commitments'][0]]
    published += [(2, after[2], ct0), (3, after[3], ct1), (4, after[4], r['refund_ciphertext'])]
    mine = pw.find_notes(ben, published, TOKEN)
    assert sorted((n['index'], n['amount']) for n in mine) == [(2, 600), (3, 400)]
    refund = pw.find_notes(dep, published, TOKEN)
    assert [(n['index'], n['amount']) for n in refund] == [(4, AMOUNT_B)]
    # The beneficiary spends both notes normally (R0), into one note of its own.
    change_ct = wallet.ciphertext('beneficiary')
    r0 = {'chain': hex(CHAIN), 'pool': hex(POOL), 'token': hex(TOKEN), 'leaves': after,
          'inputs': [{'sk': ben.sk(n['receiver_index']), 'rho': n['rho'], 'amount': str(n['amount']), 'position': n['index']} for n in mine],
          'outputs': [{'active': True, 'receiver': ben.receiver(0), 'rho': pn.random_digest(), 'amount': '1000',
                       'delivery': hex(wallet.delivery_digest(change_ct))},
                      {'active': False, 'receiver': [0] * 9, 'rho': [0] * 9, 'amount': '0', 'delivery': '0x0'}],
          'withdrawal': {'recipient': '0x0', 'amount': '0'}}
    rep = wallet.prove(r0, run_dir / 'beneficiary')
    t['beneficiary_r0'] = {k: rep[k] for k in ('trace_log_size', 'proving_seconds', 'max_rss_gib')}
    root_after = json.loads((run_dir / 'beneficiary/public.json').read_text())['root']
    # Cairo vectors (public data only).
    arr = lambda xs: 'array![' + ', '.join(hex(x) for x in xs) + ']'
    policy_id_a = pn.ref.poseidon_hash_span(pub_a['policy_id'])
    lines = ['// Generated by bench/m31-pool/policy_e2e.py: real P1 settlements (public data only).',
             f'pub const POOL: felt252 = {hex(POOL)};', f'pub const TOKEN: felt252 = {hex(TOKEN)};',
             f'pub const ESCROW: felt252 = {hex(ESCROW)};', f'pub const ESCROW_CLASS: felt252 = {hex(klass)};',
             f'pub const P1_ADAPTER: felt252 = {hex(P1_ADAPTER)};', f'pub const ARBITER: felt252 = {hex(ARBITER)};',
             f'pub const STATEMENT: felt252 = {hex(statement)};', f'pub const STATEMENT_CLASS: felt252 = {hex(statement_class)};',
             f'pub const OS_PROGRAM: felt252 = {hex(facts_a[2])};', f'pub const BASE_BLOCK: u64 = {max(facts_a[4], facts_b[4])};',
             f'pub const POLICY_ID_A: felt252 = {hex(policy_id_a)};', f'pub fn root_after() -> Array<felt252> {{ {arr(root_after)} }}']
    for i, d in enumerate(deposits):
        lines += [f'pub const DEPOSIT{i}_AMOUNT: u128 = {d["amount"]};',
                  f'pub fn deposit{i}_inner() -> Array<felt252> {{ {arr(d["inner"])} }}',
                  f'pub fn deposit{i}_ciphertext() -> Array<felt252> {{ {arr(d["ciphertext"])} }}']
    lines += [f'pub fn facts_a() -> Array<felt252> {{ {arr(facts_a)} }}', f'pub fn facts_b() -> Array<felt252> {{ {arr(facts_b)} }}',
              f'pub fn spend_a() -> Array<felt252> {{ {arr(pn.encode_spend(pub_a, pn.binding(pub_a)))} }}',
              f'pub fn spend_b() -> Array<felt252> {{ {arr(pn.encode_spend(pub_b, pn.binding(pub_b)))} }}',
              f'pub fn ciphertexts_a() -> Array<Span<felt252>> {{ array![{arr(ct0)}.span(), {arr(ct1)}.span()] }}',
              f'pub fn ciphertexts_b() -> Array<Span<felt252>> {{ array![{arr(r["refund_ciphertext"])}.span(), array![].span()] }}']
    (HERE / 'cairo/src/tests/policy_vectors.cairo').write_text('\n'.join(lines) + '\n')
    subprocess.run(['snforge', 'test', 'policy_real'], cwd=HERE / 'cairo', env=SNFORGE_ENV, check=True,
                   stdout=open(run_dir / 'snforge.log', 'w'), stderr=subprocess.STDOUT)
    log = (run_dir / 'snforge.log').read_text()
    t['settlement'] = [l.strip() for l in log.splitlines() if l.startswith('[PASS]') or l.startswith('[FAIL]') or 'GAS' in l]
    assert '[FAIL]' not in log and 'Tests:' in log, log[-3000:]
    t['policy_id_a'] = hex(policy_id_a)
    (HERE / 'results').mkdir(exist_ok=True)
    (HERE / 'results/policy-e2e.json').write_text(json.dumps(t, indent=1) + '\n')
    print(json.dumps(t, indent=1))
    print('run dir (private):', run_dir)


if __name__ == '__main__':
    main()
