"""Local end to end for hidden-asset spends and ERC721/ERC1155 notes, with real proofs
(`docs/hidden-asset-spec.md`):

  deposits: Alice's ERC20 note (pull), Alice's ERC721 note (push), and an ERC1155 escrow policy
    note (push with a policy `inner`) whose release withdraws 300 units to a fixed recipient
  S1  R0 V4, pure transfer: Alice pays Bob 600 of her 1000 ERC20 (one input + dummy); no asset
      published
  S2  R0 V4, pure transfer: Alice gives Bob the NFT (one input + dummy, one output + dummy output)
  S3  P1: the arbiter approves the ERC1155 escrow release; the executor settles it and the pool
      pays 300 units out by ERC1155 safe transfer
  S4  R0 V4, exit: Bob finds the NFT by trial decryption and withdraws it (asset published)
    -> each proof: bridge check, virtual-OS capture, large proof (PROOF2)
    -> Cairo vectors for `tests/test_hidden_asset_e2e.cairo`, which deploys pool V2, the tokens,
       adapters and escrow at the committed addresses, replays the deposits and settles all four
       with the real proof facts; the pool's tree must end at the wallets' root.

Secrets stay in a private run directory; the vectors carry public data only.
Usage: hidden_asset_e2e.py [RUN_DIR] | hidden_asset_e2e.py --summarize RUN_DIR"""
from pathlib import Path
import json, os, secrets, subprocess, sys, time
import hidden_asset as ha
import policy_note as pn
import policy_wallet as pw
import policy_e2e as pe

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CLIENT = ROOT / 'bench/m31-private-wrapper/client-port'
BRIDGES = {'R4': ROOT / 'target/bridge-r4', 'P1': ROOT / 'target/bridge-p1'}
ACCOUNTS = {'R4': ('PaymentVerifierAccount', 'TMPZR0_PAYMENT_V4'), 'P1': ('PolicyVerifierAccount', 'TMPZP1_POLICY_V1')}
wallet = pe.wallet

CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')
POOL, ERC20_TOKEN, NFT, MULTI = 0x7e57b201, 0x7e57b2a1, 0x7e57b2a2, 0x7e57b2a3
ESCROW, R4_ADAPTER, P1_ADAPTER, ACCOUNT = 0x7e57b2e5, 0x7e57b2f0, 0x7e57b2f1, 0x7e57b2c0
ARBITER, NFT_RECIPIENT = 0xa4b1, 0xb0b
NFT_ID, MULTI_ID, ERC20_AMOUNT, MULTI_AMOUNT, DEADLINE = 2, 7, 1000, 300, 10**7


def serve(kind, client_dir, out, t, name):
    """Server side for one proof: bridge check, OS capture, large proof; returns the facts and
    the statement account's address and class."""
    bridge = BRIDGES[kind]
    pin = json.loads((bridge / 'build-record.json').read_text())['circuit_hash_u32_le']
    assert json.loads((client_dir / 'trusted-config.json').read_text())['circuit_hash_u32_le'] == pin, f'{kind} circuit'
    if kind == 'R4':
        pe.run([sys.executable, str(CLIENT / 'validate_bridge_r4.py'), '--one', str(bridge), str(client_dir), str(out / 'bridge')],
               out / 'bridge.log', cwd=CLIENT)
    else:
        pe.run([sys.executable, str(CLIENT / 'validate_bridge_p1.py'), str(bridge), str(client_dir), str(out / 'bridge')],
               out / 'bridge.log', cwd=CLIENT)
    rows = [json.loads(l) for l in (out / 'bridge.log').read_text().splitlines() if l.startswith('{')]
    assert rows and all(r['passed'] for r in rows)
    t[name]['bridge'] = {'passed': len(rows), 'steps': rows[0].get('steps')}
    account, tag = ACCOUNTS[kind]
    sierra = next((bridge / 'target/contract').glob(f'*{account}.contract_class.json'))
    pe.run([sys.executable, str(CLIENT / 'capture_os.py'), '--sierra', str(sierra), '--proof-dir', str(client_dir),
            '--public', str(client_dir / 'public.json'), '--output', str(out / 'os'), '--tag-version', kind],
           out / 'capture.log', cwd=CLIENT)
    capture = json.loads((out / 'os/execution.json').read_text())
    t[name]['os'] = {'steps': json.loads((out / 'os/capture.json').read_text())['resources']['n_steps'],
                     'seconds': capture['elapsed_seconds'], 'exact_message': capture.get('exact_message_verified')}
    pe.run(['bash', str(ROOT / 'bench/m31-private-wrapper/proof2-large/run.sh'), str(out / 'os/os.pie.zip'), str(out / 'proof2'), '115G'],
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
    bind = ha.binding(public) if kind == 'R4' else pn.binding(public)
    message = pn.ref.poseidon_hash_span([statement, 0, 5, statement_class, int.from_bytes(tag.encode(), 'big'), CHAIN, POOL, bind])
    assert facts[8] == message, f'{name}: facts carry the statement account message for this binding'
    return facts, statement, statement_class, public


def summarize(run_dir):
    """The public results of a run, read back from its directory (client, bridge, OS and large
    proof reports, and the settlement gas from the snforge log)."""
    t = {'note': 'S1 and S2 are both hidden-asset transfers; their gas differs (55.2M vs 53.7M) with the tree '
                 'position of the appended pair, not with the asset. S3 appends no note (a withdrawal-only outcome).'}
    for n in ('s1', 's2', 's3', 's4'):
        d = {}
        rep = json.loads((run_dir / n / 'client/report.json').read_text())
        d['client'] = {k: rep[k] for k in ('trace_log_size', 'proving_seconds', 'proof_felts')}
        rows = [json.loads(l) for l in (run_dir / n / 'bridge.log').read_text().splitlines() if l.startswith('{')]
        d['bridge'] = {'cases': len(rows), 'passed': sum(r['passed'] for r in rows), 'steps': rows[0].get('steps')}
        capture = json.loads((run_dir / n / 'os/execution.json').read_text())
        d['os'] = {'steps': json.loads((run_dir / n / 'os/capture.json').read_text())['resources']['n_steps'],
                   'seconds': capture['elapsed_seconds'], 'exact_message': capture.get('exact_message_verified')}
        p2 = json.loads((run_dir / n / 'proof2/summary.json').read_text())
        rss = [l for l in (run_dir / n / 'proof2/run.log').read_text().splitlines() if 'Maximum resident' in l]
        d['proof2'] = {'prove_seconds': p2['prove_seconds'], 'proof_bytes': p2['proof_bytes'], 'verified': p2['verified'],
                       'max_rss_gib': round(int(rss[-1].split()[-1]) / 2**20, 1)}
        t[n] = d
    log = (run_dir / 'snforge.log').read_text()
    t['settlement_gas'] = {l.split('GAS ')[1].split('=')[0]: int(l.split('=')[-1]) for l in log.splitlines() if l.startswith('GAS apply')}
    t['settlement'] = [l.strip() for l in log.splitlines() if l.startswith('[PASS]') or l.startswith('[FAIL]')]
    return t


def main():
    if len(sys.argv) > 2 and sys.argv[1] == '--summarize':
        (HERE / 'results/hidden-asset-e2e.json').write_text(json.dumps(summarize(Path(sys.argv[2])), indent=1) + '\n')
        return
    run_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / '.local/share/templar/runs' / f'hidden-asset-e2e-{int(time.time())}'
    run_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(run_dir, 0o700)
    t = {k: {} for k in ('s1', 's2', 's3', 's4')}
    klass = pe.escrow_class()
    seeds = {k: secrets.token_bytes(32) for k in ('alice', 'bob', 'depositor')}
    (run_dir / 'seeds.json').write_text(json.dumps({k: v.hex() for k, v in seeds.items()}))
    alice, bob, dep = (pw.Wallet(seeds[k]) for k in ('alice', 'bob', 'depositor'))
    nft_asset = ha.asset_id(ha.ERC721, NFT, NFT_ID)
    multi_asset = ha.asset_id(ha.ERC1155, MULTI, MULTI_ID)

    # ---- deposits: leaves 0 (ERC20), 1 (ERC721), 2 (ERC1155 escrow policy note)
    rho0, rho1 = pn.random_digest(), pn.random_digest()
    inner0, inner1 = wallet.inner(alice.receiver(0), rho0), wallet.inner(alice.receiver(1), rho1)
    ct0 = pw.to_words(pw.seal(alice.incoming(0).public_key, pw.m301(ERC20_TOKEN, alice.receiver(0), rho0, ERC20_AMOUNT)))
    ct1 = pw.to_words(pw.seal(alice.incoming(1).public_key, pw.m301(nft_asset, alice.receiver(1), rho1, 1)))
    release = pn.fixed([], withdrawal=(ACCOUNT, MULTI_AMOUNT))
    escrow_note = pw.new_policy_note(dep, CHAIN, POOL, multi_asset, MULTI_AMOUNT, ESCROW, klass, ARBITER, DEADLINE, [release])
    inner2 = wallet.inner(escrow_note['info']['receiver'], escrow_note['rho'])
    ct2 = escrow_note['creation_ciphertext']
    leaves = [wallet.commitment(CHAIN, POOL, ERC20_TOKEN, ERC20_AMOUNT, inner0),
              wallet.commitment(CHAIN, POOL, nft_asset, 1, inner1),
              wallet.commitment(CHAIN, POOL, multi_asset, MULTI_AMOUNT, inner2)]
    published = [(0, leaves[0], ct0), (1, leaves[1], ct1), (2, leaves[2], ct2)]
    mine = {n['index']: n for n in ha.find_notes(alice, CHAIN, POOL, published)}
    assert mine[0]['asset'] == ERC20_TOKEN and mine[1]['asset'] == nft_asset, 'Alice finds both notes and their assets'
    no_withdrawal = {'recipient': '0x0', 'amount': '0'}
    ciphertexts = {}

    def spend4(name, inputs, outputs, withdrawal, asset):
        spend = {'chain': hex(CHAIN), 'pool': hex(POOL), 'token': hex(asset), 'leaves': list(leaves), 'inputs': inputs,
                 'outputs': [o for o, _ in outputs], 'withdrawal': withdrawal}
        t[name]['client'] = ha.prove4(spend, run_dir / name / 'client')
        pub = json.loads((run_dir / name / 'client/public.json').read_text())
        ciphertexts[name] = [ct for _, ct in outputs]
        for cm, ct in zip(pub['commitments'], ciphertexts[name]):
            published.append((len(leaves), cm, ct))
            leaves.append(cm)
        return pub

    # ---- S1: Alice pays Bob 600 of 1000 ERC20; one input + dummy; the asset stays hidden.
    pay, pay_ct = ha.output_to(bob, 0, ERC20_TOKEN, 600)
    change, change_ct = ha.output_to(alice, 2, ERC20_TOKEN, 400)
    a0 = mine[0]
    pub1 = spend4('s1', [{'sk': alice.sk(0), 'rho': a0['rho'], 'amount': str(ERC20_AMOUNT), 'position': 0}],
                  [(pay, pay_ct), (change, change_ct)], no_withdrawal, ERC20_TOKEN)
    assert pub1['token_out'] == '0x0'
    # ---- S2: Alice gives Bob the NFT; one output + a dummy output; hidden.
    gift, gift_ct = ha.output_to(bob, 1, nft_asset, 1)
    pub2 = spend4('s2', [{'sk': alice.sk(1), 'rho': mine[1]['rho'], 'amount': '1', 'position': 1}],
                  [(gift, gift_ct), ha.dummy_output()], no_withdrawal, nft_asset)
    assert pub2['token_out'] == '0x0'
    # ---- S3: the ERC1155 escrow release (P1), proved by an executor holding the opening.
    data = pn.data_felt([])
    s3 = pn.spend_request(CHAIN, POOL, multi_asset, list(leaves), escrow_note['cap'], escrow_note['rho'], MULTI_AMOUNT, 2,
                          escrow_note['policy'], 1, 0, data)
    t['s3']['client'] = pe.prove_client('prove-policy', s3, run_dir / 's3/client')
    # ---- S4: Bob finds the NFT by trial decryption and withdraws it; two dummy outputs.
    bobs = {n['index']: n for n in ha.find_notes(bob, CHAIN, POOL, published)}
    assert sorted((i, n['asset'], n['amount']) for i, n in bobs.items()) == [(3, ERC20_TOKEN, 600), (5, nft_asset, 1)]
    n = bobs[5]
    pub4 = spend4('s4', [{'sk': bob.sk(n['receiver_index']), 'rho': n['rho'], 'amount': '1', 'position': 5}],
                  [ha.dummy_output(), ha.dummy_output()], {'recipient': hex(NFT_RECIPIENT), 'amount': '1'}, nft_asset)
    assert int(pub4['token_out'], 16) == nft_asset

    # ---- server, per proof
    facts, accounts = {}, {}
    for name, kind in (('s1', 'R4'), ('s2', 'R4'), ('s3', 'P1'), ('s4', 'R4')):
        f, statement, statement_class, pub = serve(kind, run_dir / name / 'client', run_dir / name, t, name)
        facts[name] = f
        accounts.setdefault(kind, (statement, statement_class))
        assert accounts[kind] == (statement, statement_class)
    pub3 = json.loads((run_dir / 's3/client/public.json').read_text())
    assert pub3['index'] == 1 and int(pub3['withdrawal_amount']) == MULTI_AMOUNT

    # ---- the final tree, as the wallets see it (S4's outputs appended)
    root_after = pn.run('root', json.dumps(leaves))
    # ---- Cairo vectors (public data only)
    arr = lambda xs: 'array![' + ', '.join(hex(x) for x in xs) + ']'
    osp = facts['s1'][2]
    lines = ['// Generated by bench/m31-pool/hidden_asset_e2e.py: real R0 V4 and P1 settlements (public data only).',
             *(f'pub const {k}: felt252 = {hex(v)};' for k, v in (
                 ('POOL', POOL), ('ERC20_TOKEN', ERC20_TOKEN), ('NFT', NFT), ('MULTI', MULTI), ('ESCROW', ESCROW),
                 ('ESCROW_CLASS', klass), ('R4_ADAPTER', R4_ADAPTER), ('P1_ADAPTER', P1_ADAPTER), ('ACCOUNT', ACCOUNT),
                 ('ARBITER', ARBITER), ('NFT_RECIPIENT', NFT_RECIPIENT), ('NFT_ASSET', nft_asset), ('MULTI_ASSET', multi_asset),
                 ('R4_STATEMENT', accounts['R4'][0]), ('R4_STATEMENT_CLASS', accounts['R4'][1]),
                 ('P1_STATEMENT', accounts['P1'][0]), ('P1_STATEMENT_CLASS', accounts['P1'][1]), ('OS_PROGRAM', osp),
                 ('POLICY_ID', pn.ref.poseidon_hash_span(pub3['policy_id'])))),
             f'pub const NFT_ID: u256 = {NFT_ID};', f'pub const MULTI_ID: u256 = {MULTI_ID};',
             f'pub const ERC20_AMOUNT: u128 = {ERC20_AMOUNT};', f'pub const MULTI_AMOUNT: u128 = {MULTI_AMOUNT};',
             f'pub const BASE_BLOCK: u64 = {max(f[4] for f in facts.values())};',
             f'pub fn deposit0_inner() -> Array<felt252> {{ {arr(inner0)} }}', f'pub fn deposit0_ciphertext() -> Array<felt252> {{ {arr(ct0)} }}',
             f'pub fn nft_hook_data() -> Array<felt252> {{ {arr(ha.hook_data(inner1, ct1))} }}',
             f'pub fn multi_hook_data() -> Array<felt252> {{ {arr(ha.hook_data(inner2, ct2))} }}']
    for name in ('s1', 's2', 's4'):
        pub = json.loads((run_dir / name / 'client/public.json').read_text())
        lines += [f'pub fn facts_{name}() -> Array<felt252> {{ {arr(facts[name])} }}',
                  f'pub fn spend_{name}() -> Array<felt252> {{ {arr(ha.encode_spend(pub, ciphertexts[name]))} }}']
    lines += [f'pub fn facts_s3() -> Array<felt252> {{ {arr(facts["s3"])} }}',
              f'pub fn spend_s3() -> Array<felt252> {{ {arr(pn.encode_spend(pub3, pn.binding(pub3)))} }}',
              f'pub fn root_after() -> Array<felt252> {{ {arr(root_after)} }}', f'pub const LEAVES_AFTER: u64 = {len(leaves)};']
    (HERE / 'cairo/src/tests/hidden_asset_vectors.cairo').write_text('\n'.join(lines) + '\n')
    subprocess.run(['snforge', 'test', 'hidden_asset_real'], cwd=HERE / 'cairo', env=pe.SNFORGE_ENV, check=False,
                   stdout=open(run_dir / 'snforge.log', 'w'), stderr=subprocess.STDOUT)
    log = (run_dir / 'snforge.log').read_text()
    assert '[FAIL]' not in log and 'Tests:' in log, log[-3000:]
    (HERE / 'results').mkdir(exist_ok=True)
    summary = summarize(run_dir)
    (HERE / 'results/hidden-asset-e2e.json').write_text(json.dumps(summary, indent=1) + '\n')
    print(json.dumps(summary, indent=1))
    print('run dir (private):', run_dir)


if __name__ == '__main__':
    main()
