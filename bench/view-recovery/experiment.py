"""Local payment model, independent Cairo witnesses, and discovery measurements."""
import copy
import json
import platform
import statistics
import time
import nacl
from protocol import *
from recovery import Archive, TrustedCheckpoint, recover

RESULTS = ROOT / 'results'

def save_case(name, case, error=None):
    (RESULTS / f'{name}.args.json').write_text(json.dumps([hex(x) for x in [len(case['witness']), *case['witness']]]) + '\n')
    (RESULTS / f'{name}.public.json').write_text(json.dumps(case['public']) + '\n')
    return {'name': name, 'expected_error': error, 'public': case['public']}

def run():
    RESULTS.mkdir(exist_ok=True)
    # Only deterministic, explicitly public fixture keys. Never use these wallets.
    seeds = {name: hashlib.sha256(('PUBLIC TEST FIXTURE '+name).encode()).digest() for name in ['Alice','Bob','Carol','Dave']}
    wallets = {name: Wallet.restore(seed) for name, seed in seeds.items()}
    alice, bob, carol, dave = [wallets[name] for name in seeds]
    bob_address = bob.address
    del bob, wallets['Bob']  # Bob is absent throughout both incoming payments.
    ledger = Ledger()
    an, ae = send(alice.address, TOKEN, 1000)
    cn, ce = send(carol.address, TOKEN, 500)
    ai, ci = ledger.fund(an, ae), ledger.fund(cn, ce)
    cases = []
    bp1 = send(bob_address, TOKEN, 600)
    ac = send(alice.address, TOKEN, 400)
    case_a = make_case([(an, alice.spend_key, ai)], [bp1, ac], [], ledger.tree)
    cases.append(save_case('alice-send', case_a))
    bi1, _ = ledger.apply(case_a, [bp1[1], ac[1]])
    bp2 = send(bob_address, TOKEN, 250)
    cc = send(carol.address, TOKEN, 250)
    case_c = make_case([(cn, carol.spend_key, ci)], [bp2, cc], [], ledger.tree)
    cases.append(save_case('carol-send', case_c))
    bi2, _ = ledger.apply(case_c, [bp2[1], cc[1]])

    bob = Wallet.restore(seeds['Bob'])
    recovered = bob.view.scan(ledger.events)
    assert set(recovered) == {bi1, bi2}
    assert sum(n.amount for n in recovered.values()) == 850
    inputs = [(recovered[bi1], bob.spend_key, bi1),
              (recovered[bi2], bob.spend_key, bi2)]
    to_dave = send(dave.address, TOKEN, 500)
    change = send(bob.address, TOKEN, 310)
    out = [to_dave, change]
    withdrawals = [(0x9876, 40)]
    case_b = make_case(inputs, out, withdrawals, ledger.tree)
    validate_case(case_b)
    cases.append(save_case('bob-spend', case_b))
    def negative(name, offset, value, error):
        c = copy.deepcopy(case_b)
        c['witness'][offset] = value
        cases.append(save_case(name, c, error))
    negative('sender-key', 9, alice.spend_key, 'MEMBERSHIP')
    negative('view-key', 9, int.from_bytes(bob.view.decryption_key, 'big') % P, 'MEMBERSHIP')
    negative('full-view-authority-key', 9, bob.full_view.authority, 'MEMBERSHIP')
    negative('full-view-nullifier-key', 9, bob.full_view.nullifier_secret, 'MEMBERSHIP')
    negative('old-protocol-version', 0, tag('TEMPLAR_PUSH_POC1'), 'VERSION')
    negative('bad-path', 14, (case_b['witness'][14]+1) % P, 'MEMBERSHIP')
    negative('bad-nullifier', 12, (case_b['witness'][12]+1) % P, 'NULLIFIER')
    negative('bad-amount-range', 11, 2**128, 'AMOUNT_RANGE')
    negative('zero-rho', 10, 0, 'ZERO_NOTE')
    negative('redirect-withdrawal', len(case_b['witness'])-2, 0x9877, 'BINDING')
    negative('zero-withdrawal-address', len(case_b['witness'])-2, 0, 'RECIPIENT')
    negative('out-of-range-withdrawal-address', len(case_b['witness'])-2, 2**251, 'RECIPIENT')
    negative('replace-delivery', 9+37*2+4, (case_b['witness'][9+37*2+4]+1) % P, 'BINDING')
    negative('wrong-output-owner', 9+37*2, alice.address.receiver, 'OUTPUT')
    # Even rebinding the complete public statement cannot select a different nf.
    c = copy.deepcopy(case_b)
    c['nullifiers'][0] = (c['nullifiers'][0]+1) % P
    c['witness'][12] = c['nullifiers'][0]
    c['witness'][5] = binding(CHAIN,POOL,ledger.tree.root(),TOKEN,
                             c['nullifiers'],c['outputs'],c['withdrawals'])
    c['public'][-1] = c['witness'][5]
    cases.append(save_case('rebound-false-nullifier',c,'NULLIFIER'))
    c = copy.deepcopy(case_b)
    c['witness'][46:83] = c['witness'][9:46]
    cases.append(save_case('duplicate-input', c, 'DUPLICATE_INPUT'))
    inflated = send(dave.address, TOKEN, 501)
    c = make_case(inputs, [inflated, change], withdrawals, ledger.tree)
    cases.append(save_case('inflation', c, 'CONSERVATION'))
    clone_tree = Tree()
    first = clone_tree.insert(bp1[0].commitment)
    second = clone_tree.insert(bp1[0].commitment)
    clones = make_case([(bp1[0],bob.spend_key,first),(bp1[0],bob.spend_key,second)],
                       [],[(0x9876,1200)],clone_tree)
    validate_case(clones)
    cases.append(save_case('funded-duplicate-commitments',clones))

    # Delivery replacement is rejected before any local state mutation.
    before = (ledger.tree.root(), ledger.spent.copy(), len(ledger.events))
    try:
        ledger.apply(case_b, [change[1], to_dave[1]])
        raise AssertionError('swapped deliveries accepted')
    except ValueError as e:
        assert 'delivery' in str(e)
    assert before == (ledger.tree.root(), ledger.spent, len(ledger.events))
    ledger.apply(case_b, [to_dave[1], change[1]])
    try:
        ledger.apply(case_b, [to_dave[1], change[1]])
        raise AssertionError('replay accepted')
    except ValueError as e:
        assert 'replay' in str(e)
    def balance(wallet):
        return sum(n.amount for index, n in wallet.view.scan(ledger.events).items()
                   if n.nullifier(wallet.spend_key, index) not in ledger.spent)
    final = {name: balance(wallet) for name, wallet in [('Alice',alice),('Bob',bob),('Carol',carol),('Dave',dave)]}
    assert final == {'Alice':400, 'Bob':310, 'Carol':250, 'Dave':500}
    assert sum(final.values()) + 40 == 1500

    checkpoint = TrustedCheckpoint.from_model(ledger,bob.address,101,'public-fixture-block-101')
    archive = Archive(checkpoint.block_hash,tuple(ledger.events))
    viewer = FullView.load(bob.full_view.export(),expected_address=bob.address)
    watched = recover(viewer,archive,checkpoint)
    incoming = recover(bob.view,archive,checkpoint)
    assert incoming.received_totals == {TOKEN:1160} and incoming.balances is None
    assert watched.balances == {TOKEN:310}
    del bob
    restored = Wallet.restore(seeds['Bob'])
    recovered_wallet = recover(restored.full_view,archive,checkpoint)
    assert recovered_wallet.balances == watched.balances
    unspent = [(n,restored.spend_key,index) for index,n in recovered_wallet.notes.items()
               if index not in recovered_wallet.spent_indices]
    restored_spend = make_case(unspent,[],[(0x9876,310)],recovered_wallet.tree)
    validate_case(restored_spend)
    cases.append(save_case('restored-owner-spend',restored_spend))
    ledger.apply(restored_spend,[])
    after_checkpoint = TrustedCheckpoint.from_model(ledger,restored.address,102,'public-fixture-block-102')
    after = recover(viewer,Archive(after_checkpoint.block_hash,tuple(ledger.events)),after_checkpoint)
    assert after.balances == {TOKEN:0}
    recovery_summary = {'incoming':incoming.summary(),'full_view':watched.summary(),
                        'seed_restore':recovered_wallet.summary(),
                        'after_restored_owner_spend':after.summary(),
                        'total_withdrawn_after_restored_spend':350}

    # Pre-created, distinct other-recipient ciphertexts; no sender work timed in scan.
    other_box = SealedBox(PublicKey(alice.address.encryption_key))
    decoys = [Event(1, other_box.encrypt(bytes(256)), 1, i+100) for i in range(9998)]
    events = decoys[:3000] + [replace(bp1[1], index=bi1)] + decoys[3000:] + [replace(bp2[1], index=bi2)]
    elapsed = []
    for _ in range(3):
        start = time.perf_counter()
        found = restored.view.scan(events)
        elapsed.append(time.perf_counter()-start)
        assert len(found) == 2
    public_events = [{'index':e.index,'commitment':hex(e.commitment),'digest':hex(e.digest),'ciphertext':e.ciphertext.hex()} for e in ledger.events]
    (RESULTS/'public-events.json').write_text(json.dumps(public_events,indent=2)+'\n')
    summary = {'scope':'local state model + Cairo execution; not a deployed pool',
      'python':platform.python_version(),'pynacl':nacl.__version__,
      'payments_received_offline':2,'recovered_amount':850,'final_balances':final,
      'withdrawn':40,'plaintext_bytes':256,'ciphertext_bytes_per_note':304,
      'recovery':recovery_summary,
      'discovery':{'events':10000,'matching':2,'seconds':elapsed,'median_seconds':statistics.median(elapsed),
                   'ciphertext_download_bytes':3040000,'includes_network':False,'consumer_hardware':False},
      'replay_rejected':True,'swapped_delivery_rejected_before_state_change':True,
      'cases':cases,'keys_are_public_test_fixtures':True}
    (RESULTS/'experiment.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='cases'},indent=2))

if __name__ == '__main__':
    run()
