"""The Sepolia lifecycle on the option-A pool, with real R0 client proofs wrapped in PROOF2:

  deposits  alice 600, alice 400, bob 200, alice 100
  transfer  alice (600 + 400) -> bob 700, alice 300          two outputs, batched append
  partial   bob (700 + 200) -> bob 500, withdraw 400 to 0xb0b one output + withdrawal
  full      alice (300 + 100) -> withdraw 400 to 0xa11ce     withdrawal only

Negatives reuse a valid proof: the transfer replayed (NULLIFIER_USED) and the partial
withdrawal redirected in calldata (BAD_BINDING). Wallets sync their leaves from the pool's
events. Checkpointed by stage in the private runtime; never re-signs a posted transaction."""
from sepolia import *
import proof2, wallet

D = load(RUN / 'deployment.json')
POOL, TOKEN = int(D['pool'], 16), int(D['token'], 16)
BOB_OUT, ALICE_OUT = 0xb0b, 0xa11ce
PROOF_TX_L2 = 550_000_000
W = load(RUN / 'private-wallets.json')
for w in W.values():
    w.update(wallet.keys(w['sk']))
progress = load(RUN / 'private-progress.json', {'stage': 0, 'negatives': [], 'notes': {}})


def checkpoint(stage=None):
    if stage is not None:
        progress['stage'] = stage
    save(RUN / 'private-progress.json', progress)


def balances():
    out = {}
    for k, a in [('relayer', ACCOUNT), ('pool', POOL), ('bob_out', BOB_OUT), ('alice_out', ALICE_OUT)]:
        v = call(TOKEN, 'balance_of', [a])
        out[k] = v[0] + (v[1] << 128)
    return out


def state(label, expect):
    s = {'balances': balances(), 'leaf_count': call(POOL, 'get_leaf_count')[0], 'root': call(POOL, 'get_root')[1:],
         'block': rpc('starknet_blockNumber', [])}
    assert s['balances'] == expect, (label, s['balances'], expect)
    assert sum(s['balances'].values()) == D['supply']
    save(RUN / 'results' / f'state-{label}.json', s)
    return s


def leaves():
    """The pool's commitments in index order, from its NotePublished events."""
    key = selector('NotePublished')
    events, token = [], None
    while True:
        f = {'from_block': {'block_number': D['start_block']}, 'to_block': 'latest', 'address': D['pool'], 'keys': [[key]], 'chunk_size': 200}
        if token:
            f['continuation_token'] = token
        r = rpc('starknet_getEvents', [f])
        events += r['events']
        token = r.get('continuation_token')
        if not token:
            break
    notes = {}
    for e in events:
        data = [int(x, 16) for x in e['data']]
        assert data[1] == 9
        notes[data[0]] = data[2:11]
    assert sorted(notes) == list(range(len(notes))), 'gap in the event history'
    assert len(notes) == call(POOL, 'get_leaf_count')[0]
    return [notes[i] for i in range(len(notes))]


def new_note(name, owner, amount):
    """A note for `owner`: random rho, commitment as the pool computes it."""
    if name not in progress['notes']:
        rho = wallet.random_digest()
        inner = wallet.inner(W[owner]['receiver'], rho)
        progress['notes'][name] = {'owner': owner, 'rho': rho, 'amount': amount, 'inner': inner,
                                   'cm': wallet.commitment(CHAIN, POOL, TOKEN, amount, inner),
                                   'ciphertext': wallet.ciphertext(name)}
        checkpoint()
    return progress['notes'][name]


def deposit(name, owner, amount):
    n = new_note(name, owner, amount)
    invoke('deposit-' + name, POOL, 'deposit', [TOKEN, amount, 9, *n['inner'], 10, *n['ciphertext']], 300_000_000, HERE)
    r = load(RUN / 'steps' / ('deposit-' + name) / 'receipt.json')
    key = int(selector('NotePublished'), 16)
    published = [[int(x, 16) for x in e['data']] for e in r['events'] if int(e['from_address'], 16) == POOL and int(e['keys'][0], 16) == key]
    assert len(published) == 1 and published[0][2:11] == n['cm'], 'on-chain commitment differs from the wallet'


def spend(name, ins, outs, withdrawal=(0, 0)):
    """Prove (client), wrap (server) and return the case: public statement and pool calldata."""
    folder = RUN / 'cases' / name
    case = load(folder / 'case.json')
    if case:
        return case
    ls = leaves()
    notes = [progress['notes'][i] for i in ins]
    out_notes = [new_note(o, owner, amount) if o else None for o, owner, amount in outs]
    body = {'chain': hex(CHAIN), 'pool': hex(POOL), 'token': hex(TOKEN), 'leaves': ls,
            'inputs': [{'sk': W[n['owner']]['sk'], 'rho': n['rho'], 'amount': str(n['amount']), 'position': ls.index(n['cm'])} for n in notes],
            'outputs': [{'active': True, 'receiver': W[n['owner']]['receiver'], 'rho': n['rho'], 'amount': str(n['amount']),
                         'delivery': hex(wallet.delivery_digest(n['ciphertext']))} if n else
                        {'active': False, 'receiver': [0] * 9, 'rho': [0] * 9, 'amount': '0', 'delivery': '0x0'} for n in out_notes],
            'withdrawal': {'recipient': hex(withdrawal[0]), 'amount': str(withdrawal[1])}}
    client = wallet.prove(body, folder / 'client')
    public = load(folder / 'client/public.json')
    for n, cm in zip(out_notes, public['commitments']):
        assert (cm == n['cm']) if n else cm == [0] * 9
    server = proof2.serve(folder / 'client', folder / 'server', D)
    calldata = [CHAIN, POOL, TOKEN, 9, *public['root'], 18, *public['nullifiers'][0], *public['nullifiers'][1], 2]
    for n, cm in zip(out_notes, public['commitments']):
        calldata += [9, *cm, *([10, *n['ciphertext']] if n else [0])]
    calldata += [int(public['withdrawal_recipient'], 16), int(public['withdrawal_amount']), int(server['binding'], 16), 0]
    case = {'name': name, 'public': public, 'calldata': calldata, 'server': server,
            'client': {k: client[k] for k in client if k in ('trace_log_size', 'blinding_rows', 'revealed_fri_values', 'proving_seconds', 'build_seconds', 'proof_felts', 'max_rss_gib')}}
    save(folder / 'case.json', case)
    return case


def submit(case, name=None, calldata=None, expected='SUCCEEDED', reason=None):
    folder = RUN / 'cases' / case['name'] / 'server'
    # The sequencer reads the base block's hash from its stored window: 10 blocks behind the head.
    while rpc('starknet_blockNumber', []) < case['server']['base_block'] + 11:
        time.sleep(3)
    return proof_invoke(name or case['name'], POOL, 'apply_spend', calldata or case['calldata'], folder, PROOF_TX_L2, HERE,
                        expected=expected, reason=reason)


def negative(name, case, calldata, reason, spent):
    if name in progress['negatives']:
        return
    before = state('before-' + name, balances())
    submit(case, name, calldata, 'REVERTED', reason)
    after = balances()
    assert after == before['balances'] and call(POOL, 'get_leaf_count')[0] == before['leaf_count']
    for nf in case['public']['nullifiers']:
        assert call(POOL, 'get_nullifier_spent', [9, *nf]) == [int(spent)]
    save(RUN / 'results' / f'negative-{name}.json', {'expected_revert': reason, 'state_unchanged': True})
    progress['negatives'].append(name)
    checkpoint()


S = D['supply']
if progress['stage'] == 0:
    for name, owner, amount in [('a600', 'alice', 600), ('a400', 'alice', 400), ('b200', 'bob', 200), ('a100', 'alice', 100)]:
        deposit(name, owner, amount)
    state('funded', {'relayer': S - 1300, 'pool': 1300, 'bob_out': 0, 'alice_out': 0})
    checkpoint(1)
if progress['stage'] == 1:
    print('transfer: alice -> bob 700, change 300', flush=True)
    c = spend('transfer', ['a600', 'a400'], [('b700', 'bob', 700), ('a300', 'alice', 300)])
    try:
        submit(c)
    except RuntimeError as e:
        save(RUN / 'results/first-proof-tx-error.json', {'error': str(e)})
        raise
    s = state('transfer', {'relayer': S - 1300, 'pool': 1300, 'bob_out': 0, 'alice_out': 0})
    assert s['leaf_count'] == 6
    negative('replay-transfer', c, c['calldata'], 'NULLIFIER_USED', True)
    checkpoint(2)
if progress['stage'] == 2:
    print('partial withdrawal: bob -> change 500, 400 to 0xb0b', flush=True)
    c = spend('partial', ['b700', 'b200'], [('b500', 'bob', 500), (None, None, 0)], (BOB_OUT, 400))
    redirected = list(c['calldata'])
    at = redirected.index(BOB_OUT, len(redirected) - 4)
    redirected[at] = BOB_OUT + 1
    negative('redirected-withdrawal', c, redirected, 'BAD_BINDING', False)
    submit(c)
    s = state('partial', {'relayer': S - 1300, 'pool': 900, 'bob_out': 400, 'alice_out': 0})
    assert s['leaf_count'] == 7
    checkpoint(3)
if progress['stage'] == 3:
    print('full withdrawal: alice 300 + 100 -> 400 to 0xa11ce', flush=True)
    c = spend('full', ['a300', 'a100'], [(None, None, 0), (None, None, 0)], (ALICE_OUT, 400))
    submit(c)
    s = state('final', {'relayer': S - 1300, 'pool': 500, 'bob_out': 400, 'alice_out': 400})
    assert s['leaf_count'] == 7
    checkpoint(4)

summary = {'status': 'PASS', 'deployment': D, 'negatives': progress['negatives'], 'cases': {}, 'transactions': {}}
for name in ['transfer', 'partial', 'full']:
    case = load(RUN / 'cases' / name / 'case.json')
    summary['cases'][name] = {'client': case['client'], 'server': case['server']}
for step in sorted((RUN / 'steps').glob('*/receipt.json')):
    r = load(step)
    summary['transactions'][step.parent.name] = {k: r.get(k) for k in ('transaction_hash', 'execution_status', 'block_number',
                                                                         'actual_fee', 'execution_resources', 'revert_reason')}
save(RUN / 'results/summary.json', summary)
print('M31 POOL SEPOLIA RUN PASS', flush=True)
