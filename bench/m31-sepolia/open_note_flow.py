"""Open notes on Sepolia (R0 V3, compact client proofs wrapped as PROOF2):

  deposits  alice 600 and 400 of token A (the pool token)
  swap      alice (600 + 400) -> change 700 of A, plus 300 of A through upstream's unchanged
            Ekubo anonymizer and the live Ekubo router into one open note of token B

The wallet proves from the pool's events, binding the execution intent; the server executes
the statement account in the virtual OS on live Sepolia state and proves PROOF2; the relayer
submits `apply_spend_with_invoke` to the gateway. While the gateway rejects PROOF2, the exact
signed transaction is simulated with validation against live state (Ekubo included) and the
settlement recorded from the trace. Checkpointed in the private runtime."""
from sepolia import *
import proof2, wallet
sys_path = str(ROOT / 'bench/m31-pool')
import sys
sys.path.insert(0, sys_path)
import open_note as on  # noqa: E402

D = load(RUN / 'deployment.json')
POOL, TOKEN_A, TOKEN_B = int(D['pool'], 16), int(D['token'], 16), int(D['token_b'], 16)
ANON, ROUTER = int(D['anonymizer'], 16), int(D['ekubo_router'], 16)
BUDGET, MINIMUM = 300, 280
PROOF_TX_L2 = 550_000_000
W = load(RUN / 'private-wallets.json')
alice = W['alice']
alice.update(wallet.keys(alice['sk']))
progress = load(RUN / 'private-progress.json', {'stage': 0, 'notes': {}})


def checkpoint(stage=None):
    if stage is not None:
        progress['stage'] = stage
    save(RUN / 'private-progress.json', progress)


def leaves():
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
        notes[data[0]] = data[2:11]
    assert sorted(notes) == list(range(len(notes))) and len(notes) == call(POOL, 'get_leaf_count')[0]
    return [notes[i] for i in range(len(notes))]


def note(name, amount, token=None):
    if name not in progress['notes']:
        rho = wallet.random_digest()
        inner = wallet.inner(alice['receiver'], rho)
        progress['notes'][name] = {'rho': rho, 'amount': amount, 'inner': inner, 'ciphertext': wallet.ciphertext(name),
                                   'cm': wallet.commitment(CHAIN, POOL, token or TOKEN_A, amount, inner) if amount else None}
        checkpoint()
    return progress['notes'][name]


if progress['stage'] == 0:
    key = int(selector('NotePublished'), 16)
    for name, amount in [('a600', 600), ('a400', 400)]:
        n = note(name, amount)
        invoke('deposit-' + name, POOL, 'deposit', [TOKEN_A, amount, 9, *n['inner'], 10, *n['ciphertext']], 150_000_000, HERE)
        r = load(RUN / 'steps' / ('deposit-' + name) / 'receipt.json')
        published = [[int(x, 16) for x in e['data']] for e in r['events'] if int(e['from_address'], 16) == POOL and int(e['keys'][0], 16) == key]
        assert len(published) == 1 and published[0][2:11] == n['cm'], 'on-chain commitment differs from the wallet'
    checkpoint(1)

if progress['stage'] == 1:
    print('open-note swap: 300 A -> B through Ekubo, change 700 A', flush=True)
    folder = RUN / 'cases/swap'
    case = load(folder / 'case.json')
    if case is None:
        ls = leaves()
        ins = [progress['notes'][k] for k in ('a600', 'a400')]
        change = note('a700', 700)
        dest = note('open-b', 0, TOKEN_B)
        if 'note_id' not in progress:
            progress['note_id'] = int.from_bytes(os.urandom(8), 'big') | 1
            progress['expiry'] = rpc('starknet_blockNumber', []) + 3600
            checkpoint()
        # Upstream Ekubo anonymizer ABI: router, TokenAmount {token, i129 {mag, sign}}, PoolKey,
        # minimum_received: u256, skip_ahead: u128, note_id.
        calldata = [ROUTER, TOKEN_A, BUDGET, 0, *D['pool_key'], MINIMUM, 0, 0, progress['note_id']]
        intent = {'kind': on.INVOKE, 'adapter': ANON, 'nonce': 0, 'expiry': progress['expiry'], 'calldata': calldata,
                  'destinations': [{'note_id': progress['note_id'], 'token': TOKEN_B, 'minimum': MINIMUM,
                                    'inner': dest['inner'], 'ciphertext': dest['ciphertext']}]}
        intent_felt = on.hash_intent(CHAIN, POOL, TOKEN_A, ANON, BUDGET, intent)
        body = {'chain': hex(CHAIN), 'pool': hex(POOL), 'token': hex(TOKEN_A), 'leaves': ls,
                'inputs': [{'sk': alice['sk'], 'rho': n['rho'], 'amount': str(n['amount']), 'position': ls.index(n['cm'])} for n in ins],
                'outputs': [{'active': True, 'receiver': alice['receiver'], 'rho': change['rho'], 'amount': '700',
                             'delivery': hex(wallet.delivery_digest(change['ciphertext']))},
                            {'active': False, 'receiver': [0] * 9, 'rho': [0] * 9, 'amount': '0', 'delivery': '0x0'}],
                'withdrawal': {'recipient': hex(ANON), 'amount': str(BUDGET)}, 'intent': hex(intent_felt)}
        client = wallet.prove(body, folder / 'client')
        public = load(folder / 'client/public.json')
        assert int(public['intent'], 16) == intent_felt and public['commitments'][0] == change['cm']
        server = proof2.serve(folder / 'client', folder / 'server', D)
        tx_calldata = on.encode_spend(public, [change['ciphertext'], None], int(server['binding'], 16)) + on.encode_intent(intent) + [0]
        case = {'intent': hex(intent_felt), 'calldata': tx_calldata, 'server': server,
                'client': {k: client[k] for k in ('trace_log_size', 'blinding_rows', 'proving_seconds', 'proof_felts', 'max_rss_gib')}}
        save(folder / 'case.json', case)
    try:
        proof_invoke('swap', POOL, 'apply_spend_with_invoke', case['calldata'], folder / 'server', PROOF_TX_L2, HERE)
        outcome = {'included': True}
    except RuntimeError as e:
        outcome = {'included': False, 'gateway': load(RUN / 'steps/swap/gateway-response.json'), 'error': str(e)[:300]}
    if not outcome['included']:
        # The exact signed transaction, simulated with validation against live Sepolia state.
        tx = load(RUN / 'steps/swap/signed-request.json')['params']['invoke_transaction']
        sim = rpc('starknet_simulateTransactions', ['latest', [tx], []], timeout=300)[0]
        save(RUN / 'results/swap-simulation.json', sim)
        tr = sim['transaction_trace']
        ex = tr['execute_invocation']
        assert 'revert_reason' not in ex, ex['revert_reason'][:1500]
        call_ = ex['calls'][0]
        funded = [e for c in [call_] for e in c.get('events', []) if int(e['keys'][0], 16) == int(selector('OpenNoteFunded'), 16)]
        outcome['simulation'] = {
            'result': 'SUCCEEDED (with validation, latest block)', 'total_l2_gas': tr['execution_resources']['l2_gas'],
            'l1_data_gas': tr['execution_resources']['l1_data_gas'], 'apply_spend_with_invoke_l2_gas': call_['execution_resources']['l2_gas'],
            'fee_STRK': int(sim['fee_estimation']['overall_fee'], 16) / 1e18,
            'open_note_funded': [[int(x, 16) for x in e['data']] for e in funded],
        }
    save(RUN / 'results/swap-outcome.json', outcome)
    print(json.dumps(outcome, indent=1)[:3000], flush=True)
    checkpoint(2)
