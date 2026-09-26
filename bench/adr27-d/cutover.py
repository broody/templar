#!/usr/bin/env python3
"""ADR-0027 phase E: the Sepolia cutover and the governance drill (docs/pool-v3-spec.md §11.2–§11.4).

  python3 cutover.py status                      # read-only: verifiers, proposals, routes, etas
  python3 cutover.py STEP --i-approve-onchain-transactions [--attempt N]

Steps, each one checkpointed transaction (or two) from `account-1` through sncast:
  propose        pool.propose('R0', r0 routing adapter) and pool.propose('P1', p1 routing adapter)
  apply          pool.apply('R0') and pool.apply('P1'), within [eta, eta + T]; then reads back
  dummy          §11.4 step 2: propose an unpinned route on the R0 adapter: an inert one, keyed by the
                 test token (a contract that emits no message, so no proof can ever match it)
  cancel-dummy   cancel it
  planned        §11.4 step 3: propose the planned route (the second V6 instance the release pins)
  apply-planned  apply it within [eta, eta + T]
  remove-planned propose its removal, no sooner than max_proof_age blocks after it was applied
  apply-removal  apply the removal within [eta, eta + T]
The SDK and server checks between the steps run separately (bench/adr27-d/README.md).

Every apply checks, before sending, the pending value it applies and that the time is inside that
proposal's own window with a margin; drill steps require the R0 swap (the adapter's activation
gate). Steps are checkpointed by name: after a lapse, `--attempt 2` (3, …) re-sends under new names.
"""
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNTIME = Path(os.environ.get('TEMPLAR_ADR27_RUN', Path.home() / '.local/share/templar/runs/adr27-d'))
os.environ['TEMPLAR_SEPOLIA_RUN'] = str(RUNTIME / 'sepolia')
sys.path.insert(0, str(ROOT / 'bench/m31-sepolia'))
from sepolia import CHAIN, RUN, call, h, load, normal_tx, rpc, save  # noqa: E402

D = load(HERE / 'results/deployment.json')
P6 = load(ROOT / 'bench/account-bound-p6/results/deployment.json')
POOL = D['pool']
R0, P1 = int.from_bytes(b'R0', 'big'), int.from_bytes(b'P1', 'big')
T = 7200
LAPSE_MARGIN = 300          # seconds kept free before a proposal lapses (block time and inclusion)
INVOKE_L2_GAS = 20_000_000
L2_PRICE_BOUND = 40_000_000_000
L1_DATA_PRICE_BOUND = 4_000_000_000_000


def bounds(l2=INVOKE_L2_GAS):
    b = [('l2-gas', l2), ('l2-gas-price', L2_PRICE_BOUND), ('l1-gas', 1), ('l1-gas-price', 200_000_000_000_000),
         ('l1-data-gas', 10_000), ('l1-data-gas-price', L1_DATA_PRICE_BOUND)]
    total = l2 * L2_PRICE_BOUND + 200_000_000_000_000 + 10_000 * L1_DATA_PRICE_BOUND
    assert total <= 5 * 10**18, total
    return [a for k, v in b for a in (f'--{k}', str(v))]


def invoke(name, address, fn, calldata):
    return normal_tx(name, ['invoke', '--contract-address', h(address), '--function', fn,
                            '--calldata', *[h(x) for x in calldata], *bounds()], HERE)


def short(s):
    return int.from_bytes(s.encode(), 'big')


def route_felts(r):
    return [int(r['statement'], 16), int(r['statement_class'], 16), short(r['account_tag']), int(r['os_program'], 16),
            short('PROOF2'), short('VIRTUAL_SNOS'), short('VIRTUAL_SNOS0'), r['max_proof_age']]


def latest():
    b = rpc('starknet_getBlockWithTxHashes', ['latest'])
    return b['block_number'], b['timestamp']


def wait_until(ts, what):
    while True:
        _, now = latest()
        if now >= ts:
            return
        print(json.dumps({'waiting_for': what, 'eta': ts, 'now': now, 'seconds_left': ts - now}), flush=True)
        time.sleep(min(300, max(15, ts - now)))


def proposals(adapter):
    v = call(adapter, 'get_route_proposals')
    out, at = [], 1
    for _ in range(v[0]):
        statement = hex(v[at]); tag = v[at + 1]; at += 2
        route = None
        if tag == 0:
            route = [hex(x) for x in v[at:at + 8]]; at += 8
        out.append({'statement': statement, 'route': route, 'eta': v[at]}); at += 1
    return out


def status():
    r0a, p1a = D['r0-routing-adapter'], D['p1-routing-adapter']
    return {
        'block': latest(),
        'verifiers': {'R0': hex(call(POOL, 'get_verifier', [R0])[0]), 'P1': hex(call(POOL, 'get_verifier', [P1])[0])},
        'pool_proposals': {'R0': call(POOL, 'get_proposal', [R0]), 'P1': call(POOL, 'get_proposal', [P1])},
        'r0_adapter': {'routes': call(r0a, 'get_routes'), 'proposals': proposals(r0a)},
        'p1_adapter': {'routes': call(p1a, 'get_routes'), 'proposals': proposals(p1a)},
    }


assert int(rpc('starknet_chainId', []), 16) == CHAIN, 'the local node is not on Sepolia'
assert call(POOL, 'get_parameters')[3] == T
step = sys.argv[1] if len(sys.argv) > 1 else 'status'
attempt = int(sys.argv[sys.argv.index('--attempt') + 1]) if '--attempt' in sys.argv else 1
name = lambda n: n if attempt == 1 else f'{n}-attempt{attempt}'  # noqa: E731
state = load(RUN / 'cutover.json', {})
if step == 'status':
    print(json.dumps(status(), indent=2))
    sys.exit(0)
if '--i-approve-onchain-transactions' not in sys.argv:
    print(json.dumps({'step': step, 'note': 'nothing sent; pass --i-approve-onchain-transactions', 'status': status()}, indent=2))
    sys.exit(0)

r0a, p1a = D['r0-routing-adapter'], D['p1-routing-adapter']
planned = {**D['r0_route'], **D['planned_route']}
# An inert unpinned route: the test token as the key (deployed, so it passes check_route with its own
# class) and a drill tag. The token emits no L2→L1 message, so no proof can match it even if it were
# applied by mistake (release review F2, ADV-3).
dummy = {'statement': P6['token'], 'statement_class': hex(int(rpc('starknet_getClassHashAt', ['latest', P6['token']]), 16)),
         'account_tag': 'TMPZ_DRILL_DUMMY', 'os_program': P6['r0']['os_program'], 'max_proof_age': 1024}


def in_window(eta, what):
    _, now = latest()
    assert eta > 0, f'{what}: no pending proposal'
    assert now <= eta + T - LAPSE_MARGIN, f'{what}: the proposal lapses at {eta + T}; propose again (--attempt)'
    return now


def swapped():
    assert call(POOL, 'get_verifier', [R0]) == [int(r0a, 16)], 'the R0 routing adapter is not the pool\'s R0 verifier yet'


def pending_route(key):
    return [x for x in proposals(r0a) if int(x['statement'], 16) == int(key, 16)]


def fresh(key, route):
    """The pending proposal under `key` is `route` (eight felts, or None for a removal), not lapsed."""
    p = pending_route(key)
    _, now = latest()
    want = None if route is None else [hex(x) for x in route]
    got = p and (None if p[0]['route'] is None else [hex(int(x, 16)) for x in p[0]['route']])
    assert p and got == want and now <= p[0]['eta'] + T - LAPSE_MARGIN, f'no fresh pending proposal for {key}: {p}'
    return p[0]


def applied_planned_block():
    """The block where the planned route's addition applied, from whichever attempt succeeded."""
    blocks = [r['block_number'] for d in sorted((RUN / 'steps').glob('drill-apply-planned*'))
              if (r := load(d / 'receipt.json')) and r.get('execution_status') == 'SUCCEEDED']
    assert blocks, 'no successful drill-apply-planned receipt'
    return max(blocks)

if step == 'propose':
    # Per kind: one already swapped (or already pending with a live window) is left alone.
    for kind, key, adapter, legacy in (('R0', R0, r0a, P6['r0_adapter']), ('P1', P1, p1a, P6['p1_adapter'])):
        current = call(POOL, 'get_verifier', [key])[0]
        if current == int(adapter, 16):
            continue
        assert current == int(legacy, 16), f'{kind}: the verifier is neither the V5 adapter nor the routing adapter'
        value, eta = call(POOL, 'get_proposal', [key])
        _, now = latest()
        if value == int(adapter, 16) and now <= eta + T - LAPSE_MARGIN:
            print(json.dumps({'kind': kind, 'note': 'already pending', 'eta': eta}))
            continue
        invoke(name(f'propose-{kind.lower()}'), POOL, 'propose', [key, adapter])
        value, eta = call(POOL, 'get_proposal', [key])
        _, now = latest()
        # A fresh proposal: not a checkpoint replayed over a lapsed one.
        assert value == int(adapter, 16) and eta >= now, f'{kind}: the pending proposal is not a fresh one to the routing adapter'
    state[name('propose')] = {'R0': call(POOL, 'get_proposal', [R0]), 'P1': call(POOL, 'get_proposal', [P1])}
elif step == 'apply':
    for kind, key, adapter in (('R0', R0, r0a), ('P1', P1, p1a)):
        if call(POOL, 'get_verifier', [key]) == [int(adapter, 16)]:
            continue
        value, eta = call(POOL, 'get_proposal', [key])
        assert value == int(adapter, 16), f'{kind}: the pending value is {hex(value)}, not the routing adapter {adapter}'
        wait_until(eta, f'the {kind} timelock')
        in_window(eta, kind)
        invoke(name(f'apply-{kind.lower()}'), POOL, 'apply', [key])
    assert call(POOL, 'get_verifier', [R0]) == [int(r0a, 16)] and call(POOL, 'get_verifier', [P1]) == [int(p1a, 16)]
    state['apply'] = {'block': latest()}
elif step == 'dummy':
    swapped()
    assert call(r0a, 'get_route', [int(dummy['statement'], 16)]) == [1], 'the dummy key is a route'
    invoke(name('drill-dummy'), r0a, 'propose_route', [int(dummy['statement'], 16), 0, *route_felts(dummy)])
    fresh(dummy['statement'], route_felts(dummy))
    state['dummy'] = proposals(r0a)
elif step == 'cancel-dummy':
    assert pending_route(dummy['statement']), 'no pending dummy proposal'
    invoke(name('drill-cancel-dummy'), r0a, 'cancel_route', [int(dummy['statement'], 16)])
    assert not pending_route(dummy['statement']), 'the dummy proposal is still pending'
    state['cancel_dummy'] = proposals(r0a)
elif step == 'planned':
    swapped()
    invoke(name('drill-planned'), r0a, 'propose_route', [int(planned['statement'], 16), 0, *route_felts(planned)])
    fresh(planned['statement'], route_felts(planned))
    state['planned'] = proposals(r0a)
elif step == 'apply-planned':
    swapped()
    p = pending_route(planned['statement'])
    assert p and p[0]['route'], 'no pending addition of the planned route'
    # Exactly the pinned route, in all eight fields (a same-key replacement could differ).
    assert [int(x, 16) for x in p[0]['route']] == route_felts(planned), 'the pending route differs from the pinned planned route'
    wait_until(p[0]['eta'], 'the route timelock')
    # Re-read after the wait: the same proposal, still inside its window.
    assert fresh(planned['statement'], route_felts(planned))['eta'] == p[0]['eta'], 'the planned proposal changed while waiting'
    invoke(name('drill-apply-planned'), r0a, 'apply_route', [int(planned['statement'], 16)])
    assert call(r0a, 'get_route', [int(planned['statement'], 16)]) == [0, *route_felts(planned)], 'the planned route is not active as pinned'
    state['apply_planned'] = {'block': latest(), 'routes': call(r0a, 'get_routes')}
elif step == 'remove-planned':
    swapped()
    assert call(r0a, 'get_route', [int(planned['statement'], 16)])[0] == 0, 'the planned route is not active'
    applied = applied_planned_block()
    block, _ = latest()
    assert block >= applied + planned['max_proof_age'], f'wait until block {applied + planned["max_proof_age"]} (now {block})'
    invoke(name('drill-remove-planned'), r0a, 'propose_route', [int(planned['statement'], 16), 1])
    fresh(planned['statement'], None)
    state['remove_planned'] = proposals(r0a)
elif step == 'apply-removal':
    swapped()
    p = pending_route(planned['statement'])
    assert p and p[0]['route'] is None, 'no pending removal of the planned route'
    assert call(r0a, 'get_routes')[0] >= 2, 'removing the last route'
    wait_until(p[0]['eta'], 'the route timelock')
    assert fresh(planned['statement'], None)['eta'] == p[0]['eta'], 'the removal proposal changed while waiting'
    invoke(name('drill-apply-removal'), r0a, 'apply_route', [int(planned['statement'], 16)])
    assert call(r0a, 'get_route', [int(planned['statement'], 16)]) == [1], 'the planned route is still active'
    assert call(r0a, 'get_route', [int(D['r0_route']['statement'], 16)])[0] == 0, 'the own route is not active'
    state['apply_removal'] = {'block': latest(), 'routes': call(r0a, 'get_routes')}
else:
    sys.exit(f'unknown step {step}')
state['status'] = status()
save(RUN / 'cutover.json', state)
(HERE / 'results').mkdir(exist_ok=True)
save(HERE / 'results/cutover.json', state)
print(json.dumps(state, indent=2))
