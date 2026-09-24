"""Wallet-side policy-note helpers (`docs/policy-note-spec.md`), mirroring `cairo/src/policy.cairo`
and the P1 relation (`client-port/src/policy.rs`, via the Rust `wallet` example): policies and
their outcomes, the note's receiver and `policy_id`, P1 spend requests, the P1 binding and the
pool's `PolicySpend` calldata."""
from pathlib import Path
import importlib.util, json, secrets, subprocess

ROOT = Path(__file__).resolve().parents[2]
WALLET = ROOT / 'bench/m31-private-wrapper/client-port/target/release/examples/wallet'
_spec = importlib.util.spec_from_file_location('ref_poseidon', ROOT / 'bench/adr8/ref_poseidon.py')
ref = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ref)
P = 2**31 - 1
FIXED, SPLIT = 1, 2
s = lambda b: int.from_bytes(b, 'big')


def run(*args):
    out = subprocess.run([str(WALLET), *map(str, args)], capture_output=True, text=True, check=True).stdout
    return json.loads(out.strip().splitlines()[-1])


def random_digest():
    return [secrets.randbelow(P - 1) + 1 for _ in range(9)]


def out(receiver, rho, amount, delivery):
    return {'active': True, 'receiver': receiver, 'rho': rho, 'amount': amount, 'delivery': hex(delivery)}


def no_out():
    return {'active': False, 'receiver': [0] * 9, 'rho': [0] * 9, 'amount': 0, 'delivery': '0x0'}


def fixed(outputs, not_before=0, withdrawal=(0, 0)):
    assert len(outputs) <= 2
    outs = outputs + [no_out()] * (2 - len(outputs))
    return {'kind': FIXED, 'not_before': not_before, 'outputs': outs,
            'withdrawal_recipient': hex(withdrawal[0]), 'withdrawal_amount': withdrawal[1]}


def split(out_x, out_rest, not_before=0):
    """Both outputs with amount 0 in the preimage; `x` is chosen at settlement."""
    return {'kind': SPLIT, 'not_before': not_before, 'outputs': [{**out_x, 'amount': 0}, {**out_rest, 'amount': 0}],
            'withdrawal_recipient': '0x0', 'withdrawal_amount': 0}


def policy(controller, controller_class, handle, deadline, outcomes, salt=None):
    assert outcomes[0] is not None and outcomes[0]['kind'] == FIXED, 'slot 0 is the refund'
    slots = list(outcomes) + [None] * (4 - len(outcomes))
    return {'header': {'controller': hex(controller), 'controller_class': hex(controller_class), 'handle': hex(handle),
                       'deadline': deadline, 'salt': salt or random_digest()},
            'outcomes': slots}


def note(pol, cap, chain, pool, token, amount):
    """`{policy, pnk, receiver, policy_id, slots, rest}` for a note of `amount` under `pol`."""
    return run('policy-note', json.dumps(pol), json.dumps(cap), hex(chain), hex(pool), hex(token), amount)


def spend_request(chain, pool, token, leaves, cap, rho, amount, position, pol, index, x=0, data=0):
    return {'chain': hex(chain), 'pool': hex(pool), 'token': hex(token), 'leaves': leaves,
            'note': {'cap': cap, 'rho': rho, 'amount': str(amount), 'position': position},
            'policy': pol, 'index': index, 'x': str(x), 'data': hex(data)}


def data_felt_delivery(words):
    """The delivery digest of ten ciphertext words (`spend.cairo`, `delivery_digest`)."""
    assert len(words) == 10
    return ref.poseidon_hash_span([s(b'CTRL_DELIVERY_V1'), 304, *words])


def data_felt(data):
    """The statement's `data`: `Poseidon(data)` of the controller call's data span."""
    return ref.poseidon_hash_span(list(data))


def binding(pub):
    """`Poseidon('TMP1_BIND_V1', ...)` over a P1 `public.json` (the bridge's `binding`)."""
    h = lambda v: int(v, 16) if isinstance(v, str) else int(v)
    b = [s(b'TMP1_BIND_V1'), h(pub['chain']), h(pub['pool']), h(pub['token'])]
    b += pub['root'] + pub['nullifier'] + pub['commitments'][0] + pub['commitments'][1]
    b += [h(pub['deliveries'][0]), h(pub['deliveries'][1]), h(pub['withdrawal_recipient']), int(pub['withdrawal_amount'])]
    b += [h(pub['controller']), h(pub['controller_class']), h(pub['handle'])] + pub['policy_id']
    b += [int(pub['deadline']), int(pub['not_before']), int(pub['index']), int(pub['kind']), int(pub['x']), h(pub['data'])]
    return ref.poseidon_hash_span(b)


def span(xs):
    return [len(xs), *xs]


def encode_spend(pub, binding_felt):
    """Serde of the pool's `policy::PolicySpend` from a P1 `public.json`."""
    h = lambda v: int(v, 16) if isinstance(v, str) else int(v)
    return [h(pub['chain']), h(pub['pool']), h(pub['token']), *span(pub['root']), *span(pub['nullifier']),
            *span(pub['commitments'][0] + pub['commitments'][1]), h(pub['deliveries'][0]), h(pub['deliveries'][1]),
            h(pub['withdrawal_recipient']), int(pub['withdrawal_amount']), h(pub['controller']),
            h(pub['controller_class']), h(pub['handle']), *span(pub['policy_id']), int(pub['deadline']),
            int(pub['not_before']), int(pub['index']), int(pub['kind']), int(pub['x']), h(pub['data']), binding_felt]
