"""Wallet-side open-note helpers (R0 V3), mirroring `cairo/src/open_note.cairo` and the pool's
calldata: the execution intent felt, the upstream-style identity commitments, and Cairo Serde
encodings of `Spend` and `ExecutionIntent`."""
from pathlib import Path
import importlib.util, subprocess

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('ref_poseidon', ROOT / 'bench/adr8/ref_poseidon.py')
ref = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ref)
SNCAST = '/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin/sncast'
INVOKE, COMPUTE = 0, 1
s = lambda b: int.from_bytes(b, 'big')


def selector(name):
    return int(subprocess.check_output([SNCAST, 'utils', 'selector', name], text=True).split()[-1], 16)


SELECTORS = {INVOKE: 'privacy_invoke', COMPUTE: 'privacy_invoke_with_computation'}


def delivery_digest(ct):
    assert len(ct) == 10
    return ref.poseidon_hash_span([s(b'CTRL_DELIVERY_V1'), 304, *ct])


def hash_intent(chain, pool, token, budget_recipient, budget, intent):
    """`intent` = {kind, adapter, nonce, expiry, calldata, destinations: [{note_id, token, minimum,
    inner (9 words), ciphertext (10 felts)}]}."""
    d = intent['destinations']
    assert 0 < len(d) <= 2 and len(intent['calldata']) <= 64
    data = [s(b'OPEN_EXEC_V1'), chain, pool, token, intent['kind'], intent['adapter'], intent['nonce'],
            budget_recipient, budget, intent['expiry'], selector(SELECTORS[intent['kind']]), len(intent['calldata']),
            *intent['calldata'], len(d)]
    for x in d:
        assert len(x['inner']) == 9
        data += [x['note_id'], x['token'], x['minimum'], *x['inner'], delivery_digest(x['ciphertext'])]
    return ref.poseidon_hash_span(data)


def partial_commitment(identity):
    return ref.poseidon_hash_span([s(b'TEMPLAR_IDENTITY_V1'), *identity])


def identity_commitment(partial, nonce):
    """Upstream `commitment_from_partial`; equal to `poseidon_hash_span([partial, nonce])`
    (checked by `open_note_e2e`'s Cairo test)."""
    return ref.poseidon_hash_span([partial, nonce])


def span(xs):
    return [len(xs), *xs]


def encode_spend(public, outputs_ciphertexts, binding):
    """Serde of `spend::Spend` from a wallet `public.json` (ints in hex strings) and the active
    outputs' ciphertexts (None for an inactive slot)."""
    h = lambda x: int(x, 16) if isinstance(x, str) else int(x)
    out = [h(public['chain']), h(public['pool']), h(public['token']), *span(public['root']),
           *span(public['nullifiers'][0] + public['nullifiers'][1]), 2]
    for cm, ct in zip(public['commitments'], outputs_ciphertexts):
        out += span(cm) + span(ct or [])
    out += [h(public['withdrawal_recipient']), int(public['withdrawal_amount']), h(public['intent']),
            *span(public['identity']), binding]
    return out


def encode_intent(intent):
    out = [intent['kind'], intent['adapter'], intent['nonce'], intent['expiry'], *span(intent['calldata']),
           len(intent['destinations'])]
    for x in intent['destinations']:
        out += [x['note_id'], x['token'], x['minimum'], *span(x['inner']), *span(x['ciphertext'])]
    return out


def swap_calldata(in_token, in_amount, proceeds):
    """Calldata of the test `MockSwapAdapter.privacy_invoke(in_token, in_amount, Span<Proceeds>)`."""
    return [in_token, in_amount, len(proceeds), *[v for p in proceeds for v in (p['note_id'], p['token'], p['amount'])]]
