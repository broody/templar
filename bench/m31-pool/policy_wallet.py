"""Policy-note wallet cryptography (`docs/policy-note-spec.md` §9): seed-derived note secrets, the
compact path's 256-byte note plaintexts (`M301`, `PB01`, `PS01`), sealed boxes (random or, for the
standard refund, with a seed-derived ephemeral key) and seed-only recovery of a policy note's
refund.

The wallet's own spending and incoming keys are **fixture derivations** (`TEMPLAR_FIXTURE_*`
labels) standing in for the production wallet's; the policy derivations follow the reviewed spec.
Known-answer vectors for every derivation and encoding here are pinned in
`vectors/policy-wallet-kat.json` and checked by `test_policy_wallet.py`."""
import hashlib, hmac, json, secrets
from nacl import bindings
from nacl.public import PrivateKey, PublicKey, SealedBox
import policy_note as pn

P = 2**31 - 1
WORD = 4
FELT = 32
FELT_PRIME = 2**251 + 17 * 2**192 + 1
ADDRESS_BOUND = 2**251


def hkdf(ikm, info, n):
    """HKDF-SHA256 with an empty salt."""
    prk = hmac.new(b'\x00' * 32, ikm, hashlib.sha256).digest()
    out, t, i = b'', b'', 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def m31_9(b):
    """Nine M31 words from 72 bytes: each 8-byte big-endian chunk mod 2^31 - 1."""
    assert len(b) == 72
    words = [int.from_bytes(b[8 * i:8 * i + 8], 'big') % P for i in range(9)]
    assert any(words), 'all-zero digest: draw a new nonce'
    return words


def x25519_scalar(b):
    """A 32-byte X25519 scalar, clamped per RFC 7748."""
    s = bytearray(b)
    s[0] &= 248
    s[31] &= 127
    s[31] |= 64
    return bytes(s)


def felt_bytes(v):
    return int(v).to_bytes(FELT, 'big')


def words_bytes(ws):
    assert len(ws) == 9
    return b''.join(int(w).to_bytes(WORD, 'big') for w in ws)


def bytes_words(b):
    return [int.from_bytes(b[WORD * i:WORD * i + WORD], 'big') for i in range(9)]


# ---------------------------------------------------------------- wallet (fixture keys)

class Wallet:
    """A wallet from a 32-byte seed: spending secrets and incoming keys per receiver index
    (fixture labels), and the policy seed `s_pol`."""

    def __init__(self, seed):
        self.seed = seed
        self.s_pol = hkdf(seed, b'TEMPLAR_POLICY_SEED', 32)

    def sk(self, i):
        return m31_9(hkdf(self.seed, b'TEMPLAR_FIXTURE_SPEND' + i.to_bytes(4, 'big'), 72))

    def receiver(self, i):
        return pn.run('keys', __import__('json').dumps(self.sk(i)))['receiver']

    def incoming(self, i):
        return PrivateKey(x25519_scalar(hkdf(self.seed, b'TEMPLAR_FIXTURE_INCOMING' + i.to_bytes(4, 'big'), 32)))

    def policy_secrets(self, chain, pool, nonce):
        """`cap, rho, salt, rho_refund, esk_refund` for policy nonce `ν` (spec §9.1)."""
        ctx = felt_bytes(chain) + felt_bytes(pool) + nonce
        d = lambda label: m31_9(hkdf(self.s_pol, label + ctx, 72))
        return {'cap': d(b'TEMPLAR_POLICY_CAP'), 'rho': d(b'TEMPLAR_POLICY_RHO'), 'salt': d(b'TEMPLAR_POLICY_SALT'),
                'rho_refund': d(b'TEMPLAR_POLICY_REFUND_RHO'),
                'esk_refund': x25519_scalar(hkdf(self.s_pol, b'TEMPLAR_POLICY_REFUND_EPH' + ctx, 32))}


# ---------------------------------------------------------------- sealed boxes and payload words

def seal(pk, message, esk=None):
    """A libsodium sealed box (`epk ‖ box(m, nonce = BLAKE2b-24(epk ‖ pk))`); with `esk` the
    ephemeral key is given instead of random, so the box is reproducible byte for byte."""
    if esk is None:
        return SealedBox(PublicKey(bytes(pk))).encrypt(message)
    epk = bindings.crypto_scalarmult_base(esk)
    nonce = hashlib.blake2b(epk + bytes(pk), digest_size=24).digest()
    return epk + bindings.crypto_box(message, nonce, bytes(pk), esk)


def open_box(sk, box):
    try:
        return SealedBox(sk).decrypt(box)
    except Exception:
        return None


def to_words(box):
    """304 bytes as nine 31-byte and one 25-byte big-endian felts (the pool's payload words)."""
    assert len(box) == 304
    return [int.from_bytes(box[31 * i:31 * i + 31], 'big') for i in range(9)] + [int.from_bytes(box[279:], 'big')]


def from_words(ws):
    assert len(ws) == 10
    return b''.join(int(w).to_bytes(31, 'big') for w in ws[:9]) + int(ws[9]).to_bytes(25, 'big')


# ---------------------------------------------------------------- plaintexts (256 bytes)

def m301(token, receiver, rho, amount, pad=b''):
    x = b'M301' + felt_bytes(token) + words_bytes(receiver) + words_bytes(rho) + int(amount).to_bytes(16, 'big')
    x += pad
    return x + b'\x00' * (256 - len(x))


def parse_m301(x):
    if x[:4] not in (b'M301', b'PS01'):
        return None
    return {'version': x[:4].decode(), 'token': int.from_bytes(x[4:36], 'big'), 'receiver': bytes_words(x[36:72]),
            'rho': bytes_words(x[72:108]), 'amount': int.from_bytes(x[108:124], 'big'),
            'side': x[124] if x[:4] == b'PS01' else None}


def ps01(token, receiver, rho, side, note_amount):
    """A split output's plaintext: the x side (`side = 0`) carries no amount; the remainder side
    (`side = 1`) carries the note amount (spec §9.3)."""
    x = b'PS01' + felt_bytes(token) + words_bytes(receiver) + words_bytes(rho)
    x += int(note_amount if side == 1 else 0).to_bytes(16, 'big') + bytes([side])
    return x + b'\x00' * (256 - len(x))


def pb01(token, amount, header, rest, nonce, refund_index):
    x = (b'PB01' + felt_bytes(token) + int(amount).to_bytes(16, 'big') + felt_bytes(int(header['controller'], 16))
         + felt_bytes(int(header['controller_class'], 16)) + felt_bytes(int(header['handle'], 16))
         + int(header['deadline']).to_bytes(8, 'big') + words_bytes(rest) + nonce + refund_index.to_bytes(4, 'big'))
    assert len(x) == 212
    return x + b'\x00' * 44


def parse_pb01(x):
    if x[:4] != b'PB01' or any(x[212:]):
        return None
    f = lambda a, b: int.from_bytes(x[a:b], 'big')
    return {'token': f(4, 36), 'amount': f(36, 52), 'controller': f(52, 84), 'controller_class': f(84, 116),
            'handle': f(116, 148), 'deadline': f(148, 156), 'rest': bytes_words(x[156:192]), 'nonce': x[192:208],
            'refund_index': f(208, 212)}


# ---------------------------------------------------------------- the standard refund and creation

def standard_refund(w, chain, pool, token, amount, refund_index, secrets_):
    """The standard refund outcome (spec §4.4, §9.2) and its reproducible ciphertext words."""
    receiver = w.receiver(refund_index)
    pk = w.incoming(refund_index).public_key
    box = seal(pk, m301(token, receiver, secrets_['rho_refund'], amount), esk=secrets_['esk_refund'])
    words = to_words(box)
    return pn.fixed([pn.out(receiver, secrets_['rho_refund'], amount, pn.data_felt_delivery(words))]), words


def new_policy_note(w, chain, pool, token, amount, controller, controller_class, handle, deadline, others, refund_index=0):
    """A depositor's policy note: seed-derived secrets, the standard refund in slot 0, `others`
    in slots 1..3, and the creation ciphertext (a `PB01` backup sealed to the depositor)."""
    while True:
        nonce = secrets.token_bytes(16)
        try:
            s = w.policy_secrets(chain, pool, nonce)
            break
        except AssertionError:
            continue  # an all-zero derived digest: draw a new nonce (spec §9.1)
    refund, refund_words = standard_refund(w, chain, pool, token, amount, refund_index, s)
    pol = pn.policy(controller, controller_class, handle, deadline, [refund, *others], salt=s['salt'])
    info = pn.note(pol, s['cap'], chain, pool, token, amount)
    backup = pb01(token, amount, pol['header'], info['rest'], nonce, refund_index)
    creation_words = to_words(seal(w.incoming(refund_index).public_key, backup))
    return {'policy': pol, 'cap': s['cap'], 'rho': s['rho'], 'amount': amount, 'info': info,
            'refund_ciphertext': refund_words, 'creation_ciphertext': creation_words, 'nonce': nonce.hex()}


def recover(w, chain, pool, published, max_index=4):
    """Seed-only recovery: trial-decrypt `published` (`(index, commitment, ciphertext words)`, as
    `NotePublished` gives them) and rebuild each policy note's refund from its `PB01` backup. Each
    result carries what `prove-refund` needs; the leaf is checked against the recomputed `cm`."""
    found = []
    keys = [(i, w.incoming(i)) for i in range(max_index)]
    for index, cm, words in published:
        try:
            box = from_words(words)
        except (ValueError, OverflowError, AssertionError):
            continue
        for i, sk in keys:
            x = open_box(sk, box)
            b = parse_pb01(x) if x else None
            # Anyone can seal a PB01 to this wallet: validate every field and treat any failure as
            # "not ours", so one hostile payload cannot stop the scan (review PI-3).
            if b is None or not pb01_valid(b, max_index):
                continue
            try:
                s = w.policy_secrets(chain, pool, b['nonce'])
                refund, refund_words = standard_refund(w, chain, pool, b['token'], b['amount'], b['refund_index'], s)
                header = {'controller': hex(b['controller']), 'controller_class': hex(b['controller_class']),
                          'handle': hex(b['handle']), 'deadline': b['deadline'], 'salt': s['salt']}
                d = pn.run('policy-digest', json.dumps(header), json.dumps(refund), json.dumps(b['rest']),
                           json.dumps(s['cap']), hex(chain), hex(pool), hex(b['token']), b['amount'], json.dumps(s['rho']))
            except Exception:
                continue
            if d['commitment'] != cm:
                continue
            found.append({'index': index, 'token': b['token'], 'amount': b['amount'], 'header': header, 'refund': refund,
                          'rest': b['rest'], 'cap': s['cap'], 'rho': s['rho'], 'refund_ciphertext': refund_words,
                          'policy_id': d['policy_id']})
    return found


def pb01_valid(b, max_index):
    """Field ranges of a decrypted `PB01` backup before it reaches any tool."""
    return (0 < b['token'] < ADDRESS_BOUND and 0 < b['amount'] < 2**128 and 0 < b['controller'] < ADDRESS_BOUND
            and b['controller_class'] < FELT_PRIME and b['handle'] < FELT_PRIME and b['deadline'] < 2**64
            and all(r < P for r in b['rest']) and b['refund_index'] < max_index)


def find_notes(w, chain, pool, published, token, settled=(), max_index=4):
    """Ordinary notes for this wallet among `published` (trial decryption of `M301`/`PS01`).

    Each candidate's commitment is recomputed and must equal its leaf (review IC-3/PI-5): a payload
    whose amount disagrees with the commitment is not credited. A `PS01` split output takes its
    amount from `settled`, the pool's `PolicySettled` events as `(first_index, x)` pairs: the x side
    (side 0) receives `x`, the remainder side (side 1) its note amount minus `x`."""
    out = []
    for index, cm, words in published:
        try:
            box = from_words(words)
        except (ValueError, OverflowError, AssertionError):
            continue
        for i in range(max_index):
            x = open_box(w.incoming(i), box)
            m = parse_m301(x) if x else None
            if not m or m['token'] != token or m['receiver'] != w.receiver(i):
                continue
            amount = m['amount']
            if m['version'] == 'PS01':
                event = next((xv for first, xv in settled if first <= index <= first + 1), None)
                if event is None:
                    continue
                amount = event if m['side'] == 0 else m['amount'] - event
            if not 0 < amount < 2**128:
                continue
            inner = pn.run('inner', json.dumps(m['receiver']), json.dumps(m['rho']))
            if pn.run('commitment', hex(chain), hex(pool), hex(token), amount, json.dumps(inner)) != cm:
                continue
            out.append({'index': index, 'commitment': cm, 'receiver_index': i, **m, 'amount': amount})
    return out


def acceptance_problems(opening, leaves, chain, pool, token, expected_class, current_block, margin_blocks,
                        own=None):
    """The spec §9.3 checklist for a beneficiary or executor given a policy note's opening. Returns
    the problems found (empty when the note can be accepted): the commitment is in `leaves`, the
    controller class is the expected reference one, the deadline leaves `margin_blocks` for
    proving and PROOF2 wrapping (§7.2), every felt is canonical, and, with `own = (wallet,
    outcome_index, output_index, ciphertext_words)`, the caller's own output decrypts to the
    committed receiver, randomness and amount under the committed delivery digest."""
    problems = []
    pol = opening['policy']
    h = pol['header']
    info = pn.note(pol, opening['cap'], chain, pool, token, opening['amount'])
    inner = pn.run('inner', json.dumps(info['receiver']), json.dumps(opening['rho']))
    cm = pn.run('commitment', hex(chain), hex(pool), hex(token), opening['amount'], json.dumps(inner))
    if cm not in leaves:
        problems.append('commitment not in the tree')
    if int(h['controller_class'], 16) != expected_class:
        problems.append('unexpected controller class')
    if int(h['deadline']) < current_block + margin_blocks:
        problems.append('deadline too close to settle in time')
    felts = [h['controller'], h['controller_class'], h['handle']]
    for o in pol['outcomes']:
        if o:
            felts += [o['withdrawal_recipient']] + [x['delivery'] for x in o['outputs']]
            if (int(o['withdrawal_recipient'], 16) != 0) != (int(o['withdrawal_amount']) != 0):
                problems.append('withdrawal recipient without amount, or amount without recipient')
    if any(int(f, 16) >= FELT_PRIME for f in felts):
        problems.append('non-canonical felt')
    if own:
        w, k, j, words = own
        o = pol['outcomes'][k]['outputs'][j]
        x = None
        for i in range(4):
            x = open_box(w.incoming(i), from_words(words))
            if x:
                break
        m = parse_m301(x) if x else None
        if (not m or pn.data_felt_delivery(words) != int(o['delivery'], 16) or m['receiver'] != o['receiver']
                or m['rho'] != o['rho'] or (m['version'] == 'M301' and m['amount'] != o['amount'])):
            problems.append('own output does not decrypt to the committed output')
    return {'policy_id': info['policy_id'], 'problems': problems}
