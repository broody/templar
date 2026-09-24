"""Policy-note wallet checks (`docs/policy-note-spec.md` §9), runnable as a script:

- known-answer vectors (`vectors/policy-wallet-kat.json`) for every seed derivation and encoding:
  the policy secrets, the refund's reproducible sealed box, the `M301`/`PB01`/`PS01` plaintexts
  and the resulting `o₀`, policy, `policy_id` and commitment (review IC-2/PI-4);
- compatibility of the reproducible box with libsodium's sealed-box opening;
- seed-only recovery that survives a hostile `PB01` (review PI-3);
- note discovery that rejects a payload whose amount disagrees with the leaf, and split receipt
  from `PolicySettled` (review IC-3/PI-5);
- the acceptance checklist and its deadline guard (review IC-4).

`python3 test_policy_wallet.py` checks; `--regenerate` rewrites the vectors (only when an encoding
changes on purpose)."""
from pathlib import Path
import json, sys
from nacl.public import SealedBox
import policy_note as pn
import policy_wallet as pw

HERE = Path(__file__).resolve().parent
KAT = HERE / 'vectors/policy-wallet-kat.json'
CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')
POOL, TOKEN, ESCROW, CLASS, ARBITER = 0x7e57b001, 0x7e57b0a1, 0x7e57b0e5, 0x2a7fca624bf22a78bc9b38e40eb7e8292b9405fd4559faf17f2c4c2648544e1, 0xa4b1
SEED = bytes(range(32))
NONCE = bytes(range(0x10, 0x20))
AMOUNT, DEADLINE = 1000, 10**7


def vectors():
    """Every value pinned by the known-answer file, from fixed inputs."""
    w = pw.Wallet(SEED)
    s = w.policy_secrets(CHAIN, POOL, NONCE)
    receiver = w.receiver(0)
    pk = bytes(w.incoming(0).public_key)
    m301 = pw.m301(TOKEN, receiver, s['rho_refund'], AMOUNT)
    box = pw.seal(w.incoming(0).public_key, m301, esk=s['esk_refund'])
    refund, words = pw.standard_refund(w, CHAIN, POOL, TOKEN, AMOUNT, 0, s)
    pol = pn.policy(ESCROW, CLASS, ARBITER, DEADLINE, [refund], salt=s['salt'])
    info = pn.note(pol, s['cap'], CHAIN, POOL, TOKEN, AMOUNT)
    inner = pn.run('inner', json.dumps(info['receiver']), json.dumps(s['rho']))
    cm = pn.run('commitment', hex(CHAIN), hex(POOL), hex(TOKEN), AMOUNT, json.dumps(inner))
    pb01 = pw.pb01(TOKEN, AMOUNT, pol['header'], info['rest'], NONCE, 0)
    ps01 = [pw.ps01(TOKEN, receiver, s['rho'], side, AMOUNT) for side in (0, 1)]
    return {
        'inputs': {'seed': SEED.hex(), 'nonce': NONCE.hex(), 'chain': hex(CHAIN), 'pool': hex(POOL), 'token': hex(TOKEN),
                   'amount': AMOUNT, 'controller': hex(ESCROW), 'controller_class': hex(CLASS), 'handle': hex(ARBITER),
                   'deadline': DEADLINE, 'refund_index': 0},
        's_pol': w.s_pol.hex(), 'spend_secret_0': w.sk(0), 'receiver_0': receiver, 'incoming_pk_0': pk.hex(),
        'cap': s['cap'], 'rho': s['rho'], 'salt': s['salt'], 'rho_refund': s['rho_refund'],
        'esk_refund': s['esk_refund'].hex(), 'epk_refund': box[:32].hex(),
        'refund_m301': m301.hex(), 'refund_box': box.hex(), 'refund_words': [hex(x) for x in words],
        'refund_delivery': hex(pn.data_felt_delivery(words)), 'refund_outcome': refund,
        'slots': info['slots'], 'rest': info['rest'], 'policy': info['policy'], 'pnk': info['pnk'],
        'receiver': info['receiver'], 'policy_id': info['policy_id'], 'inner': inner, 'commitment': cm,
        'pb01': pb01.hex(), 'ps01_x_side': ps01[0].hex(), 'ps01_rest_side': ps01[1].hex(),
    }


def check_kat():
    got = vectors()
    if '--regenerate' in sys.argv:
        KAT.parent.mkdir(exist_ok=True)
        KAT.write_text(json.dumps(got, indent=1) + '\n')
        print('regenerated', KAT)
    want = json.loads(KAT.read_text())
    bad = [k for k in want if want[k] != got.get(k)]
    assert not bad, f'known-answer mismatch: {bad}'
    w = pw.Wallet(SEED)
    assert SealedBox(w.incoming(0)).decrypt(bytes.fromhex(want['refund_box'])) == bytes.fromhex(want['refund_m301'])
    # The HKDF here against an independent implementation (empty salt = 32 zero bytes).
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    for n in (32, 72):
        ref = HKDF(algorithm=hashes.SHA256(), length=n, salt=None, info=b'TEMPLAR_POLICY_CAP').derive(SEED)
        assert pw.hkdf(SEED, b'TEMPLAR_POLICY_CAP', n) == ref
    print(f'known answers: {len(want)} values match; the reproducible box opens with libsodium')


def check_recovery():
    """A hostile PB01 sealed to the wallet does not stop the scan; the real note is recovered."""
    w = pw.Wallet(SEED)
    note = pw.new_policy_note(w, CHAIN, POOL, TOKEN, AMOUNT, ESCROW, CLASS, ARBITER, DEADLINE, [])
    inner = pn.run('inner', json.dumps(note['info']['receiver']), json.dumps(note['rho']))
    cm = pn.run('commitment', hex(CHAIN), hex(POOL), hex(TOKEN), AMOUNT, json.dumps(inner))
    hostile = bytearray(pw.pb01(TOKEN, AMOUNT, note['policy']['header'], note['info']['rest'], NONCE, 0))
    hostile[4:36] = b'\xff' * 32            # a 256-bit token: out of range for every tool
    words = pw.to_words(pw.seal(w.incoming(0).public_key, bytes(hostile)))
    found = pw.recover(w, CHAIN, POOL, [(0, [1] * 9, words), (1, cm, note['creation_ciphertext'])])
    assert [f['index'] for f in found] == [1], found
    print('recovery: a hostile PB01 is skipped; the real note is recovered')


def check_discovery():
    """A lying amount is not credited; split outputs take their amounts from PolicySettled."""
    w = pw.Wallet(SEED)
    receiver, rho = w.receiver(0), pn.random_digest()
    inner = pn.run('inner', json.dumps(receiver), json.dumps(rho))
    cm = lambda a: pn.run('commitment', hex(CHAIN), hex(POOL), hex(TOKEN), a, json.dumps(inner))
    seal = lambda m: pw.to_words(pw.seal(w.incoming(0).public_key, m))
    honest = seal(pw.m301(TOKEN, receiver, rho, 600))
    lying = seal(pw.m301(TOKEN, receiver, rho, 6000))
    found = pw.find_notes(w, CHAIN, POOL, [(0, cm(600), honest), (1, cm(600), lying)], TOKEN)
    assert [(n['index'], n['amount']) for n in found] == [(0, 600)], found
    # A split of 1000 with x = 250: side 0 receives 250, side 1 the remaining 750.
    rho1 = pn.random_digest()
    inner1 = pn.run('inner', json.dumps(receiver), json.dumps(rho1))
    cm1 = pn.run('commitment', hex(CHAIN), hex(POOL), hex(TOKEN), 750, json.dumps(inner1))
    x_side = seal(pw.ps01(TOKEN, receiver, rho, 0, 1000))
    rest_side = seal(pw.ps01(TOKEN, receiver, rho1, 1, 1000))
    found = pw.find_notes(w, CHAIN, POOL, [(4, cm(250), x_side), (5, cm1, rest_side)], TOKEN, settled=[(4, 250)])
    assert [(n['index'], n['amount']) for n in found] == [(4, 250), (5, 750)], found
    assert pw.find_notes(w, CHAIN, POOL, [(4, cm(250), x_side)], TOKEN) == [], 'no PolicySettled, no credit'
    print('discovery: lying amounts rejected; split amounts from PolicySettled')


def check_acceptance():
    w, ben = pw.Wallet(SEED), pw.Wallet(bytes(32))
    rho = pn.random_digest()
    words = pw.to_words(pw.seal(ben.incoming(0).public_key, pw.m301(TOKEN, ben.receiver(0), rho, 900)))
    settle = pn.fixed([pn.out(ben.receiver(0), rho, 900, pn.data_felt_delivery(words))], withdrawal=(0x77, 100))
    note = pw.new_policy_note(w, CHAIN, POOL, TOKEN, AMOUNT, ESCROW, CLASS, ARBITER, DEADLINE, [settle])
    inner = pn.run('inner', json.dumps(note['info']['receiver']), json.dumps(note['rho']))
    leaf = pn.run('commitment', hex(CHAIN), hex(POOL), hex(TOKEN), AMOUNT, json.dumps(inner))
    opening = {'policy': note['policy'], 'cap': note['cap'], 'rho': note['rho'], 'amount': AMOUNT}
    ok = pw.acceptance_problems(opening, [leaf], CHAIN, POOL, TOKEN, CLASS, 100, 1000, own=(ben, 1, 0, words))
    assert ok['problems'] == [] and ok['policy_id'] == note['info']['policy_id'], ok
    late = pw.acceptance_problems(opening, [leaf], CHAIN, POOL, TOKEN, CLASS, DEADLINE - 10, 1000)
    assert late['problems'] == ['deadline too close to settle in time'], late
    other = pw.acceptance_problems(opening, [], CHAIN, POOL, TOKEN, CLASS + 1, 100, 1000)
    assert set(other['problems']) == {'commitment not in the tree', 'unexpected controller class'}, other
    forged = pw.to_words(pw.seal(ben.incoming(0).public_key, pw.m301(TOKEN, ben.receiver(0), rho, 901)))
    bad = pw.acceptance_problems(opening, [leaf], CHAIN, POOL, TOKEN, CLASS, 100, 1000, own=(ben, 1, 0, forged))
    assert bad['problems'] == ['own output does not decrypt to the committed output'], bad
    print('acceptance: checklist and deadline guard behave')


if __name__ == '__main__':
    check_kat()
    check_recovery()
    check_discovery()
    check_acceptance()
