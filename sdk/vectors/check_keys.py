"""Independent reference for the SDK's new formats (docs/sdk-spec.md §3-§5, §12.1): recomputes
`keys.json` from its seeds with nothing from templar-core. BIP-39 from the canonical wordlist,
HKDF-SHA256 from hmac, `wide9`, RFC 7748 clamping and X25519 via libsodium (PyNaCl), F4Jumble per
ZIP-316, Bech32m per BIP-350, fingerprints, viewing keys, the store key, and sealed boxes against
libsodium in both directions. The receiver and nullifier key come from the bench wallet (the
relation's own hash, `wallet keys`), and the delivery digest from the bench's Poseidon.

    python3 sdk/vectors/check_keys.py
"""
import hashlib, hmac, json, subprocess, sys
from pathlib import Path

from nacl import bindings
from nacl.public import PrivateKey, SealedBox

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'bench/m31-pool'))
import policy_note as pn  # noqa: E402  (bench Poseidon and the bench wallet binary)
import policy_wallet as pw  # noqa: E402

P = 2**31 - 1
WORDS = (HERE / 'bip39-english.txt').read_text().split()
assert hashlib.sha256((HERE / 'bip39-english.txt').read_bytes()).hexdigest() == '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda'


def mnemonic(entropy):
    """BIP-39: entropy then its first len/32 checksum bits, in 11-bit words (24 for 32 bytes,
    21 for a bound wallet's 28)."""
    n = len(entropy) * 8
    cs = n // 32
    bits = int.from_bytes(entropy, 'big') << cs | hashlib.sha256(entropy).digest()[0] >> (8 - cs)
    count = (n + cs) // 11
    return ' '.join(WORDS[(bits >> (11 * (count - 1 - i))) & 2047] for i in range(count))


def hkdf(seed, info, n, salt=b'TEMPLAR_WALLET_V1'):
    prk = hmac.new(salt, seed, hashlib.sha256).digest()
    out, t, i = b'', b'', 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def wide9(b):
    return [int.from_bytes(b[16 * k:16 * k + 16], 'big') % P for k in range(9)]


def clamp(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def felt32(x):
    return int(x, 16).to_bytes(32, 'big') if isinstance(x, str) else x.to_bytes(32, 'big')


def words36(d):
    return b''.join(w.to_bytes(4, 'big') for w in d)


# ------------------------------------------------------------------ F4Jumble (ZIP-316)

def _h(i, u, n):
    return hashlib.blake2b(u, digest_size=n, person=b'UA_F4Jumble_H' + bytes([i, 0, 0])).digest()


def _g(i, u, n):
    out = b''
    j = 0
    while len(out) < n:
        out += hashlib.blake2b(u, digest_size=64, person=b'UA_F4Jumble_G' + bytes([i]) + j.to_bytes(2, 'little')).digest()
        j += 1
    return out[:n]


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def f4jumble(m):
    ll = min(64, len(m) // 2)
    lr = len(m) - ll
    a, b = m[:ll], m[ll:]
    x = xor(b, _g(0, a, lr))
    y = xor(a, _h(0, x, ll))
    d = xor(x, _g(1, y, lr))
    c = xor(y, _h(1, d, ll))
    return c + d


# ------------------------------------------------------------------ Bech32m (BIP-350)

CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


def _polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def bech32m(hrp, data):
    bits, acc, five = 0, 0, []
    for byte in data:
        acc = acc << 8 | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            five.append(acc >> bits & 31)
    if bits:
        five.append(acc << (5 - bits) & 31)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = _polymod(expanded + five + [0] * 6) ^ 0x2bc830a3
    check = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + '1' + ''.join(CHARSET[d] for d in five + check)


def encode(hrp, kind, body):
    pad = hrp.encode() + b'\x00' * (16 - len(hrp))
    return bech32m(hrp, f4jumble(bytes([1, kind]) + body + pad))


# ------------------------------------------------------------------ checks

def main():
    v = json.loads((HERE / 'keys.json').read_text())
    chain, pool = felt32(int.from_bytes(b'SN_SEPOLIA', 'big')), felt32(v['pool'])
    checked = 0
    for w in v['wallets']:
        seed = bytes.fromhex(w['seed'])
        assert mnemonic(seed) == w['mnemonic'], 'mnemonic'
        assert hkdf(seed, b'TEMPLAR_STORE_V1' + chain + pool, 32).hex() == w['store_key'], 'store key'
        for a in w['accounts']:
            ctx = chain + pool + a['index'].to_bytes(4, 'big')
            sk = wide9(hkdf(seed, b'TEMPLAR_SPEND_V1' + ctx, 144))
            assert sk == a['sk'], 'sk'
            ivk = clamp(hkdf(seed, b'TEMPLAR_INCOMING_V1' + ctx, 32))
            assert ivk.hex() == a['ivk'], 'ivk'
            pk = bindings.crypto_scalarmult_base(ivk)
            assert pk.hex() == a['pk'], 'pk'
            k = pn.run('keys', json.dumps(sk))
            assert k['receiver'] == a['receiver'] and k['nk'] == a['nk'], 'receiver / nk (bench relation)'
            body = chain + pool + words36(a['receiver']) + pk
            assert encode('templarsep', 1, body) == a['address'], 'address'
            fp = hashlib.sha256(b'TEMPLAR_ADDRESS_FP_V1' + bytes([1, 1]) + body).hexdigest()[:20]
            assert '-'.join(fp[4 * i:4 * i + 4] for i in range(5)) == a['fingerprint'], 'fingerprint'
            assert encode('templarivksep', 2, chain + pool + words36(a['receiver']) + ivk) == a['incoming_viewing_key'], 'ivk export'
            assert encode('templarfvksep', 3, chain + pool + words36(a['ak']) + words36(a['nk']) + ivk) == a['full_viewing_key'], 'fvk export'
            checked += 1
    # Bound wallets (docs/account-bound-note-spec.md §6.2): the bound salt and labels, A in every
    # context, receivers bound to A (the relation's WAUTH key, from the bench wallet).
    bound_checked = 0
    bpool = felt32(v['bound_pool'])
    for b in v['bound_seeds']:
        seed = bytes.fromhex(b['seed'])
        assert len(seed) == 28 and mnemonic(seed) == b['mnemonic'] and len(b['mnemonic'].split()) == 21, 'bound mnemonic'
        hk = lambda info, n: hkdf(seed, info, n, salt=b'TEMPLAR_BOUND_WALLET_V1')
        for w in b['wallets']:
            actx = chain + bpool + felt32(w['account'])
            assert hk(b'TEMPLAR_BOUND_STORE_V1' + actx, 32).hex() == w['store_key'], 'bound store key'
            assert hk(b'TEMPLAR_BOUND_STORE_ID_V1' + actx, 32).hex() == w['store_id_key'], 'bound store id key'
            for a in w['accounts']:
                ctx = actx + a['index'].to_bytes(4, 'big')
                sk = wide9(hk(b'TEMPLAR_BOUND_SPEND_V1' + ctx, 144))
                assert sk == a['sk'], 'bound sk'
                ivk = clamp(hk(b'TEMPLAR_BOUND_INCOMING_V1' + ctx, 32))
                assert ivk.hex() == a['ivk'], 'bound ivk'
                pk = bindings.crypto_scalarmult_base(ivk)
                assert pk.hex() == a['pk'], 'bound pk'
                k = pn.run('keys5', json.dumps(sk), w['account'])
                assert k['receiver'] == a['receiver'] and k['nk'] == a['nk'] and k['ak'] == a['ak'], 'bound receiver / nk / ak (bench relation)'
                ordinary = pn.run('keys', json.dumps(sk))
                assert ordinary['receiver'] != a['receiver'], 'a bound receiver is never the ordinary one'
                body = chain + bpool + words36(a['receiver']) + pk
                assert encode('templarsep', 1, body) == a['address'], 'bound address'
                fp = hashlib.sha256(b'TEMPLAR_ADDRESS_FP_V1' + bytes([1, 1]) + body).hexdigest()[:20]
                assert '-'.join(fp[4 * i:4 * i + 4] for i in range(5)) == a['fingerprint'], 'bound fingerprint'
                bound_checked += 1
    sb = v['sealed_boxes']
    ivk = bytes.fromhex(sb['recipient_ivk'])
    pk = bytes.fromhex(sb['recipient_pk'])
    for b in sb['boxes']:
        esk, msg, sealed = bytes.fromhex(b['esk']), bytes.fromhex(b['message']), bytes.fromhex(b['sealed'])
        # The core's box equals libsodium's with the same ephemeral key, and libsodium opens it.
        assert pw.seal(pk, msg, esk=esk) == sealed, 'sealed box bytes'
        assert SealedBox(PrivateKey(ivk)).decrypt(sealed) == msg, 'libsodium opens the core box'
        words = pw.to_words(sealed)
        assert [hex(x) for x in words] == b['words'], 'words'
        assert hex(pn.data_felt_delivery(words)) == b['delivery'], 'delivery digest'
    # libsodium refuses the blocked keys the core refuses (an all-zero shared secret).
    for blocked in [bytes(32), (1).to_bytes(32, 'little'), ((1 << 255) - 20).to_bytes(32, 'little')]:
        refused = False
        try:
            bindings.crypto_box_seal(b'x', blocked)
        except Exception:  # noqa: BLE001
            refused = True
        assert refused, f'libsodium sealed to blocked key {blocked.hex()}'
    print(json.dumps({'accounts': checked, 'bound_accounts': bound_checked, 'sealed_boxes': len(sb['boxes']), 'result': 'all vectors match'}))


if __name__ == '__main__':
    main()
