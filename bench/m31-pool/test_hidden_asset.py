"""Wallet helpers for hidden-asset spends (`hidden_asset.py`, spec §6): dummy outputs look like
real ones byte for byte in structure, dummy values are sampled like the Rust wallet's, and
receiving resolves assets through the registry with the commitment recomputed.
Usage: python3 test_hidden_asset.py"""
import json, secrets
import hidden_asset as ha
import policy_note as pn
import policy_wallet as pw

CHAIN, POOL, NFT = int.from_bytes(b'SN_SEPOLIA', 'big'), 0x7e57b201, 0x7e57b2a2
X25519_P = 2**255 - 19


def epk_ok(words):
    """A sealed box starts with the ephemeral X25519 public key: a u-coordinate below p (so its
    top bit is clear in little endian)."""
    epk = pw.from_words(words)[:32]
    u = int.from_bytes(epk, 'little')
    return epk[31] & 0x80 == 0 and u < X25519_P


def test_dummy_ciphertexts_have_the_real_layout():
    bob = pw.Wallet(secrets.token_bytes(32))
    for _ in range(64):
        _, real = ha.output_to(bob, 0, NFT, 1)
        dummy, words = ha.dummy_output()
        assert len(real) == len(words) == 10 and epk_ok(real) and epk_ok(words)
        assert int(dummy['amount']) == 0 and int(dummy['delivery'], 16) != 0
    # 304 random bytes fail the key layout about half the time, so a shortcut would stand out.
    bad = sum(not epk_ok(pw.to_words(secrets.token_bytes(304))) for _ in range(256))
    assert bad > 64, bad


def test_dummy_values_are_canonical_and_nonzero():
    for _ in range(1000):
        d = ha.fresh_digest()
        assert len(d) == 9 and any(d) and all(0 <= w < pn.P for w in d)


def test_receiving_resolves_assets_through_the_registry():
    alice = pw.Wallet(secrets.token_bytes(32))
    nft_asset = ha.asset_id(ha.ERC721, NFT, 2)
    erc20 = 0x7e57b2a1
    published = []
    for i, (asset, amount) in enumerate([(nft_asset, 1), (erc20, 50)]):
        out, words = ha.output_to(alice, i, asset, amount)
        inner = pn.run('inner', json.dumps(out['receiver']), json.dumps(out['rho']))
        cm = pn.run('commitment', hex(CHAIN), hex(POOL), hex(asset), amount, json.dumps(inner))
        published.append((i, cm, words))
    notes = {n['index']: n for n in ha.find_notes(alice, CHAIN, POOL, published, {nft_asset: (ha.ERC721, NFT, 2)})}
    assert notes[0]['standard'] == ha.ERC721 and notes[0]['contract'] == NFT and notes[0]['token_id'] == 2
    assert notes[1]['standard'] == ha.ERC20 and notes[1]['contract'] == erc20
    # A registry entry that does not re-derive its identifier is not trusted.
    lying = {nft_asset: (ha.ERC721, NFT, 3)}
    assert [n['index'] for n in ha.find_notes(alice, CHAIN, POOL, published, lying)] == [1]
    # A payload whose commitment disagrees is not credited.
    tampered = [(0, published[1][1], published[0][2])]
    assert ha.find_notes(alice, CHAIN, POOL, tampered) == []


if __name__ == '__main__':
    for name, f in list(globals().items()):
        if name.startswith('test_'):
            f()
            print('ok', name)
