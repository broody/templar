"""Wallet-side helpers for hidden-asset spends and ERC721/ERC1155 notes (`docs/hidden-asset-spec.md`),
mirroring `cairo/src/{assets,spend4}.cairo` and the R0 V4 relation (`client-port/src/payment4.rs`,
through the Rust `wallet prove4`): asset identifiers, M301 payloads under an asset, dummy outputs,
receiving by trial decryption with the commitment recomputed, and the pool's V4 `Spend` calldata.
"""
from pathlib import Path
import importlib.util, json, os, secrets, subprocess
from nacl.public import PrivateKey
import policy_note as pn
import policy_wallet as pw

ROOT = Path(__file__).resolve().parents[2]
CLIENT = ROOT / 'bench/m31-private-wrapper/client-port'
ERC20, ERC721, ERC1155 = 20, 721, 1155
BOUND = 2**251
s = lambda b: int.from_bytes(b, 'big')


def asset_id(standard, contract, token_id):
    """`Poseidon('TEMPLAR_ASSET_V1', standard, contract, id.low, id.high)`, below 2^251."""
    a = pn.ref.poseidon_hash_span([s(b'TEMPLAR_ASSET_V1'), standard, contract, token_id % 2**128, token_id >> 128])
    assert a < BOUND, 'identifier at or above 2^251: this (contract, id) cannot be deposited'
    return a


def output_to(w, i, asset, amount):
    """A real output to wallet `w`'s receiving index `i`: `(output, ciphertext words)`."""
    rho = pn.random_digest()
    receiver = w.receiver(i)
    words = pw.to_words(pw.seal(w.incoming(i).public_key, pw.m301(asset, receiver, rho, amount)))
    return {'receiver': receiver, 'rho': rho, 'amount': str(amount), 'delivery': hex(pn.data_felt_delivery(words))}, words


def dummy_output():
    """A zero-value note to a fresh random receiver, with a real sealed box of a random plaintext
    to a fresh X25519 key (spec §6: never 304 random bytes)."""
    words = pw.to_words(pw.seal(PrivateKey.generate().public_key, secrets.token_bytes(256)))
    return {'receiver': pn.random_digest(), 'rho': pn.random_digest(), 'amount': '0',
            'delivery': hex(pn.data_felt_delivery(words))}, words


def find_notes(w, chain, pool, published, max_index=4):
    """Ordinary notes of any asset for `w` among `published` `(index, commitment, words)`: trial
    decryption of `M301`, accepted only when the commitment recomputed from the decrypted asset,
    amount and owner equals the leaf (spec §6, HA-M5)."""
    found = []
    for index, cm, words in published:
        try:
            box = pw.from_words(words)
        except (ValueError, OverflowError, AssertionError):
            continue
        for i in range(max_index):
            x = pw.open_box(w.incoming(i), box)
            m = pw.parse_m301(x) if x else None
            if not m or m['version'] != 'M301' or m['receiver'] != w.receiver(i) or not 0 < m['amount'] < 2**128:
                continue
            inner = pn.run('inner', json.dumps(m['receiver']), json.dumps(m['rho']))
            if pn.run('commitment', hex(chain), hex(pool), hex(m['token']), m['amount'], json.dumps(inner)) != cm:
                continue
            found.append({'index': index, 'commitment': cm, 'receiver_index': i, 'asset': m['token'], **m})
    return found


def prove4(spend, out, max_fri_columns=16):
    """An R0 V4 proof through the Rust wallet (4 pinned cores), with its resource usage."""
    out.mkdir(parents=True, exist_ok=True)
    (out / 'spend.json').write_text(json.dumps(spend))
    env = dict(os.environ, RAYON_NUM_THREADS='4')
    r = subprocess.run(['/usr/bin/time', '-v', 'taskset', '-c', '0-3', str(pn.WALLET), 'prove4', str(out / 'spend.json'),
                        str(out), str(max_fri_columns)], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr[-3000:]
    report = json.loads((out / 'report.json').read_text())
    rss = [l for l in r.stderr.splitlines() if 'Maximum resident' in l]
    report['max_rss_gib'] = int(rss[-1].split()[-1]) / 2**20
    return {k: report[k] for k in ('trace_log_size', 'blinding_rows', 'proving_seconds', 'proof_felts', 'max_rss_gib')}


def binding(pub):
    """`Poseidon('TMR0_BIND_V4', ...)` over a V4 `public.json` (the bridge's and pool's binding)."""
    h = lambda v: int(v, 16)
    b = [s(b'TMR0_BIND_V4'), h(pub['chain']), h(pub['pool']), h(pub['token_out'])]
    b += pub['root'] + pub['nullifiers'][0] + pub['nullifiers'][1]
    b += pub['commitments'][0] + [h(pub['deliveries'][0])] + pub['commitments'][1] + [h(pub['deliveries'][1])]
    b += [h(pub['withdrawal_recipient']), int(pub['withdrawal_amount']), h(pub['intent'])] + pub['identity']
    return pn.ref.poseidon_hash_span(b)


def encode_spend(pub, ciphertexts):
    """Serde of the pool's `spend4::Spend` from a V4 `public.json` and both outputs' ciphertexts."""
    h = lambda v: int(v, 16)
    out = [h(pub['chain']), h(pub['pool']), h(pub['token_out']), *pn.span(pub['root']),
           *pn.span(pub['nullifiers'][0] + pub['nullifiers'][1]), 2]
    for cm, ct in zip(pub['commitments'], ciphertexts):
        out += pn.span(cm) + pn.span(ct)
    out += [h(pub['withdrawal_recipient']), int(pub['withdrawal_amount']), h(pub['intent']), *pn.span(pub['identity']),
            binding(pub)]
    return out


def hook_data(inner, ciphertext):
    """A push deposit's `data`: `inner₉ ‖ ciphertext₁₀`."""
    assert len(inner) == 9 and len(ciphertext) == 10
    return [*inner, *ciphertext]
