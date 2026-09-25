"""Execute the R0 V5 payment bridge on real client proofs (`docs/account-bound-note-spec.md` §5.1).

Accepts every shape's statement in both modes with its exact binding (recomputed independently
with bench/adr8/ref_poseidon.py, AB-IM4), rejects altered statements and encodings, and rejects
real proofs of forged statements the circuit admits but the bridge must not: V4's eight
(hidden-asset-spec §4.5) and V5's six (an account at 2^251 and at p, a zero `valid_until`, and a
limb at 2^28 in the account and in either `valid_until` limb). Standalone Cairo only; no OS, no large proof.

`validate_bridge_r5.py WORK PROOFS OUT`: WORK is a bridge built by build_bridge_arith.py; PROOFS
holds one directory per `{ordinary,bound}-{shape}` and per `forge-*` statement from
examples/prove_payment_r5.rs.
"""
from pathlib import Path
import hashlib, importlib.util, json, sys
from validate_bridge_proving import CHAIN, run

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ref_poseidon', HERE.parents[1] / 'adr8/ref_poseidon.py')
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)
P = 2**31 - 1
N_LIMBS = 140
CLAIMED_SUMS = 2 + N_LIMBS + 1
MODES = ['ordinary', 'bound']
SHAPES = ['transfer', 'single', 'one-out', 'partial', 'full', 'invoke', 'shadow', 'nft']
FORGERIES = {
    'voluntary-reveal': 'exit rule',
    'zero-delivery': 'delivery',
    'recipient-only': 'withdrawal',
    'identity-no-intent': 'identity intent',
    'duplicate-nullifier': 'duplicate nullifier',
    'asset-range': 'address range',
    'recipient-range': 'address range',
    'zero-chain': 'zero context',
    'account-range': 'account range',
    'account-noncanonical': 'non-canonical felt',
    'valid-until-zero': 'valid_until',
    'account-limb-range': 'limb range',
    'valid-until-limb-range': 'limb range',
    'valid-until-hi-limb-range': 'limb range',
}


def binding(pub):
    """`TMR0_BIND_V5` (spec §5.2): V4's fields then `valid_until`; never the account."""
    s = lambda b: int.from_bytes(b, 'big')
    b = [s(b'TMR0_BIND_V5'), int(pub['chain'], 16), int(pub['pool'], 16), int(pub['token_out'], 16)]
    b += pub['root'] + pub['nullifiers'][0] + pub['nullifiers'][1]
    b += pub['commitments'][0] + [int(pub['deliveries'][0], 16)] + pub['commitments'][1] + [int(pub['deliveries'][1], 16)]
    b += [int(pub['withdrawal_recipient'], 16), int(pub['withdrawal_amount'])]
    b += [int(pub['intent'], 16)] + pub['identity'] + [int(pub['valid_until'])]
    return ref.poseidon_hash_span(b)


def args(pub, data, chain=CHAIN, **over):
    p = {**pub, **over}
    span = lambda xs: [len(xs), *xs]
    return [chain, int(p['pool'], 16), int(p['token_out'], 16), *span(p['root']),
            *span(p['nullifiers'][0] + p['nullifiers'][1]), *span(p['commitments'][0] + p['commitments'][1]),
            *span([int(d, 16) for d in p['deliveries']]), int(p['withdrawal_recipient'], 16),
            int(p['withdrawal_amount']), int(p['intent'], 16), *span(p['identity']),
            int(p['account'], 16), int(p['valid_until']), *data]


def load(d, forged=False):
    pub = json.loads((d / 'public.json').read_text())
    assert forged or int(pub['chain'], 16) == CHAIN
    data = [int(x, 16) for x in json.loads((d / 'cairo-arguments.json').read_text())]
    assert data[0] == len(data) - 1 and data[1] == 35, 'span length and 35 outputs'
    return pub, data


def main():
    work, proofs, out = map(Path, sys.argv[1:4])
    out.mkdir(parents=True, exist_ok=False)
    bump = lambda xs, i: [(x + 1) % P if k == i else x for k, x in enumerate(xs)]
    cases = []  # (name, arguments, expected output or None, expected rejection reason or None)
    bindings = {}
    for mode in MODES:
        for shape in SHAPES:
            pub, data = load(proofs / f'{mode}-{shape}')
            hidden = int(pub['token_out'], 16) == 0
            exits = pub['withdrawal_amount'] != 0 or int(pub['intent'], 16) != 0
            assert hidden == (not exits), f'{shape}: token_out published exactly on exit'
            assert (int(pub['account'], 16) != 0) == (mode == 'bound'), f'{mode}-{shape}: account'
            bindings[f'{mode}-{shape}'] = binding(pub)
            cases.append((f'{mode}-{shape}-valid', args(pub, data), [CHAIN, int(pub['pool'], 16), int(pub['token_out'], 16), binding(pub)], None))
            other = hex(0x1234) if hidden else '0x0'
            cases.append((f'{mode}-{shape}-claimed-token-out', args(pub, data, token_out=other), None, None))
    # Altered statements and encodings, on a transfer and on a withdrawal, in both modes.
    for name in ('ordinary-transfer', 'bound-transfer', 'bound-partial'):
        pub, data = load(proofs / name)
        eq, triple_xor = CLAIMED_SUMS, CLAIMED_SUMS + 2 * 4
        assert data[eq:eq + 4] != [0] * 4 and data[triple_xor:triple_xor + 4] == [0] * 4, 'claimed-sum layout'
        # A tampered output limb fails. The tag, the padding and a transfer's asset fail a named
        # bridge check before proof verification (AB-IM7); the others fail verification.
        named = {'tag': 'statement tag', 'padding': 'statement padding'}
        if name == 'ordinary-transfer':
            named['token-out'] = 'exit rule'
        for label, at in [('tag', 0), ('token-out', 20), ('nullifier', 38), ('commitment', 74), ('account', 127), ('valid-until', 136), ('padding', 138)]:
            bad = data.copy(); bad[2 + at] = (bad[2 + at] + 1) % P
            cases.append((f'{name}-{label}-output', args(pub, bad), None, named.get(label)))
        bad = data.copy(); bad[eq] = (bad[eq] - 1) % P; bad[triple_xor] = 1
        cases.append((f'{name}-absent-claimed-sum', args(pub, bad), None, None))
        bad = data.copy(); bad[len(bad) // 2] ^= 1
        cases.append((f'{name}-proof-body', args(pub, bad), None, None))
        cases.append((f'{name}-wrong-chain', args(pub, data, chain=int.from_bytes(b'SN_MAIN', 'big')), None, None))
        cases.append((f'{name}-wrong-pool', args(pub, data, pool=hex(int(pub['pool'], 16) + 1)), None, None))
        cases.append((f'{name}-wrong-root', args(pub, data, root=bump(pub['root'], 4)), None, None))
        cases.append((f'{name}-wrong-nullifier', args(pub, data, nullifiers=[pub['nullifiers'][0], bump(pub['nullifiers'][1], 0)]), None, None))
        cases.append((f'{name}-swapped-outputs', args(pub, data, commitments=pub['commitments'][::-1]), None, None))
        cases.append((f'{name}-wrong-delivery', args(pub, data, deliveries=[pub['deliveries'][0], hex(int(pub['deliveries'][1], 16) + 1)]), None, None))
        cases.append((f'{name}-wrong-withdrawal-recipient', args(pub, data, withdrawal_recipient=hex(int(pub['withdrawal_recipient'], 16) + 1)), None, None))
        cases.append((f'{name}-wrong-withdrawal-amount', args(pub, data, withdrawal_amount=int(pub['withdrawal_amount']) + 1), None, None))
        cases.append((f'{name}-wrong-intent', args(pub, data, intent=hex(int(pub['intent'], 16) + 1)), None, None))
        cases.append((f'{name}-wrong-identity', args(pub, data, identity=bump(pub['identity'], 0)), None, None))
        # V5: the account and expiry are the proof's, not the caller's.
        cases.append((f'{name}-wrong-account', args(pub, data, account=hex(int(pub['account'], 16) + 1)), None, None))
        cases.append((f'{name}-account-dropped', args(pub, data, account='0x0'), None, None) if int(pub['account'], 16) else
                     (f'{name}-account-added', args(pub, data, account=hex(0x1234)), None, None))
        cases.append((f'{name}-wrong-valid-until', args(pub, data, valid_until=int(pub['valid_until']) + 1), None, None))
        good = args(pub, data)
        n = len(good) - len(data)
        cases.append((f'{name}-trailing', good[:n] + [data[0] + 1, *data[1:], 0], None, None))
        cases.append((f'{name}-truncated', good[:n] + [data[0] - 1, *data[1:-1]], None, None))
    # Real proofs of forged statements: only the bridge's own check rejects each.
    for kind, reason in FORGERIES.items():
        pub, data = load(proofs / f'forge-{kind}', forged=True)
        cases.append((f'forge-{kind}', args(pub, data, chain=int(pub['chain'], 16)), None, reason))
    report = {'scope': 'standalone Cairo execution of the R0 V5 payment bridge (fork circuit_air); no OS, no large proof',
              'executable_sha256': hashlib.sha256((work / 'target/dev/templar_membership_bridge.executable.json').read_bytes()).hexdigest(),
              'bindings': {k: hex(v) for k, v in bindings.items()},
              'cases': []}
    for name, a, expected, reason_substring in cases:
        code, output, usage = run(work, out, name, a)
        accept = expected is not None
        reason = None if accept else next((l.strip() for l in (out / f'{name}.log').read_text().splitlines() if 'panicked' in l.lower()), None)
        if accept:
            ok = code == 0 and output is not None and [v % ref.P for v in output[-4:]] == expected
        else:
            ok = code != 0 and (reason_substring is None or (reason is not None and reason_substring in reason))
        row = {'name': name, 'expected_accept': accept, 'passed': ok, 'exit_code': code, 'output': output, 'usage': usage, 'reason': reason}
        report['cases'].append(row)
        steps = json.loads(usage)['resources']['n_steps'] if usage else None
        print(json.dumps({'name': name, 'passed': ok, 'steps': steps, 'reason': reason}), flush=True)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    assert all(c['passed'] for c in report['cases'])


if __name__ == '__main__':
    main()
