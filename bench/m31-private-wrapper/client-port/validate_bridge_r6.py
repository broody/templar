"""Execute the R0 V6 payment bridge on real client proofs (`docs/pool-v3-spec.md` §4.4, §5.1).

Accepts every shape's statement, and `valid_until` 1 and 2^56 − 1, with its exact binding
(recomputed independently with bench/adr8/ref_poseidon.py); rejects altered statements and
encodings; exercises the V6 decode offsets on real proofs (each nonzero padding limb 129–131,
`valid_until` at 127–128 zero and each limb at 2^28, the `R0C6` tag), each rejected by its named
bridge check before proof verification; rejects real proofs of forged statements the circuit admits
but the bridge must not (V4's eight and V6's three `valid_until` forgeries); and rejects a V5 proof
(another client circuit). Standalone Cairo only; no OS, no large proof.

`validate_bridge_r6.py WORK PROOFS OUT [V5_PROOF]`: WORK is a bridge built by build_bridge_arith.py;
PROOFS holds one directory per shape, `valid-until-{1,max}` and per `forge-*` statement from
prove_r6_suite.py; V5_PROOF is any R0 V5 proof directory.
"""
from pathlib import Path
import hashlib, importlib.util, json, sys
from validate_bridge_proving import CHAIN, run

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ref_poseidon', HERE.parents[1] / 'adr8/ref_poseidon.py')
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)
P = 2**31 - 1
N_OUTPUTS = 33
N_LIMBS = 4 * N_OUTPUTS
CLAIMED_SUMS = 2 + N_LIMBS + 1
VALID_UNTIL_AT = 127
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
    'valid-until-zero': 'valid_until',
    'valid-until-limb-range': 'limb range',
    'valid-until-hi-limb-range': 'limb range',
}


def binding(pub):
    """`TMR0_BIND_V5` (spec §5.2): V4's fields then `valid_until`."""
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
            int(p['valid_until']), *data]


def load(d, forged=False, outputs=N_OUTPUTS):
    text = (d / 'public.json').read_text()
    pub = json.loads(text)
    assert forged or int(pub['chain'], 16) == CHAIN
    data = [int(x, 16) for x in json.loads((d / 'cairo-arguments.json').read_text())]
    assert data[0] == len(data) - 1 and data[1] == outputs, f'span length and {outputs} outputs'
    return pub, data


def main():
    work, proofs, out = map(Path, sys.argv[1:4])
    v5 = Path(sys.argv[4]) if len(sys.argv) > 4 else None
    out.mkdir(parents=True, exist_ok=False)
    bump = lambda xs, i: [(x + 1) % P if k == i else x for k, x in enumerate(xs)]
    cases = []  # (name, arguments, expected output or None, expected rejection reason or None)
    bindings = {}
    for name in SHAPES + ['valid-until-1', 'valid-until-max']:
        pub, data = load(proofs / name)
        hidden = int(pub['token_out'], 16) == 0
        exits = pub['withdrawal_amount'] != 0 or int(pub['intent'], 16) != 0
        assert hidden == (not exits), f'{name}: token_out published exactly on exit'
        assert 'account' not in pub, f'{name}: a V6 statement has no account'
        if name == 'valid-until-1':
            assert pub['valid_until'] == 1
        if name == 'valid-until-max':
            assert pub['valid_until'] == 2**56 - 1
        bindings[name] = binding(pub)
        cases.append((f'{name}-valid', args(pub, data), [CHAIN, int(pub['pool'], 16), int(pub['token_out'], 16), binding(pub)], None))
        other = hex(0x1234) if hidden else '0x0'
        cases.append((f'{name}-claimed-token-out', args(pub, data, token_out=other), None, None))
    # Altered statements and encodings, on a transfer and on a withdrawal.
    for name in ('transfer', 'partial'):
        pub, data = load(proofs / name)
        eq, triple_xor = CLAIMED_SUMS, CLAIMED_SUMS + 2 * 4
        assert data[eq:eq + 4] != [0] * 4 and data[triple_xor:triple_xor + 4] == [0] * 4, 'claimed-sum layout'
        # A tampered output limb fails. The tag, each padding limb, the valid_until encoding and a
        # transfer's asset fail a named bridge check before proof verification; the others fail
        # verification.
        named = {'tag': 'statement tag', 'padding-129': 'statement padding', 'padding-130': 'statement padding',
                 'padding-131': 'statement padding'}
        if name == 'transfer':
            named['token-out'] = 'exit rule'
        for label, at in [('tag', 0), ('token-out', 20), ('nullifier', 38), ('commitment', 74), ('valid-until', VALID_UNTIL_AT),
                          ('valid-until-hi', VALID_UNTIL_AT + 1), ('padding-129', 129), ('padding-130', 130), ('padding-131', 131)]:
            bad = data.copy(); bad[2 + at] = (bad[2 + at] + 1) % P
            cases.append((f'{name}-{label}-output', args(pub, bad), None, named.get(label)))
        for label, lo, hi, reason in [('valid-until-zero', 0, 0, 'valid_until'), ('valid-until-lo-2^28', 1 << 28, 0, 'limb range'),
                                      ('valid-until-hi-2^28', 1, 1 << 28, 'limb range')]:
            bad = data.copy(); bad[2 + VALID_UNTIL_AT] = lo; bad[2 + VALID_UNTIL_AT + 1] = hi
            cases.append((f'{name}-{label}-output', args(pub, bad), None, reason))
        bad = data.copy(); bad[2 + 1] = 0x52304335  # R0C5, V5's tag
        cases.append((f'{name}-v5-tag-output', args(pub, bad), None, 'statement tag'))
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
        cases.append((f'{name}-wrong-valid-until', args(pub, data, valid_until=int(pub['valid_until']) + 1), None, None))
        good = args(pub, data)
        n = len(good) - len(data)
        cases.append((f'{name}-trailing', good[:n] + [data[0] + 1, *data[1:], 0], None, None))
        cases.append((f'{name}-truncated', good[:n] + [data[0] - 1, *data[1:-1]], None, None))
    # Real proofs of forged statements: only the bridge's own check rejects each.
    for kind, reason in FORGERIES.items():
        pub, data = load(proofs / f'forge-{kind}', forged=True)
        cases.append((f'forge-{kind}', args(pub, data, chain=int(pub['chain'], 16)), None, reason))
    # A V5 proof is another client circuit.
    if v5 is not None:
        pub5, data5 = load(v5, outputs=35)
        cases.append(('v5-proof', args(pub5, data5), None, 'not the client circuit'))
    report = {'scope': 'standalone Cairo execution of the R0 V6 payment bridge (fork circuit_air); no OS, no large proof',
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
    failed = [c['name'] for c in report['cases'] if not c['passed']]
    print(json.dumps({'cases': len(report['cases']), 'failed': failed}))
    assert not failed


if __name__ == '__main__':
    main()
