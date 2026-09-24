"""Execute the R0 V4 payment bridge on real client proofs (`docs/hidden-asset-spec.md` §4.5).

Accepts every shape's statement with its exact binding (recomputed independently with
bench/adr8/ref_poseidon.py), rejects altered statements and encodings, and rejects real proofs of
forged statements the circuit admits but the bridge must not: a voluntary asset reveal, a zero
delivery digest, a recipient without an amount, an identity without an intent, and a duplicate
nullifier. Standalone Cairo only; no OS, no large proof.

`validate_bridge_r4.py WORK PROOFS OUT`: WORK is a bridge built by build_bridge_arith.py; PROOFS
holds one directory per shape and per `forge-*` statement from examples/prove_payment_r4.rs.
"""
from pathlib import Path
import hashlib, importlib.util, json, sys
from validate_bridge_proving import CHAIN, run

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ref_poseidon', HERE.parents[1] / 'adr8/ref_poseidon.py')
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)
P = 2**31 - 1
N_LIMBS = 128
CLAIMED_SUMS = 2 + N_LIMBS + 1
SHAPES = ['transfer', 'single', 'one-out', 'partial', 'full', 'invoke', 'shadow', 'nft']
FORGERIES = {
    'voluntary-reveal': 'exit rule',
    'zero-delivery': 'delivery',
    'recipient-only': 'withdrawal',
    'identity-no-intent': 'identity intent',
    'duplicate-nullifier': 'duplicate nullifier',
}


def binding(pub):
    s = lambda b: int.from_bytes(b, 'big')
    b = [s(b'TMR0_BIND_V4'), int(pub['chain'], 16), int(pub['pool'], 16), int(pub['token_out'], 16)]
    b += pub['root'] + pub['nullifiers'][0] + pub['nullifiers'][1]
    b += pub['commitments'][0] + [int(pub['deliveries'][0], 16)] + pub['commitments'][1] + [int(pub['deliveries'][1], 16)]
    b += [int(pub['withdrawal_recipient'], 16), int(pub['withdrawal_amount'])]
    b += [int(pub['intent'], 16)] + pub['identity']
    return ref.poseidon_hash_span(b)


def args(pub, data, chain=CHAIN, **over):
    p = {**pub, **over}
    span = lambda xs: [len(xs), *xs]
    return [chain, int(p['pool'], 16), int(p['token_out'], 16), *span(p['root']),
            *span(p['nullifiers'][0] + p['nullifiers'][1]), *span(p['commitments'][0] + p['commitments'][1]),
            *span([int(d, 16) for d in p['deliveries']]), int(p['withdrawal_recipient'], 16),
            int(p['withdrawal_amount']), int(p['intent'], 16), *span(p['identity']), *data]


def load(d):
    pub = json.loads((d / 'public.json').read_text())
    assert int(pub['chain'], 16) == CHAIN
    data = [int(x, 16) for x in json.loads((d / 'cairo-arguments.json').read_text())]
    assert data[0] == len(data) - 1 and data[1] == 32, 'span length and 32 outputs'
    return pub, data


def main():
    work, proofs, out = map(Path, sys.argv[1:4])
    out.mkdir(parents=True, exist_ok=False)
    bump = lambda xs, i: [(x + 1) % P if k == i else x for k, x in enumerate(xs)]
    cases = []  # (name, arguments, expected output or None, expected rejection reason or None)
    for shape in SHAPES:
        pub, data = load(proofs / shape)
        hidden = int(pub['token_out'], 16) == 0
        exits = pub['withdrawal_amount'] != 0 or int(pub['intent'], 16) != 0
        assert hidden == (not exits), f'{shape}: token_out published exactly on exit'
        cases.append((f'{shape}-valid', args(pub, data), [CHAIN, int(pub['pool'], 16), int(pub['token_out'], 16), binding(pub)], None))
        # Claiming an asset the proof does not publish, or hiding one it does, fails.
        other = hex(0x1234) if hidden else '0x0'
        cases.append((f'{shape}-claimed-token-out', args(pub, data, token_out=other), None, None))
    # Altered statements and encodings, on a transfer and on a withdrawal.
    for shape in ('transfer', 'partial'):
        pub, data = load(proofs / shape)
        eq, triple_xor = CLAIMED_SUMS, CLAIMED_SUMS + 2 * 4
        assert data[eq:eq + 4] != [0] * 4 and data[triple_xor:triple_xor + 4] == [0] * 4, 'claimed-sum layout'
        bad = data.copy(); bad[2] ^= 1
        cases.append((f'{shape}-tag', args(pub, bad), None, None))
        bad = data.copy(); bad[2 + 20] = (bad[2 + 20] + 1) % P
        cases.append((f'{shape}-token-out-output', args(pub, bad), None, None))
        bad = data.copy(); bad[2 + 38] = (bad[2 + 38] + 1) % P
        cases.append((f'{shape}-nullifier-output', args(pub, bad), None, None))
        bad = data.copy(); bad[2 + 74] = (bad[2 + 74] + 1) % P
        cases.append((f'{shape}-commitment-output', args(pub, bad), None, None))
        bad = data.copy(); bad[eq] = (bad[eq] - 1) % P; bad[triple_xor] = 1
        cases.append((f'{shape}-absent-claimed-sum', args(pub, bad), None, None))
        bad = data.copy(); bad[len(bad) // 2] ^= 1
        cases.append((f'{shape}-proof-body', args(pub, bad), None, None))
        cases.append((f'{shape}-wrong-chain', args(pub, data, chain=int.from_bytes(b'SN_MAIN', 'big')), None, None))
        cases.append((f'{shape}-wrong-pool', args(pub, data, pool=hex(int(pub['pool'], 16) + 1)), None, None))
        cases.append((f'{shape}-wrong-root', args(pub, data, root=bump(pub['root'], 4)), None, None))
        cases.append((f'{shape}-wrong-nullifier', args(pub, data, nullifiers=[pub['nullifiers'][0], bump(pub['nullifiers'][1], 0)]), None, None))
        cases.append((f'{shape}-swapped-outputs', args(pub, data, commitments=pub['commitments'][::-1]), None, None))
        cases.append((f'{shape}-wrong-delivery', args(pub, data, deliveries=[pub['deliveries'][0], hex(int(pub['deliveries'][1], 16) + 1)]), None, None))
        cases.append((f'{shape}-wrong-withdrawal-recipient', args(pub, data, withdrawal_recipient=hex(int(pub['withdrawal_recipient'], 16) + 1)), None, None))
        cases.append((f'{shape}-wrong-withdrawal-amount', args(pub, data, withdrawal_amount=int(pub['withdrawal_amount']) + 1), None, None))
        cases.append((f'{shape}-wrong-intent', args(pub, data, intent=hex(int(pub['intent'], 16) + 1)), None, None))
        cases.append((f'{shape}-wrong-identity', args(pub, data, identity=bump(pub['identity'], 0)), None, None))
        good = args(pub, data)
        n = len(good) - len(data)
        cases.append((f'{shape}-trailing', good[:n] + [data[0] + 1, *data[1:], 0], None, None))
        cases.append((f'{shape}-truncated', good[:n] + [data[0] - 1, *data[1:-1]], None, None))
    # Real proofs of forged statements: only the bridge's own check rejects each.
    for kind, reason in FORGERIES.items():
        pub, data = load(proofs / f'forge-{kind}')
        cases.append((f'forge-{kind}', args(pub, data), None, reason))
    report = {'scope': 'standalone Cairo execution of the R0 V4 payment bridge (fork circuit_air); no OS, no large proof',
              'executable_sha256': hashlib.sha256((work / 'target/dev/templar_membership_bridge.executable.json').read_bytes()).hexdigest(),
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
