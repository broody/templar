"""Execute the R0 payment bridge on a real client proof: exact statement and binding acceptance,
and rejection of altered statements, encodings and an absent-component claimed sum. The binding
is recomputed independently (bench/adr8/ref_poseidon.py). Standalone Cairo only; no OS, no proof."""
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


def binding(pub):
    s = lambda b: int.from_bytes(b, 'big')
    b = [s(b'TMR0_BIND_V3'), int(pub['chain'], 16), int(pub['pool'], 16), int(pub['token'], 16)]
    b += pub['root'] + pub['nullifiers'][0] + pub['nullifiers'][1]
    b += pub['commitments'][0] + [int(pub['deliveries'][0], 16)] + pub['commitments'][1] + [int(pub['deliveries'][1], 16)]
    b += [int(pub['withdrawal_recipient'], 16), int(pub['withdrawal_amount'])]
    b += [int(pub['intent'], 16)] + pub['identity']
    return ref.poseidon_hash_span(b)


def args(pub, data, chain=CHAIN, **over):
    p = {**pub, **over}
    span = lambda xs: [len(xs), *xs]
    return [chain, int(p['pool'], 16), int(p['token'], 16), *span(p['root']),
            *span(p['nullifiers'][0] + p['nullifiers'][1]), *span(p['commitments'][0] + p['commitments'][1]),
            *span([int(d, 16) for d in p['deliveries']]), int(p['withdrawal_recipient'], 16),
            int(p['withdrawal_amount']), int(p['intent'], 16), *span(p['identity']), *data]


def main():
    work, proof_dir, out = map(Path, sys.argv[1:4])
    out.mkdir(parents=True, exist_ok=False)
    pub = json.loads((proof_dir / 'public.json').read_text())
    assert int(pub['chain'], 16) == CHAIN
    data = [int(x, 16) for x in json.loads((proof_dir / 'cairo-arguments.json').read_text())]
    assert data[0] == len(data) - 1 and data[1] == 32, 'span length and 32 outputs'
    eq, triple_xor = CLAIMED_SUMS, CLAIMED_SUMS + 2 * 4
    assert data[eq:eq + 4] != [0] * 4 and data[triple_xor:triple_xor + 4] == [0] * 4, 'claimed-sum layout'
    expected = [CHAIN, int(pub['pool'], 16), int(pub['token'], 16), binding(pub)]
    bump = lambda xs, i: [(x + 1) % P if k == i else x for k, x in enumerate(xs)]
    cases = [('valid', args(pub, data), True)]
    bad = data.copy(); bad[2] ^= 1
    cases.append(('tag', args(pub, bad), False))
    bad = data.copy(); bad[2 + 38] = (bad[2 + 38] + 1) % P
    cases.append(('nullifier-output', args(pub, bad), False))
    bad = data.copy(); bad[2 + 56] = (bad[2 + 56] + 1) % P
    cases.append(('commitment-output', args(pub, bad), False))
    bad = data.copy(); bad[eq] = (bad[eq] - 1) % P; bad[triple_xor] = 1
    cases.append(('absent-claimed-sum', args(pub, bad), False))
    bad = data.copy(); bad[len(bad) // 2] ^= 1
    cases.append(('proof-body', args(pub, bad), False))
    cases.append(('wrong-chain', args(pub, data, chain=int.from_bytes(b'SN_MAIN', 'big')), False))
    cases.append(('wrong-pool', args(pub, data, pool=hex(int(pub['pool'], 16) + 1)), False))
    cases.append(('wrong-token', args(pub, data, token=hex(int(pub['token'], 16) + 1)), False))
    cases.append(('wrong-root', args(pub, data, root=bump(pub['root'], 4)), False))
    cases.append(('wrong-nullifier', args(pub, data, nullifiers=[pub['nullifiers'][0], bump(pub['nullifiers'][1], 0)]), False))
    if pub['commitments'][0] != pub['commitments'][1]:
        # (A full withdrawal has two zero commitments: swapping them is the same statement.)
        cases.append(('swapped-outputs', args(pub, data, commitments=pub['commitments'][::-1]), False))
    cases.append(('wrong-delivery', args(pub, data, deliveries=[pub['deliveries'][0], hex(int(pub['deliveries'][1], 16) + 1)]), False))
    cases.append(('wrong-withdrawal-recipient', args(pub, data, withdrawal_recipient=hex(int(pub['withdrawal_recipient'], 16) + 1)), False))
    cases.append(('wrong-withdrawal-amount', args(pub, data, withdrawal_amount=int(pub['withdrawal_amount']) + 1), False))
    cases.append(('wrong-intent', args(pub, data, intent=hex(int(pub['intent'], 16) + 1)), False))
    cases.append(('wrong-identity', args(pub, data, identity=bump(pub['identity'], 0)), False))
    # A forged proof (math review M2): valid STARK and LogUp sum for a forged statement, balanced on
    # the absent triple_xor claimed sum. Only the absent-component check can reject it.
    forged_dir = proof_dir / 'forged-absent-sum'
    if forged_dir.exists():
        fpub = json.loads((forged_dir / 'public.json').read_text())
        fdata = [int(x, 16) for x in json.loads((forged_dir / 'cairo-arguments.json').read_text())]
        cases.append(('absent-sum-forgery', args(fpub, fdata), False))
    good = args(pub, data)
    n = len(good) - len(data)
    cases.append(('trailing', good[:n] + [data[0] + 1, *data[1:], 0], False))
    cases.append(('truncated', good[:n] + [data[0] - 1, *data[1:-1]], False))
    report = {'scope': 'standalone Cairo execution of the R0 payment bridge (fork circuit_air); no OS, no PROOF2',
              'executable_sha256': hashlib.sha256((work / 'target/dev/templar_membership_bridge.executable.json').read_bytes()).hexdigest(),
              'expected_binding': hex(expected[-1]), 'cases': []}
    for name, a, accept in cases:
        code, output, usage = run(work, out, name, a)
        ok = (code == 0 and output is not None and [v % ref.P for v in output[-4:]] == expected) if accept else code != 0
        reason = None if accept else next((l.strip() for l in (out / f'{name}.log').read_text().splitlines() if 'panicked' in l.lower()), None)
        if name == 'absent-sum-forgery':
            ok = ok and reason is not None and 'absent component claims a nonzero sum' in reason
        row = {'name': name, 'expected_accept': accept, 'passed': ok, 'exit_code': code, 'output': output, 'usage': usage, 'reason': reason}
        report['cases'].append(row)
        steps = json.loads(usage)['resources']['n_steps'] if usage else None
        print(json.dumps({'name': name, 'passed': ok, 'steps': steps, 'reason': reason}), flush=True)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    assert all(c['passed'] for c in report['cases'])


if __name__ == '__main__':
    main()
