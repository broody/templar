"""Execute the P1 policy bridge on a real client proof: exact statement and binding acceptance,
and rejection of every altered statement field, altered outputs and encodings, an absent-component
claimed sum, and an R0 proof. The binding is recomputed independently (`policy_note.binding`,
reference Poseidon). Standalone Cairo only; no OS, no proof.

`validate_bridge_p1.py WORK P1_PROOF_DIR OUT [R0_PROOF_DIR]`"""
from pathlib import Path
import hashlib, importlib.util, json, sys
from validate_bridge_proving import CHAIN, run

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('policy_note', HERE.parents[1] / 'm31-pool/policy_note.py')
pn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pn)
P = 2**31 - 1
N_LIMBS = 164
CLAIMED_SUMS = 2 + N_LIMBS + 1
FIELDS = ['chain', 'pool', 'token', 'root', 'nullifier', 'commitments', 'deliveries', 'withdrawal_recipient',
          'withdrawal_amount', 'controller', 'controller_class', 'handle', 'policy_id', 'deadline', 'not_before',
          'index', 'kind', 'x', 'data']


def statement_args(p):
    """Serde of the bridge's `Statement` (fixed arrays without a length, spans with one)."""
    h = lambda v: int(v, 16) if isinstance(v, str) else int(v)
    span = lambda xs: [len(xs), *xs]
    return [h(p['chain']), h(p['pool']), h(p['token']), *span(p['root']), *span(p['nullifier']),
            *span(p['commitments'][0]), *span(p['commitments'][1]), h(p['deliveries'][0]), h(p['deliveries'][1]),
            h(p['withdrawal_recipient']), int(p['withdrawal_amount']), h(p['controller']), h(p['controller_class']),
            h(p['handle']), *span(p['policy_id']), int(p['deadline']), int(p['not_before']), int(p['index']),
            int(p['kind']), int(p['x']), h(p['data'])]


def main():
    work, proof_dir, out = map(Path, sys.argv[1:4])
    r0_dir = Path(sys.argv[4]) if len(sys.argv) > 4 else None
    out.mkdir(parents=True, exist_ok=False)
    pub = json.loads((proof_dir / 'public.json').read_text())
    assert int(pub['chain'], 16) == CHAIN
    data = [int(x, 16) for x in json.loads((proof_dir / 'cairo-arguments.json').read_text())]
    assert data[0] == len(data) - 1 and data[1] == 41, 'span length and 41 outputs'
    eq, triple_xor = CLAIMED_SUMS, CLAIMED_SUMS + 2 * 4
    assert data[eq:eq + 4] != [0] * 4 and data[triple_xor:triple_xor + 4] == [0] * 4, 'claimed-sum layout'
    expected = [CHAIN, int(pub['pool'], 16), int(pub['token'], 16), pn.binding(pub)]
    bump_hex = lambda v: hex(int(v, 16) + 1)
    bump = lambda xs, i: [(x + 1) % P if k == i else x for k, x in enumerate(xs)]
    args = lambda p, d=data: statement_args(p) + d
    cases = [('valid', args(pub), True)]
    for name, limb in [('tag', 0), ('nullifier-output', 38), ('commitment-output', 47), ('policy-id-output', 127),
                       ('index-output', 144), ('x-output', 146), ('data-output', 154)]:
        bad = data.copy(); bad[2 + limb] = (bad[2 + limb] + 1) % P
        cases.append((name, args(pub, bad), False))
    bad = data.copy(); bad[eq] = (bad[eq] - 1) % P; bad[triple_xor] = 1
    cases.append(('absent-claimed-sum', args(pub, bad), False))
    bad = data.copy(); bad[len(bad) // 2] ^= 1
    cases.append(('proof-body', args(pub, bad), False))
    # Every statement field altered in the expected statement.
    altered = {
        'chain': hex(int.from_bytes(b'SN_MAIN', 'big')), 'pool': bump_hex(pub['pool']), 'token': bump_hex(pub['token']),
        'root': bump(pub['root'], 4), 'nullifier': bump(pub['nullifier'], 0),
        'commitments': [pub['commitments'][1], pub['commitments'][0]],
        'deliveries': [pub['deliveries'][0], bump_hex(pub['deliveries'][1])],
        'withdrawal_recipient': bump_hex(pub['withdrawal_recipient']), 'withdrawal_amount': int(pub['withdrawal_amount']) + 1,
        'controller': bump_hex(pub['controller']), 'controller_class': bump_hex(pub['controller_class']),
        'handle': bump_hex(pub['handle']), 'policy_id': bump(pub['policy_id'], 3), 'deadline': int(pub['deadline']) + 1,
        'not_before': int(pub['not_before']) + 1, 'index': (int(pub['index']) + 1) % 4, 'kind': 3 - int(pub['kind']),
        'x': int(pub['x']) + 1, 'data': bump_hex(pub['data']),
    }
    assert set(altered) == set(FIELDS)
    for field, value in altered.items():
        cases.append((f'wrong-{field}', args({**pub, field: value}), False))
    if r0_dir:
        # An R0 proof is not a P1 proof: different circuit hash (and tag and output count).
        r0 = [int(x, 16) for x in json.loads((r0_dir / 'cairo-arguments.json').read_text())]
        cases.append(('r0-proof', args(pub, r0), False))
    good = args(pub)
    n = len(good) - len(data)
    cases.append(('trailing', good[:n] + [data[0] + 1, *data[1:], 0], False))
    cases.append(('truncated', good[:n] + [data[0] - 1, *data[1:-1]], False))
    report = {'scope': 'standalone Cairo execution of the P1 policy bridge (fork circuit_air); no OS, no PROOF2',
              'executable_sha256': hashlib.sha256((work / 'target/dev/templar_membership_bridge.executable.json').read_bytes()).hexdigest(),
              'expected_binding': hex(expected[-1]), 'cases': []}
    for name, a, accept in cases:
        code, output, usage = run(work, out, name, a)
        ok = (code == 0 and output is not None and [v % pn.ref.P for v in output[-4:]] == expected) if accept else code != 0
        reason = None if accept else next((l.strip() for l in (out / f'{name}.log').read_text().splitlines() if 'panicked' in l.lower()), None)
        row = {'name': name, 'expected_accept': accept, 'passed': ok, 'exit_code': code, 'output': output, 'usage': usage, 'reason': reason}
        report['cases'].append(row)
        steps = json.loads(usage)['resources']['n_steps'] if usage else None
        print(json.dumps({'name': name, 'passed': ok, 'steps': steps, 'reason': reason}), flush=True)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    assert all(c['passed'] for c in report['cases'])


if __name__ == '__main__':
    main()
