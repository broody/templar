"""Execute the arithmetic-profile client bridge on a real client proof: exact statement
acceptance, rejection of altered statements and encodings, and rejection of a claimed sum moved
onto an absent component. Standalone Cairo only; no OS, no proof."""
from pathlib import Path
import hashlib, json, sys
from validate_bridge_proving import CHAIN, run

P = 2**31 - 1
N_OUTPUT_LIMBS = 32
# Serialized CircuitProof: [len, n_outputs, 32 output limbs, interaction_pow, claimed sums (4 each) ...]
CLAIMED_SUMS = 2 + N_OUTPUT_LIMBS + 1


def main():
    work, proof_dir, public_path, out = map(Path, sys.argv[1:5])
    out.mkdir(parents=True, exist_ok=False)
    public = json.loads(public_path.read_text())
    pool = int(public['pool'], 16)
    assert int(public['chain'], 16) == CHAIN
    data = [int(x, 16) for x in json.loads((proof_dir / 'cairo-arguments.json').read_text())]
    assert data[0] == len(data) - 1 and data[1] == 8, 'span length and 8 outputs'
    eq, triple_xor = CLAIMED_SUMS, CLAIMED_SUMS + 2 * 4
    assert data[eq:eq + 4] != [0] * 4 and data[triple_xor:triple_xor + 4] == [0] * 4, 'claimed-sum layout'
    root = public['root']
    rs = [len(root), *root]
    expected = [CHAIN, pool, *root]
    cases = [('valid', [CHAIN, pool, *rs, *data], True)]
    bad = data.copy(); bad[2] ^= 1
    cases.append(('tag', [CHAIN, pool, *rs, *bad], False))
    bad = data.copy(); bad[2 + 20] = (bad[2 + 20] + 1) % P
    cases.append(('root-output', [CHAIN, pool, *rs, *bad], False))
    bad = data.copy(); bad[eq] = (bad[eq] - 1) % P; bad[triple_xor] = 1
    cases.append(('absent-claimed-sum', [CHAIN, pool, *rs, *bad], False))
    bad = data.copy(); bad[len(bad) // 2] ^= 1
    cases.append(('proof-body', [CHAIN, pool, *rs, *bad], False))
    cases.append(('wrong-pool', [CHAIN, pool + 1, *rs, *data], False))
    cases.append(('wrong-chain', [int.from_bytes(b'SN_MAIN', 'big'), pool, *rs, *data], False))
    wrong = root.copy(); wrong[4] = (wrong[4] + 1) % P
    cases.append(('wrong-root', [CHAIN, pool, len(wrong), *wrong, *data], False))
    cases.append(('trailing', [CHAIN, pool, *rs, data[0] + 1, *data[1:], 0], False))
    cases.append(('truncated', [CHAIN, pool, *rs, data[0] - 1, *data[1:-1]], False))
    report = {'scope': 'standalone Cairo execution of the arithmetic-profile client bridge (fork circuit_air); no OS, no PROOF2',
              'executable_sha256': hashlib.sha256((work / 'target/dev/templar_membership_bridge.executable.json').read_bytes()).hexdigest(),
              'cases': []}
    for name, args, accept in cases:
        code, output, usage = run(work, out, name, args)
        ok = (code == 0 and output is not None and output[-len(expected):] == expected) if accept else code != 0
        reason = next((l.strip() for l in (out / f'{name}.log').read_text().splitlines() if 'panicked' in l.lower() or 'error' in l.lower()), None)
        row = {'name': name, 'expected_accept': accept, 'passed': ok, 'exit_code': code, 'output': output, 'usage': usage, 'reason': None if accept else reason}
        report['cases'].append(row)
        print(json.dumps({k: row[k] for k in ('name', 'passed', 'usage', 'reason')}), flush=True)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    assert all(c['passed'] for c in report['cases'])


if __name__ == '__main__':
    main()
