"""Execute the circuit-A bridge on a real circuit-A proof: exact statement acceptance and
rejection of altered statements and encodings. Standalone Cairo only; no OS, no proof."""
from pathlib import Path
import hashlib, json, subprocess, sys

HERE = Path(__file__).resolve().parent
SCARB = '/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb'
CHAIN = int.from_bytes(b'SN_SEPOLIA', 'big')


def run(work, out, name, args):
    path = out / f'{name}.arguments.json'
    path.write_text(json.dumps([hex(a) for a in args]))
    r = subprocess.run([SCARB, '--json', '--manifest-path', str(work / 'Scarb.toml'), 'execute', '--no-build',
                        '-p', 'templar_membership_bridge', '--arguments-file', str(path),
                        '--print-program-output', '--print-resource-usage', '--output', 'none'],
                       capture_output=True, text=True, timeout=1800)
    (out / f'{name}.log').write_text(r.stdout + r.stderr)
    lines = [json.loads(l) for l in r.stdout.splitlines() if l.startswith('{') and '"program_output"' in l]
    output = list(map(int, lines[-1]['program_output'].split())) if lines else None
    usage = [l for l in r.stdout.splitlines() if 'steps' in l.lower()]
    return r.returncode, output, usage[-1] if usage else None


def main():
    work, proof_dir, public_path, out = map(Path, sys.argv[1:5])
    out.mkdir(parents=True, exist_ok=False)
    public = json.loads(public_path.read_text())
    pool = int(public['pool'], 16)
    assert int(public['chain'], 16) == CHAIN
    data = [int(x, 16) for x in json.loads((proof_dir / 'cairo-arguments.json').read_text())]
    assert data[0] == len(data) - 1 and data[1] == 17, 'span length and 17 outputs'
    expected = [0, CHAIN, pool, *public['root']]  # leading 0: panic-free status word
    cases = [('valid', [CHAIN, pool, *data], True)]
    bad = data.copy(); bad[2] ^= 1
    cases.append(('digest-output', [CHAIN, pool, *bad], False))
    bad = data.copy(); bad[2 + 8 * 4] ^= 1
    cases.append(('root-output', [CHAIN, pool, *bad], False))
    cases.append(('wrong-pool', [CHAIN, pool + 1, *data], False))
    cases.append(('wrong-chain', [int.from_bytes(b'SN_MAIN', 'big'), pool, *data], False))
    cases.append(('trailing', [CHAIN, pool, data[0] + 1, *data[1:], 0], False))
    cases.append(('truncated', [CHAIN, pool, data[0] - 1, *data[1:-1]], False))
    report = {'scope': 'standalone Cairo execution of circuit-A bridge; no OS, no PROOF2',
              'executable_sha256': hashlib.sha256((work / 'target/dev/templar_membership_bridge.executable.json').read_bytes()).hexdigest(),
              'cases': []}
    for name, args, accept in cases:
        code, output, usage = run(work, out, name, args)
        ok = (code == 0 and output is not None and output[-len(expected) + 1:] == expected[1:]) if accept else code != 0
        row = {'name': name, 'expected_accept': accept, 'passed': ok, 'exit_code': code, 'output': output, 'usage': usage}
        report['cases'].append(row)
        print(json.dumps(row), flush=True)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    assert all(c['passed'] for c in report['cases'])


if __name__ == '__main__':
    main()
