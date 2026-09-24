"""Known-answer/differential executions of the exact Cairo Blake component."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
from workload import HERE, NEW_PREFIX, frame, candidate_message, inspect, packed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--public', type=Path, required=True)
    parser.add_argument('--proof', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    _, unique, workload = inspect(args.public, args.proof)
    cases = [('abc-rfc7693', b'abc')]
    assert hashlib.blake2s(b'abc').hexdigest() == '508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982'
    cases += [(f'boundary-{n}', bytes((i * 73 + 11) % 256 for i in range(n))) for n in (0, 1, 63, 64, 65, 127, 128, 129)]
    for kind in ('node', 'small', 'base', 'claims'):
        job = next(j for j in unique if j['kind'] == kind)
        cases.append((f'original-frame-{kind}', job['message']))
        cases.append((f'candidate-frame-{kind}', candidate_message(job)))
    if workload['format'] == 'TMPZK002':
        client = HERE.parent / 'm31-private-blake/client'
        circuit = frame(b'circuit', [(client / 'src' / name).read_bytes() for name in
                         ['air.rs', 'hash.rs', 'constants.rs', 'poly.rs', 'crypto.rs', 'proof.rs']], NEW_PREFIX)
        public = json.loads(args.public.read_text())
        x = b'TMPZK002' + hashlib.blake2s(circuit).digest() + json.dumps(public, separators=(',', ':')).encode()
        public_message = frame(b'public', [x], NEW_PREFIX)
        proof = args.proof.read_bytes()
        state = frame(b'state', [bytes(4), proof[8:40], hashlib.blake2s(public_message).digest()], NEW_PREFIX)
        coins = frame(b'coins', [x, proof[488:520], (15).to_bytes(4, 'little'), (14).to_bytes(4, 'little')], NEW_PREFIX)
        cases.extend([('actual-circuit', circuit), ('actual-public', public_message), ('actual-state', state), ('actual-coins-block14', coins)])
    rows = []
    for name, message in cases:
        words = packed(message)
        arguments = out / (name + '.arguments.json')
        arguments.write_text(json.dumps([hex(x) for x in [len(message), len(words), *words]]))
        command = ['scarb', '--json', '--manifest-path', str(HERE / 'blake/Scarb.toml'),
                   'execute', '--no-build', '--arguments-file', str(arguments),
                   '--print-program-output', '--print-resource-usage', '--output', 'none']
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (out / (name + '.stdout.log')).write_text(result.stdout)
        (out / (name + '.stderr.log')).write_text(result.stderr)
        assert result.returncode == 0, (name, result.stderr, result.stdout)
        execution = next(json.loads(line) for line in result.stdout.splitlines() if '"program_output"' in line)
        values = list(map(int, execution['program_output'].split()))
        assert values[0] == 8
        digest = b''.join(word.to_bytes(4, 'little') for word in values[1:])
        assert digest == hashlib.blake2s(message).digest(), name
        row = {'name': name, 'bytes': len(message), 'compressions': max(1, (len(message) + 63) // 64),
               'digest': digest.hex(), 'all_256_bits_match': True, 'resources': execution['resources'], 'command': command}
        rows.append(row)
        print(json.dumps({'case': name, 'bytes': len(message), 'steps': row['resources']['n_steps'], 'passed': True}), flush=True)
    # Encoding negatives: all bytes and the unused high bytes must be constrained.
    for name, serialized in [('padding', [1, 1, 256]), ('length', [1, 0]), ('u32', [4, 1, 2**32]), ('cap', [65537, 0])]:
        path = out / (name + '.arguments.json')
        path.write_text(json.dumps(list(map(hex, serialized))))
        command = ['scarb', '--json', '--manifest-path', str(HERE / 'blake/Scarb.toml'), 'execute', '--no-build', '--arguments-file', str(path), '--output', 'none']
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        (out / (name + '.stdout.log')).write_text(result.stdout)
        (out / (name + '.stderr.log')).write_text(result.stderr)
        assert result.returncode != 0, name
    report = {'status': 'passed', 'scope': 'exact unkeyed Blake2s-256 component, not private proof verification',
              'positive_cases': rows, 'negative_cases': 4, 'workload': workload,
              'source_sha256': hashlib.sha256((HERE / 'blake/src/lib.cairo').read_bytes()).hexdigest()}
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
