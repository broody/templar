"""Prepare a public cost batch; no client private inputs or membership claims."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import struct
from workload import HERE, candidate_message, inspect, packed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--public', type=Path, required=True)
    parser.add_argument('--proof', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--nodes', type=int, default=64)
    parser.add_argument('--base', type=int, default=1)
    parser.add_argument('--small', type=int, default=16)
    parser.add_argument('--claims', type=int, default=1)
    args = parser.parse_args()
    _, unique, workload = inspect(args.public, args.proof)
    spec = importlib.util.spec_from_file_location('public_reference', HERE.parent / 'push-e2e/reference.py')
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)
    selected = []
    for kind, count in [('claims', args.claims), ('base', args.base), ('small', args.small), ('node', args.nodes)]:
        choices = [j for j in unique if j['kind'] == kind]
        assert 0 <= count <= len(choices)
        selected.extend(choices[:count])
    serialized, expected_words, inventory = [len(selected)], [], []
    for job in selected:
        message = candidate_message(job)
        words = packed(message)
        digest = hashlib.blake2s(message).digest()
        expected = list(struct.unpack('<8I', digest))
        serialized += [len(message), len(words), *words, *expected]
        expected_words += expected
        inventory.append({'kind': job['kind'], 'key': job['key'], 'bytes': len(message),
                          'blocks': max(1, (len(message) + 63) // 64), 'blake2s': digest.hex()})
    values = [int.from_bytes(b'BLAKE_COST_V1', 'big'), int.from_bytes(b'SN_SEPOLIA', 'big'),
              len(selected), sum(j['bytes'] for j in inventory), sum(j['blocks'] for j in inventory),
              reference.hash_span(expected_words)]
    result = {'scope': 'candidate hash workload only; no Blake membership proof or privacy claim',
              'candidate_salt_bytes': 192, 'source_workload': workload,
              'calldata': [hex(v) for v in [len(serialized), *serialized]],
              'public_values': list(map(hex, values)), 'expected_digest_words': expected_words,
              'jobs': inventory}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'jobs': len(selected), 'bytes': values[3], 'blocks': values[4], 'calldata_felts': len(serialized) + 1}))


if __name__ == '__main__':
    main()
