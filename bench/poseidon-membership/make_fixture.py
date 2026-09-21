"""Create public synthetic membership vectors using the existing felt reference.

This is fixture construction, not a prover or an implementation of AIR constraints.
No wallet data, keys, network services or randomness are used.
"""
from pathlib import Path
import hashlib
import importlib.util
import json

HERE = Path(__file__).resolve().parent
REFERENCE = HERE.parent / 'stwo-e2e/reference.py'
spec = importlib.util.spec_from_file_location('membership_felt_reference', REFERENCE)
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)


def synthetic_felt(label):
    return int.from_bytes(hashlib.sha256(('templar-public-membership:' + label).encode()).digest(), 'big') % ref.P


def make_fixture():
    depth = 32
    indices = [0x13579BDF, 0xECA86420]
    leaves = [synthetic_felt('leaf-0'), synthetic_felt('leaf-1')]
    nodes = {(0, i): value for i, value in zip(indices, leaves)}
    for level in range(depth):
        parents = {index >> 1 for (height, index) in nodes if height == level}
        for parent in parents:
            left = nodes.get((level, parent * 2), ref.Z[level])
            right = nodes.get((level, parent * 2 + 1), ref.Z[level])
            nodes[level + 1, parent] = ref.hash_span([left, right])
    root = nodes[depth, 0]
    paths = []
    permutations = []
    for path_id, (index, leaf) in enumerate(zip(indices, leaves)):
        current = leaf
        levels = []
        siblings = []
        for level in range(depth):
            bit = (index >> level) & 1
            sibling = nodes.get((level, (index >> level) ^ 1), ref.Z[level])
            left, right = (sibling, current) if bit else (current, sibling)
            first_input = [left, right, 0]
            first_output = ref.hades(first_input)
            second_input = [(first_output[0] + 1) % ref.P, first_output[1], first_output[2]]
            second_output = ref.hades(second_input)
            parent = second_output[0]
            assert parent == ref.hash_span([left, right])
            assert parent == nodes[level + 1, index >> (level + 1)]
            levels.append({'level': level, 'direction_bit': bit, 'left': hex(left),
                           'right': hex(right), 'parent': hex(parent)})
            for phase, inputs, outputs in [('absorb', first_input, first_output), ('finalize', second_input, second_output)]:
                permutations.append({'path': path_id, 'level': level, 'phase': phase,
                                     'input': list(map(hex, inputs)), 'output': list(map(hex, outputs))})
            siblings.append(hex(sibling))
            current = parent
        assert current == root
        paths.append({'index': index, 'leaf': hex(leaf), 'siblings': siblings, 'levels': levels})
    return {
        'classification': 'all values public and synthetic; no wallet secrets; no append-history claim',
        'version': 1, 'depth': depth, 'field_modulus': hex(ref.P),
        'hash': 'core::poseidon::poseidon_hash_span([left,right])',
        'root': hex(root), 'paths': paths, 'parent_hash_count': 64,
        'permutation_count': len(permutations), 'permutations': permutations,
        'reference_file': str(REFERENCE),
        'reference_sha256': hashlib.sha256(REFERENCE.read_bytes()).hexdigest(),
    }


if __name__ == '__main__':
    result = make_fixture()
    assert result['permutation_count'] == 128
    path = HERE / 'fixtures/two-paths.json'
    path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'fixture': str(path), 'root': result['root'],
                      'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                      'paths': 2, 'depth': 32, 'parent_hashes': 64, 'permutations': 128}))
