"""Independent scalar-integer oracle and Cairo fixtures; public synthetic inputs only.

Constants are parsed verbatim from the pinned Plonky3 source, while the linear
layers and sponge are implemented here with Python integers and explicit matrices.
The native specialist separately runs the actual Plonky3 implementation.
"""
from pathlib import Path
import hashlib
import json
import re

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SOURCE = REPO / 'target/m31-tree/upstream-plonky3/mersenne-31/src/poseidon2.rs'
P = 2**31 - 1
STARK = 2**251 + 17*2**192 + 1
TAG = [0x544d5031, 1]


def constants(suffix, count):
    source = SOURCE.read_text().split('pub const MERSENNE31_POSEIDON2_RC_24_' + suffix, 1)[1]
    source = source.split('= ', 1)[1]
    source = source.split('];', 1)[0] if suffix != 'INTERNAL' else source.split(']);', 1)[0]
    values = [int(s, 16) for s in re.findall(r'0x[0-9a-fA-F]+', source)]
    assert len(values) == count and all(0 <= x < P for x in values)
    return values


INITIAL = constants('EXTERNAL_INITIAL', 96)
FINAL = constants('EXTERNAL_FINAL', 96)
INTERNAL = constants('INTERNAL', 22)


def external(v):
    matrix = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
    blocks = [sum(row[j] * v[i+j] for j in range(4)) % P
              for i in range(0, 24, 4) for row in matrix]
    return [(blocks[i] + sum(blocks[k] for k in range(i % 4, 24, 4))) % P
            for i in range(24)]


def permute(v):
    assert len(v) == 24 and all(0 <= x < P for x in v)
    v = external(v)
    for row in range(4):
        v = external([pow((x + INITIAL[24*row+i]) % P, 5, P) for i, x in enumerate(v)])
    for rc in INTERNAL:
        v[0] = pow((v[0] + rc) % P, 5, P)
        total = sum(v)
        v = [(total - 2*v[0]) % P] + [(total + (1 << (i-1))*v[i]) % P for i in range(1, 24)]
    for row in range(4):
        v = external([pow((x + FINAL[24*row+i]) % P, 5, P) for i, x in enumerate(v)])
    return v


def sponge(message):
    assert all(0 <= x < P for x in message)
    state = [0]*24
    offset = 0
    while True:
        rest = len(message)-offset
        take = min(rest, 15)
        state[:take] = message[offset:offset+take]
        if take < 15:
            state[take:15] = [1] + [0]*(14-take)
        elif rest == 15:
            state[15] = (state[15]+1) % P
        state = permute(state)
        if rest <= 15:
            return state[:9]
        offset += take


def leaf(value):
    assert 0 <= value < STARK
    return sponge(TAG+[1, 0]+[(value >> (28*i)) & (2**28-1) for i in range(9)])


def node(level, left, right):
    assert 1 <= level <= 32 and len(left) == len(right) == 9
    return sponge(TAG+[2, level]+left+right)


def packed(v):
    assert len(v) == 9 and all(0 <= x < P for x in v)
    return [str(sum(v[i] << (31*i) for i in range(8))), str(v[8])]


def main():
    expected = [0x2040f051,0x7261dbfa,0x4fbd519e,0x2320ecaf,0x039ef27c,0x48d60ad5,
                0x73ca17ff,0x6023111a,0x6c5e31e7,0x373cd90d,0x75a3ae11,0x00ecc878,
                0x33a7c097,0x244c2171,0x7552a38e,0x58d20817,0x00feecb7,0x47c43c88,
                0x30d3001c,0x24d09ba6,0x71f241d9,0x1c72ab2e,0x4749f79d,0x61ff7579]
    assert permute(list(range(24))) == expected, 'upstream permutation golden mismatch'
    permutations = [{'input': x, 'output': permute(x)} for x in
                    [list(range(24)), [0]*24, [P-1 if i % 2 else i for i in range(24)]]]
    sponges = [{'input': list(range(n)), 'output': sponge(list(range(n)))}
               for n in [0, 1, 4, 13, 14, 15, 16, 22, 29, 30, 31]]
    leaves = [{'input': str(x), 'output': leaf(x)} for x in [*range(33), 2**28-1, 2**28, 2**248, STARK-1]]
    zeros = [sponge(TAG+[3, 0])]
    for level in range(1, 33): zeros.append(node(level, zeros[-1], zeros[-1]))
    nodes = [{'level': level, 'left': left, 'right': right, 'output': node(level, left, right)}
             for level, left, right in [(1, list(range(9)), [P-1-i for i in range(9)]),
                                       (32, [P-1]*9, [0]*9)]]
    stored = {}
    roots = []
    for index in range(32):
        value = leaf(index+1)
        stored[0, index] = value
        current = index
        for level in range(32):
            sibling = stored.get((level, current ^ 1), zeros[level])
            value = node(level+1, value, sibling) if current % 2 == 0 else node(level+1, sibling, value)
            current //= 2
            stored[level+1, current] = value
        roots.append({'count': index+1, 'root': value, 'packed': packed(value)})
    oracle_path = HERE/'client/fixtures/golden-vectors.json'
    oracle = json.loads(oracle_path.read_text())
    for v in oracle['permutations']: assert permute(v['input']) == v['output']
    for v in oracle['sponges']: assert sponge(v['input']) == v['digest']
    for v in oracle['leaves']: assert leaf(int(v['felt'], 0)) == v['digest']
    for v in oracle['nodes']: assert node(v['level'], v['left'], v['right']) == v['digest']
    assert zeros == oracle['empty']
    for a, b in zip(roots, oracle['append_roots'], strict=True):
        assert a['count'] == b['count'] and a['root'] == b['root']
        assert list(map(int, a['packed'])) == [int(v, 0) for v in b['packed']]
    result = {'scope': 'Independent Python integer reference; all native Plonky3 oracle vectors matched',
              'plonky3_oracle_sha256': hashlib.sha256(oracle_path.read_bytes()).hexdigest(),
              'native_oracle_cases': {k:len(v) for k,v in oracle.items() if isinstance(v,list)},
              'reference_commit': '00fe0a985b398d3ef1f10d69543ca2b8f9f236da',
              'constants_source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
              'permutations': permutations, 'sponges': sponges, 'leaves': leaves,
              'empty_hashes': zeros, 'nodes': nodes, 'roots': roots}
    (HERE/'results/cairo-reference-vectors.json').write_text(json.dumps(result, indent=2)+'\n')
    output = ['//! Generated exact Plonky3 width24 constants. See generate-cairo-vectors.py and bundled licenses.']
    for name, values in [('initial_constants', INITIAL), ('internal_constants', INTERNAL), ('final_constants', FINAL)]:
        output.append(f'pub fn {name}() -> Array<u32> {{ array![{",".join(map(str, values))}] }}')
    (HERE/'cairo/src/m31_constants.cairo').write_text('\n\n'.join(output)+'\n')
    tests = ['use m31_tree_bench::m31_hash::{permutation,sponge,leaf_hash,node_hash,empty_leaf,pack,unpack,Digest};']
    def arr(xs): return 'array!['+','.join(map(str,xs))+']'
    for i,v in enumerate(permutations):
        tests.append(f'#[test]\nfn permutation_golden_{i}() {{ assert_eq!(permutation({arr(v["input"])}.span()), {arr(v["output"])}); }}')
    for i,v in enumerate(sponges):
        tests.append(f'#[test]\nfn sponge_golden_{i}() {{ assert_eq!(unpack(sponge({arr(v["input"])}.span())), {arr(v["output"])}); }}')
    for i,v in enumerate([leaves[0],leaves[1],leaves[16],*leaves[-4:]]):
        tests.append(f'#[test]\nfn leaf_golden_{i}() {{ assert_eq!(unpack(leaf_hash({v["input"]})), {arr(v["output"])}); }}')
    for i,v in enumerate(nodes):
        tests.append(f'#[test]\nfn node_golden_{i}() {{ assert_eq!(unpack(node_hash({v["level"]},pack({arr(v["left"])}.span()),pack({arr(v["right"])}.span()))), {arr(v["output"])}); }}')
    tests.append(f'#[test]\nfn empty_leaf_golden() {{ assert_eq!(unpack(empty_leaf()), {arr(zeros[0])}); }}')
    def digest(v):
        lo,hi=packed(v); return f'Digest {{ low: {lo}, high: {hi} }}'
    tests.append('pub fn expected_root(count: u32) -> Digest { match count { '+
                 ','.join(f'{v["count"]} => {digest(v["root"])}' for v in roots)+
                 ', _ => panic!("unknown golden root") } }')
    tests.append(f'pub fn expected_empty_root() -> Digest {{ {digest(zeros[32])} }}')
    (HERE/'cairo/src/golden.cairo').write_text('\n\n'.join(tests)+'\n')
    print(json.dumps({'permutation_cases': len(permutations), 'sponge_cases': len(sponges),
                      'prefix_roots': len(roots), 'upstream_permutation_golden': True}))


if __name__ == '__main__': main()
