"""Generate complete public prefix1/2/8 storage fixtures using independent references.

Run with the existing cairo-lang Python environment (see cairo-results.md).
No prover source is imported. node_key and root ring match the copied tree.
"""
from pathlib import Path
import importlib.util
import json
import argparse
from starkware.cairo.common.poseidon_hash import poseidon_hash_many
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('m31reference', HERE/'generate-cairo-vectors.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def tree(leaf, parent, zero):
    zeros=[zero]
    for level in range(1,33): zeros.append(parent(level,zeros[-1],zeros[-1]))
    nodes={}; roots=[]; snapshots={}
    for index in range(32):
        value=leaf(index+1); at=index; nodes[0,at]=value
        for level in range(32):
            sibling=nodes.get((level,at^1),zeros[level])
            value=parent(level+1,value,sibling) if at%2==0 else parent(level+1,sibling,value)
            at//=2;nodes[level+1,at]=value
        roots.append(value)
        if index+1 in [1,2,8]: snapshots[index+1]=dict(nodes)
    return zeros, roots, snapshots

cases=[('felt',tree(lambda x:x, lambda level,a,b:poseidon_hash_many([a,b]), 0)),
       ('m31',tree(m.leaf,m.node,m.sponge(m.TAG+[3,0])))]
text=['//! Generated complete prefix1/2/8 states; generator and references are outside measured calls.',
      'use m31_tree_bench::m31_hash::Digest;']
json_out={}
for kind,(zeros,roots,snapshots) in cases:
    nodes=snapshots[8]
    typ='felt252' if kind=='felt' else 'Digest'
    def fmt(v):
        if kind=='felt': return str(v)
        lo,hi=m.packed(v);return f'Digest {{ low: {lo}, high: {hi} }}'
    text.append(f'pub fn {kind}_nodes() -> Array<(felt252,{typ})> {{ array!['+
                ','.join(f'({index*2**64+level},{fmt(v)})' for (level,index),v in sorted(nodes.items()))+'] }')
    text.append(f'pub fn {kind}_nodes_for(count: u32) -> Array<(felt252,{typ})> {{ match count {{ '+
                ','.join(str(count)+' => array!['+
                    ','.join(f'({index*2**64+level},{fmt(v)})' for (level,index),v in sorted(snapshot.items()))+']'
                    for count,snapshot in snapshots.items())+', _ => panic!("unsupported snapshot") } }')
    text.append(f'pub fn {kind}_history_for(count: u32) -> Array<{typ}> {{\n'
                f"    assert(count <= 8, 'FIXTURE_COUNT');\n"
                f'    let values={kind}_history(); let mut result=array![]; let mut i: usize=0;\n'
                f'    while i <= count {{ result.append(*values.at(i)); i+=1; }}; result\n'+'}')
    text.append(f'pub fn {kind}_zeros() -> Array<{typ}> {{ array!['+','.join(map(fmt,zeros))+'] }')
    text.append(f'pub fn {kind}_history() -> Array<{typ}> {{ array!['+','.join(map(fmt,[zeros[32]]+roots[:8]))+'] }')
    text.append(f'pub fn {kind}_expected(count: u32) -> {typ} {{ match count {{ '+
                ','.join(f'{i+1} => {fmt(v)}' for i,v in enumerate(roots))+', _ => panic!("unknown prefix") } }')
    json_out[kind]={'nodes':[{'level':k[0],'index':k[1],'value':v} for k,v in sorted(nodes.items())],
                    'zeros':zeros,'history':[zeros[32]]+roots[:8],'count':8,'ring_index':9,'roots':roots}
    if kind=='m31':
        oracle=json.loads((HERE/'client/fixtures/golden-vectors.json').read_text())
        assert roots==[v['root'] for v in oracle['append_roots']]
        assert zeros==oracle['empty']
(HERE/'cairo/src/snapshots.cairo').write_text('\n\n'.join(text)+'\n')
parser=argparse.ArgumentParser()
parser.add_argument('--source-only', action='store_true')
args=parser.parse_args()
if not args.source_only:
    (HERE/'results/prefix8-snapshots.json').write_text(json.dumps(json_out,indent=2)+'\n')
print(json.dumps({k:{'nodes':len(v['nodes']),'zeros':len(v['zeros']),'history':len(v['history'])} for k,v in json_out.items()}))
