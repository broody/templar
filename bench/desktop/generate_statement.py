#!/usr/bin/env python3
from pathlib import Path
import shutil
ROOT=Path(__file__).resolve().parent
native='''fn hash<let N: u32>(values: [Field; N]) -> Field {
    let mut s = [0, 0, 0, N as Field * 18446744073709551616];
    for block in 0..((N + 2) / 3) {
        for j in 0..3 {
            let i = block * 3 + j;
            if i < N { s[j] = s[j] + values[i]; }
        }
        s = std::hash::poseidon2_permutation(s, 4);
    }
    s[0]
}
'''
felt=(ROOT.parent/'adr16/src/main.nr').read_text().split('fn hash_pair(')[0]+'''
fn hash<let N: u32>(values: [Field; N]) -> Field {
    let mut s = [Felt252::zero(); 3];
    for block in 0..(N / 2) {
        Felt252::from(values[block*2]).validate_in_field();
        Felt252::from(values[block*2+1]).validate_in_field();
        s[0] = s[0] + Felt252::from(values[block*2]);
        s[1] = s[1] + Felt252::from(values[block*2+1]);
        s = hades(s);
    }
    if N % 2 == 1 {
        Felt252::from(values[N-1]).validate_in_field();
        s[0] = s[0] + Felt252::from(values[N-1]); s[1] = s[1] + Felt252::one();
    } else { s[0] = s[0] + Felt252::one(); }
    bignum::bignum::to_field(hades(s)[0])
}
'''
tag=lambda x:str(int.from_bytes(x.encode(),'big'))
body='''
struct Input { salt: u128, owner: Field, amount: u128, index: u32, path: [Field; 32] }
struct Invoice { inner: Field, amount: u128 }
fn main(chain: Field, pool: Field, root: Field, token: Field,
        n_in: u32, inputs: [Input; 2], n_out: u32, outputs: [Invoice; 2],
        withdrawal: u128, recipient: Field) -> pub [Field; 8] {
    assert(n_in > 0 & n_in <= 2); assert(n_out <= 2); assert(token != 0);
    if withdrawal == 0 { assert(recipient == 0); } else { assert(recipient != 0); }
    let mut nullifiers = [0; 2]; let mut commitments = [0; 2];
    let mut sum_in: Field = 0; let mut sum_out: Field = withdrawal as Field;
    for i in 0..2 {
        if i < n_in {
            let note = inputs[i]; assert(note.amount > 0);
            let secret = hash([NS, note.salt as Field, note.owner]);
            let inner = hash([NI, secret]);
            let mut node = hash([CM, token, note.amount as Field, 0, 0, inner]);
            for level in 0..32 {
                let right = ((note.index >> level) & 1) == 1;
                let left = if right { note.path[level] } else { node };
                let r = if right { node } else { note.path[level] };
                node = hash([left,r]);
            }
            assert(node == root);
            nullifiers[i] = hash([NF,secret]); assert(nullifiers[i] != 0);
            sum_in = sum_in + note.amount as Field;
        }
        if i < n_out {
            let invoice = outputs[i]; assert(invoice.inner != 0); assert(invoice.amount > 0);
            commitments[i] = hash([CM,token,invoice.amount as Field,0,0,invoice.inner]);
            assert(commitments[i] != 0);
            sum_out = sum_out + invoice.amount as Field;
        }
    }
    if n_in == 2 { assert(nullifiers[0] != nullifiers[1]); }
    assert(sum_in == sum_out);
    let binding = hash([BIND, VERSION,chain,pool,root,n_in as Field,nullifiers[0],nullifiers[1],
                        n_out as Field,commitments[0],commitments[1],token,withdrawal as Field,recipient]);
    [VERSION,chain,pool,root,0,0,0,binding]
}
'''
for name,text in [('NS','NOTE_SECRET_TAG:V3'),('NI','NOTE_INNER_TAG:V3'),('CM','COMMITMENT_TAG:V3'),('NF','NULLIFIER_TAG:V3'),('BIND','TX_BIND_TAG:V2'),('VERSION','TEMPLAR_DESKTOP1')]:
 body=f'global {name}: Field = {tag(text)};\n'+body
for family,head in [('native',native),('felt',felt)]:
 d=ROOT/f'statement-{family}';(d/'src').mkdir(parents=True,exist_ok=True)
 deps='\n[dependencies]\nbignum = { path = "../../adr16/vendor/noir-bignum" }\n' if family=='felt' else ''
 (d/'Nargo.toml').write_text('[package]\nname = "bench"\ntype = "bin"\nauthors = [""]\ncompiler_version = ">=1.0.0"\n'+deps)
 (d/'src/main.nr').write_text('// Experimental ordinary 2/2/1 statement; not a production format.\n'+head+body)
 if family=='felt':shutil.copy2(ROOT.parent/'adr16/src/ark_constants.nr',d/'src/ark_constants.nr')
