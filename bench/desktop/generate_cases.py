#!/usr/bin/env python3
"""Generate identical chained pair-hash workloads for the two field choices."""
from pathlib import Path
import shutil
ROOT=Path(__file__).resolve().parent
source=(ROOT.parent/'adr16/src/main.nr').read_text().split('fn main(')[0]
for family in ['felt','native']:
    for n in [1,2,4,8,16,32,64,256]:
        d=ROOT/'cases'/f'{family}-{n}';(d/'src').mkdir(parents=True,exist_ok=True)
        deps='\n[dependencies]\nbignum = { path = "../../../../adr16/vendor/noir-bignum" }\n' if family=='felt' else ''
        # Resolve from Nargo.toml: cases/felt-N -> desktop -> bench -> adr16.
        deps=deps.replace('../../../../adr16','../../../adr16')
        (d/'Nargo.toml').write_text('[package]\nname = "bench"\ntype = "bin"\nauthors = [""]\ncompiler_version = ">=1.0.0"\n'+deps)
        (d/'Prover.toml').write_text('a = "1"\nb = "2"\n')
        if family=='felt':
            shutil.copy2(ROOT.parent/'adr16/src/ark_constants.nr',d/'src/ark_constants.nr')
            main=source+f'''fn main(a: Field, b: Field) -> pub Felt252 {{
    let mut acc = Felt252::from(a);
    let mut cur = Felt252::from(b);
    for _ in 0..{n} {{
        acc = hash_pair(acc, cur);
        cur = cur + Felt252::one();
    }}
    acc
}}
'''
        else:
            main=f'''fn main(a: Field, b: Field) -> pub Field {{
    let mut acc = a;
    for i in 0..{n} {{
        acc = std::hash::poseidon2_permutation([acc, b + i as Field, 0, 2 * 18446744073709551616], 4)[0];
    }}
    acc
}}
'''
        (d/'src/main.nr').write_text(main)
