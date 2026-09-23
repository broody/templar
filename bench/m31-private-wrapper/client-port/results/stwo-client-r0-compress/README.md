# R0 payment with single-permutation tree nodes: log18, ~0.3 GiB client

2026-09-23. **Experimental format variant.** The lane-packed R0 payment
([`../stwo-client-r0-lanes/`](../stwo-client-r0-lanes/README.md)) with each Merkle node hashed
by **one** truncated Poseidon2 permutation instead of a two-permutation sponge. The trace drops
from 295k to 175k rows, from log19 to log18, with the tree still 32 deep. Client memory halves
again. Everything else in the relation and statement is unchanged.

| Stage | Sponge nodes, log19 | **Single-permutation nodes, log18** |
| --- | ---: | ---: |
| Client, 4 threads, normal | 1.1 GiB, 2.0–3.6 s | **0.57–0.59 GiB, 1.4–4.1 s** |
| Client, 4 threads, bounded (16 columns) | 0.54 GiB, 2.4–2.6 s | **0.29–0.31 GiB, 1.7–2.0 s** |
| Client, 1 thread, normal / bounded | 1.09 / 0.53 GiB | 0.56 / 0.28 GiB, 4.7–10.4 s |
| Bridge, standalone Cairo | 3.53M steps | 3.39M steps, 15/15 checks |
| Virtual OS | 5.13M steps | 4.96M steps, exact message |
| PROOF2 large path | 117.5 s / 55.0 GiB | **120.3 s / 54.4 GiB**, verified, 3/3 rejections |

For comparison, the original client-proves-everything pipeline measured 6.12 GiB / 22.7 s
(bounded) on the same four cores, about 20× this client's memory.

## The node format

```
node(level, left, right) = P([TAG, 1, NODE1, level, left₀..₈, right₀..₈, 0, 0])[0..9]
```

`P` is the client's width-24 Poseidon2-M31 permutation. `TAG = 'TMR0'` and `NODE1 = 8`, a kind
used by no sponge-mode hash; every sponge frame carries its own kind in the same position.
The output is truncated to nine words (279 bits). This is the construction Plonky3 uses for
Merkle compression (`TruncatedPermutation`, over BabyBear at width 16). The sponge format used
two permutations per node because the 22-word input exceeds its rate of 15.

`payment::Tree` selects the format: `Tree::Sponge` is the default, and `Tree::Compress` is this
variant (`prove_payment_r0 … --compress-nodes`). The two give different roots for the same notes
(`tests/payment_r0.rs::tree_formats_differ`). The pinned circuit hash tells the bridge which
circuit a proof is for.

## Tests

`tests/payment_r0.rs` runs every check for both formats:
- the circuit statement matches the native reference;
- the topology is fixed;
- five broken witnesses fail;
- the native rules;
- finalization with the unused-variable lint.

All client-port tests pass.

## Needs review before adoption

Security of truncated-permutation compression rests on the permutation behaving like a random
permutation. With 22 of 24 words controlled by the input, the generic collision bound for a
279-bit output is about 2^139. A review must still confirm:
1. that the permutation's round numbers (chosen for sponge use) hold for compression, where an
   attacker controls more of the state;
2. that fixing the capacity-like tail to `[0, 0]` and the frame words is sound domain separation
   from the sponge-mode hashes;
3. the intended security level for Merkle collision resistance against the protocol's 96-bit
   (classical) target.

Until then this is a measured option, not an adopted format. The depth-32 sponge-node tree
remains the reference R0 format.
