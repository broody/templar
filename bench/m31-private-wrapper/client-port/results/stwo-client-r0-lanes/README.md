# R0 payment with lane-packed hashing: log19, half the client memory

2026-09-23. The R0 payment relation from [`../stwo-client-r0/`](../stwo-client-r0/README.md)
now runs its Poseidon2 permutations **four to a row**, one per QM31 lane. The trace drops from
631k to 295k qm31_ops rows, from log20 to log19. The statement, formats and hash values are
unchanged: the native reference is the same and the proof statement matches it. Client memory
halves, and the server stages get lighter too.

| Stage | log20 (one lane) | **log19 (lane-packed)** |
| --- | ---: | ---: |
| Client, 4 threads, normal | 2.2 GiB, 2.5–3.8 s | **1.1 GiB, 2.0–3.6 s** |
| Client, 4 threads, bounded (16 columns) | 1.1 GiB, 4.4–5.2 s | **0.54 GiB, 2.4–2.6 s** |
| Client, 1 thread, normal / bounded | 2.2 / 1.1 GiB, 9.5–30 s | 1.09 / 0.53 GiB, 4.7–14 s |
| Bridge, standalone Cairo | 3.77M steps | 3.53M steps, 15/15 checks |
| Virtual OS | 5.42M steps | 5.13M steps, exact message |
| PROOF2 large path | 139 s / 64.2 GiB | **117.5 s / 55.0 GiB**, verified, 3/3 rejections |

The original client-proves-everything pipeline measured 6.12 GiB / 22.7 s (bounded) and
9.00 GiB / 16.7 s on the same four cores. This client is about 11× lighter in bounded mode.

## How lanes work

A QM31 value has four M31 coordinates. Poseidon2 over M31 uses only operations that act on
each coordinate separately:
- additions;
- multiplication by a base-field constant, since a QM31 times an M31 scalar scales each
  coordinate;
- the S-box products, emitted as `pointwise_mul` gates.

So `sym::compile_lanes` emits the permutation once for four independent states. It broadcasts
added round constants to `(c, c, c, c)` and turns variable products into `pointwise_mul`.
`membership::sponge_lanes` works as follows:
- It packs each absorbed word from four messages with `from_partial_evals`; those inputs are
  base-field values, so the packing is injective.
- It runs the lane permutation.
- It unpacks the digest by guessing each lane as a base-field value and asserting the lanes
  repack to the packed word, so the split is unique.

Lanes without a message hash zeros, and the result is discarded.

R0 schedules its hashes by dependency:

| Stage | Hashes | Lanes |
| --- | --- | ---: |
| Keys | `ak`, `nk` for both inputs | 4 |
| Owners and output inner hashes | `receiver` for both inputs; `inner` for both outputs | 4 |
| Input inner hashes | `inner` for both inputs | 2 |
| Commitments | four note commitments | 4 |
| Membership | both paths, per level | 2 |
| Nullifiers | both nullifiers | 2 |

That is 75 lane-packed permutations instead of 164 single ones.

Tests (`tests/payment_r0.rs`):
- the statement matches the native reference;
- the topology is fixed;
- five broken witnesses fail;
- the native rules;
- finalization with the unused-variable lint.

All 23 client-port tests pass.

## Toward log18

log18 holds 262,144 rows, and the circuit needs 295k. The membership paths are the limit:
each level is two sequential permutations (a 22-word message through a rate-15 sponge), and the
two paths fill only two lanes. Making each tree node **one** permutation would take the paths
from 64 to 32 lane steps, about 170k rows in total. That means a truncated-permutation
compression of the 22-word node input, as Plonky3's Merkle trees do. It is a **format change**
that needs its own security review, so it is not done here.
