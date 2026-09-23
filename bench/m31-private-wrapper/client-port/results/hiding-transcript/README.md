# Hiding: full-transcript invariant search with pinned challenges

2026-09-23 (`examples/hiding_transcript.rs`, fork `4de7408a6`). **No linear combination of
everything a proof reveals depends on the witness.** That includes FRI, composition and
interaction values. It holds at the production query count, on a small circuit with private
multiplications.

## Method

1. **Pinned challenges.** A test-only channel (`PinnedChannel` / `PinnedMC`) ignores
   everything mixed into it and accepts PoW nonce 0. The OODS point, the lookup and DEEP
   coefficients, the FRI folding values and the query positions are therefore identical for
   every proof. The prover itself is unmodified (`prove_circuit_assignment_bounded`).
2. **Revealed vector per proof.** OODS samples and opened values of the base, interaction and
   composition trees; every FRI layer's witness values; the last-layer polynomial; the claimed
   LogUp sums.
3. **Seed invariants.** Prove one witness under many seeds and rank the differences. The
   kernel holds every linear combination that no seed changes.
4. **Witness dependence.** Many invariants are public structure that holds for every honest
   transcript: FRI folding, DEEP quotients, low-degree relations in the small last layers,
   and the LogUp balance. So each invariant is evaluated on a **second witness with the same
   public output** (the circuit's output is `acc + (0 − acc) = 0`). An invariant whose value
   moves is a leak.

## Results

| Run | Coordinates | Seeds | Rank | Invariants | Witness-dependent |
| --- | ---: | ---: | ---: | ---: | ---: |
| 35 queries (production), 2¹⁴ trace, 1,830 blinding iterations | 6,449 | 5,676 | 5,636 | 813 | **0** |
| 5 queries, 2¹¹ trace, 210 iterations | 1,049 | 1,012 | 972 | 77 | **0** |
| Control: 5 queries, pre-fix blinding | 1,049 | 976 | 936 | 113 | **72** |

- **The control.** It has 36 more invariants than the fixed run: 4 limbs × (5 queries + 4 OODS
  coordinates), exactly H2 at this scale. 72 of its invariant basis vectors take a different
  value on the second witness.
- **The 813 invariants at 35 queries**, by the coordinate each one is solved for:
  - 768 deep FRI layer witnesses and 5 last-layer coefficients: folding and low-degree
    structure;
  - 36 claimed sums of the 9 absent components, always zero;
  - 4 for `qm31_ops`' claimed sum, which the LogUp balance fixes from `eq`'s sum and the
    public outputs.

  All are witness-independent. The 35-query run took 8.4 minutes.

## What this shows, and what it does not

- **Shown.** With the challenges fixed, the linear span of the whole revealed transcript
  varies with the seed in every witness-dependent direction. This is H2's check applied to
  every value a proof carries, including the nonlinear interaction and composition trees and
  all FRI layers.
- **Not shown:**
  - **Nonlinear relations.** A witness-dependent polynomial relation of degree ≥ 2 among
    revealed values would not appear.
  - **Distribution, beyond linear structure.** In particular the interaction columns'
    `1/(γ − ·)` values.
  - **The real circuit.** The circuit is small and synthetic. The blinding is
    circuit-independent, but the R0 circuit itself was not run end to end this way. Its base
    and interaction openings were covered by `hiding_invariants` and `hiding_points`.
  - **Merkle hashes of unopened leaves.** These need the random-oracle argument.
