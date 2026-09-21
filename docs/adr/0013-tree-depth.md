# ADR-0013: Tree depth 32

- Status: Accepted
- Date: 2026-09-20
- Deciders: broody
- Amends: spec §2 (`TREE_DEPTH`), §9.2 cost figures; m1-invariant-review §E/§D.4.

## Context

`TREE_DEPTH = 64` was frozen at spec time without a capacity argument. It is the
dominant recurring cost on both sides of the system:

- **On-chain**: every leaf insert rehashes 64 levels (64 sibling reads + 64 node
  writes + 64 Poseidon) — measured ~11.3 M l2 gas steady-state (review §E), the
  largest line item in every spend and in `deposit()`.
- **In-circuit**: the membership path is 64 × H(a,b) = 128 non-native
  permutations per input note — ~85% of the M2 statement's constraints (measured
  5.33 M constraints for a 1-in/1-out statement with the general emulated
  layer), and therefore the binding constraint on the M4 phone-proving budget.

Capacity need not exceed the pool's lifetime leaf count. 2^64 is absurdly
over-provisioned; even 2^32 ≈ 4.3 B leaves sustains 1 M new notes/day for ~12
years (every note creation consumes one leaf, including change and transfer
outputs), and orders of magnitude more at realistic volumes. Worst case, a full
tree is a redeploy-and-migrate event (notes are portable via spend-into-v3),
not a protocol failure.

## Decision

`TREE_DEPTH = 32` (2^32 leaves). Amends the spec §2 constants table; the M2
circuit (`packages/circuit`) follows the same constant. Landed before the
Groth16 ceremony precisely because depth is baked into the circuit — after the
ceremony this change would cost a re-run.

## Alternatives considered

- **Keep 64** — rejected: pays ~2× insert gas and ~1.45× circuit size forever
  for capacity no deployment will ever use.
- **Depth 40** (1.1 T leaves) — the conservative middle: +25% insert gas and
  path constraints vs 32, for headroom beyond any plausible adoption curve.
  Rejected as unneeded insurance; noted here in case 2^32 ever feels tight.
- **Depth 20 (Tornado's)** — rejected the other way: 1 M leaves is inside real
  usage for a successful pool with change notes.

## Consequences

- Insert gas halves (re-measured in review §E); `deposit()` and every spend get
  cheaper by the same stroke. Constructor zero-chain init halves too.
- Circuit membership cost halves: ~64 of ~148 permutations per input note
  disappear; the 1-in/1-out statement drops from 5.33 M to **3.12 M**
  constraints with the general emulated layer (measured in `packages/circuit`,
  Groth16 prove+verify passing), and the optimized-limb target (ADR-0008) moves
  the phone-proving budget accordingly.
- Capacity is now a *finite* documented quantity (2^32 leaves) with a stated
  mitigation (migration); review §D.4 updated.
- All Merkle paths, the zero-hash chain, and golden fixtures change — pinned by
  re-run test suites on both sides (Cairo + gnark).
