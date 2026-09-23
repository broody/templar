# Hiding finding H2: add-gate blinding leaves `dst − op0 − op1` unblinded

2026-09-23. First result of the [hiding test plan](../../reviews/hiding-test-plan.md).
**The arithmetic-profile R0 proof reveals witness-only values.** The H1 fix (enough blinding
rows) does not address this: the problem is the structure of the blinding rows.

## Cause

`circuit_common::finalize::qm31_zk_blinding` blinds `qm31_ops` with three add gates per
iteration: `x + 0 = x`, `0 + y = y` and `z + 0 = z`, with random `x`, `y` and `z`.
- The component commits `op0`, `op1` and `dst` as separate columns, 4 limbs each.
- On every blinding row, `dst = op0 + op1` exactly, so `D_k = dst_k − op0_k − op1_k` is zero
  there for each limb `k`.
- The verifier opens all twelve columns at every query and samples them at the
  out-of-domain point.
- It can therefore form `D` at those points. `D`'s polynomial is determined by the witness's
  non-add gates alone: the multiplications and subtractions inside every Poseidon2 hash of
  keys, notes and paths.

## Test (`examples/hiding_leak.rs`)

The test proves an R0 V2 transfer (2¹⁸ trace, 2,390 blinding iterations, 2²/35 FRI) with
blinding seed A. It then rebuilds the committed base trace with seed B and looks up proof A's
openings in it.

| Check | Result |
| --- | ---: |
| `D` extension identical for seeds A and B | all 1,048,576 points |
| Proof A's opened `dst − op0 − op1` found in seed B's `D` extension | **35 / 35** |
| Control: opened `op0` found in seed A's extension | 35 / 35 |
| Control: opened `op0` found in seed B's extension | 0 / 35 |

A chance 4-limb match has probability about 2⁻¹²⁴ per query. The individual columns are
blinded; their combination is not.

## What leaks

Per proof, the verifier learns `D` at 35 query points, 4 limbs each, plus 4 QM31
out-of-domain samples: about 156 M31 values that are fixed linear functions of private data.
- **One proof:** that is 156 combinations of about 10⁵ secret-dependent values. It does not
  directly recover a key, but the proof is not zero-knowledge.
- **Retries of the same witness:** `D` does not depend on the seed, so each retry reveals
  the same polynomial at fresh points, and the evaluations accumulate.
- **Several payments by one user:** rows that depend only on the spending key (receiver and
  nullifier-key derivation) sit at fixed positions, so that part of `D` repeats across the
  user's proofs.

## Scope

- The blinding code is upstream's, unchanged. Upstream's full profile uses the same
  `qm31_zk_blinding`, so its proofs likely have the same property. This is not yet tested
  there.
- The `eq` component blinds with `x == x`, but equality is a constraint on every row, so
  `in0 − in1` is zero everywhere and reveals nothing.
- This supersedes "count is necessary, not sufficient" in ADR-0024. The count was satisfied;
  the structure was not.

## Fix direction

Blinding rows must leave no public linear combination of a component's columns constant. For
`qm31_ops`, mixing gate types works: add rows span `(a, b, a + b)` and sub rows span
`(a, b, a − b)`, and together they span all of `(op0, op1, dst)` for each limb. Random mul
rows would also do. The general check is that the blinding rows' column vectors have full rank
per component, followed by the full leakage-rank audit of the plan.
