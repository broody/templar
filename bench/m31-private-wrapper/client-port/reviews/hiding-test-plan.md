# Hiding: a test plan

2026-09-23. **In progress.** Layer 1, first two checks done:
- `examples/hiding_leak.rs` found **H2**, an unblinded column combination
  ([results](../results/hiding-leak/README.md)), fixed in the fork;
- `examples/hiding_rank.rs` is the per-component rank check below: 0 unblinded
  combinations after the fix.

Originally shelved in favour of the server log20 work. This is the plan for
answering as much of the stwo-circuits hiding question (ADR-0024 gate 4,
broody/templar#2) as tests can. It would feed a written argument and review, not replace
them: tests can falsify zero-knowledge and establish exact sub-claims, but cannot prove it.

## Starting point

- The arithmetic-only profile removes lookup tables, whose multiplicities would leak.
- H1 is fixed: padding rows are sized for every revealed FRI value. The check is a count,
  `revealed + 10 ≤ blinding` (2,390 rows at 2¹⁸), which is necessary, not sufficient.
- Still open (math review): interaction and composition openings, unsalted Merkle
  leaves, correlations across columns, and repeated proofs of the same witness.

## Layer 1: exact leakage audit (the core)

**Done: structural rank check** (`hiding_rank`). Trace the same witness with two seeds, and
take the rank of the difference matrix per component and tree. The kernel is exactly the set
of public column combinations the blinding never reaches. After the H2 fix: base `eq` 4/4,
base `qm31_ops` 12/12, interaction `eq` 4/4, interaction `qm31_ops` 8/8. This check is
necessary for everything below it. It does not bound how many evaluations each blinded
direction can absorb; the rank test below does.

**Done: per-point rank test for `qm31_ops`** (`hiding_points`,
[results](../results/hiding-points/README.md)). The 35 query points plus OODS give full rank
(468/468), and 560 points per column also give full rank (6,768/6,768). The pre-fix control
shows a deficit of exactly 156, which is H2. Still to do in this layer: `eq`, and the FRI and
interaction parts, which are nonlinear and are covered by layer 2 and the argument.

**Original design of the per-point test:**

For a real R0 transfer proof, with its challenges and query positions fixed, everything the
verifier sees about a base-trace column is linear in that column's values:
- the out-of-domain samples;
- the opened values at query positions;
- the FRI coset values (linear in the quotients, and so in the trace).

Build that map over M31, as a matrix `A`. Split its columns into witness rows and padding
rows: `revealed = A_w · w + A_r · r`. If `A_r` has full row rank, the revealed values are
uniform for any `w`. That is an exact statement for the linear part, much stronger than
the count.

- **Cross-column correlation.** A padding row is a valid circuit row, not free randomness.
  For example, in `qm31_ops`, `out = in0 · in1`. The audit therefore has to model which
  padding-row values are independent: `in0` and `in1` uniform, `out` determined by them.
  It must either restrict the rank argument to those columns, or bound the dependency.
- **Retries.** Two proofs of the same witness use fresh padding each time. Stack both maps
  and check the rank again, so that retries cannot leak by combining proofs.
- **Output:** per column, the revealed count, `rank(A_r)` and the slack; for retries, the
  combined rank.

## Layer 2: attack tests

An attacker program takes one proof, or several proofs of the same witness, and tries to
recover private values: secret-key limbs, amounts and positions. It uses linear algebra over
every revealed value, together with the unsalted Merkle leaves.
- It must fail on the production blinding.
- It must succeed when the blinding is deliberately cut below the revealed count. Otherwise
  the test proves nothing.

## Layer 3: statistical distinguishers

Take circuits whose witnesses differ in one secret bit, with the same public outputs.
Generate many proofs of each, and test the revealed values for correlation with the bit:
per-value χ² tests and a simple classifier. This catches only gross leaks.

## What remains for the written argument

- The composition polynomial and LogUp interaction openings, which are nonlinear in the
  witness.
- The random-oracle treatment of unsalted Merkle hashes of unopened rows.
- A simulation argument over the whole transcript, reusing layer 1 for the linear part.
