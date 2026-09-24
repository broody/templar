# Hiding: per-point rank test for the `qm31_ops` openings

2026-09-23 (`examples/hiding_points.rs`, fork `4de7408a6`). **With the H2 fix, the base
`qm31_ops` openings a proof reveals are uniformly random for every witness.** That is an exact
result: a full-rank linear map from independent uniform variables.

## Method

- **Each revealed value is a linear functional.** The value of a committed column at a point
  `P` off the trace domain is `Σ_i w_P(i) · t[i]`, with barycentric weights `w_P` (stwo's
  `barycentric_weights`).
- **Blinding rows, classified by pattern.** Rows that change with the seed are grouped as
  `x + 0`, `0 + y`, `z + 0`, `x · y` and the eq yield `e + 0`: exactly 2,390 of each.
- **Linearization.** Conditioning on `x` and `e` (conservative) makes every functional affine
  in the `y` and `z` limbs: 19,120 independent uniform M31 variables. The mul row is
  `x · y`, which is linear in `y` for fixed `x`.
- **The check.** The functional matrix restricted to those variables must have full row
  rank.

## Results

| Openings of the 12 columns | Functionals | Rank |
| --- | ---: | ---: |
| 35 LDE query points + 1 OODS point (a proof's openings) | 468 | **468** |
| 560 LDE points per column + OODS (conservative bound for FRI layer 0: 35 queries × 16) | 6,768 | **6,768** |
| Control: pre-fix blinding, 35 points + OODS | 468 | 312 |

The control's deficit is **156**: 35 × 4 query limbs plus 4 × 4 OODS coordinates, exactly
H2's leak. So the test detects the leak and measures its size.

## What this covers, and what it does not

- **Covered:** every base `qm31_ops` value a verifier opens (queries and OODS), at random
  points of the right kind. The 560-point bound also covers the base columns' contribution
  at every FRI layer-0 coset point, as if it were revealed column by column.
- **Not covered:**
  - The deeper FRI layers. They are functionals over many more points.
  - The interaction (LogUp) and composition columns. They are nonlinear in the same blinding
    variables, so a linear rank test cannot model them; that needs the attack tests and a
    written argument.
  - The `eq` component's openings (4 columns, 2,390 random rows); same method, not yet run.
