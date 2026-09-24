# Hiding: seed-invariant search over all committed columns

2026-09-23 (`examples/hiding_invariants.rs`, fork `4de7408a6`). **No linear combination of
the revealed values is independent of the blinding seed.** The search covers the base and
interaction (LogUp) trees of both components.

## Method

- One R0 transfer witness is traced under many seeds, with the lookup challenges fixed.
- Each of the 28 columns (base `qm31_ops` 12, base `eq` 4, interaction `qm31_ops` 8,
  interaction `eq` 4) is evaluated at fixed random points: 4 LDE points, the OODS point `z`,
  and `z` minus one trace step (the previous-row mask).
- That gives 336 M31 functionals per seed. We rank the differences between seeds, and any
  seed-invariant combination appears as a rank deficit.
- Unlike the linear rank tests, this samples the real distribution, so it reaches the
  interaction columns, which are nonlinear in the blinding.

## Results

| Blinding | Functionals | Seeds | Rank | Seed-invariant combinations |
| --- | ---: | ---: | ---: | ---: |
| Fixed (mul row) | 336 | 336 | **336** | **0** |
| Control: pre-fix (add-only) | 336 | 366 | 288 | 48, all in base `qm31_ops` |

The control's 48 is exactly H2: `dst − op0 − op1` for 4 limbs, at 4 LDE points plus 2 OODS
points × 4 coordinates. Each run takes about 2 minutes.

## Scope

- **A necessary condition.** Linear invariance only, at a few points per column. A nonlinear
  relation would not show up.
- **Not covered:** the composition tree and the FRI layers. The next step is a
  full-transcript version with the challenges pinned.
