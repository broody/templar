# R0 with blinding sized for every opened value (math review H1)

2026-09-23. The [math review](../../reviews/math-review.md) (H1) found that upstream's
`n_queries + NON_QUERY_INFO_LEAK = 45` blinding covers the trace query openings but not FRI.
With fold step 4, every FRI layer opens the queried point's whole coset. The blinding is now
sized for everything a proof reveals:

```
blinding = n_queries × Σ_layers 2^fold_step + NON_QUERY_INFO_LEAK
         = 35 × (16 + 16 + 16 + 16 + 4) + 10 = 2,390   (2¹⁸ trace, fold schedule 4,4,4,4,2)
```

`examples/support/mod.rs` has `fri_fold_schedule`, `blinding_budget` and
`revealed_fri_values`. The provers size the blinding from the final trace, rebuilding once if
the blinding would grow the trace. After proving they assert:

```
revealed FRI values (all layer witnesses + last layer) + 10 ≤ blinding
```

Measured revealed values are 1,692–1,782 per proof. With the 35 queried points, every committed
column gets 2,390 random rows against about 1,770 revealed values. The stock-component prover
(`prove_client_sc`) uses the same rule.

R0 here is the lane-packed relation with single-permutation tree nodes, as in
[`../stwo-client-r0-compress/`](../stwo-client-r0-compress/README.md):

| | 45 blinding | **2,390 blinding** |
| --- | ---: | ---: |
| eq component | log11 | log12 |
| Trace | log18 | log18 |
| Client, 4 threads, normal | 0.58 GiB, 1.4–4.1 s | 0.58 GiB, 1.5–3.9 s |
| Client, 4 threads, bounded | 0.30 GiB, 1.7–2.0 s | **0.30 GiB, 1.6–2.1 s** |
| Bridge | 3.39M steps | 3.33M steps, 15/15 checks |
| Virtual OS | 4.96M steps | 4.89M steps, exact message |
| PROOF2 | 120.3 s / 54.4 GiB | 115.1 s / 51.7 GiB, verified, 3/3 rejections |

The larger blinding costs nothing measurable. The server differences are within run-to-run
variation (fresh witness and proof each time).

## What this does and does not establish

A per-column random-row count at least as large as the number of revealed values is
**necessary** for a padding-based simulation argument. It is **not** that argument. Still open,
as the math review lists them:
- interaction and composition openings, which carry no randomness of their own;
- unsalted Merkle leaves;
- constraint correlations and repeated query positions.

The alternatives (fold step 1 in the first layer, or an FRI masking polynomial with salted
leaves) remain options for the full argument. The hiding question in broody/templar#2 should be
restated with this count.
