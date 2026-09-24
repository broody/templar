# K3 masking / degree-slack / ZK API inventory — pinned deps

2026-09-22. Read-only inventory for Astra's next-experiment design. No builds,
tests, or probes run; dependency source was not modified by this inventory.
Context: the [independent hiding review](hiding-review.md) closed gamma with a
NO-GO; this inventory supports the [polynomial masking
plan](polynomial-masking-plan.md), a specification path only. The inventory
catalogues source; it is not a theorem or proof of absence.

## Revisions and provenance

- Both dep trees are vendored directories inside the templar worktree and
  contain no `.git` metadata of their own; `target/` is git-ignored, so
  parent-repo `git status` silence is not evidence about their contents. The
  pinned revisions are recorded provenance — stwo `489a0f3` (with local
  storage-only patches per [hiding-spec.md](hiding-spec.md)), stwo-circuits
  `5ef951a` (`../compact-recursion/review.md:25`,
  `../compact-recursion/results/measurements.md:56`) — not independently
  verified clean git checkouts.
- Parent repo HEAD at inventory time:
  `0f5448bafe2885199482b8d5a512dc98745c5692`.

## Exact searches and scope

Paths: `target/m31-append/stwo/crates/{stwo/src/core,stwo/src/prover,constraint-framework,examples}`,
`target/direct-air/stwo-circuits/crates`, and `bench/compact-recursion`
(caller check only). Patterns: `(?i)blind|add_zk|zero.?knowledge|\bzk\b|randomize`;
`(?i)zerofier|zero.?poly|mask.*random|random.*poly`;
`max_constraint_log_degree_bound|composition_log_degree_bound|get_lifting_log_size|max_log_degree_bound`;
`(?i)is_first|selector`; `SmallRng|ChaCha|rand::` (excluding `*test*`);
`add_zk_blinding|finalize_context` (callers). All absence findings below are
scoped to exactly these searched paths; no global absence is claimed.

## (a) Existing public APIs and callers

| API | Definition | Callers found |
| --- | --- | --- |
| `add_zk_blinding(ctx, seed_bytes, n_padding)` | `stwo-circuits/crates/circuit_common/src/finalize.rs:154-167`; per-iteration helpers `qm31_zk_blinding` :76, `eq_zk_blinding` :93, `triple_xor_zk_blinding` :127, `m31_to_u32_zk_blinding` :135, `blake_g_gate_zk_blinding` :141, via `random_u32_var` :107 / `random_m31_var` :119, ChaCha20 seeded :160 | Only `cairo_verifier/src/privacy_test.rs:185` (a test; import :5) |
| `finalize_context` (valid-row zero padding) | `finalize.rs:61-69`; pads each component to pow2 with `0+0` etc. rows (`pad_qm31_ops` :9, `pad_eq` :20, `pad_triple_xor` :29, `pad_m31_to_u32` :38, `pad_blake_g_gate` :47) | `circuit_common/src/preprocessed.rs:476`, `circuit_prover/src/prover_test.rs:467`, `cairo_verifier/src/privacy_test.rs:108,140`, `bench/compact-recursion/client/src/main.rs:151` |
| stwo trace masks (NOT hiding) | `EvalAtRow::next_trace_mask` / `next_interaction_mask`, `constraint-framework/src/lib.rs:95-110`; offsets compiled into `mask_points` at `component.rs:256-266` | every AIR `evaluate()` |
| Preprocessed column support | `PreProcessedColumnId` is a bare id struct, `constraint-framework/src/preprocessed_columns.rs:4-7`; wired via `TraceLocationAllocator`/`preprocessed_column_indices` (`component.rs:113-118,269-275`) | M31 bench uses none (`client/src/lib.rs:81` empty list) |
| Public selectors | `IsFirst` preprocessed column exists only in examples: `examples/src/xor/gkr_lookups/mod.rs:16-22` | gkr example only |

In the searched pinned stwo `core`/`prover`/`constraint-framework` paths
(excluding examples and test modules), no symbol matching blinding/zk/
randomize was found.

## (b) Random-poly × zerofier injection / independent FRI mask

No such mechanism was found in the searched paths. The commit path
interpolates and Merkle-commits the raw trace columns with no blinding term:
`prover/pcs/mod.rs:106-124` (`commit`), `:407-417` (`extend_evals` →
`interpolate_columns`), `:432-435`. Composition polynomial is built from the
committed trace plus one channel-drawn `random_coeff`
(`prover/mod.rs:54,64-69`) — Fiat-Shamir binding, not masking. In the searched
paths, `SmallRng`/random-polynomial helpers appeared only under `#[cfg(test)]`
or bench code (`prover/pcs/quotient_ops.rs:285-286,463-478`;
`core/fri.rs:1104`; `prover/fri.rs:499`; `core/air/accumulation.rs:41`). The
PCS verifier checks sampled values and FRI openings
(`core/pcs/verifier.rs:59-116`); no independent FRI mask implementation was
found in the searched paths. These
are scoped inventory observations, not a proof that no such mechanism could
exist elsewhere.

Astra's integration check: `TreeBuilder::extend_polys`
(`prover/pcs/mod.rs:419-430`) accepts caller-provided `CircleCoefficients`.
There is an entry point for supplying different polynomials; it does not add
randomness or make the resulting protocol zero knowledge. The degree/domain
and verifier changes below still require a reviewed construction.

## (c) Degree/domain assumptions to review if degree slack is introduced

- `FrameworkEval::max_constraint_log_degree_bound` contract:
  `constraint-framework/src/component.rs:109,223-228`; the M31 bench sets
  `log_size + 1` (`client/src/m31.rs:227-229`).
- `FrameworkComponent::trace_log_degree_bounds`
  (`constraint-framework/src/component.rs:232-245`) derives private-column
  degree bounds from `eval.log_size()`. Prover constraint evaluation also
  derives the constraint domain from that same size
  (`constraint-framework/src/prover/component_prover.rs:110-111`). Adding
  masking degree slack therefore requires explicitly reviewing this coupling;
  increasing a parameter alone is not a qualified masking protocol.
- Quotient evaluation assumes the trace domain vanishing polynomial:
  `component.rs:296` (`coset_vanishing(CanonicCoset::new(max_log_degree_bound))`),
  and prover-side subdomain expansion `constraint-framework/src/prover/component_prover.rs:109-124,296-299`.
- Composition split and lifting derivation: `core/verifier.rs:17,50-70`;
  `core/pcs/utils.rs:215-221` (`get_lifting_log_size`, asserts
  trace ≤ lifting); `core/pcs/mod.rs:31-42` (`PcsConfig.lifting_log_size`);
  bench pins `lifting = log_size + 3` (`client/src/lib.rs:49-55`).
- FRI config bounds: `core/fri.rs:39-47` (last-layer degree 0..=10, blowup
  1..=16); circle domain limits `core/poly/circle/domain.rs:15`
  (`MIN_CIRCLE_DOMAIN_LOG_SIZE = 1`).
- Prover composition generation: `prover/mod.rs:53-69`.

## (d) Does the compact-recursion M0 demo call the blinding helper?

No. `bench/compact-recursion/client/src/main.rs:151` calls only
`finalize_context` (valid-row zero padding). No caller of `add_zk_blinding`
was found in `bench/compact-recursion` (grep: only a doc mention in
`review.md:27`); its single caller in the searched paths is the
`privacy_test.rs:185` test. Distinction: circuit-DSL blinding appends *random
valid rows through real gates* (`finalize.rs:76-148`) — constrained trace
content — whereas stwo "masks" are OOD sampling offsets
(`component.rs:256-266`); no unconstrained polynomial-mask mechanism was found
in the searched paths.

Classification only; no memory estimates and no security recommendations.
