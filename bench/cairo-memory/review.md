# Cairo memory experiment: invariant review

Reviewed 2026-09-21 against pinned S-two `489a0f3`, stwo-cairo `9b6be27`, and the archived phase-local prover experiment. This is a targeted source review of storage lifetimes and deterministic recomputation, not a cryptographic audit or a production qualification.

The reviewed change is suitable for performance measurement. No protocol-equivalence finding remains open in this patch. The executed focused tests support that conclusion; end-to-end replay, proof-byte comparisons, cap testing, and repeated-request measurements are separate release evidence recorded under `results/`.

## Scope and implementation

- The PCS adds an explicit opt-in memory mode. It builds each owned Merkle commitment with the original implementation, retains its root and logical height, and releases its other hash layers. At opening time it reconstructs one tree using the original implementation, checks the reconstructed root against the retained root, and invokes the original decommitment routine.
- The PCS releases owned polynomial coefficient buffers and any barycentric weight map after all out-of-domain samples have been materialized as owned field values. Subsequent PCS work reads evaluations, samples, and commitments.
- The stwo-cairo wrapper accepts the memory option without changing `ProverParameters` or `PcsConfig`. Its original entry point delegates with the option disabled.
- The privacy-prove integration enables the new mode only for the Cairo stage. The recursive circuit stage, Cairo verifier context, blinding, serialization, and compression routines are unchanged relative to the previous phase-local experiment.
- The service routes an explicit environment choice to that option. The pre-existing cached proving entry point is unchanged.

The core S-two and stwo-cairo source changes are in [stwo.patch](stwo.patch) and [stwo-cairo.patch](stwo-cairo.patch). The experiment integration is in [integration.patch](integration.patch).

## Invariants checked

**Commitment and opening identity.** The original polynomial evaluation buffers remain available and unchanged. Reconstruction uses the same column order, stable sort by column length, lifting size, hash implementation, and unpacked-leaf setting (`log_rows_per_leaf = 0`). Equal-length column ordering therefore remains identical. The original decommitment implementation determines queried values, authentication witness order, and auxiliary node maps. Root equality is asserted before an opening is returned, including in release builds. A mismatch fails closed.

**Logical height.** Several existing PCS and prover operations derive lifting or domain size from `commitment.layers.len() - 1`. The patch keeps that length unchanged and replaces only non-root buffers with empty columns. The explicit private recomputation marker distinguishes this representation. FRI commitment trees, which can use packed leaves, are not pruned or reconstructed through this path.

**Polynomial lifetime.** Coefficients remain available through composition generation and out-of-domain sampling. Sampling completes before buffers are released, including when Rayon is enabled. `PointSample` owns the sampled field values. Neither quotient construction nor later opening code reads coefficient buffers or the released barycentric weights. Borrowed trees and their coefficients are never mutated.

**Transcript.** The patch does not move, insert, or remove any channel mix/draw operation. Roots and samples are mixed at their original positions. Rebuilding a Merkle tree performs no channel operation. FRI challenges, proof-of-work, query selection, and the final proof layout are unchanged.

**Protocol and arithmetic.** AIR constraints, degree bounds, domain construction, lookup arguments, field operations, hashing, security parameters, FRI equations, and verifier checks are unchanged. No unsafe block is added or modified. This patch preserves the existing lifted Merkle layout rather than introducing another paper/implementation variant.

The governing references are the pinned S-two distilled whitepaper's `alg:merkle` / `s:cross:domain:merkle` anchors, `e:FiatShamir:randomness`, and `prot:STARK:IOPP`. The repository's existing DIVERGENCE-006 records the baseline lifted-tree variant; this experiment preserves it. The S-two soundness checklist, STARK foundations, circle mathematics, AIR constraint guidance, testing strategy, and divergence log were read for this review.

## API and default boundaries

- `CommitmentSchemeProver::new` and `with_memory_pool` retain the previous behavior. `set_low_memory_mode()` must be called before committing any tree; this requirement is enforced.
- `prove_cairo_with_precompute` retains the previous behavior. The new wrapper is opt-in.
- `LowMemoryOptions::default()` has `recompute_cairo_commitments = false` and coefficient caching enabled.
- In the experiment service, `TEMPLAR_LOW_MEMORY=1` selects the phase-local prover, and `TEMPLAR_RECOMPUTE_CAIRO_COMMITMENTS` defaults to `1` inside that branch. The harness sets the latter explicitly. Thus the experiment service's opt-in branch and the library default have deliberately different defaults.
- The public commitment field documents that non-root layer buffers can be empty after opting into the scheme mode. A downstream caller must not directly open those pruned layers instead of using the owning PCS.
- Adding private fields is a source-level compatibility change for downstream struct-literal construction. No such external literals were found in the pinned S-two, stwo-cairo, stwo-circuits, proving-utils, or sequencer graph. This is not a claim of universal source compatibility.

## Test evidence reviewed

The new tests exercise both CPU and SIMD backends, coefficient caching on and off, and owned versus borrowed preprocessed commitments. They compare full and reduced-mode proof fields, query locations, queried values, hash witnesses, and auxiliary node maps. They also confirm that borrowed trees and their coefficient retention are unchanged.

Merkle cases cover unequal heights, unsorted inputs, stable order among equal-height columns, lifting beyond the largest column, empty queries, duplicate queries, the last leaf, and an empty root-only tree. Negative cases cover a changed opening value, a changed out-of-domain sample, and a stale retained root; the latter must fail before returning an opening.

The reviewed logs show **9 PCS tests passed** and **13 lifted-Merkle tests passed**, both with and without the `parallel` feature: 44 test executions in total, including existing tests and all four new test functions. Commands and exit codes are retained in `results/stwo-{pcs,merkle}-{parallel,scalar}.{json,log}`. The filenames' `scalar` suffix means no Rayon parallel feature; both backend types are exercised in each configuration. Release replay results were still in progress when this source review was written; their final records are independent evidence and should be checked before using the experiment's measurements.

## Limits

This first implementation retains the complete expanded polynomial evaluation ensemble and temporarily builds a complete Merkle tree before pruning or opening it. It does not provide bounded-memory polynomial evaluation or streamed leaf hashing. Ordinary-payment measurements from the previous experiment put those expanded field cells alone at approximately 6.9 GiB; lifetime changes cannot make that ensemble fit the proposed browser budget below 2 GiB.

Retained objects being dropped does not guarantee immediate RSS reclamation by a native allocator. Desktop suitability therefore requires measured process/cgroup memory, hard caps, and repeated requests, not only allocation accounting. No actual 8/16 GiB desktop, browser/WASM runtime, or live settlement with the modified prover is qualified by this review.

## Reviewed source SHA-256

| File under `target/cairo-memory` | SHA-256 |
| --- | --- |
| `stwo/crates/stwo/src/prover/pcs/mod.rs` | `3e8a0b51f147c19dd9c2b94ef347672256705f1e603e4531aad03c524f2ad423` |
| `stwo-cairo/stwo_cairo_prover/crates/prover/src/prover.rs` | `26255a0bb6d9cd3d0ed34bcb432344874207838d32aa7ffc8434ca9f662b431f` |
| `proving-utils/crates/privacy_prove/src/low_memory.rs` | `4f3868460b86cf08064a8264770a74ff7d9628765202a1a39685e3272b9cde75` |
| `sequencer/crates/starknet_transaction_prover/src/proving/prover.rs` | `e214ac7f64e32eb4a7d38e2ae8fc8881a64aa12bed9f4fb4a1b53ca2dd38c0be` |
