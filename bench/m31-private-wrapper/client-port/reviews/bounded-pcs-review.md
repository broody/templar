# Bounded-memory PCS port: independent review

Reviewed 2026-09-23. Subject: commit `8acdbe55d` on `target/proving-arith` (branch `templar/arithmetic-profile`). It is a three-way merge of the bounded-memory PCS patch. The merge base is pristine stwo `489a0f3`, "ours" is `target/direct-air/stwo`, and "theirs" is `8acdbe55d^`. The commit also adds a circuit-prover entry point. Paths below are relative to `target/proving-arith/crates/` unless stated otherwise. Line numbers refer to the files at `8acdbe55d`.

This is a source review plus differential tests. It is not a cryptographic audit, and it does not qualify the port for production.

## Verdict: CONDITIONAL GO for continued research use

The runtime port is correct. I rebuilt the merge myself with `git merge-file` over the three versions. It gives exactly 11 conflicts in `pcs/mod.rs`, 1 in `quotient_ops.rs`, 1 in `air/component_prover.rs` and 0 in the framework adapter. Every committed resolution equals "upstream behaviour + patch intent".

Proofs are identical in the cases I checked. That includes the auxiliary data the verifier conversion uses, which the committed test does not check. It also includes preprocessed lifting heights that differ from the trace height, which no committed test covers.

Conditions:

1. **Fix the workspace build break (M1).** It does not affect runtime behaviour.
2. **Extend the circuit-prover equality test to cover `aux` (M2).** Until then, only this review's out-of-tree experiment shows that the bridge input is identical.

## Findings

### M1 (Medium): the port breaks the build of `stwo-examples` and of the `relation-tracker` feature

**Problem.** `Poly.evals` is now `Option<_>` (`stwo/src/prover/air/component_prover.rs:43`). The original patch also adapted three consumers of that field; the review of that patch pins them in `bench/bounded-memory/review.md:104-112`. The port did not carry those adaptations over:

- `cargo check -p stwo-examples` fails at `examples/src/blake/air.rs:439` (`c.evals.domain`) and at `examples/src/xor/gkr_lookups/mle_eval.rs:207,225,247` (`&c.evals`).
- `cargo check -p stwo-cairo-prover --features relation-tracker` fails at `prover/src/debug_tools/relation_tracker.rs:45` (`poly.evals.clone().interpolate()`).

**Failure scenario.** `cargo test --workspace`, or any build with `--all-features`, fails. The next upstream rebase of this branch will hit the same errors. No runtime path is affected, and the default builds of `stwo`, `stwo-cairo-prover`, `stwo-constraint-framework` and `circuit-prover` compile.

**Fix.** Port the three adaptations from `target/direct-air`:
- use `.as_ref().expect(..)` on `evals`;
- use `committed_domain` for log sizes;
- in `relation_tracker`, interpolate from the coefficients when the evaluations are evicted.

### M2 (Medium, test gap): the circuit-prover equality test ignores `aux`, which the verifier conversion consumes

**Problem.** `circuit_prover/src/prover_test.rs:605-637` compares only `format!("{:?}", stark_proof.proof)`, the claims and the circuit hash. But `stark_verifier/src/proof_from_stark_proof.rs:94,134-146,166-217` builds the circuit/Cairo-verifier input from:
- `aux.unsorted_query_locations`;
- `aux.trace_decommitment[..].all_node_values`;
- `aux.fri.{first_layer,inner_layers}`.

The trace `all_node_values` come from the regenerated Merkle trees in bounded mode (`stwo/src/prover/pcs/mod.rs:512-518`, `:542-548`).

**Failure scenario.** Suppose a future change makes regenerated-tree aux diverge, for example by returning the witness nodes of a different tree object. The committed test would still pass while the bridge input changed.

**Evidence that this does not happen today.** I added a scratch test (`scratchpad/review-pcs/repo/crates/circuit_prover/src/prover_test.rs`, `review_bounded_aux_and_verifier_input_identical`) and it passes. It covers:
- the arithmetic, Fibonacci/full and Blake/full profiles;
- `max_fri_columns` of 1, 7, 16 and 2^20;
- one `BaseColumnPool` shared across the bounded and unbounded runs.

It asserts that the Debug form of `.proof` is equal, that all aux fields are equal (the hash maps are compared with `PartialEq`, not Debug), and that `prepare_circuit_proof_for_circuit_verifier` gives equal `Proof<QM31>` for Fibonacci.

**Fix.** Add the aux assertions to the committed test. Also compare the output of `prepare_circuit_proof_for_cairo_verifier`, which is the bridge felts.

### L1 (Low, memory): in low-memory mode, barycentric weight buffers go back to the pool instead of being freed

**Problem.** In `ours`, low-memory mode called `drop(weights_hash_map)` right after out-of-domain sampling. After the merge, `compute_samples` hands the weight buffers back to `base_column_pool` (`pcs/mod.rs:263-270`, upstream behaviour). The only later `take_or_alloc` is in the next commit. So a borrowed pool keeps these buffers alive through FRI and decommitment, and until the pool is dropped.

**When it matters.** Only when weights are built at all, which means some polynomial has no coefficients:
- low-memory mode without bounded mode, or
- bounded mode with a borrowed preprocessed tree that has no coefficients.

The circuit prover stores coefficients everywhere, so the client path never builds weights and is unaffected.

**Fix.** When `low_memory_mode` is set, drop the weights instead of calling `give_back`. Or accept the behaviour and document it.

### L2 (Low, memory, inherited): weights are built for every column once any column lacks coefficients

**Problem.** `needs_weights` (`pcs/mod.rs:235-241`) is decided globally. After that, `build_weights_hash_map` (`:184-223`) computes a 4-column buffer for every (column size, point) pair, including columns that will be evaluated from coefficients.

**Failure scenario.** Bounded mode with a borrowed preprocessed tree that has no coefficients allocates weights for all trace sizes. That can be a large transient allocation in Cairo-sized proofs.

**Fix.** Pass only the polynomials with `coeffs.is_none()` to `build_weights_hash_map`.

### L3 (Low, failure mode): the regenerated FRI and composition inputs have no root check

**Problem.** Tree openings regenerate evaluations and assert the Merkle root (`pcs/mod.rs:517`, `:547`; these are `assert_eq!`, so they are active in release builds). Two other regeneration paths use different code and are not checked against the root:
- The FRI numerator prefixes come from `get_evaluation_on_prefix` with per-size subdomain twiddles (`quotient_ops.rs:162,178`), or with full twiddles built per column (`air/component_prover.rs:112`).
- The constraint-framework SubDomain prefixes (`constraint-framework/src/prover/component_prover.rs:45-79`) are the same kind of path.

**Failure scenario.** A wrong prefix regeneration would not panic. In the composition path, the out-of-domain sanity check in `prove_ex` (`stwo/src/prover/mod.rs:112-121`) would most likely catch it. In the FRI path, the prover would emit a proof that the verifier rejects. That is fail-safe, because it is not unsound, but it is not fail-fast.

**Current mitigation.** The research harness verifies every proof natively (`client-port/examples/prove_client_arith.rs:112`).

**Fix, optional.** In debug or test builds, cross-check a sample of regenerated prefix rows against the full evaluation. Alternatively, keep native verification mandatory in every bounded-mode harness.

### I1 (Info): panics, not errors

All bounded-mode failures are panics:
- the root mismatches at `pcs/mod.rs:517,547`;
- an owned tree without coefficients: `pcs/mod.rs:487`, `air/component_prover.rs:57`;
- `evaluations()` in bounded mode: `pcs/mod.rs:170`;
- a missing coefficient in `get_evaluation_on_domain` or `get_evaluation_on_prefix`;
- calling `set_bounded_memory_mode` after a commitment: `pcs/mod.rs:90`.

None of them returns `ProvingError`. Each one fails closed: no proof is produced. For a client that should be converted to an error eventually.

### I2 (Info): the scheme twiddles must cover every owned tree's committed domain

`decommit_with_twiddles` regenerates each tree with `self.twiddles` (`pcs/mod.rs:367,509`). An owned preprocessed tree whose committed domain is larger than the scheme's twiddle tree would panic or fail the root assertion. It cannot produce a bad opening.

This holds for the circuit prover. Its twiddles cover `trace_log_size + max(blowup, composition bound)` (`circuit_prover/src/prover.rs:84-95`), and its preprocessed trace fits inside that. A Cairo port would need to check it again.

## 1. Merge correctness

The 11 `pcs/mod.rs` conflicts:

| # | Region | Resolution (committed file) | Assessment |
|---|---|---|---|
| 1 | imports | adds `Col, Column` and `compute_fri_quotients_bounded` to upstream's imports (`:24,27`) | correct |
| 2 | `commit` tree construction | upstream `config.lifting_log_size(self.trees.len())` + `let mut tree` (`:111-119`) | correct: the per-tree height comes from upstream |
| 3 | `commit` retain/evict before mixing | patch block, then upstream `MC::mix_hash` (`:120-126`) | correct: the root is read after pruning, and `layers[0]` is kept |
| 4 | `commit_tree` | patch block (Owned trees only), then `mix_hash` (`:137-145`) | correct: borrowed trees are untouched |
| 5 | `evaluations()` | patch `expect` on `Option` (`:161-174`) | correct: unreachable in bounded mode (the bounded branch never calls it) |
| 6 | `build_weights_hash_map` | upstream pooled `barycentric_weights_into`, with `committed_domain` for the log size (`:191-220`) | correct |
| 7 | weights decision | moved into upstream's `compute_samples`, as `needs_weights` = any poly without coefficients (`:235-241`) | correct. It differs from upstream only when a tree breaks the store-flag convention: upstream would `unwrap` a `None` there, or build unnecessary weights. The sampled values are identical either way, because both methods evaluate the same interpolant exactly. |
| 8 | the coefficient-drop block | placed right after `compute_samples`, before mixing the samples into the channel (`:283-298`); `drop(weights)` removed because `compute_samples` gives them back to the pool | correct placement; same point in the transcript as in `ours`. See L1 for the weight-buffer lifetime. |
| 9 | `CommitmentTreeProver::new` | upstream non-`Option` `lifting_log_size`; the patch's `evals.as_ref().unwrap()` (`:468-472`) | correct: the `unwrap` is safe because the evaluations always exist when a tree is built |
| 10 | `retain_merkle_root` / `evict_evaluations` / `decommit_with_twiddles` | patch code, with `<MC::H as Hasher>::Hash` (`:477-519`) | correct |
| 11 | `decommit` | patch recompute branch (`:525-552`) | correct |

Specific checks:

- **Height used when regenerating trees.** `MerkleProverLifted::commit` pushes one leaf layer plus `lifting_log_size` further layers (`stwo/src/prover/vcs_lifted/prover.rs:52-79`). So `layers.len() - 1 == lifting_log_size` for every non-empty tree. An empty tree returns one layer and asserts `lifting_log_size == 0` (`:41-50`), which gives 0 == 0.

  `retain_merkle_root` replaces only `layers[1..]` with `Col::zeros(0)` and keeps the vector length. So each tree is regenerated at the height it was committed at, whether that came from `config.lifting_log_size(i)` or from an externally supplied tree, and including a preprocessed tree whose height differs from the trace trees.

  The query mapping for such a preprocessed tree (`prepare_preprocessed_query_positions`, `pcs/mod.rs:343-347`) is unchanged upstream code. It reads the same `layers.len()`, which is preserved.

  I verified this with a scratch test, `review_split_lifting_{cpu,simd}`, over (preprocessed height, trace height) = (8,9), (9,9), (10,9) and (8,10). It covers owned and borrowed-without-coefficients preprocessed trees and three trees in total. It compares bounded (1, 2 and 64 columns) and low-memory mode against baseline for proof Debug, query locations and `all_node_values`, and runs the verifier. All cases pass.
- **Pool return at the end** (`:374-383`). Only retained `Some(evals)` buffers go back, and only for owned trees. Evicted buffers were already dropped in `Poly::evict_evaluations` (`air/component_prover.rs:56-59`), which matches the patch's intent of "dropped, not pooled". Borrowed trees are skipped.
- **`quotient_ops.rs` merge.** The single conflict was only imports and formatting. `compute_fri_quotients` between `489a0f3` and "theirs" is a rustfmt reflow with no semantic change. The upstream "~110 changed lines" are formatting, `rng.gen` renamed to `rng.random`, and test config construction. The committed merge moves the cross-size combine into the shared `combine_accumulated_numerators` (`:217-259`), which both paths call. It is byte-for-byte the same code as upstream's inline block.
- **`air/component_prover.rs`.** The upstream change was the weight type (`SecureColumnByCoords`); the committed file keeps it. The patch's `Option` evaluations, `committed_domain` and the prefix helper are carried over unchanged apart from formatting.
- **`constraint-framework` adapter.** It merged cleanly. Upstream removed the `is_disabled` skip, and the port follows upstream there. The SubDomain regeneration (`:45-79`) is the patch's logic unchanged.

## 2. Protocol equivalence

With `max_fri_columns = None`, the only non-upstream behaviour is the `needs_weights` predicate. The circuit prover always stores coefficients, so that predicate gives `None` exactly as upstream does. Opening goes through the unchanged `decommit` path, because every polynomial has evaluations and nothing is pruned.

With bounded mode on:

- **Transcript.** No channel operation is added, removed or moved. The order is unchanged: `mix_hash` of each root at commit, then `mix_felts` of the samples, `draw_secure_felt`, FRI commit, grind, `mix_u64` and FRI decommit (`pcs/mod.rs:300-341`). The `random_coeff` draw is simply hoisted into a local variable (`:305`) before the branch; the draw happens at the same point.
- **Sampled values.** Coefficient evaluation is used whenever coefficients exist, as upstream does with the store flag set. The results are exact field values, so they cannot depend on the path taken.
- **FRI quotients** (`quotient_ops.rs:137-215`):
  - Random powers and periodicity samples come from `build_samples_with_randomness_and_periodicity`, called once with the original tree/column order and committed sizes (`:148-153`). Those are the same inputs the unbounded path gets, because `committed_domain == evals.domain` by construction (`air/component_prover.rs:52`).
  - The new `accumulate_numerators` (CPU `backend/cpu/quotients.rs:23-49`; SIMD `backend/simd/quotients.rs:35-80` plus `accumulate_numerators_on_subdomain`) reads only the first `size >> log_blowup` rows. So a prefix with blowup 0 reads the same rows, and it takes the same branch for SIMD vs. the CPU fallback because the subdomain sizes are equal.
  - Chunk partials for the same point are combined with `B::accumulate` and `+=` (`:193-205`), which is exact field addition.
  - The per-size vectors stay in ascending size order, as `lift_and_accumulate` requires.
  - `compute_quotients_and_combine` and the upstream code that changed (CPU fallback, `batch_inverse`) are shared by both paths.
- **Decommitment order and bytes.** The tree order, the stable column sort inside `MerkleProverLifted::commit` and the `decommit` routine are all unchanged. The committed tests and the scratch tests show equal proofs, equal `all_node_values` and equal FRI aux.

I found no way for bounded mode to change the proof bytes.

## 3. Failure behaviour

See I1, I2 and L3.

- **Root checks.** They are release-mode `assert_eq!` (`pcs/mod.rs:517,547`), and the committed stale-root test exercises them (`:630-636`).
- **Evict asserts.** An owned tree without coefficients panics at commit time (`:486-494`).
- **Silent errors.** No silent-error path exists for openings. A mis-regenerated FRI prefix would produce a proof that the verifier rejects (L3).

## 4. Test adequacy

Tests I ran:
- **Worktree, with `parallel`:** `stwo` `prover::pcs` 13/13, `prover::air` 3/3; framework 18/18; `circuit-prover` 29/29.
- **Scratch copy, without `parallel`:** `stwo` pcs+air 18/18, which includes my 2 extra tests; framework 16/16.

How the adapted tests compare with the original ones:

- **Lifting heights.** The old `check_pcs` and `check_bounded_pcs` used `None`, which meant the maximum domain size, 8. The new tests use 8 explicitly, so nothing is lost. The extra lifting in `check_recomputed_tree` is kept (9 over a maximum of 8, `pcs/mod.rs:596-601`).
- **Framework config.** `FriConfig::new(4, 0, 3, 3, 1)` matches the old `pow_bits: 4` + `FriConfig::new(0, 3, 3, 1)`. Trace lifting `log_size + 3` equals the old `None`. Preprocessed lifting 0 is required for the empty tree.
- **Gaps:**
  1. No committed test uses different preprocessed and trace heights, the feature upstream added. Adopt `review_split_lifting`.
  2. The circuit-prover test ignores aux (M2).
  3. There is no circuit test with a borrowed preprocessed tree (`prove_circuit_with_precompute_bounded` with `MaybeOwned::Borrowed`), and no negative test for an owned preprocessed tree without coefficients (it should panic).
  4. The circuit test uses a new pool for each proof, so it never exercises pool reuse across modes. My scratch test does.
  5. There is no circuit-level run without the `parallel` feature.
  6. There is no CPU-backend circuit run; only the SIMD backend is covered at circuit level.

## 5. Memory claim (587 MB to 295 MB)

The claim is plausible. What bounded mode stops retaining for each owned tree:
- the expanded evaluations, which are 4 times the coefficients at `log_blowup = 2` (`client-port/examples/support/mod.rs:34`);
- every non-root Merkle layer.

My estimate, not measured: at trace log 18 the lifting height is 20, so each retained lifted tree is about 2 × 2^20 × 32 B ≈ 64 MiB of hashes. With four trees (preprocessed, trace, interaction, composition), Merkle retention alone is up to about 256 MiB. So the reduction is likely dominated by Merkle pruning rather than by evicting evaluations.

What still materializes:
- **Commit.** One complete tree at a time: all of its evaluations plus its full Merkle tree (`pcs/mod.rs:112-125`).
- **Opening.** The same again for each tree, one after another (`:362-372`), while the FRI prover's layers stay alive.
- **Composition.**
  - All columns of the current component are regenerated at once (framework `:45-79`).
  - The domain accumulator is kept at the composition size.
  - The composition polynomial coefficients are kept.
  - Prefix requests smaller than the coefficient vector evaluate the full committed domain and build full twiddles for each column (`air/component_prover.rs:112-114`); this costs time and memory.
- **FRI.**
  - Up to `max_fri_columns` prefix columns at a time, plus per-size subdomain twiddles.
  - The per-(size, point) accumulators for every size are kept until the combine step. Chunking does not bound them.
  - The full quotient evaluation and the FRI layer trees.
- **Always present.** Coefficients for every tree, twiddles, the witness `values`, and the preprocessed circuit.

The measurements in `results/stwo-client-arith/bounded-memory/runs.json` have caveats:
- They used a fresh witness and seed for each run, so the `proof_felts` differ. The release runs do not show byte-identical proofs; that equality is established only by the tests.
- They ran with `RAYON_NUM_THREADS=1`. Peak memory with more threads is unmeasured.
- Only one bounded proof went through the bridge.
- The time overhead is noisy: bounded runs took 4.1–12.5 s against 2.8–5.9 s unbounded.

## Limits

- This review covers only the four ported runtime files and the circuit-prover entry point. The unported streamed-Merkle API was not reviewed.
- Nothing here was checked on Cairo or `stwo-cairo`, where the preprocessed tree differs in size, ownership and twiddles.
- No independent measurement of peak RSS was made, and no WASM or browser run.
- The scratch experiments are in `/tmp/claude-1000/-home-broody-development-templar/5fc13b65-b1f1-4714-b584-08d0d0577803/scratchpad/review-pcs/repo` (a copy of the tree at `8acdbe55d`). The worktree was not modified.
