# Cairo performance review: R0 bridge, virtual OS, PROOF2, pool

2026-09-23. Independent review of the R0 payment bridge on the arithmetic-only route with
single-permutation tree nodes (`target/bridge-r0c`, proof `r0c/t4-16-1`). All experiments ran on
copies in the session scratchpad. No committed code was changed. Step counts are deterministic
execution counts. The PROOF2 time is from one run.

## Summary

**Three local changes to the vendored FRI/PCS verifier cut the bridge by 41%.** They take it
from 3.39M to 2.00M steps and the virtual OS from 4.96M to 3.33M. PROOF2 barely moves, from
120.3 s / 54.4 GiB to 114.6 s / 52.6 GiB. **PROOF2 cost is set by the largest Cairo AIR
component's log size, not by step count.** That size is log21 today, and the three components
at log21 do not scale with bridge steps. **The account's compiled CASM (82,828 felts) is over
the sequencer's 81,920-felt CASM limit.** Pruning the absent circuit components brings it to
58,087.

| Measurement | Baseline (`bridge-r0c`) | Optimized (this review) |
| --- | ---: | ---: |
| Bridge, standalone steps | 3,393,583 | **2,002,753** (−41.0%) |
| Bridge range checks | 483,384 | 237,896 |
| Bridge Blake opcodes (compress + finalize) | 3,886 | 3,886 |
| Account steps inside OS (PC segment 19) | 3,927,695 | 2,259,890 |
| OS-own steps (segment 14) | 1,032,316 | 1,065,365 |
| Bootloader steps (segment 0) | 199,389 | 199,389 |
| Virtual OS `n_steps` | 4,960,011 | **3,325,255** (−33.0%) |
| Blake compressions, whole bootloader run | 13,123 | 13,392 |
| Poseidon builtin instances (OS) | 15,038 | 15,038 |
| Cairo AIR padded rows / max component log | 19.22M / 21 | 14.70M / 21 |
| PROOF2 prove time / peak RSS | 120.3 s / 54.4 GiB | **114.6 s / 52.6 GiB** (verified, 3/3 rejections) |
| Account Sierra / CASM felts | 50,725 / **82,828** | 51,663 / 84,748; with pruning **28,085 / 58,087** |
| Validation (`validate_bridge_r0.py`) | 15/15 | 15/15 (both variants); verifier_core unit tests 73/73 |

**Poseidon2-M31 pool cost (Q4):** measured in contract mode (snforge 0.63):
- One width-24 permutation costs **1.40M L2 gas** (12,120 steps + 2,639 range checks standalone).
- A depth-32 append path costs **46.0M gas with single-permutation nodes** and **90.7M with sponge
  nodes**. The felt252 Poseidon path costs 0.45M. The M31 path is about 100× (compress) to 200×
  (sponge) the felt252 cost.
- Two appends in `apply_spend` hash for about **92M gas (compress) or 181M (sponge)**. Adjacent
  outputs appended as a pair cost about 48M or 95M. Storage is extra.

## Ranked optimizations

The PROOF2 column is the expected effect on the large-path prover. Most bridge savings show up
only as OS steps unless a max-log component shrinks (see Q3).

| # | Change | Measured / estimated effect | Effort | Security impact |
| --- | --- | --- | --- | --- |
| 1 | **Batch M31 inversion in FRI folding.** One Montgomery batch per layer instead of Fermat inversion per twiddle (`fri.cairo:510-646`, `fields/m31/naive.cairo:10`). | **−885,886 steps (−26.1%)**, measured | ~120 lines in the fork's `fri.cairo` | None. Same arithmetic, and a zero twiddle still panics. 15/15 bridge checks, 73/73 verifier_core tests. |
| 2 | **Coset twiddles by point addition.** `P0 + k·step` replaces a `to_point` table lookup and a `bit_reverse_index` per point (`circle.cairo:212`, `utils.cairo:178`). | **−238,316 steps (−7.0%)**, measured | ~40 lines | None. |
| 3 | **`fri_answers`: skip empty degree bounds, one batch inversion across all queries.** The loop at `pcs/quotients.cairo:89-127` runs `tree_take_n` and a CM31 batch inverse for every degree bound 0..18, for all 35 queries. | **−266,628 steps (−7.9%)**, measured | ~60 lines | None. Zero denominators still panic. |
|   | **1+2+3 combined** | Bridge −41.0%, OS −33.0%, PROOF2 −5.7 s / −1.8 GiB (one run) | | |
| 4 | **Prune absent components** in the arithmetic profile: assert log size 0 instead of carrying 9 evaluators (`circuit_air.cairo:108-260`). | Sierra −23.6k felts (−46%), CASM −26.7k, OS −11k steps, −94 Blake. **Fixes the CASM limit breach (Q5).** Measured. | Small; profile-specific build | None. Log sizes are pinned constants, and absent sums are already rejected. |
| 5 | **FRI last-layer degree bound 0 → 2.** The fold schedule goes from 4+(4,4,4,2) to 4+(4,4,4), removing one inner layer and its Merkle paths per query. | Est. −0.1 to −0.2M steps, −2 to 3k calldata felts. Not measured. | Client config + circuit-hash repin | None. Soundness still comes from blowup × queries + PoW. |
| 6 | **Fewer queries at higher blowup:** log-blowup 3, 24 queries, PoW 26 (98 bits). | Est. −0.5M bridge steps, −~1.2k Blake, −30% calldata. The client's LDE doubles (≈ +0.3 GiB, +60–100% prove time). Not measured. | Client + bridge config | Same conjectured formula (≥ 96 bits). |
| 7 | **Pack calldata:** Blake hash 8→2 felts, QM31 4→1, M31 values 8/felt. | +~0.1M bridge steps (measured micro-costs below). Poseidon tx-hash instances 15k → ~4–8k. That removes the log22 cliff risk and saves 2.4–3.6M padded rows (≈ −3 to −5 s at log21). | Client serializer + Cairo deserializer | None (encoding only). Keep the exact-length check. |
| 8 | **Code layout for class hashing:** build only present components in `CircuitAirNewImpl::new` (4,122 hashed felts, 317 executed). Move `assert!` formatting and `Debug` impls out of hot functions. | Est. −10 to −20k hashed felts: −1.3 to −2.6k Blake, −0.17 to −0.35M OS steps | Medium | None |
| ✗ | `inlining-strategy = "avoid"` | Measured **worse**: account 8.0M steps, CASM 96,996 | — | — |
| ✗ | `qm31_opcode` feature | Not usable: `qm31_*` libfuncs are absent from the audited list, and there is no QM31 opcode in the privacy component set | — | — |
| ✗ | More PoW bits for fewer queries | 26→30 bits saves 2 of 35 queries at 16× phone grinding | — | — |

The profile of the optimized bridge now ranks the next targets:
- FRI inner-layer decommit, 922k steps: Merkle, `fri_fold` (251k) and position bookkeeping
  (`compute_decommitment_positions_and_rebuild_evals`, 138k).
- Proof deserialization, 350k (17.5%).
- Merkle verification overall, 384k.
- `fri_answers`, 249k.

## Q1: Where do the bridge's 3.39M steps go?

**Method.**
- Ran `scarb execute --save-profiler-trace-data` on a copy with Sierra debug info. The resulting
  binary gave identical step counts.
- The installed cairo-profiler 0.14 fails on `local_into_box`, so I wrote my own attribution. It
  recompiles the executable's Sierra to CASM with cairo-lang 2.19.0-rc.3 (bytecode head matches;
  length 70,254 vs 70,255), maps each traced pc to its Sierra statement and inlined-function
  stack, and rebuilds call frames from `fp`.
- Blake opcodes were counted by decoding the instruction at each traced pc.
- All figures are inclusive steps.

| Phase | Baseline | Optimized | Notes |
| --- | ---: | ---: | --- |
| Proof deserialization (`CircuitProofSerde`) | 350,394 (10.3%) | 350,394 (17.5%) | Blake hashes 162k (~2,050 hashes × 8 felts), QM31 81k, M31 76k |
| Circuit hash (`compute_circuit_hash`) | 550 | 550 | |
| Statement decode (`felt_from_limbs` + limbs) + binding Poseidon | ~8k + 1,122 | same | |
| Claim / lookup sums / absent-component checks | ~42k | ~42k | `lookup_sum` 40k |
| OODS / composition evaluation | 17,303 | 17,303 | Only 2 components are evaluated |
| Channel, PoW | <5k; PoW 212 | same | |
| PCS `verify_values` | 2,921,597 (86.1%) | 1,530,767 | |
| ↳ quotients `fri_answers` | 515,442 | 248,807 | `tree_take_n` 183k → 34k |
| ↳ PCS tree Merkle + query prep | ~222k | ~222k | |
| ↳ FRI decommit | 2,183,641 (64.3%) | 1,059,439 | first layer 136k; inner layers 2.05M → 0.92M |
| M31 Fermat inversion (inside FRI) | **1,088,222 (32.1%)** | 23,080 | ~3.2k inversions × ~340 steps |
| `to_point` / `bit_reverse_index` | 205k / 149k | 34k / 61k | |
| Merkle verify (all trees), Blake opcodes | 383,934; 3,886 opcodes | same | 22 compress + 3,864 finalize |

The earlier finding in `bridge-capacity/README.md` (checked `u256_inv_mod`, −15%) was not carried
into the arithmetic-profile fork. Batch inversion (#1) supersedes it.

**Micro-costs for the encoding decision (#7).** Measured per item, with argument-copy overhead
subtracted:

| Item | Current encoding | Packed encoding |
| --- | --- | --- |
| Blake hash | 79 steps + 17 range checks, 8 felts | 132 steps + 35 range checks, 2 felts as u128 |
| QM31 | 59 steps + 8 range checks, 4 felts | 71 steps + 21 range checks, 1 felt |

Packing costs a little Cairo. Its value lies in calldata and the Poseidon tx-hash (Q3).

## Q2: OS overhead beyond the bridge (4.96M − 3.39M = 1.57M)

**Method.** Replayed each captured PIE through the privacy bootloader
(`proof2-large/blake-attribution/blake_sites.rs`, rebuilt from the preserved dependencies). Steps
and Blake opcodes were counted by PC segment. Executed PCs were mapped onto the compiled class's
`bytecode_segment_lengths` and on to Sierra functions: the class was recompiled with debug info
via `cairo-lang-starknet-classes`, reproducing 82,828 felts exactly.

| Component | Steps | Blake | Share of the 1.57M |
| --- | ---: | ---: | --- |
| Contract-mode inflation of the verifier (gas accounting, `__validate__`, syscalls) | 534,112 (account 3,927,695 vs standalone 3,393,583) | 0 | 34% |
| OS: compiled-class hash of the executed bytecode segments | ≈ 0.85–0.95M | ≈ 7,100 | ≈ 57% |
| OS: everything else (tx hash over 29,959 calldata felts = 15,038 Poseidon instances, syscalls, L1 message, state) | ≈ 0.1–0.2M | ~220 | ≈ 9% |
| Bootloader (not in OS `n_steps`) | 199,389 | 1,914 | — |

**Class hashing.**
- The class-hash cost comes from two measured deltas, 15.9 and 17.7 steps per hashed felt.
- The OS hashes every visited segment in full: 209 of 292 segments, **53,554 felts**, although
  only **17,668 PCs** execute.
- Largest wasted segments:
  - `CircuitAirNewImpl::new`: 4,122 felts, 317 executed. It builds all 11 components.
  - `verify_payment`: 2,426 felts, 497 executed.
  - `FriVerifierImpl::commit`: 1,359 felts, 189 executed.
  - `fold_circle`: 1,262 felts, 421 executed.
  - `CircuitProofSerde::deserialize`: 1,046 felts, 165 executed.
  - `M31Debug::fmt`: 754 felts, 1 executed.

**Gas-accounting inflation.** It scales with loop iterations and calls. After the optimizations
it is 257k (+12.8%).

**Reductions.**
- Change #4 plus #8 cut the hashed felts: −1.3 to −2.6k Blake, −0.2 to −0.35M steps.
- Change #7 cuts the Poseidon tx hash.
- Fewer loop iterations cut the gas inflation; changes #1–3 already halved it.
- Code *size* matters only through visited segments. Unvisited code (for example absent
  components' evaluators) costs Sierra/CASM size, not OS steps.

## Q3: PROOF2 cost vs OS steps

**Method.** Ran `capacity trace` (Cairo AIR claim generation, no proof) on each retained PIE,
then made one PROOF2 run (`run.sh`, 105G cap) on the optimized PIE.

| Run | OS steps | Blake | Poseidon | Padded rows | Max log | PROOF2 | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| StarkWare sample | 0.28M (with bootloader) | 2,346 | — | 1.25M | 19 | 87 s | 42.1 GiB |
| **Optimized r0c (this review)** | 3.33M | 13,392 | 15,038 | 14.70M | 21 | **114.6 s** | **52.6 GiB** |
| r0c single-perm nodes | 4.96M | 13,123 | 15,038 | 19.22M | 21 | 120.3 s | 54.4 GiB |
| r0 lanes | 5.13M | 13,353 | 15,950 | 19.48M | 21 | 117.5 s | 55.0 GiB |
| r0 log20 | 5.42M | 13,678 | **17,236** | 24.36M | **22** | 139 s | 64.2 GiB |
| stock | 7.22M | 17,511 | 23,032 | 28.74M | 22 | 140 s | 63.1 GiB |

(Membership arith, 4.93M → 116 s / 52.2 GiB, has no retained PIE and was not traced.)

**The cost comes in tiers by the largest component log**, which sets the lifting domain.
- Max log 19 gives 87 s, log 21 gives about 115–120 s, and log 22 gives about 139–140 s.
- Within a tier, row count barely matters. The optimized run removed 4.5M padded rows (−23%) and
  33% of the steps but saved only 5.7 s / 1.8 GiB. r0c and r0 lanes differ by 3 s with near-equal
  rows, which is the noise level.

**Why r0 log20 jumped to 139 s.** Its Poseidon builtin count crossed 16,384 (17,236), doubling
`cube_252`, `range_check_252_width_27` and the Poseidon round chains to log22. Stock also has
Blake above 16,384.

**The three log21 components in the optimized run do not depend on bridge steps:**
- `blake_g` (about 128 rows per compression) needs **≤ 8,192 Blake compressions** for log20. Today
  there are 13.4k: bootloader 1.9k, OS class hash 7.4k, bridge Merkle 3.9k.
- `cube_252` and `range_check_252_width_27` need **≤ 8,192 Poseidon instances**, which means
  calldata of about 16k felts or less. Today there are 15.0k, from the tx hash of 29,959 calldata
  felts.
- `assert_eq_opcode_double_deref` and `memory_id_to_small` dropped from 21 to 20 with the
  optimizations.

**What would materially change PROOF2:**
1. **Keep away from the log22 cliff.** It costs +20 s / +10 GiB. r0c is at 92% of the Poseidon
   threshold (15,038 / 16,384): about 2.7k more calldata felts crosses it. Blake is at 80%
   (13,123 / 16,384). Calldata packing (#7) is the cheap insurance.
2. **Reach max log 20.** Interpolation suggests about 100–105 s / ~47 GiB; this is not measured.
   It needs both counts ≤ 8,192: calldata packing, and cutting Blake by about 5.2k (class-hash
   bytecode 55k → ~18k hashed felts, or fewer bridge Merkle hashes via #6). That is a large
   code-size effort for about 15 s.
3. The floor is 87 s / 42 GiB (log25 leaf). Today's 120 s is 33 s above it, and steps alone
   cannot remove that.

## Q4: On-chain pool cost with an M31 Poseidon2 tree

**Method.**
- Generated a fully unrolled width-24 Poseidon2-M31 permutation in Cairo (`review-cairo/p2/gen.py`),
  using the constants from `bench/m31-private-blake/client/src/constants.rs` and the round order in
  `hash.rs`: 4 external, 22 internal, 4 external rounds, `x^5`.
- Arithmetic uses lazy reduction: felt252 accumulation, reduction by `M31Trait::reduce_u64/u128`,
  a 2-reduction S-box, and internal rounds reduced every 4 rounds (bounds < 2^123).
- The output matches the Plonky3 golden vectors in `bench/m31-tree/cairo/src/golden.cairo` and a
  Python reference over 10 chained permutations.
- Costs were measured standalone (`scarb execute`) and in contract mode with snforge 0.63, which
  reports L2 gas.

| Item | Steps / range checks | L2 gas (contract) |
| --- | ---: | ---: |
| Poseidon2-M31 permutation, first straightforward version | 20,300 / 5,877 | — |
| **Poseidon2-M31 permutation, optimized** | **12,120 / 2,639** | **1.40M** |
| Depth-32 path, single-permutation nodes (`P([TAG,1,8,level,l9,r9,0,0])[0..9]`) | ≈ 0.39M steps | **46.0M** |
| Depth-32 path, sponge nodes (2 permutations, rate 15) | ≈ 0.78M steps | **90.7M** |
| Depth-32 path, felt252 `poseidon_hash_span([l, r])` (reference pool) | ≈ 1.3k steps + 32 builtins | 0.45M (14.1k/node) |

**`apply_spend`, two outputs, hashing only:**
- Independent appends (64 nodes): **~92M gas (compress) or ~181M (sponge)**, about 0.8M or 1.6M
  steps.
- Batch-appending both outputs (32 + merge-level nodes, ~33–34 for adjacent indices): **~48M or
  ~95M**.
- The reference felt252 pool hashes the same two appends for ~0.9M gas. The earlier
  `bench/m31-tree` measurement of a full warm append including storage was 5.12M (felt) and 788M
  (straightforward M31 port).
- This implementation is about 17× cheaper than that M31 port, but still roughly 50–100× the
  felt252 pool per spend.

**Storage.**
- A 9-word digest takes 2 felts. The reference `insert_leaf` (`controlled-push-e2e/cairo/src/tree.cairo:123-167`)
  writes every path node, so M31 digests double those writes, to 66 felts per append.
- A frontier-only tree (32 stored digests, writing only the changed frontier slot and the root)
  would cut this regardless of the hash.

**Limits.** Both variants fit under the 1B `execute_max_sierra_gas` per transaction. The
unrolled permutation adds about 15–18k Sierra felts to the pool contract (the bench contract is
18,521).

**Options if this is too costly:**
- Batch-append outputs.
- Keep the tree update off-chain and prove it inside PROOF2. This needs a design for the race
  against concurrent spends, for example an on-chain felt252 accumulator of commitments that is
  rooted periodically.
- Keep single-permutation nodes, which halve the cost if the node format passes review.

## Q5: Account class size headroom

The sequencer enforces two different 81,920-felt limits:
- The gateway limits **Sierra length** (`apollo_gateway/src/stateless_transaction_validator.rs:319`,
  config 81,920).
- The Sierra→CASM compiler limits **CASM bytecode** (`apollo_sierra_compilation_config/src/config.rs:9`:
  `80 * 1024`, passed to `--max-bytecode-size`; `cairo-lang-sierra-to-casm` `compiler.rs:486`
  returns `CodeSizeLimitExceeded`).

Paths are in the sequencer checkout at
`/tmp/templar-stwo-privacy-dtgn6e8l/…/sequencer-e6b6fd2…`.

| Variant | Sierra felts | CASM felts | Status |
| --- | ---: | ---: | --- |
| Baseline account (`bridge-r0c`) | 50,725 (62%) | **82,828 (101.1%)** | **Over the CASM limit by 908** |
| Optimized (#1–3) | 51,663 | 84,748 | Over by 2,828 |
| Optimized + pruned absent components (#4) | **28,085** | **58,087 (71%)** | 23.8k CASM headroom |
| `inlining-strategy = "avoid"` | 59,374 | 96,996 | Worse |

**Risk.**
- The local capture fixture never runs the sequencer's compiler, so the breach did not show up.
- The sequencer compiles with its own cairo-lang version, so the exact CASM count may differ
  slightly. At 101% of the limit the declaration should be expected to fail.

**Growth.**
- Statement growth is cheap: a few hundred felts per extra decoded field.
- Things that would threaten the limit:
  - Moving pool logic, or an in-account Poseidon2-M31 (~15–18k Sierra, more CASM), into the
    account.
  - Keeping all 11 circuit components as the circuit gains present components.
  - Monomorphized verifier variants, for example two node formats in one class.
- Adopt #4 (or a build that includes only the profile's components). Add a CASM-size check
  (≤ 81,920 with margin) to `build_bridge_arith.py`, next to the existing Sierra figure.

## Limits

- **PROOF2:** one run for the optimized PIE. Near-identical workloads differ by about 3 s between
  runs. The tier model rests on 6 traced PIEs, and the log20 estimate is an interpolation.
- **Estimates:** changes #5, #6 and #8 and the calldata-packing PROOF2 effect are estimates. They
  need client proofs with new configurations (FRI config, encoding), which were not generated.
  The optimized bridge was validated only on the one r0c proof and its 14 negative cases.
- **Profiler:** the phase attribution is my trace-based profiler. Inclusive counts deduplicate
  recursion, and there is a small `<unknown>` bucket (0.8%). OS-own attribution between class
  hashing and the rest comes from two differential measurements, not a function-level OS profile.
- **Pool:** figures cover hashing only, measured locally with snforge. They are not network fee
  quotes and exclude storage, events and the rest of `apply_spend`. The node-format encodings in
  the bench contract mirror `payment::Tree` framing, but the sponge padding was not cross-checked
  against the Rust `payment.rs` vectors. Step and gas costs do not depend on the exact word
  values.
- **Scratch artifacts:** they live under the session scratchpad `review-cairo/` and are not
  preserved: `ws` (optimized), `ws-prune`, `p2`/`p2c` (Poseidon2), `attr` (segment probe),
  `trace/*/claim.json`, `proof2-opt3/summary.json`, PIE sha256 `6ecc2617…`.

## Appendix: the verifier changes (fork `stwo_cairo_verifier`, vendored copy)

<details><summary>#1 + #2 in <code>verifier_core/src/fri.cairo</code> (condensed)</summary>

```cairo
fn fold_line(self: @SparseEvaluation, fold_alpha: QM31, source_domain: LineDomain, fold_step: u32) -> Array<QM31> {
    let order = even_bit_reversed_order(fold_step);           // bit_reverse_index(j, fold_step) for even j, once per layer
    let step_point = CirclePointIndexImpl::subgroup_gen(fold_step).to_point();
    let half = pow2(fold_step - 1);
    let mut twiddles = array![];
    for idx in *self.subset_domain_initial_indexes {
        let points = coset_points(source_domain.coset.index_at(*idx), step_point, half); // P0 + k*step by addition
        let mut x_coords = array![];
        for k in order { x_coords.append((*points.at(*k)).x); }
        append_coset_fold_twiddles(x_coords.span(), ref twiddles); // x's of every fold round, in order of use
    }
    let inverses = BatchInvertible::batch_inverse(twiddles);   // one M31 inversion per layer
    let mut inverses = inverses.span();
    let mut folded_eval = array![];
    for subset_eval in self.subset_evals.span() {
        assert!(subset_eval.len() == pow2(fold_step));
        folded_eval.append(fold_coset_with_inverses(subset_eval.span(), ref inverses, fold_alpha));
    }
    assert!(inverses.is_empty());
    folded_eval
}
// fold_circle: same pattern; per subset appends y(P_k0), y(P_k1) pairs then the line-fold x's.
```
</details>

<details><summary>#3 in <code>verifier_core/src/pcs/quotients.cairo</code> (condensed)</summary>

```cairo
// Build per-degree-bound batches only for bounds that have columns.
if n_cols_total != 0 || !sample_batches.is_empty() { /* gen QuotientConstants, append */ }
// Denominators for every (query, batch), one CM31 batch inversion, then accumulate.
for pos in query_positions { let p = domain point; domain_points.append(p);
    for (batches, _, _) in bounds { for b in *batches { denominators.append(fused_quotient_denominator(b.point, p)); } } }
let inverses = BatchInvertible::batch_inverse(denominators);
// accumulate_row_quotients_with_inverses(inverses.slice(..n_batches), row values, constants, p)
```
</details>

<details><summary>#4 in <code>circuit_air/src/circuit_air.cairo</code></summary>

The nine `if *component_log_sizes.X != 0 { X.evaluate_constraints_at_point(...) }` blocks for the
absent components are replaced by `assert(*component_log_sizes.X == 0, 'absent component');`.
</details>
