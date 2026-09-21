# Pinned felt252 Poseidon component inventory

This is a source-only inventory for the synthetic, validity-only membership
benchmark. No source changes, compilation, downloads, timing runs, or browser
qualification were performed for this inventory. The public-transcript boundary
described in [README.md](/home/broody/development/templar/bench/poseidon-membership/README.md)
is separate from a future statement over hidden paths.

## Source identity and locations

The inspected Cairo source is based on
`9b6be2710e4d7124bc93fe80a5af36556d42ed29`; S-two is based on
`489a0f3ee44a59e03944ad9aa4f3e5a91a3d3f08`. Existing isolated sources include
earlier allocation/storage patches; these pins describe their upstream bases.
See [environment.json](/home/broody/development/templar/bench/poseidon-membership/environment.json).
The inspected source snapshot remains unchanged.

For the exact paths below, `C` denotes
`/home/broody/development/templar/target/direct-air/stwo-cairo/stwo_cairo_prover/crates`,
and `S` denotes
`/home/broody/development/templar/target/direct-air/stwo/crates`.
Component AIR is at `C/cairo-air/src/components/<name>.rs`; the corresponding
witness generator is at `C/prover/src/witness/components/<name>.rs`.

The main orchestration reference is
[cairo_claim_generator.rs](/home/broody/development/templar/target/direct-air/stwo-cairo/stwo_cairo_prover/crates/prover/src/witness/cairo_claim_generator.rs:1339).
It shows the dependency order and arguments for writing all Poseidon subtraces.

## Reusable subset and its boundary

There is no intrinsic dependency from the felt252 permutation components back
to Cairo CPU opcodes, registers, or a virtual OS. The existing
`poseidon_aggregator` accepts three input memory-value IDs and three output IDs;
its witness generator resolves those IDs to felt252 values. It deduplicates
identical ID tuples and tracks multiplicities. Its own rows are padded to at
least 16 and then to a power of two.

The unchanged arithmetic/lookup closure is:

| Component | Trace columns | Interaction columns, as M31 coordinates | Role/dependencies |
| --- | ---: | ---: | --- |
| `poseidon_aggregator` | 342 | 56 | Resolves six values; calls round chains, cubing, width-27 and small range checks |
| `poseidon_full_round_chain` | 126 | 24 | Cubing, round keys, `range_check_3_3_3_3_3` |
| `poseidon_3_partial_rounds_chain` | 169 | 36 | Cubing, round keys, width-27, `range_check_4_4` and `range_check_4_4_4_4` |
| `cube_252` | 141 | 200 | Eight `range_check_9_9` relations and eight `range_check_20` relations |
| `range_check_252_width_27` | 20 | 32 | `range_check_9_9` and `range_check_18` |
| `poseidon_round_keys` | 1 | 4 | Fixed 64-row table and 30 preprocessed key columns |
| Six fixed range-check tables | See next section | See next section | Close all arithmetic range lookups |

The aggregator also consumes `MemoryIdToBig` lookups. A general statement can
close those using the existing `memory_id_to_big` and `memory_id_to_small` AIRs
and their witness generator, with dynamic sequence columns and additional
`range_check_9_9` requests. The big table uses 29 trace plus 32 interaction
columns per row; the small table uses 9 plus 12. The public
`MemoryBuilder`/`Memory` implementation is in `C/adapter/src/memory.rs`.

For this benchmark, the reviewer approved replacing those memory AIRs with an
exact, verifier-derived public lookup boundary when it authenticates **every**
memory lookup, including multiplicities and padding behavior. The witness
generator may still use the existing in-memory value resolver. This removes
memory-table proof work, not the need to bind those values. It does not supply
constraints for a hidden-path statement.

`poseidon_builtin` is optional and unnecessary for direct value-ID dispatch.
It introduces the address-based Cairo memory interface (`MemoryAddressToId`),
plus 6 trace and 16 interaction columns. Avoiding it avoids that extra interface.

The permutation subset alone does not prove ordered Merkle membership. The
benchmark's verifier must authenticate child order, canonical field values,
sponge transitions/padding, leaf/index/root, and the public permutation and
memory lookup boundaries, and bind the public statement into the transcript.
For a future hidden-path proof, those checks need reviewed AIR constraints.

## Exact hashing and fast deduction

The existing membership reference is
[statement.cairo](/home/broody/development/templar/bench/controlled-push-e2e/cairo/src/statement.cairo:46):
each parent is `poseidon_hash_span([left, right])`.
The exact sponge implementation is
[/home/broody/.cache/scarb/registry/std/v2.18.0/core/src/poseidon.cairo](/home/broody/.cache/scarb/registry/std/v2.18.0/core/src/poseidon.cairo:129),
with finalization at line 104:

1. Start from `(0,0,0)`.
2. Add each complete input pair to the first two state elements, then permute.
3. Always perform final padding and another permutation: add one to `s0` for
   an even input count; for an odd count, absorb the remaining input into `s0`
   and add one to `s1`.
4. Return the final `s0`.

Consequently a two-element parent hash takes **two Hades permutations**:

| Workload | Parent hashes | Logical permutation calls |
| --- | ---: | ---: |
| One depth-32 path | 32 | 64 |
| Two depth-32 paths | 64 | 128 |

These counts exclude leaf construction or other application/domain hashes.
Deduplication and SIMD/power-of-two padding can make component row counts
different from logical call counts; both should be reported.

The scalar and packed deduction helpers are in
[fast_deduction/poseidon.rs](/home/broody/development/templar/target/direct-air/stwo-cairo/stwo_cairo_prover/crates/prover/src/witness/fast_deduction/poseidon.rs).
They expose `Cube252::deduce_output`, `PoseidonFullRoundChain::deduce_output`,
`Poseidon3PartialRoundsChain::deduce_output`, and packed equivalents. They are
round-level helpers, not a complete hash-span interface. The existing
[aggregator witness](/home/broody/development/templar/target/direct-air/stwo-cairo/stwo_cairo_prover/crates/prover/src/witness/components/poseidon_aggregator.rs:514)
wires the full permutation: full-round chain indices 0–3, partial-round groups
4–30, full-round indices 31–34, and the intervening transformations. Reusing
that generator preserves the optimized constants and representation rules.
`Felt252Width27` conversions and the cubing helper have explicit Montgomery
representation compensation; ordinary field operations should not be silently
substituted into this wiring.

## Fixed-table size calculation

Each M31 coordinate occupies four bytes. Each QM31 interaction column contributes
four M31 columns. For a fixed table with log size `L`, preprocessing columns `P`,
trace columns `T`, and M31 interaction columns `I`, the logical base storage is:

`bytes = 2^L × (P + T + I) × 4`.

| Table | L | P | T | I | Base MiB | LDE ×4 MiB | LDE ×8 MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `range_check_20` | 20 | 1 | 8 | 16 | 100 | 400 | 800 |
| `range_check_9_9` | 18 | 2 | 8 | 16 | 26 | 104 | 208 |
| `range_check_18` | 18 | 1 | 2 | 4 | 7 | 28 | 56 |
| `range_check_3_3_3_3_3` | 15 | 5 | 1 | 4 | 1.25 | 5 | 10 |
| `range_check_4_4_4_4` | 16 | 4 | 1 | 4 | 2.25 | 9 | 18 |
| `range_check_4_4` | 8 | 2 | 1 | 4 | 0.0068359375 | 0.02734375 | 0.0546875 |
| `poseidon_round_keys` | 6 | 31 | 1 | 4 | 0.0087890625 | 0.03515625 | 0.0703125 |
| **Total** | | **46** | | | **136.515625** | **546.0625** | **1092.125** |

These are exact logical array sizes from the pinned component definitions,
**not measured RSS or an unavoidable simultaneous-memory lower bound**.
Coefficient retention, recomputation, and streaming can change which arrays
coexist. Additional costs include variable component traces, dynamic sequence
columns, lookup-data buffers, multiplicities, coefficient/interpolation work,
Merkle hashes, composition/FRI buffers, stacks, serialization, and allocator
overhead. In particular, retained Merkle trees are not counted here.

Without preprocessing, the fixed tables' trace plus interaction arrays total
127.881103515625 MiB at base domains. `range_check_20` alone contributes 96 MiB
of that. It forces maximum trace log size at least 20 even for a tiny workload;
blowup log 2 means LDE log 22, and blowup log 3 means LDE log 23.

The likely benchmark config is the existing Cairo strength: PoW 27, blowup log
3, 23 queries, fold step 4, last-layer degree log 0. Its convenience strength
calculation is `27 + 3 × 23 = 96`. Therefore the ×8 column above is the relevant
baseline if all fixed-table LDEs coexist. The ×4 column is included for comparison,
not as a proposal to change security settings.

Required fixed preprocessing is exactly: `poseidon_round_keys_0..29`, `seq_6`,
`seq_18`, `seq_20`, the five `range_check_3_3_3_3_3_column_*` columns, four
`range_check_4_4_4_4_column_*`, two `range_check_4_4_column_*`, and two
`range_check_9_9_column_*`. Add only the dynamic sequence sizes actually used by
the aggregator and any included memory AIR. This dedicated statement must pin
its own ordered subset and root; it must not claim the stock canonical Cairo
preprocessing root. `testing_preprocessed_tree(20)` filters by size only and
still includes unrelated columns.

## Existing harnesses and native thread accounting

- `C/prover/src/debug_tools/assert_constraints.rs::assert_component` is a public
  helper for checking each generated component trace with its claimed lookup sum.
- `C/prover/src/prover.rs::test_poseidon_builtin_constraints` and
  `test_poseidon_aggregator` exercise the faithful felt252 components, but run a
  complete Cairo program. They are useful regression references, not an existing
  isolated membership prover.
- `S/examples/src/state_machine/mod.rs` demonstrates a multi-component proving,
  interaction, public-boundary, and verification harness. Its protocol plumbing
  is reusable with an explicitly reviewed statement.
- `S/examples/src/poseidon/mod.rs` implements a different Poseidon2 construction
  over M31 with placeholder constants. It is **not** a semantic replacement for
  Starknet felt252 Poseidon; only generic proving scaffolding is relevant.

The existing
[cube_252 witness](/home/broody/development/templar/target/direct-air/stwo-cairo/stwo_cairo_prover/crates/prover/src/witness/components/cube_252.rs:40)
creates its own `rayon::ThreadPoolBuilder`, requests an **8 MiB stack per worker**,
and calls `build().unwrap()`. It does not set `.num_threads(...)` and is separate
from a caller's scoped pool. The comment warns that reducing the stack can cause
stack overflow. Worker count, `RAYON_NUM_THREADS`, and CPU affinity therefore
need recording. Stack reservation is not necessarily resident RSS.

## WASM portability inventory: source evidence only

| Area | What the selected source does | Consequence for later browser work |
| --- | --- | --- |
| Threads | Witness prelude unconditionally imports Rayon; generators use parallel iterators. `cube_252` explicitly constructs a private pool. Prover dependencies force S-two/framework `parallel`, and common's `prover` feature also enables it. | There is no demonstrated serial feature switch for this whole witness subset. A serial implementation path or an explicit browser-worker pool integration must be qualified; the native private-pool call is a concrete portability issue. |
| Synchronization | Aggregator uses `DashMap` plus `AtomicU32`; table multiplicities use atomic increments over packed buffers; shared data uses `Arc`. | A serial port must preserve multiplicities and deterministic ordering. A threaded port needs suitable worker/shared-memory support; source inspection alone does not establish it. |
| SIMD | Prover/common require nightly `portable_simd`; packed M31 has 16 lanes. S-two has an explicit `wasm32 + simd128` multiplication path and portable fallbacks. Felt252 witness types also use `std::simd`. | The arithmetic is not exclusively x86, but successful target compilation and browser performance remain untested. 16 logical lanes do not imply one hardware WASM instruction. |
| Randomness | The chosen non-test witness functions deterministically derive traces from inputs and constants; no explicit application RNG call was found. HashMap/DashMap use standard randomized hashing. The prover manifest enables JS randomness backends for indirect getrandom 0.2/0.3 dependencies on WASM. | Those dependency declarations are useful compatibility preparation, not a browser qualification or a statement about a future privacy construction. This benchmark adds no such construction. |
| Filesystem/environment | No file, network, or environment access appears in the selected arithmetic/table witness functions. They consume in-memory values and preprocessed columns. Rayon configuration can depend on the host environment. | A browser API can supply those values in memory. CLI fixture reading, output files, and timing are harness responsibilities, not intrinsic Poseidon arithmetic dependencies. |
| Memory/stack | Large fixed vectors, cloned memory values, lookup buffers and polynomial work remain; cube witness has the explicit large native stack noted above. | Native RSS cannot establish a WASM linear-memory or stack bound. Linear-memory high-water usage, copies, worker stacks, and allocation failures need separate measurement. |

Relevant exact files: `C/prover/Cargo.toml`, `C/common/Cargo.toml`,
`C/prover/src/lib.rs`, `C/common/src/lib.rs`,
`C/prover/src/witness/prelude.rs`, `C/prover/src/witness/utils.rs`,
`C/common/src/prover_types/simd.rs`, and
`S/stwo/src/prover/backend/simd/m31.rs` (the explicit WASM multiplication branch
starts near line 410 in the inspected snapshot). No WASM build was attempted.
