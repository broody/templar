# Coefficient-backed memory experiment: invariant review

Reviewed 2026-09-21 against pinned S-two `489a0f3ee44a59e03944ad9aa4f3e5a91a3d3f08`, stwo-cairo `9b6be27`, stwo-circuits `5ef951a`, proving-utils `3035dd00421daa541894297bd754db6e2787807b`, and sequencer `e6b6fd2e9932909107833579e5b6efd6c75fa0af`. This is a targeted source and differential-test review of storage scheduling and deterministic recomputation. It is not a cryptographic audit, browser qualification, or production qualification.

The reviewed implementation is suitable for continued native memory work. No protocol-equivalence finding remains open in the reviewed source. The final focused tests and release integration checks passed for the four archived valid workloads. Independent review confirmed 15 serialized proofs byte-for-byte against matching-request outputs from the previous archive, unchanged-verifier acceptance, 45 mutation rejections, and successful repeated proving under an 8 GiB process-group cap. Both 4 GiB probes failed with recorded out-of-memory kills. The evidence and its limits are detailed below.

## Runtime scope

The opt-in PCS mode retains coefficients and the committed domain for each owned polynomial while releasing its expanded evaluations after commitment. It also retains only each owned Merkle root and logical height. Commitment and opening still materialize one complete tree using the original FFT and Merkle implementations. Opening regenerates the tree, checks its root against the retained root in release builds, and invokes the original decommitment routine.

Composition generation regenerates only the columns needed by the current framework component. FRI numerator accumulation regenerates a configured number of columns at a time on the exact prefix domain that the cached implementation reads. These are three distinct memory bounds: one tree during commitment/opening, one component during composition, and a column batch during FRI. Selecting a batch size of 16 does **not** bound the entire prover to 16 live columns.

The experiment applies this policy independently to the Cairo proof and the recursive circuit proof. The phase-local pool/tree ownership and release of the completed Cairo proof before the recursive stage are inherited from the earlier experiment. The original cached proving entry point remains available.

## Invariants checked

**Polynomial identity and domains.** `Poly` now stores its committed domain independently and makes expanded evaluations optional. Evaluation eviction asserts that coefficients exist. Regeneration uses those unchanged coefficients and the original domain; no coefficients are truncated. For a requested bit-reversed prefix, the helper asserts that `committed_domain.split(log_split).0` equals the requested domain. This matters because that prefix generally is not a smaller canonical domain. When a requested prefix is smaller than the coefficient vector, the implementation regenerates the complete committed evaluation and copies the prefix. This fallback preserves the polynomial but can temporarily use more memory than the requested prefix.

**Composition and offsets.** The component adapter retains the original `EvaluationMode` decision, constraint evaluators, offset mapping, and accumulator finalization. An evicted column is regenerated on its own committed-domain prefix, including when columns have different committed heights. Existing retained columns remain borrowed. The tests include actual STARK proving with negative and positive row masks, rather than only comparing unshifted helper vectors. Cairo and the recursive circuit use the framework adapter; this review does not assert compatibility for arbitrary custom `ComponentProver` implementations.

**FRI numerator equivalence.** Sample randomness and periodicity are prepared once from the original tree/column order and full committed-domain sizes before sorting or chunking. Powers of the challenge are not restarted at batch boundaries. Each chunk calls the existing numerator implementation on exactly the prefix it formerly read, with a local blowup factor of zero. Partial sums for the same sample point and height are combined using field addition. The original cross-height lifting, denominator processing, quotient interpolation, and extension are then reused. Equal-height partial sums are merged before calling the existing lifting routine, preserving its increasing-size precondition. This is a regrouping of the same finite-field sum; no FRI equation or challenge assignment changes.

**Commitments, openings, and transcript.** The active runtime uses the original full-tree commitment routine with the original column order, stable sorting, lifting size, hash implementation, and unpacked-leaf setting. Reconstructed-root equality is asserted before returning an opening. The original decommitment routine preserves queried-value, authentication-witness, and auxiliary-map ordering. Retaining empty non-root buffers preserves the layer-vector length used as logical height. Packed FRI trees are outside this retention policy. No transcript mix/draw operation is inserted, removed, or moved; reconstruction itself does not use the channel.

**Lifetimes and borrowed caches.** Evicted evaluation buffers are dropped rather than returned to a pool that would retain their capacity. Coefficients survive out-of-domain sampling whenever their evaluations have been evicted. Owned retained-evaluation columns may still release coefficients after sampling, as in the earlier experiment. Borrowed trees are neither pruned nor evicted. The weight-map decision checks actual coefficient availability, so a borrowed cache without coefficients can still use barycentric sampling. An externally supplied owned tree must have retained coefficients before it can be evicted; the PCS enforces that requirement. The integration constructs both owned preprocessed trees with coefficients whenever their bounded option is enabled.

**Parameters and privacy.** The wrappers change allocation choices only. AIR constraints, degree bounds, lookup arguments, field operations, channel implementation, proof-of-work settings, FRI parameters, query counts, Cairo verifier context, zero-knowledge blinding, serializer, compressor, and proof version remain unchanged. The Cairo proof commitment used as the recursive blinding seed is still read from the same location. No proof-system unsafe block was added or changed by this experiment. The inherited native-only allocation counter delegates to `System` with unchanged pointers/layouts and retains its documented safety justification; it is diagnostic code, not the proof arithmetic.

The governing theory references are the pinned distilled whitepaper's `alg:merkle`, `s:cross:domain:merkle`, `e:FiatShamir:randomness`, and `prot:STARK:IOPP`, together with the circle FFT/domain definitions. The S-two soundness checklist, STARK foundations, circle mathematics, AIR guidance, testing strategy, and paper/implementation divergence log were read for this review. Existing DIVERGENCE-006 describes the baseline lifted Merkle layout; the runtime preserves it. No new paper/implementation divergence was identified.

## Additive streamed Merkle work

The exported patch also contains a provider-based lifted Merkle API. It is **not called by the first measured runtime milestone**. Its SIMD Blake implementation requests at most 16 columns for each Blake message block, preserves stable ordering, cumulative byte counts, zero padding, final-block finalization, pair-preserving lifting, and both existing hash variants. Its generic fallback requests all columns and is explicitly not memory bounded. It builds ordinary unpacked leaves; packed FRI behavior is unchanged.

Review identified and resolved an exact-byte issue for tiny columns: gathering through the field accessor can canonicalize the redundant M31 representation of zero. The final implementation reads the same safe raw slice representation as the existing tiny-column path, preserving hash input bytes. Tests deliberately include raw `P` zero values. The new safe transpose/output conversion introduces no unsafe block. This additive API has differential coverage, but its tests do not establish a memory reduction in the currently integrated prover because that prover does not use it.

## API and defaults

- Constructors default to the legacy retention behavior. `set_bounded_memory_mode(n)` asserts `n > 0`, must run before any commitments, and forces coefficient retention and root-only Merkle retention.
- Existing Cairo and recursive proving entry points delegate with the bounded option disabled. `LowMemoryOptions::default()` uses `None` for both stage batch sizes and `false` for Cairo Merkle recomputation.
- In the experiment service, the phase-local branch is selected by `TEMPLAR_LOW_MEMORY=1`. Its inherited Cairo recomputation selector defaults to enabled. The two new `TEMPLAR_BOUNDED_*_COLUMNS` selectors default to disabled; absent or zero means `None`. Core prover code reads no environment variables. The benchmark harness explicitly chooses its stage and batch-size settings.
- `Poly.evals` changing to `Option` and the independent domain field are source-level API changes. The pinned dependency family has been adapted together; universal downstream source compatibility is not claimed.
- `CommitmentSchemeProver::evaluations()` requires retained evaluations. Custom components must support coefficient-backed access before using the new mode. The XOR/GKR example still explicitly requires retained evaluations and is not a supported bounded-mode component.
- Direct access to an opt-in tree's public Merkle layers cannot assume non-root buffers are retained. The owning PCS reconstructs those buffers when opening.

## Test evidence reviewed

The archived command metadata records exit code zero for the following final suites. The `scalar` filename suffix means the Rayon `parallel` feature is disabled; it does not mean that SIMD backend tests were omitted.

| Suite | Parallel | Without parallel |
| --- | ---: | ---: |
| PCS and quotient tests | 13 | 13 |
| Bounded prefix tests | 2 | 2 |
| Full constraint-framework library | 18 | 16 |
| Streamed Merkle tests | 3 | 3 |
| Lifted Merkle prover tests | 5 | 5 |
| Total | 41 | 39 |

These are **80 passing test executions**, including original tests and new differential cases. An earlier `framework-bounded-parallel` log records two additional repeated adapter tests, so the archived focused logs contain 82 executions overall. The final full-framework logs supersede that earlier subset. Commands, environment, timings, and results are in `results/{stwo-*,framework-*}.{json,log}`.

Coverage includes CPU/SIMD backends, cached and evicted representations, borrowed/owned preprocessed trees, coefficient caching on/off, unequal domain sizes, multiple trees/sample points, periodicity samples, batch sizes 1/3/16/17/64, blowup factors 1/3, zero and constant polynomials, and prefix requests below the coefficient degree. PCS tests compare proof fields, query positions, and auxiliary maps; verify the result; reject altered sampled/opened values; and check that borrowed caches are unchanged. The inherited stale-root test checks fail-closed reconstruction.

The framework tests compare full STARK proof fields and verify both CPU/SIMD bounded proofs for nonconstant traces, log sizes 3/6, blowup factor 3, batch size 1, and masks `[-1, 0, 1]`. Adapter tests cover both subdomain and extension modes and mismatched committed heights. Test-only small parameters are not production security settings.

Each streamed-Merkle matrix run covers 148 scenarios across the two hash variants, including empty input, unequal/small heights, extra lifting, final block sizes around 16-column boundaries, and redundant raw-zero encodings. It compares legacy CPU, legacy SIMD, and streamed leaves, complete tree layers, roots, opening values, witnesses, and auxiliary data. Provider order/batch limits and invalid count/length/lifting inputs are tested.

## Release integration evidence

The final release archive contains seven successful run records with 15 proofs: one preceding-experiment ordinary baseline, one ordinary run with bounded mode enabled, one run with bounded mode disabled in the same new binary, and three repeated requests for each of ordinary payment, controlled payment, ReturnNote, and 8/8/4. The twelve repeated-workload proofs all completed under an 8 GiB cgroup cap, with zero swap and no OOM event. The repeated requests in each workload use the same fixture; this is a short repeated-request check, not a varied-load or long-duration leak test.

The reviewer independently read all proof files and compared their bytes with the previous archive at the same private-request hash, checked public messages and the recorded proof version/program/message-digest bindings, and read every original-verifier log. All 15 proofs matched exactly, all were accepted, and each log recorded rejection of a changed message digest, changed program hash, and corrupted proof bytes. This preserves the existing deterministic behavior for these fixtures; it does not establish exhaustive equivalence for all inputs. The separate tampered-intent fixture reverted with `BINDING` before proving and produced no proof; it is not counted among the 45 verifier mutation checks.

The bounded release binary SHA-256 is `8eaa1763abd7216f43fff2a935a3646e5643f55763236b41885ee77f5286d471`. Its build metadata lists `stwo_proving` without allocation instrumentation. The independently checked original-verifier SHA-256 is `492e2ea2b2bbc9eef05239407e9f3cbcc39199934b3f3bb02172aba3fd198934`.

| Run | Peak process RSS GiB | Peak cgroup GiB | Proving seconds |
| --- | ---: | ---: | ---: |
| Ordinary, preceding baseline, one request | 8.949 | 8.871 | 16.644 |
| Ordinary, same new binary with bounded mode disabled, one request | 8.998 | 8.922 | 16.744 |
| Ordinary, bounded both stages, one request | 5.686 | 5.600 | 23.065 |
| Ordinary, three requests under 8 GiB cap | 6.120 | 6.034 | 22.688–23.084 |
| Controlled, three requests under 8 GiB cap | 5.910 | 5.823 | 22.817–23.234 |
| ReturnNote, three requests under 8 GiB cap | 5.836 | 5.750 | 22.734–22.782 |
| 8/8/4, three requests under 8 GiB cap | 6.311 | 6.226 | 23.405–23.917 |

The matched ordinary same-binary comparison shows about 37% lower RSS and 38% longer proving. Those percentages compare one fresh prover process per setting; they are not population averages or a desktop performance guarantee. Proving durations come from the service's `prove_duration_ms`; they exclude transaction execution and the harness's independent verification. RSS high-water and cgroup accounting are separate measurements and are not interchangeable.

Both ordinary 4 GiB probes recorded `Result=oom-kill`, `oom_kill=1`, zero swap, and no proof. The second run enabled diagnostic spans. Its final entered span is Cairo `Compute base trace commitment` → `Commitment` → `Extension`, before the Merkle span. This localizes the observed failure to full-tree expansion in this configuration. A future streamed hash provider called only after that complete expansion would not remove this observed allocation floor; commitment construction must avoid materializing the complete expanded tree as well. The traced failure is diagnostic evidence, not a successful timing comparison.

The memory and timing records were produced on an i9-10980XE host with approximately 126 GiB RAM, four distinct physical CPUs pinned, four Rayon workers, one request at a time, and `-Ctarget-cpu=native`. The cgroup limits cover the prover service; the RPC cache, harness, and standalone verifier run outside it. No special native allocator tuning was enabled. Native CPU support, warm public-read caching, and the larger host still limit transfer of timing and total-memory claims to consumer machines. Full details are retained in `results/summary.json`, each run's resource/cgroup record, and its verifier logs.

## Measurement and deployment limits

This milestone still has a largest-tree floor, component-sized temporaries, retained coefficients, twiddles, quotient/FRI buffers, and the recursive circuit witness. It is not a constant-memory prover. Reduced allocation lifetime does not guarantee immediate native RSS reclamation. Runtime and memory cost of repeated FFT/Merkle work require measurement under actual caps with swap disabled, including multiple requests.

The targeted tests and release replays support unchanged proof semantics and serialized bytes for the cases exercised. No physical 8/16 GiB desktop, WASM/browser runtime, or live Sepolia transaction using this modified prover is qualified here. Moving below an 8 GiB process cap does not by itself establish comfort on an 8 GiB machine running an operating system, wallet, and other applications. The 4 GiB OOM probes demonstrate that this implementation has not reached that lower process budget, and browser linear-memory limits still require separate implementation and measurement.

## Reviewed source SHA-256

Paths are relative to `target/bounded-memory`. The table covers all Rust files changed against the pinned original dependency/service trees, including inherited phase-local routing and optional diagnostic files. The latter are pinned for archive completeness rather than presented as new bounded-mode proof changes. Cargo isolation and release artifact hashes are validated separately by the benchmark archive tooling.

| File | SHA-256 |
| --- | --- |
| `stwo/crates/constraint-framework/src/prover/component_prover.rs` | `492d234a2157d7efbcb09efbfdf2fc7dc3539d6153252255c19aa54fcde76e8e` |
| `stwo/crates/examples/src/blake/air.rs` | `874803babf21ffe0468ebde715e05e34eaeb462e69e14377741c4b5b80a9856d` |
| `stwo/crates/examples/src/xor/gkr_lookups/mle_eval.rs` | `37291a5a389f81fabc74cc3c8202f2d7d34fd80aa687a27a846b5f398913ae91` |
| `stwo/crates/stwo/src/prover/air/component_prover.rs` | `cb5debfbe1908c8c8ee42e5d24fab1ab1fc4295d321f94c89b7c541d057e117e` |
| `stwo/crates/stwo/src/prover/backend/simd/blake2s_lifted.rs` | `f928b29cb3b4e49be619b09f0d696b21c42fadc9093d3ff328f3dc36cf6cd437` |
| `stwo/crates/stwo/src/prover/pcs/mod.rs` | `28196748fe6d477e0636816dc00922d6ca3914bc3e477663794106e9502b5851` |
| `stwo/crates/stwo/src/prover/pcs/quotient_ops.rs` | `f5d38747be4bcd21e9cb509ee87fc221f71bb04fd73edb3eec39cce0ec63bcf1` |
| `stwo/crates/stwo/src/prover/vcs_lifted/ops.rs` | `ee01931c1ca344fdd640ff106caf9ec7ee0b1f51b5d002e7a4cc656ccd78acfb` |
| `stwo/crates/stwo/src/prover/vcs_lifted/prover.rs` | `89b33cf4a14a02418841a648ec0f485a1608015ef9ecc2f550c6a15e5976251b` |
| `stwo-cairo/stwo_cairo_prover/crates/prover/src/debug_tools/relation_tracker.rs` | `5c12e44b0b48894fa38664288ef1476808c56a307010e92ba0198f190a84930c` |
| `stwo-cairo/stwo_cairo_prover/crates/prover/src/prover.rs` | `0bf0910afd724510092d0b27de7619b2faec3a674bcc151f2b56bba1c555c772` |
| `stwo-circuits/crates/circuit_prover/src/prover.rs` | `1da80ccc0a74f4d01f7fe27eebec19b4f2e3c2f918a3ba88b019c885530fe8c4` |
| `proving-utils/crates/privacy_prove/src/lib.rs` | `e8e42edefc71f8557bba0f6912ab12b6ea2d4bf14d13c773851f18167873498b` |
| `proving-utils/crates/privacy_prove/src/low_memory.rs` | `ed4a92e3d7a979e150e100788e28f97e3e3569cd97c6b1655c9fd27f01f5cc22` |
| `sequencer/crates/starknet_transaction_prover/src/main.rs` | `69df518fef0ba653b8eef042815864307a4728af04e4cf3475a38ff219920ecd` |
| `sequencer/crates/starknet_transaction_prover/src/memory_profile.rs` | `ab043d2267e6361ac529a1dc8d32a197fd8b2188047eaa7450396cae1eb71b6e` |
| `sequencer/crates/starknet_transaction_prover/src/proving/prover.rs` | `c40d56bb55b1ce9b9600f971be07e4b1ec4369b261688545d13e9e7bc2fa064a` |
| `sequencer/crates/starknet_transaction_prover/src/proving/prover_test.rs` | `4b3d786febcdd1ea275bfb9bd9c3d3a068334322aaed82d34461d64f1081984e` |
| `sequencer/crates/starknet_transaction_prover/src/proving/virtual_snos_prover.rs` | `68d0f6ff29241f2e951f6491514f9bbf84c3c2ff536caf460363c60144f85e69` |
