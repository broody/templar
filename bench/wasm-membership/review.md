# WASM membership portability review

Status: narrow portability source review and cross-runtime browser evidence complete. The isolated public benchmark passes in the tested Chrome environment with exact preserved-native proof bytes. This is a feasibility result for the stated public relation and environment, not a privacy or deployment qualification.

This work ports the existing synthetic **public-transcript membership validity** benchmark. It preserves its two depth-32 paths, 128 felt252 Hades permutation requests, exact public lookup boundary and native verifier. It does not introduce a private membership relation, new blinding construction, payment relation or protocol deployment. No new privacy/disclosure analysis is part of this review. Earlier `bench/poseidon-membership` and `target/direct-air` sources and archives must remain unchanged.

## Basis and required invariants

The reviewer follows the delegated Math Reviewer role in `target/wasm-membership/stwo/AGENTS.md` and the Cairo repository rules. The required soundness checklist, AIR constraint and divergence-log skills, and whitepaper flat-AIR/lookup anchors are unchanged from the prior review; their new copies were compared byte-for-byte. The performance and testing skills were also read for this port.

The portable implementation must preserve canonical felt parsing, dictionary IDs, duplicate aggregation, padded memory-read obligations, all twelve AIR components, trace packing/order, lookup multiplicities and field arithmetic. Its explicit PCS configuration remains PoW 27, log blowup 3, 23 queries, fold 4, last-layer log degree 0, lifting 23, ordinary Blake2s and 24-bit interaction PoW. The same public statement, claims and commitment transcript must produce the same Fiat–Shamir challenges. The coefficient-backed mode remains 16-column FRI regeneration with one full tree at commitment/opening; it is not a global 16-column memory bound.

The approved changes are limited to:

- Moving the existing statement/prove/verify logic into an in-memory core, leaving filesystem and command-line handling in a native wrapper.
- Replacing the clock on WASM for measurement only. Timing, progress callbacks and memory telemetry must never enter the proof statement or transcript.
- Selecting single-worker scheduling on WASM and bypassing the explicit native Rayon pool around `cube_252::write_trace_simd`, while running the identical witness body and preserving the native pool path.
- Adding WASM bindings that transport the proof as opaque bytes and summaries/statements as UTF-8 strings. Felt values, `u64` nonces and serialized proof fields must not pass through JavaScript `Number` conversions.

No arithmetic replacement, constraint removal, parameter reduction, lookup simplification or new commitment/FRI algorithm is approved. If portability requires such a change, this experiment stops at the documented blocker.

## Scheduling and platform review

The installed `rayon-core 1.13.0` documentation and `registry.rs::default_global_registry` implement a current-thread fallback when the target rejects native thread creation. Structured parallel iteration and `join` execute sequentially in this mode; unstructured `spawn` calls are not equivalently supported. A source search of the selected witness components and S-two/framework proof path found no such unstructured spawn. The concrete selected-path blocker is the cube252 witness generator's explicit native `ThreadPoolBuilder`, because explicit pools do not take the implicit fallback path.

A WASM-only `num_threads(1).use_current_thread()` global initialization is acceptable if guarded to work once per worker/module and if repeated proof calls do not fail merely because initialization already occurred. The cube pool bypass must retain the exact inputs, row counts and trace-writing closure. Replacing scheduling must not change the number of initialized lanes, relation terms or padding rows. Existing upstream SIMD implementations and WASM fallbacks should be reused; no new unsafe arithmetic path is approved.

The native deterministic grinder selects the smallest valid nonce in its defined search order, including its parallel implementation. Consequently full envelope byte equality across native and WASM is expected for this deterministic benchmark. A different but valid nonce can produce a valid different proof in general, but it would require an explained implementation change here; it must not be used to dismiss an unexplained cross-runtime mismatch.

The inspected user reference, `AbdelStark/stwo-wasm-demo`, exposes an older Fibonacci prove/verify example through `wasm-bindgen`. It demonstrates a binding shape, not compatibility or resource viability for these felt252 components and parameters. It supplies no substitute for cross-runtime testing of this port.

## Final source review

The in-memory implementation keeps the original config, component/witness construction, statement validation, channel initialization, verifier, and negative-check helpers unchanged. `statement.rs` differs only in its test fixture include path. The original proving pipeline moves into `prove_fixture(&str)`; file reads/writes move to the native CLI, and bounded mode is fixed to the previously tested value 16. Shape and summary strings are returned as artifacts. None of these runtime artifacts enters the serialized proof envelope or transcript.

`platform.rs` uses native `std::time::Instant` on native targets and browser `performance.now()` for WASM timing. WASM linear memory is reported from the actual memory page count, widened to `u64` before multiplication by 65,536. A `Once` guard installs the panic hook and one-current-thread Rayon global pool. Browser exports take an opaque fixture string or proof bytes and return proof bytes plus opaque JSON; no proof-field conversion through JavaScript numbers is introduced.

Independent comparison of Rust sources and Cargo manifests/locks in the isolated dependency copies found no S-two change and exactly one stwo-cairo change: `witness/components/cube_252.rs`. It retains the original native 8 MiB-stack pool and, only for wasm32, executes the same moved closure directly. Inputs, padded sizes, lane initialization, trace writing and subcomponent lookup insertion are unchanged. The inspected file SHA256 is `b0b1a3678a34f2b25ae4a67e69ff52f0a4dfea12eaa3b04d2f53972594a6017f`.

No new unsafe block, arithmetic formula, degree bound, constraint or verification check was introduced or removed in these diffs. The identified measurement-label issue was corrected before the final WASM build: `proof_verified_in_runtime` reports the runtime check, `native_proof_verified` is false on WASM, and `execution_target` is explicit. Preserved-native verification remains a separate exported-proof check. A compile-time guard requires the documented `simd128` target feature. No unresolved proof-semantic blocker was found in the reviewed source.

## Frozen source and build evidence

The initial `wasm32-unknown-unknown` release build and `wasm-bindgen --target web` both completed successfully. The recorded toolchain is `nightly-2026-01-15`, with `+simd128`, an 8 MiB WASM stack and a 4 GiB maximum linear-memory declaration. These settings permit an execution attempt; they do not show its actual resource use or success. The generated WASM is 11,223,495 bytes, SHA256 `9e84a321253f36e41930024b9fd0e07ac8f6bb9efcf6b4f939472d31bfcf117f`.

All 12 file hashes in `target/wasm-membership/build-wasm-artifacts.json` were independently recomputed and matched. Reviewed source identities:

| File | SHA256 |
| --- | --- |
| `client/src/lib.rs` | `7e555bbd8896928e59271e729ce7a19d3804c7c0f698dedfd0c142d1bfc70b4e` |
| `client/src/platform.rs` | `b1757a64e2aba2f47e5dd5006e154168dd47081abe52e2b5611f1ab943846081` |
| `client/src/main.rs` | `7bbacfcab72afa3de5cafa08ddbc5004e7c458a857c2364c000ef9c6507a10a3` |
| `client/src/statement.rs` | `9047353575b07c2964b952352dd717a29d7f65307d769375321f61613d48ee7a` |
| `client/Cargo.toml` | `29a990f2236cd942c6f618b9fdcd466732e84442e0be9397851bd9c822473c88` |
| `client/Cargo.lock` | `20f53b4813336b976a00f3b415cda86ecf99f6bb3f057f42db72e1a6cd5929e2` |

Paths in this table are relative to `bench/wasm-membership`. The only changed upstream source file is pinned separately in the source-review section. No source change to the earlier native experiment is part of this port.

The refactored native target also builds successfully. The archived native test driver exits 0 with all three retained statement tests passing: duplicate/padding accounting, reference/verifier bookkeeping and public-link mutation rejection. Its executable SHA256 is `28bc5c1467ead725eef519cf235b5a7bf54b294776dde09f1890dff93134db30`. A separate native regression execution of the split core also generates and verifies a complete proof with exact preserved-reference envelope equality; the reviewer independently checked its file bytes and `results/port-native-parity/validation.json`. This execution is regression validation, not a performance benchmark.

## Cross-runtime execution evidence

The reviewer inspected the raw browser results, command/resource summaries and preserved-native cross-check, and independently compared all four exported envelope files against the earlier native reference. Every comparison is exact byte equality: 334,307 bytes, SHA256 `7883c50e7125e608365e7887b50df589ac57bcc91438fe2f1f660caf56a9631e`. The contained STARK proof remains 258,621 bytes. There is no serialization, nonce, transcript or proof difference to explain between the tested native and WASM paths.

Four proofs completed in Chrome 153.0.8010.47 headless on the development host, across two browser launches. Each uses one proof worker with `simd128` and non-shared wasm32 memory. The entire browser/harness process group was restricted to four CPU cores; that is separate from the proof's single-worker scheduling.

| Experiment | Proof executions | Prove plus in-runtime verify | Linear-memory capacity | Whole browser/harness cgroup peak |
| --- | --- | --- | --- | --- |
| `chrome-three-runs-8g-v2`, 8 GiB cap | Fresh worker, then two repeats in the same worker | 41.7199 s, 41.1825 s, 40.9315 s | 2,308,505,600 bytes for each | 2.22643 GiB for the complete experiment |
| `chrome-fresh-4g`, 4 GiB cap | Fresh browser and worker | 41.7744 s | 2,308,505,600 bytes | 2.20558 GiB |

Both process-budget experiments exit 0 with no swap and no OOM kills. The linear-memory capacity is 2.149963 GiB, starts at 8,519,680 bytes, and stays at its first-proof high-water value through the two same-worker repeats and after freeing result handles. This is evidence of stable capacity for these three calls; it does not establish the absence of allocator leaks under arbitrary workloads. The 4 GiB cap is a budget for the measured browser/harness process group, not a qualification of a machine with only 4 GiB physical RAM shared with its OS and other applications.

Each proof verifies in WASM. The browser test suite also passes all 13 distinct proof/statement mutations and three public-boundary controls once per browser launch: two check executions, not four independent suites. The tests run separately from the reported prove/verify duration. They include an actual sampled-value corruption and a changed preprocessed root, as well as public-link changes and the structurally valid unlinked permutation-output change. The three controls exercise duplicate multiplicity, padding obligations and the canonical public memory dictionary.

The preserved native executable independently accepts the first exported browser proof and passes its 13 mutation and three boundary controls, with exit code 0 in `results/native-cross-check/command.json`. Its hash is the earlier frozen native hash `9c44542bd838100722358edc8c92f91e08012c4e59ebbf2b6ea35813c95c8974`. Because all four exported files are identical, this is native verification of **one unique artifact** shared by all four browser executions. It does not rely only on agreement between a newly compiled prover and newly compiled verifier.

The raw evidence is in `results/chrome-three-runs-8g-v2`, `results/chrome-fresh-4g`, `results/native-cross-check`, `results/port-native-parity` and `results/aggregate.json`. Native build/test driver logs are under `target/wasm-membership`. Frozen source identities above were rechecked after the native build.

## Interpretation and limits

The proof-call duration surrounds the synchronous WASM prove-and-verify function. Result extraction, hashing and archival upload occur afterward; module initialization and fixture/reference fetching occur before. These are not cold-network page-load times. The inherited phase key `native_verify_seconds` in raw summaries means verification **inside the current runtime**; on wasm32 it is WASM verification. The preserved-native cross-check is the separate process described above.

`memory.buffer.byteLength` measures grown linear-memory capacity. It does not shrink when Rust frees objects and is not browser-process RSS. Cgroup peaks include the browser and harness, while summing Chrome process RSS double-counts shared mappings. The reported cgroup and linear-capacity values must retain their distinct labels; neither should be replaced by the outer Node process's `/usr/bin/time` peak. The WASM build declares a 4 GiB maximum linear memory, but that declaration is not its observed consumption. This experiment does not test a 2 GiB browser cap and does not claim 2 GiB is a universal browser hard limit.

The reviewed changes preserve the public benchmark's proof semantics and demonstrate browser feasibility on this headless Chrome development host. They do not measure Firefox, Safari, mobile browsers, physical consumer hardware, cancellation/recovery or a complete private payment. The prior public relation's scope and unresolved qualification of any future private relation remain unchanged. No cryptographic redesign or adoption signoff follows from these measurements.

No builds or measurements were performed by the reviewer. Review consists of source comparison, pinned artifact/hash checks and independent inspection of the recorded executions; it is not a general soundness or security audit.
