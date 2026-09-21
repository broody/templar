# Client privacy construction and cost review

Status: **no-go for qualifying a new compact private client construction from the reviewed sources; the approved exact fixed-Cairo cost experiment is complete.** The source review found an upstream privacy workflow, but no documented general hiding construction applicable to arbitrary custom verifier circuits or the direct Poseidon AIR. The unchanged wrapper passes at an 8 GiB native process cap and fails at 4 GiB with both tested worker counts. This is a reference-cost result, not a claim that upstream privacy use is disproved.

No new disclosure/recovery diagnostic, masking construction or private wallet data is part of this milestone. Earlier archives remain unchanged. The reviewer implements no proof-system code and runs no builds or benchmarks. Source-equivalence and recorded-execution review are complete below.

## Review basis and source identities

The delegated Math Reviewer role follows the applicable S-two, stwo-circuits and stwo-cairo `AGENTS.md` files. The required soundness checklist, AIR engineering, paper/code divergence and STARK foundations skills were read. The current monorepo's `CLAUDE.md` and circuit/proving-utils guide rules were also read. Their soundness requirements apply to any future new statement or constraint logic; this milestone authorizes only read-only design review and unchanged-protocol cost orchestration.

Reviewed snapshots:

| Source | Revision | Role |
| --- | --- | --- |
| Existing stwo-circuits | `5ef951a12727e3489a2ee991c580a5b925c59c69` | Pinned Templar reference |
| Archived stwo-circuits HEAD | `4d8a7a062f7465f6244a7ab8ac40d515377fe6f8` | Later repository state; README points to migration |
| Current proving monorepo | `cd7bc5f4697fb188a27e09f9242f1dd76df8afdc` | Current public implementation inspected |
| Existing proving-utils | `3035dd00421daa541894297bd754db6e2787807b` plus previously reviewed storage/orchestration patches | Exact accepted fixed-Cairo cost reference |

The archived repository's [migration notice](https://github.com/starkware-libs/stwo-circuits/blob/4d8a7a062f7465f6244a7ab8ac40d515377fe6f8/README.md) moves development to `starkware-libs/proving`. The new monorepo was inspected rather than treating the archived HEAD as the latest construction.

The entire helper region from `qm31_zk_blinding` through `add_zk_blinding` is byte-identical across all three circuit snapshots: SHA256 `772f5e0c966f98416404f3e6e5180534fb7d37dce0076f1aae73f9dbba0e5343`. The respective complete `finalize.rs` hashes are `d2154883128f83b512af2e61ac881662ad18853adb618700b83f0855e41f49ce`, `e1536b7b9a29e068143f1a4b8fa27d3fd4bb70da8f22c0fc150e76be61667e47` and `cab63ca2267dd53c885714dfe605d098c28afa2cdd4766aedcdfc4b43642d9dc`. Nearby changes generalize padding and component-size utilities; they do not supply a different blinding construction.

## What upstream actually supplies

`add_zk_blinding` adds valid randomized rows to five gate components: QM31 arithmetic, equality, triple XOR, M31-to-u32 conversion and Blake G. It seeds ChaCha20 with caller-provided bytes and appends the requested number of rows. Its generic value type supports value-free topology construction as well as assigned circuits; that generic interface is not a claim that it blinds arbitrary AIR witness polynomials. The code comments call this ZK blinding. [Current implementation](https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/circuit_common/src/finalize.rs)

The concrete privacy workflow constructs a fixed Cairo verifier circuit, checks the assignment, derives the seed from the **inner Cairo witness commitment**, calls the blinder with the **outer circuit query count**, proves the circuit, and emits the serialized outer proof with its public output preimage. The raw inner proof is an intermediate local artifact, not part of that returned proof payload. The topology-only path uses a zero seed solely to produce the same public scaffold. This exact seed policy must not be silently replaced by an OS-seed policy, a public seed or a new row-count formula in a cost comparison. Describing the function as seeded does not by itself prove that its inputs meet any particular hiding theorem. [Current privacy prover](https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/privacy_prove/src/lib.rs), [current fixed verifier and preprocessing](https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/privacy_circuit_verify/src/lib.rs)

The fixed verifier uses a trusted bootloader, expected preprocessed root, ordered column IDs/sizes and exact proof settings. Its tests check these constants and exercise proof acceptance and serialization. The separate `test_zk_padding` checks that a selected large circuit stays within the same power-of-two component sizes after blinding; it is not a general zero-knowledge theorem or audit. The in-tree guides describe the blinder as injecting randomness for ZK, without a complete applicability specification for arbitrary custom circuits. [Fixed-config tests](https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/privacy_circuit_verify/src/tests.rs), [padding test](https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/cairo_verifier/src/privacy_test.rs)

The reviewed Circle STARK and S-two paper distillations ground the AIR consistency, LogUp multiplicity, composition, OOD, FRI and Fiat–Shamir obligations. In particular, `e:flat:AIR:consistency`, `prot:STARK:IOPP` and `thm:NIROP:soundness:general` concern statement consistency and knowledge soundness. They do not establish the required simulator/hiding argument for this exact five-gate random-row construction at arbitrary circuit shapes. No such complete argument or audit coverage was identified in the reviewed source documentation. This is a bounded evidence statement, not an assertion that no supporting work exists anywhere.

Haböck and Al Kindi's [A note on adding zero-knowledge to STARKs, ePrint 2024/1037](https://eprint.iacr.org/2024/1037), including the [author-uploaded revised text](https://www.researchgate.net/publication/381742262_A_note_on_adding_zero-knowledge_to_STARKs), provides relevant general theory. It treats small-field univariate Reed–Solomon/FRI constructions, witness-polynomial randomization, a separate FRI masking step, and quotient/permutation treatment. This is a concrete theoretical construction, not an audit of the S-two five-gate helper. Applying it here would require an explicit mapping to the circle-domain, multi-table LogUp and actual transcript implementation; this milestone neither supplies that mapping nor implements a new masking path.

The monorepo also changes proof configuration structure, output encoding and registry machinery. A source upgrade therefore changes more than a privacy helper and cannot be treated as a drop-in resolution for the pinned protocol.

## Applicability and statement binding

| Candidate | Existing implementation support | Decision in this milestone |
| --- | --- | --- |
| Fixed Cairo privacy recursion | Concrete upstream caller, fixed preprocessing/config and verification path | Existing synthetic cost reference; unchanged-path split is approved |
| Application expressed in circuit DSL | Gates and generic proving APIs exist | No privacy qualification for a new topology from API availability alone |
| Direct Poseidon AIR with `add_zk_blinding` | Function operates on circuit gates, not these AIR columns | No-go; applying it is not an existing supported AIR masking construction |
| Private direct-AIR proof verified inside a blinded circuit | Generic `Statement`/`CircuitEval` interfaces can express verification | New statement adapter plus a justified outer hiding construction are required; no-go as an already supported private client route |

For a future recursive construction, public data at one layer can become witness data at another. This only works if its validation and binding are actually enforced at the new layer. The native public membership benchmark checks canonical felt encodings, both index directions at every depth, child/sibling links, exact hash-span padding, endpoints, the deterministic value dictionary, deduplicated requests and padded memory-read obligations in host verification code. It then derives the public lookup boundary for 128 permutation requests and 768 memory reads. Simply guessing the resulting boundary or merely verifying the STARK inside a circuit would omit those host checks from the new relation. They must become constrained logic, or be enforced by an independently sound inner AIR. This is additional implementation and proving cost even if a suitable hiding construction is established.

The current generic `Statement` interface asks the adapter to supply claims-to-mix, components, sizes, preprocessed IDs/root, public lookup boundary and optional claim checks. It does not automatically convert native validation code into constraints. [Generic statement interface](https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/stark_verifier/src/statement.rs)

Any future candidate must keep note secrets, path siblings/positions, private amounts or policy data, raw inner proof and any private seed local. It must publicly bind the intended chain/pool and protocol version, accepted root, nullifiers, output commitments and intentionally public action fields. A receiver must enforce the expected circuit/topology identity and exact output interpretation; a proof-supplied root/config is not authority. Secret-dependent topology, table sizes, output lengths and branch selection must be included in the privacy definition or eliminated by a fixed public shape. Fresh proving randomness alone does not address topology disclosure.

A recursive output hash also needs an explicit final interpretation. Upstream's generic verifier documentation requires the outer verifier to reconstruct the chain of hashes over preprocessed roots and outputs. Passing a STARK verification check without binding that final hash to the application statement is insufficient. [Generic circuit verifier](https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/circuit_verifier/src/verify.rs)

The specialist's [integration inventory](integration-plan.md) also identifies nontrivial compatibility costs before a compact inner proof can even enter that verifier: ordinary Blake2s versus the circuit verifier's reduced-channel transcript, different claim-prefix ordering, value-dependent JSON statement encoding and locally required extended-proof auxiliary data absent from the saved compact envelope. Existing generated component evaluators are useful building blocks, but do not remove those protocol and binding obligations. This review does not approve a protocol change to bypass them.

## Approved minimum cost probe

The existing measurements mix stage snapshots with allocator history. A fresh-process split can answer a concrete remaining performance question: how much the **existing fixed client recursion itself** costs, including its full setup and serialization, after removing retained Cairo-stage allocations. It cannot establish the footprint or privacy of a new compact relation.

The approved harness may export the complete typed Cairo proof and matching output preimage from the **accepted proving-utils synthetic PIE and fixed bootloader**, then import them in a fresh process and execute the exact pinned recursive wrapper. The bundled `stwo-circuits/test_data/privacy` raw proof uses a different bootloader and must not be substituted. All exported data in this experiment is synthetic; exporting a real user's raw inner proof would violate the intended client boundary.

Required invariants and acceptance evidence:

- Preserve every serialized inner proof/auxiliary field consumed by recursion, matching output preimage, statement interpretation, fixed bootloader and trusted preprocessed root. Reject malformed/mismatched imports; exported metadata must not become verifier authority.
- Preserve exact channel/hash mode, FRI and interaction PoW settings, all context validity checks, commitment-derived blinding seed and outer query-count padding. For the pinned reference these remain Cairo blowup 3 / 23 queries / PoW 27 and circuit blowup 2 / 35 queries / PoW 26, fold 4 and last-layer log degree 0, with their unchanged lifting sizes and interaction settings.
- Reuse only the previously reviewed coefficient-backed storage mode with 16-column FRI batching. This remains one-full-tree commitment/opening plus component-local composition, not a global 16-column memory bound.
- Regenerate or load preprocessing only under its pinned fixed identity. Measure cold setup separately from any explicitly described reusable-cache case, and retain total fresh-process RSS/cgroup peak and elapsed time including loading and serialization.
- Generate the same synthetic transaction with the unsplit accepted path and require **exact final proof-byte equality**. Verify the split output with the preserved native verifier and require rejection when the corresponding public output is changed. A new prover and new verifier agreeing with each other is not enough.
- Keep application execution/Cairo proof, inner-proof serialization/load, circuit topology/setup, assignment/blinding, recursive STARK, final serialization and final verification identifiable. Stage times are additive only when measured with the same boundaries; peak memory must come from the actual whole process, not the sum of stage peaks.

No new custom AIR, custom `Statement`, proof parameter change, masking adjustment or disclosure diagnostic is approved by this signoff. The next implementation gate for compact private proofs requires a versioned upstream or independently reviewed hiding construction with an applicability statement covering the actual circuit family/topology, all exported information and randomness policy. Separately, its complete application relation and output binding need source review. Until then, the cost probe is explicitly a reference measurement, and the public browser membership results remain public-relation results.

## Split-harness source and execution review

The isolated `checkpoint.rs` source extraction and native CLI were inspected and approved for building. The wrapper suffix, from trusted `get_cairo_verifier_config()` through the final `PrivacyProofOutput` return, is byte-identical to the previously reviewed low-memory function. The original copied `low_memory.rs` itself is also byte-identical and remains the unsplit oracle. The only setup difference is computing the same maximum-domain twiddles in a fresh process. Typed checkpoint fields contain only the full Cairo proof and matching output preimage, with no new configuration authority.

The CLI adds a synthetic-local magic prefix, complete fixed-integer bincode slice decoding, and rejects wrong format, truncated input and trailing bytes. Checkpoint/output files use create-new semantics and mode 0600. The input byte buffer is dropped before recursive proving starts. The wall-clock interval begins before reading input and ends after artifact writes; the external harness additionally includes summary writing and teardown. Proof verification is a separate command, explicitly excluded from wrapper timings. That command uses the existing fixed verifier and requires rejection after changing one public output-preimage felt. These are orchestration/format checks; they do not add or modify cryptographic checks.

No new unsafe block, constraint, field formula, degree bound, transcript message, proof parameter or blinding rule is present in this split. An independent Rust/Cargo-source comparison against `target/bounded-memory` found no changes among 201 S-two files, 321 Cairo files, 345 circuit files or 1,606 sequencer files. Of 55 original proving-utils files, only `lib.rs` changes to export the new module; `checkpoint.rs` is the sole addition. The archived extraction patch reproduces those files exactly.

Frozen reviewed identities (all SHA256):

| File | Hash |
| --- | --- |
| `target/client-privacy-feasibility/proving-utils/crates/privacy_prove/src/checkpoint.rs` | `08b95ce66c91a9c980c3529ee2b4f8aba7f7a131d621d5e417e71c828c776ae3` |
| `target/client-privacy-feasibility/proving-utils/crates/privacy_prove/src/lib.rs` | `5ce3634d23a3537d393eff4a7d4604d01ea0a4db5d6e26251fc2915111fa28c2` |
| Unchanged `target/client-privacy-feasibility/proving-utils/crates/privacy_prove/src/low_memory.rs` | `ed4a92e3d7a979e150e100788e28f97e3e3569cd97c6b1655c9fd27f01f5cc22` |
| `bench/client-privacy-feasibility/client/src/main.rs` | `ebcd32fad9362a67c6461bc5217f32628d599f1cc12378eb205fc4c54c73c417` |
| `bench/client-privacy-feasibility/client/Cargo.toml` | `dbd239e38ddaf16e87d4111d21d6b83271f9b2398a4e33db5d0ba484a786ef2d` |
| Final `bench/client-privacy-feasibility/client/Cargo.lock` | `e5f9ce66382808ae3fe67181b5f9f9f0e20af93444ec141c1fb02be970f65256` |
| Final `bench/client-privacy-feasibility/verify_results.py` | `130ab7109a8793f032b762906c3704dbc6f18dde08cea287bbe2c513a70afd84` |
| `bench/client-privacy-feasibility/measure.py` | `df53ef41dbae679ead9d5c2584c55048706c1d30f14e1dc5c69e30c902b92616` |
| `bench/client-privacy-feasibility/verify_saved_plus_one.rs` | `a2f8fb28c0cc618885bf69b50b5c7c1455be25b1ec932cfb6c74c76334b115e5` |

The verifier adapter was also reviewed against the accepted sequencer source. It maps the single-task output preimage to `[PROOF1, variant, program_hash, ...task_output]`, checks the skipped output-length field, and pins the independent verifier executable identity. The synthetic variant is not a transaction-submission assertion. It requires exact proof and output-preimage equality before verification.

The original negative-test harness doubles two fact values. This synthetic fixture's final output is zero, so that operation is not a mutation. Its original nonzero guard correctly prevented counting that control as a rejection. A reviewed test-only adapter therefore retains the exact preserved verifier call and changes the two mutations to **add one**. The build script asserts that this is the only adapter-source change, links the existing preserved verifier libraries, and records their hashes; no verifier-library code is rebuilt or changed. The third control still corrupts a compressed proof byte. Its legacy log label “changed message digest” means the final public fact for this generic fixture. A preserved binary's valid-acceptance line followed by failure of its ineffective zero-doubling test must be described separately from a complete passing suite.

The new adapter executable is `b8658ac824cbfe38edd45b35c35d469c5239662a9c305d57713b2dde01b86a28`. Independently checked preserved library hashes are `8a037b84b78d5a4ff4fe7fe0364ca840529eb2f5fe7b1ef4f386c3e4053f8220` for the selected `starknet_api` rlib and `1bc95c834ab8b024218a322a2d5889fb9913dca97f6fd95eee2066e03ce86756` for `starknet_proof_verifier`; full identities and build command are in `results/verifier-adapter-build/metadata.json`.

The release build and all three checkpoint-format tests pass. The frozen executable hash is `86073d1ee5b6dfae0264aeddedb5e12d17215aa51480a70a03810f5ef8630b0c`, built with `nightly-2026-01-15` and `-Ctarget-cpu=native`. The reviewer independently checked all 996 source entries in `results/build/metadata.json`, the executable and final lockfile hash. Proof equivalence is established separately by the execution evidence below.

## Recorded runtime evidence and final decision

The reviewer inspected the six run summaries, phase logs, verification records and aggregate `results/measurements.json`. There are **three completed final proof executions**, one checkpoint preparation and two OOM probes. The unsplit four-worker result and both successful fresh-wrapper results have identical full proof bytes and identical nine-felt output preimages. The reviewer independently compared their actual files: 235,734 bytes, SHA256 `9326c1eaad137c1b865b417b36d041928b1e5d9ec15b363662f0535eed868153`. These are three executions producing one unique artifact, not three distinct statement fixtures. The typed local checkpoint is 998,918 bytes, SHA256 `81500ea26cf4ab0ae8f53fe2a1975b8e09522c0f8cbd31bcea5acb702f54d43a`.

| Run | CPU/Rayon workers | Process cap | Peak process RSS | Peak cgroup charge | Whole harness elapsed | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Cairo checkpoint preparation | 4 | 8 GiB | 4.9892 GiB | 4.9544 GiB | 12.0054 s | Complete; no final recursive proof |
| Unsplit bootloader plus both proof stages | 4 | 8 GiB | 5.2076 GiB | 5.1712 GiB | 20.9512 s | Final proof verified |
| Fresh fixed wrapper | 4 | 8 GiB | 4.7822 GiB | 4.7575 GiB | 11.5000 s | Exact proof parity; verified |
| Fresh fixed wrapper | 1 | 8 GiB | 4.5867 GiB | 4.5608 GiB | 35.1738 s | Exact proof parity; verified |
| Fresh fixed wrapper | 4 | 4 GiB | Incomplete | 4.0000 GiB | 3.2478 s to termination | OOM during recursive proving |
| Fresh fixed wrapper | 1 | 4 GiB | Incomplete | 4.0000 GiB | 8.2283 s to termination | OOM during recursive proving |

RSS in this table is the completed process's `/usr/bin/time` maximum, while cgroup charge is a separate process-group accounting measure. Sampled high-water RSS is also archived and differs slightly in the unsplit run. Successful runs report no OOM kills; both failed runs record one OOM kill, and swap is disabled throughout. The failure logs enter “Prove the cairo-circuit verifier” after completing context and preprocessing setup. They do not identify a more precise failing inner subphase, so no finer allocation diagnosis is claimed.

The whole-harness duration includes process launch, input loading, fresh setup, proof generation, serialization/output writing and teardown/measurement overhead. The inner wrapper-call intervals are 11.0281 s with four workers and 34.7013 s with one. Independent verification is outside those measurements: the accepted proof plus three mutation controls takes 0.438–0.475 s per separate adapter invocation. Those are suite durations, not isolated verifier-call latency. The source-level original wrapper and split wrapper retain identical cryptographic work; disk checkpointing and fresh allocation/setup are deliberate orchestration costs.

The original preserved executable accepts the valid unsplit artifact, then hits the documented zero-doubling test limitation. The zero-safe adapter using the preserved verifier libraries completely succeeds for all three output folders: three valid acceptances and **nine rejection executions of three distinct controls**. They cover changed final public output, changed program hash and corrupted compressed proof bytes. Successful proof verification and these negative controls validate the split's semantics and public output binding for the fixture; they do not establish hiding.

The experiment therefore closes the narrow scheduling-equivalence and fixed-wrapper sizing questions. A fresh native process removes prior Cairo allocation history but still needs approximately 4.6–4.8 GiB RSS for this wrapper. Reducing to one worker does not make the tested implementation fit the 4 GiB cap. There is one run per listed configuration, so this is a bounded sizing experiment rather than reliability qualification or a statistical performance study.

It does not measure a complete private Templar payment, a compact private membership wrapper, WASM linear memory, or physical consumer hardware. The fixed Cairo wrapper cannot directly ingest the earlier ordinary-Blake public membership artifact, and their independent memory peaks must not be added to predict a combined browser footprint. Any browser continuation must measure the actual complete client pipeline after the construction and statement-binding gates are resolved. The custom-private no-go remains unchanged; no masking or protocol change is justified solely to hit a memory target.

This review approves the isolated unchanged-protocol cost experiment and its stated conclusions. It is not a security audit or approval of a new client privacy construction.
