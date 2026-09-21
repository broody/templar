# Client-local verifier integration inventory

The supported fixed Cairo privacy caller already keeps a typed Cairo proof local, assigns it to a fixed verifier circuit, and publishes the resulting circuit proof and intended output preimage. The compact membership benchmark is **not a drop-in input** to that caller. Its AIR evaluators are reusable, but its transcript and host-side membership checks require additional constrained code. Generic verifier APIs alone do not establish that the existing blinding construction covers a new circuit topology.

This inventory does not qualify a new private membership protocol. No custom AIR, masking rule, or recursive `Statement` was implemented. The approved next measurement is the unchanged fixed Cairo wrapper in a separate process, described below.

## Versions inspected

| Source | Identity | Role |
|---|---|---|
| Pinned S-two | `489a0f3ee44a59e03944ad9aa4f3e5a91a3d3f08` plus archived bounded-storage patch | Current experiments |
| Pinned S-two Cairo | `9b6be2710e4d7124bc93fe80a5af36556d42ed29` | Current AIR and verifier |
| Pinned circuits | `5ef951a12727e3489a2ee991c580a5b925c59c69` plus archived bounded-storage wrapper | Current recursive verifier |
| Archived circuits repository | `4d8a7a062f7465f6244a7ab8ac40d515377fe6f8` | Comparison only; README redirects development to proving |
| Current proving monorepo | `cd7bc5f4697fb188a27e09f9242f1dd76df8afdc` | Comparison only, no repinning |

Pinned sources are under `target/direct-air/{stwo,stwo-cairo,stwo-circuits}`; comparison clones are under `target/client-privacy-feasibility/{upstream-circuits,upstream-proving}`. The current repository is [starkware-libs/proving](https://github.com/starkware-libs/proving/tree/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc).

## Reusable pieces

The pinned [`Statement` trait](../../target/direct-air/stwo-circuits/crates/stark_verifier/src/statement.rs) exposes ordered public-claim mixing, the component list, component sizes, trusted preprocessed-column IDs/root, a public lookup boundary, and claim consistency checks. Its generic [`verify`](../../target/direct-air/stwo-circuits/crates/stark_verifier/src/verify.rs) constrains lookup balance, OOD composition, FRI, query selection, and Merkle openings. It takes the fixed `ProofConfig` and the statement's trusted preprocessing authority from the application.

All twelve membership components have generated [`CircuitEval`](../../target/direct-air/stwo-circuits/crates/stark_verifier/src/constraint_eval.rs) adapters in [`cairo_verifier/src/all_components.rs`](../../target/direct-air/stwo-circuits/crates/cairo_verifier/src/all_components.rs): Poseidon aggregator, full-round chain, three-partial-round chain, cube252, round keys, width27 range check, and fixed range checks 3/3/3/3/3, 4/4/4/4, 4/4, 9/9, 18, and 20. A future subset statement can reuse their equations, while preserving the benchmark's actual commitment/component ordering and its dedicated preprocessing subset. The stock `CairoStatement` cannot be substituted: it also checks the Cairo program, CPU boundaries, public memory, and enabled builtins.

[`proof_from_stark_proof`](../../target/direct-air/stwo-circuits/crates/stark_verifier/src/proof_from_stark_proof.rs) provides the witness conversion to the circuit's fixed proof layout. It needs `ExtendedStarkProof`, including auxiliary query locations, authentication data, and FRI witnesses. The compact benchmark saves only `StarkProof`; retaining or regenerating the extra data is additional client work and memory. It must remain local with the inner proof and circuit assignment.

The example [`SimpleStatement`](../../target/direct-air/stwo-circuits/crates/stark_verifier_examples/src/simple_statement.rs) and its verifier tests demonstrate generic validity plumbing, fixed graph construction with `NoValue`, and negative checks. Their small test parameters are not intended-security privacy performance evidence.

## Compatibility gaps

| Boundary | Pinned implementation | Current monorepo | Consequence for archived membership proof |
|---|---|---|---|
| Transcript hash | Reduced Blake2sM31 channel | Still reduced Blake2sM31 channel | Neither directly verifies the benchmark's ordinary Blake2s transcript |
| Merkle hash representation | Reduced hash represented by two QM31s | Full unreduced hash words, with reduction retained for the channel | New raw-root support is not ordinary-channel compatibility |
| Proof converter | `ExtendedStarkProof<Blake2sM31MerkleHasher>` | `ExtendedStarkProof<Blake2sMerkleHasher>` | Hasher type alone no longer identifies channel semantics; do not reinterpret old proof bytes |
| Statement mixing | Grouped QM31 values | Grouped constrained u32 words | Helpful byte encoding support, but custom prefix/order still differs |
| Fixed prefix | Salt, PCS config, trusted preprocessing root, statement claims | Same structure | Benchmark domain separator and serialized statement occur in another order |
| Output representation | Two reduced QM31 digest outputs | Unreduced digest-word outputs | New output ABI requires an explicit migration and verifier change |

Sources: pinned [channel](../../target/direct-air/stwo-circuits/crates/stark_verifier/src/channel.rs), current [channel](../../target/client-privacy-feasibility/upstream-proving/crates/stark_verifier/src/channel.rs), current [converter](../../target/client-privacy-feasibility/upstream-proving/crates/stark_verifier/src/proof_from_stark_proof.rs), current [statement](../../target/client-privacy-feasibility/upstream-proving/crates/stark_verifier/src/statement.rs), and current [verification order](../../target/client-privacy-feasibility/upstream-proving/crates/stark_verifier/src/verify.rs).

The benchmark's [`initial_channel`](../poseidon-membership/client/src/main.rs) and [`mix_serialized`](../poseidon-membership/client/src/statement.rs) use domain-separated, length-prefixed JSON bytes. Canonical felt strings have value-dependent lengths. Preserving that exact proof protocol inside a fixed circuit requires constrained byte encoding, lengths, and hashing with fixed topology; serializing secret values on the host and trusting the resulting digest is insufficient. A future circuit-friendly fixed-width statement encoding could avoid that complexity, but would be an explicitly reviewed protocol change and produce new inner proofs.

## Membership bookkeeping that must become constraints

The current public verifier checks the following in [`Statement::validate` and `PublicData::boundary`](../poseidon-membership/client/src/statement.rs). Once the intermediate transcript is a private circuit input, the wrapper must constrain these checks or an updated inner AIR must enforce them:

1. Canonical felt252 encoding and bounded integer indices; exactly two depth-32 paths; index-bit selection of left/right children; leaf, parent-chain, and shared-root endpoints.
2. Both permutations of `poseidon_hash_span([left,right])`, including absorption order, all intermediate state coordinates, and the padding `+1` modulo the felt252 prime. The wrapper need not recalculate Poseidon if its constrained requests are bound to the verified inner AIR.
3. The deterministic value-to-memory-ID dictionary and consistent permutation input/output tuples; multiplicities for duplicate requests; the padded aggregator row and its zero multiplicity. Sorting, deduplication and shape must not be trusted host witness preprocessing.
4. All 128 requested positive Poseidon lookup terms and all 768 negative memory terms for the 128 padded rows. Zero-multiplicity padding still makes six unconditional memory reads. The fixture has 126 unique requests, so it already exercises both cases.
5. Equality of the constrained boundary plus **all** component claimed sums to zero, using the verified transcript's lookup challenges. A guessed boundary sum is not a membership proof.

The fixed outer preprocessing root must bind the circuit topology before witness assignment. Value-dependent dictionary size, deduplication, component heights, JSON lengths, or branching must not silently change that topology. A general private path circuit therefore needs a fixed capacity/padding design and a deliberate public output schema. Whether leaves, indices, or note commitments are public cannot be decided merely by choosing which values to omit from the JSON envelope.

## Existing fixed caller and authority

Pinned [`privacy_recursive_prove_low_memory`](../../target/bounded-memory/proving-utils/crates/privacy_prove/src/low_memory.rs) converts a full typed Cairo proof, obtains the output from its matching preimage, builds the fixed Cairo verifier context, checks context validity, adds existing blinding, finalizes it, proves the circuit, and emits versioned compressed PROOF1 bytes. The inner proof is assigned locally and dropped before the recursive proof stage. It is not the object sent to a remote prover.

Its trusted [`privacy_circuit_verify`](../../target/bounded-memory/proving-utils/crates/privacy_circuit_verify/src/lib.rs) supplies the bootloader, selected components, PCS configuration, preprocessing roots, output addresses, and circuit proof configuration. The final verifier recomputes the intended output hash from `output_preimage`. The mandatory `u` wire is bound by the circuit lookup relation. The recursive [`CircuitConfig`/output hash chain](../../target/direct-air/stwo-circuits/crates/circuit_verifier/src/verify.rs) must come from application authority; accepting arbitrary prover-selected topology/root without checking the outer output chain would not bind the intended statement.

The current monorepo retains this fixed caller structure in [`privacy_prove`](../../target/client-privacy-feasibility/upstream-proving/crates/privacy_prove/src/lib.rs) and trusted output/config checks in [`privacy_circuit_verify`](../../target/client-privacy-feasibility/upstream-proving/crates/privacy_circuit_verify/src/lib.rs), with the newer output ABI above. It does not provide a ready-made compact membership wrapper.

Pinned and current [`add_zk_blinding`](../../target/client-privacy-feasibility/upstream-proving/crates/circuit_common/src/finalize.rs) add random rows to five supported circuit witness gate families. This is not a generic blinder for arbitrary custom AIR. The fixed privacy caller derives the seed from the local inner witness commitment and uses the outer query count for padding. This inventory preserves that existing construction and does not claim its applicability to a new arbitrary topology. That requires a separate privacy review; successful native verification or an API named `privacy` is not such a review.

## Approved bounded cost probe

Measure only the **existing fixed Cairo wrapper** first. It answers whether the present wrapper's preparation, fixed circuit tables, proving and serialization fit the intended client budget. It does not measure a private version of the compact membership relation.

- Use the existing synthetic `privacy_prove/test_data/privacy_tx_cairo_pie.zip`, SHA256 `9e193692b3f2f26a21dd04f11ca5b44cfb618fdf49d8a042d2030d3c2f9ba354`, with the accepted proving-utils bootloader. The separate circuits test proof uses a different bootloader and must not be substituted.
- In copied dependencies only, export a typed Cairo proof plus matching output preimage at the existing stage boundary. Keep the original unsplit function unchanged as the parity oracle. The checkpoint is synthetic, local-only, and not a network format.
- A fresh measured process imports it, rebuilds max-domain twiddles and trusted fixed preprocessing/configuration, executes the exact original context/check/blinding/finalization/prove/serialize suffix, and writes PROOF1. Include checkpoint loading and all allocations through output writing. Use existing bounded storage with 16-column batches only; retain all security parameters.
- Require full PROOF1 byte equality with the same-input unsplit path, preserved native verifier acceptance, and rejection with changed public output. Record checkpoint and source identities separately from the final public proof.
- Report complete wrapper process RSS/time, plus phase measurements if available. A later end-to-end client budget must include inner proof and auxiliary generation as well. Circuit fixed XOR/range tables remain even for a small verifier graph; the compact inner proof's browser result cannot predict this wrapper cost.

No new generic privacy cost probe is approved at this point. After the wrapper cost and privacy applicability gates, the smallest next compatibility step would be a fixed, reviewed circuit-friendly statement using the existing component adapters, first with synthetic inputs and complete negative binding tests. It would still require the membership bookkeeping above and would not inherit a privacy claim from the generic verifier.
