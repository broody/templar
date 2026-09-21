# Direct client proof: privacy and bridge review

Review status: **privacy gate unresolved; synthetic diagnostics and bridge compatibility work only**. Reviewed against the pinned S-two `489a0f3`, stwo-circuits `5ef951a`, stwo-cairo `9b6be27`, and the separately proposed Cairo bridge source `16700cc9a03fe43a6801ca87b4ff685aeb26339d`. Earlier experiment sources and archives are unchanged. This document is not an audit or a claim that proof verification establishes zero knowledge.

## Required privacy boundary

The proposed server receives a client artifact and public application data. It must not receive the raw application witness, unblinded direct-AIR proof, private blinding seed, or a diagnostic trace. A later zero-knowledge PROOF1 wrapper cannot undo information already disclosed to that server. The client artifact therefore needs its own hiding argument against the server.

There are two structurally plausible client constructions:

1. Express the application directly using the pinned upstream circuit gate family, blind and prove that circuit locally, and send its circuit proof. This is the shortest compatibility experiment because the existing circuit verifier/serializer already represents that family.
2. Produce a custom direct-AIR proof locally, verify it inside a supported circuit, blind and prove that verification circuit locally, and send only the resulting circuit proof. This leaves the raw inner proof local but adds another client proving stage. It does not solve the masking question for the outer client circuit.

Calling `add_zk_blinding` on an unrelated custom AIR is not supported: the function adds rows to five specific circuit gate components, not arbitrary witness polynomials.

The smallest proposed compatibility relation is a fixed pair of private QM31 values with their canonical byte encoding hashed through `circuits::blake` to two public QM31 values. That helper reduces the eight Blake2s digest words to M31; its output is not a raw Blake2s-256 digest. This is a synthetic relation, not Templar's felt252/Poseidon payment relation. The library retains fixed lookup tables even for a tiny relation, so its measured footprint cannot be inferred from application gate count alone.

## What the pinned blinding function does

`circuit_common/src/finalize.rs::add_zk_blinding` seeds ChaCha20 from caller-supplied bytes and repeats five helpers `n_padding` times. They append valid random rows for QM31 arithmetic, equality, triple XOR, M31-to-u32 conversion, and Blake G gates. Trivial arithmetic gates yield the fresh random variables so the gate lookup relation remains balanced. `finalize_context` subsequently pads component lengths to powers of two. Neither function proves or checks a relation between `n_padding` and all information disclosed by a proof.

The upstream caller uses the circuit query count as `n_padding`. The source-level test called `test_zk_padding` checks that the selected large circuit's sizes remain within the same powers of two; it does not test a simulator, hiding, mask rank, or witness recovery. The pinned paper distillations establish circle interpolation, soundness, transcript, and commitment properties, but do not provide a zero-knowledge theorem for this exact five-component padding construction.

A fresh 256-bit seed from the client's operating-system CSPRNG is required for the proposed experiment's witness assignment. It must remain private and must not be a public commitment, public output, fixed constant, or server-selected value. A fixed seed is acceptable only for constructing a value-free public topology or explicit reproducible synthetic tests, never as a claimed private production transcript. The seed is an input to the randomness mechanism; a fresh seed alone does not establish masking sufficiency.

## Concrete question under investigation

SECURITY-ESCALATION:

- File: pinned `stwo-circuits/crates/circuit_common/src/finalize.rs`, especially `eq_zk_blinding` and `add_zk_blinding`.
- Attack surface: a server observing a proposed custom circuit proof.
- Invariant at risk: proof observations must not reveal private circuit values beyond public outputs.
- Observation: the equality component receives `n_padding` independently chosen M31 values per coordinate, while a proof discloses queried trace evaluations and a QM31 out-of-domain evaluation of each trace coordinate. One QM31 OOD value can supply up to four base-field linear equations.
- Current conclusion: counting 35 random rows against 35 queries does not account for the OOD disclosure and is insufficient evidence of zero knowledge. Whether it permits recovery depends on actual folded query positions, independent equation rank, the circuit's private rows, and the finalized topology.
- Action: a bounded synthetic rank/recovery diagnostic is authorized. There is no privacy-qualified client artifact signoff yet.

The diagnostic uses a fixed synthetic circuit with a private guessed `x`, an explicit `eq(x,x)`, and public constant output. It preserves the upstream gate family, uses 35 blinding rows and the pinned proof parameters, and derives the actual final equality row order. Its observation matrix consists of the trace-basis interpolation coefficients at actual equality-domain query positions plus the four base-field coordinates of the actual folded OOD evaluation. Public rows are subtracted; random-row columns form the masking matrix. It compares the rank with and without the private-row column, and attempts recovery from only public topology and proof observations. Query-only and fresh-seed controls distinguish an OOD-rank issue from seed reuse. Results must report ranks and recovery, not merely whether proofs differ.

A successful diagnostic would establish leakage for that specific custom circuit and call pattern. It would not by itself establish extraction of note secrets from the existing large V1 recursion circuit or from a Blake-only circuit whose equality rows might contain only public outputs. Those statements require analysis of their actual private rows and other components. A negative diagnostic would also not prove zero knowledge.

No arbitrary padding increase is approved as a privacy fix. Query-plus-OOD rank is only one necessary check: gate correlations, interaction claimed sums, cumulative-sum offsets, lookup multiplicities, composition/FRI disclosures, mask reuse, and repeated transcripts still require a complete argument. The existing code's independent random inputs do not automatically imply independently random values in every derived witness column.

## Topology, statement, and parameter prerequisites

A candidate artifact needs one fixed, public topology per explicitly selected mode. Build the value-free topology, include the exact blinding scaffold, finalize and preprocess it before private assignment. Verify that the assigned topology and ordered named preprocessed columns match. Use guessed variables for private inputs: private values must not become circuit constants, gate counts, branch selections, wire addresses, or output lengths. Secret-dependent topology can leak even if all polynomial openings were perfectly masked.

The bridge must pin the exact preprocessed root, ordered column identifiers/log sizes, component layout, output count and interpretation, lifting size, PCS configuration, and application/verifier version. A proof-supplied root or config is not an authority. Public outputs must bind the intended application statement; for a payment relation that includes the relevant chain/pool domain, roots, nullifiers, commitments, action data, and amounts that are intentionally public. For the tiny experiment it is only the specified Blake digest.

The proposed tiny proof parameters copy the pinned circuit settings: blowup log 2, 35 FRI queries, fold step 4, last-layer degree log 0, query PoW 26, and interaction PoW 20. The convenience `security_bits()` calculation gives 96; it is not an independent theorem covering every topology, table size, or assumption. The verifier must require exact parameter equality, and lifting must be derived from and then fixed for the actual complete circuit/table ensemble. Default test parameters are not acceptable. The outer PROOF1 settings remain pinned and unchanged.

## Cairo bridge compatibility review

The pinned June 11 Cairo tree does not contain the complete fixed-circuit verifier being considered. The proposed bridge-local vendor is the June 25 commit `16700cc9`; it is not a replacement for the pinned outer Rust proving family. Its changes from June 11 include an explicit serialized `lifting_log_size` in `PcsConfig` and corresponding transcript mixing, component/claim metadata, validation of consumed masks, duplicate-query handling, and a composition-bound API refactor. At this exact commit the FRI file change is only deriving `PartialEq`, not a new last-layer degree rule. The composition refactor substitutes a trace bound for the old composition bound with the relation `old_composition_log = new_trace_log + 1` for these degree-two constraints.

Two compatibility adaptations are required and must be explicit:

- Tiny circuits change the size-sorted order of named preprocessed columns. Regenerate the Cairo preprocessed index symbols as well as the log-size array, root, and lifting constant. The verifier derives component sizes through those symbols; changing only the array is insufficient.
- The pinned Rust `CairoSerialize<PcsConfig>` omits `lifting_log_size`, while the proposed Cairo ABI includes it. Use an isolated, documented bridge serializer for that exact ABI, with explicit option tag/order. Do not silently change the pinned outer proof serializer.

The exact June 25 Cairo verifier uses ordinary Blake2s channel and Merkle digests, rather than the outer proof's Blake2sM31 mode. The synthetic inner artifact therefore selects the already-supported Rust `Blake2sMerkleChannel` generic prover path and pins that choice in its manifest. No new Cairo hash equations are introduced, and the outer PROOF1 hash variant remains unchanged. This is an inner-protocol compatibility choice, not a claim that inner bytes match an existing outer proof.

The verifier must check all four commitment roots/structures, compiled config/root/output length, interaction and query PoW, lookup sum and multiplicity bounds, composition/OOD identity, all FRI layers, and opening consistency. The final output is a hash of the fixed preprocessed root and the circuit's public output values; the server wrapper must bind that output to the application's public statement. Feature selection must keep the software QM31 path and intended Blake hash variant consistent.

Synthetic compatibility tests should cover both Rust/Cairo acceptance and rejection of altered outputs, roots, lifting/config, OOD/query values, truncated input, and unintended trailing input. Exact serialization and transcript fixtures are needed in addition to successful deserialization. Such tests establish interoperability and selected rejection behavior, not zero knowledge.

## Decision boundary

Only synthetic masking diagnostics and bridge compatibility work are approved at this stage. Measuring a two-input/two-output, depth-32 felt252/Poseidon client payment relation is gated on a defensible privacy construction and the tiny wrapper path. No production pool, payment protocol, or deployed verifier change is authorized by this review. If the masking diagnostic exposes leakage or the complete hiding argument remains unavailable, this experiment must report the unresolved gate rather than present a memory target as achieved for a private client wallet.
