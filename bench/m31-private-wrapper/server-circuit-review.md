# Public server hash circuit: consolidated source review

2026-09-22. **Source-level GO for the isolated public hash circuit; NO-GO for this batch through the unchanged outer prover at its present capacity.** The inspected circuit constrains ordinary full Blake2s-256 and binds its input and output batches. Native and Cairo verification passed, but the actual PROOF1 attempt failed with `Not enough twiddles!` and produced no outer proof. This is not a private-membership verifier: it does not establish Merkle authentication, transcript, AIR, OOD or FRI validity of the original client proof. Those checks must eventually be proved too. No original-client privacy review is repeated here.

The user requested this consolidated review after implementation. The nested S-two checklist, AIR-constraint and divergence guidance were read and applied. The primitive reference is [RFC 7693, sections 2–3 and Appendix B](https://www.rfc-editor.org/rfc/rfc7693). Existing circuit gate AIR and its Cairo mirror are reused, rather than a new hash arithmetization. I inspected source and existing logs only; no implementation, build, test or benchmark was run by this reviewer.

## Full-word constraints

Each variable word is represented by a QM31 value `(lo16, hi16, 0, 0)`. `full_blake` first emits `triple_xor(word, zero, zero)` and equates its result to the original word. This is a constraint, not merely a host assertion:

- The TripleXor AIR splits both input limbs into low and high bytes. Its fixed `VerifyBitwiseXor_8` table constrains those bytes to `[0,255]`, so both limbs lie in `[0,65535]`. The split identity alone would not establish that range; the table lookups are essential.
- Its `Gate` relation identifies the circuit address and the two limbs, with the remaining QM31 coordinates implicitly zero. The same address is yielded with the complete QM31 value by the circuit arithmetic/guess machinery. Their global lookup balance therefore binds the missing coordinates to zero.
- This check applies to every variable message word before it becomes either BlakeG message addend `f0` or `f1`. That matters: the `VerifyTripleSum32` carry equations alone do not range-check those addends. Native `unpack_u32` assertions are not the reason the proof enforces canonicality.

The existing BlakeG AIR's carry and XOR/rotation constraints implement wrapping 32-bit addition and rotations16/12/8/7. State inputs start as correctly constrained packed constants or outputs of preceding gates. All state and message wires are connected through fixed preprocessing addresses and the Gate relation. Final feed-forward uses TripleXor on all eight state words. No `HashValue` conversion or M31 reduction is used, so high digest bits survive.

For a partial final word, boolean guesses satisfy `b*(b-1)=0` in the field QM31, hence are exactly0 or1. The reconstruction uses packed powers of two for only the actual byte positions. Each 16-bit limb's sum is at most65535, below M31's modulus; there is no modular wrap or carry between coordinates. Equality to the original word forces every unused high byte to zero. The guesses' values affect only assignment generation, not topology.

The IV, parameter XOR `0x01010020`, SIGMA table, ten rounds and eight G calls per round match the standard. Length and loop counts are fixed topology parameters. Empty input produces one zero block with count0; exact multiples of64 finalize their last full block without adding an empty one. The4,000,000-byte bound keeps the high counter word zero. `finish` registers the existing broadcast-basis constant's use before normal constant finalization; its reflexive equality adds no witness-dependent topology or unchecked constant.

## What the statement binds

For a fixed ordered vector of message lengths, the circuit accepts variable packed message words and publishes sixteen packed `u32` words:

```text
outputs[0..8]  = Blake2s256(concat_i(u32le(length_i) || zero_word_pad(message_i)))
outputs[8..16] = Blake2s256(concat_i(Blake2s256(message_i)))
```

The first encoding is lossless before hashing: each length determines exactly how many words follow, and the tail constraint makes padding canonical. The second encoding has exactly eight words per digest and preserves order. The two results occupy distinct fixed public addresses3..18. Both are computed in the circuit from the same message variables; a supplied `Job.digest` is not accepted as an unconstrained circuit result.

The host's `expected` function independently uses the standard Rust Blake2s implementation, checks the supplied job digests and computes the sixteen expected words. Native verification checks those exact public values. The Cairo verifier is deliberately generic over valid inputs of its compiled shape: it returns `Blake2s256(trusted_preprocessed_root || sixteen_QM31_values)`. Each QM31 value contributes four canonical M31 coordinates encoded as four little-endian `u32`s, so this outer preimage is **not** the same as simply concatenating sixteen packed digest words.

The account splits the returned full256-bit hash into four `u64` limbs without field overflow, includes class, chain and a distinct experiment domain, and emits it only after verification succeeds. **The outer harness must compare this value with its independently computed expected batch binding**, alongside the original program/class/fact checks. Otherwise a proof for a different valid batch of the same shape would be accepted as the chosen benchmark. This comparison identifies the proved public workload; the actual hashing remains inside the proved circuit. No membership-validity claim can be attached to this output.

## Fixed topology and Cairo compatibility

The trusted preprocessing root is computed separately from a `NoValue` build before using the actual assignment's proof. The real and NoValue circuits must compare equal. Hash loops, partial-tail gates and constants depend on lengths, not message contents. Added same-length/different-content coverage checks that property explicitly. The trusted manifest is a local build artifact; accepting a proof producer's replacement manifest would change verification authority and is outside this design.

`build_server_bridge.py` checks purpose and exactly sixteen output addresses, then reuses the existing validated generator. It requires all45 named preprocessing columns, their stable order, component/table dimensions, `u` address2, the root's eight full words, and the complete PCS config. For this instance the config is ordinary Blake2s channel/Merkle, PoW26, blowup-log2,35 queries, fold4, final-degree-log0, lifting22; interaction PoW remains20. This is the existing circuit proof configuration, not a change to the frozen private client.

The Cairo verifier hardcodes the trusted root, output count and all config fields, derives component sizes, checks relation-use limits, public lookup sum, interaction PoW, and invokes the existing complete STARK verifier. The new wrapper requires exactly one deserialized proof and rejects trailing data. The account does not take an unchecked native acceptance flag.

Known bridge issues are addressed by existing mechanisms: the local serializer explicitly includes `lifting_log_size`, the channel uses ordinary full Blake2s rather than the reduced-M31 variant, and preprocessing is nonempty so the earlier empty-tree height mismatch does not apply. The input converter uses the existing size-sorted queried-value transpose. Successful native verification alone does not prove that the complete Cairo wire path is compatible; cross-runtime execution remains required.

## Evidence inspected and remaining acceptance checks

The retained native report records one 82-job public batch totaling 57,046 bytes and 934 message-hash compressions, complete native verification and four rejected proof mutations: changed output, trace root, preprocessing root and config. Padded BlakeG length is 262,144 rows; the overall trace ceiling is log20 because of fixed lookup tables. The 16GiB/four-thread run completed with reported peak RSS 3.534GiB and no swap/OOM. Those figures cover this circuit and its two additional binding hashes, not full membership verification or browser proving.

The final focused test log inspected at `/tmp/templar-server-tests.log` records five passing tests: two inherited config/transcript-wire tests and three new circuit tests. The latter exercise thirteen message lengths, all eight full hash words through the aggregate comparisons, output/G-result corruption, partial-word padding, value-independent topology and four malformed packed encodings (either limb65536, or nonzero coordinate2/3). The malformed encodings are applied to an already built assignment, avoiding a constructor-only panic. These `Circuit::check` tests exercise native semantic gate checks, **not an independent execution of the AIR on malicious traces**; actual AIR range and relation constraints were separately inspected above.

The original first test attempt failed on the upstream constant-finalizer unused-wire diagnostic. The final `finish` helper preserves that diagnostic and registers the constrained basis constant's use; the later focused log passes. No verifier constraint was removed to bypass the failure.

`results/server-circuit/cairo-validation.json` records verification of the same saved circuit proof in Cairo with an exact independently expected full output hash. Seven negatives reject: changed output, interaction nonce, config, trusted root, trace root, trailing data and truncation. The valid execution used 5,018,523 steps and reported peak RSS 0.780GiB. This establishes the standalone circuit-to-Cairo compatibility gate for this artifact.

The narrow outer-binding adapters were also read: `prepare_server_outer.py` recomputes both batch bindings from public messages using Python's standard Blake2s and the trusted build root; it does not take expected values from proof claims. `run_server_outer.py` pins original prover/verifier binaries and the supplied synthetic fixture, checks program/anchor/config and exact account message/fact binding, and calls the original verifier if proof generation succeeds.

That final generation did **not** succeed. `results/server-circuit/outer/report.json` and `prover.log` record `Not enough twiddles!` after virtual OS execution, under a 64GiB cap with peak RSS 34.353GiB and zero swap. The logged OS work was 7,301,958 steps / 4.571 seconds. This is a capacity failure rather than a reported OOM or circuit-verification failure. No PROOF1 was produced, so no new outer-verifier acceptance or outer-mutation success is claimed for this circuit. The representative direct-hash PROOF1 from the preceding experiment does not substitute for it. Raising twiddle/domain parameters, changing the verifier route or reducing its work would require a separate concrete implementation decision; none is approved implicitly here.

## Source identities

SHA256 identities at this review, relative to `bench/m31-private-wrapper/` unless qualified:

```text
server-circuit/src/full_blake.rs
  172b4c6b6926a7cc2353e746192ca464f9c428a7c0a93e9eeb9a9aa2d72eeaa6
server-circuit/src/main.rs
  fafb80c2d8ff7597ad45d89f8bab8454bfa0464c09641a85211e31d862b257ba
build_server_bridge.py
  1220e69763f7412bcd1e7e1b9c16f4f4c12cb9fdc96afe9cb5a26d712808d68a
server-cairo/bridge/src/lib.cairo
  bb714d2bac61447d8c58cba3b63309c12b9783b934570b285e4cc74f29daf0b5
server-cairo/account/src/lib.cairo
  0a8aa51ecdf7bd1feffd65313660045c41bc8d6a462bf3dd49bdb7d20269bcc9
results/server-circuit/proof/trusted-config.json
  7e00ca3366bfc7c6cdd044a3c525a1bcb9a33376566609ba1ce806ed705f48bd
results/server-circuit/bridge-build.json
  07cae03e453cdf538943535a939037ed8fd16eb1cb901039b6ce2b0cd3176343
prepare_server_outer.py
  f5c6dff2ad58ea7aef3811660ea7d4323ce4c76e7eb59906630044010bfb0f87
run_server_outer.py
  2740d6d16efbd09042998888baa88addd8cfecbbc988ec0d79c1ffe0eac97751
results/server-circuit/cairo-validation.json
  279e157d511f6ac4b9e482a05c073f6b5db5c389d4c94957ebfe3e8216a66b86
results/server-circuit/outer/report.json
  c0c52ebd1d5d891ddebf170ffe6a685618fae80df06985ae145d76253c740e81
results/server-circuit/outer/prover.log
  e6bde7cf250f4a0a65d05fcabf5b4d1cc002fa9efc74d1074fd46827b1d2db93
../direct-air/cairo/generate_constants.py
  d59cb7fd2cc48afeaefc49d24823da325f41529f1a2faa5328f3cb37392fb028
../direct-air/cairo/serialize_full_config.rs
  15e7ec0377291998604dc88b8ec03e1602d614f8d376c41f81ab3ad8e6a4b3c6
```

The bridge build manifest records every reused vendor source and the two generated topology files. Inspected Rust AIR files under `target/direct-air/stwo-circuits/crates/circuit_prover/src/circuit_air/components/` have hashes `5f7de9c7e20dafde6da060cc2b8d62b1497104ccea8f2a85a5059635fa84f5eb` (TripleXor) and `401d8e4106d8d3184ab7fee2251809f4abb2b9dca704690c23fc1b9a6343980b` (BlakeG). The focused test log's hash is `c225d42363a741e3fd3fbe3a2647a9b53a9dbdc3d951924a48cbedf715f95257`. All original client proof, masking and protocol sources are outside this milestone and remain unchanged by this review.
