# Bridge capacity: consolidated source review

2026-09-22. **Source GO for the isolated inverse replacement and the explicitly reconfigured research wrapper. Runtime capacity NO-GO for the measured enlarged wrapper under96GiB.** The optimized standalone Cairo verifier passed, but enlarged proving was OOM-killed before producing either a Cairo proof or a recursive proof. There is no new proof whose original-verifier compatibility can be claimed.

Scope is only `bridge-capacity/{capacity.rs,setup_large.py,setup_optimized.py,stock.rs,capture.rs,capture.py,build.py}` and their generated changes. Root and nested S-two/Cairo reviewer instructions, the soundness checklist, AIR-constraint and relevant field guidance were applied. No original private-client or Blake-construction review is repeated. The reviewer read source, manifests and existing results; no implementation, build, test, proof run or delegation was performed.

## Checked M31 inversion

The isolated replacement preserves the input's nonzero assertion. It invokes Cairo2.18's standard `u256_inv_mod(a,p)` for `p=2^31−1`, then checks conversion to `u32`, canonical conversion into M31, and the existing field multiplication identity `a*b=1`.

The primary implementation is Scarb core2.18's `core/src/math.cairo`: `u256_inv_mod` wraps `u256_guarantee_inv_mod_n`. Its multiplication guarantees are not unchecked hints: `core/src/integer.cairo` defines `U128MulGuaranteeDestruct`, whose destructor calls `u128_mul_guarantee_verify`. Discarding the tuple's guarantee values therefore validates them. Independently, the added canonical M31 product check uniquely determines the inverse of nonzero a in this field. It cannot accept an alternative noncanonical representative. Zero cannot pass that identity and is rejected before invoking the primitive.

This changes how an existing arithmetic result is obtained, not the proof statement, transcript, trusted circuit root, field or PCS settings. File comparison found exactly one changed file among104 copied vendor Cairo files: `verifier_core/src/fields/m31/naive.cairo`. That file contains the replacement and two regression tests. No other verifier path was edited.

Read evidence: [optimized validation](results/bridge-capacity/optimized/k3-validation/optimized-cairo-validation.json) records the same saved server-circuit proof accepted with the same expected full output, and all seven prior mutations rejected. The two direct inverse tests pass, including zero rejection and products/inverse-of-inverse across ten boundary values. Standalone steps fall from5,018,523 to4,247,207, a15.37% reduction. That validation ran concurrently with a build, so its wall time and RSS are explicitly **not comparable performance measurements**. Step counts remain the appropriate comparison.

## Expanded preprocessing and trust reconstruction

`setup_large.py` copies pinned Cairo9b6be27 and circuits5ef951a. It extends only CanonicalSmall's sequence ceiling20→22 and updates its maximum size, column count156→158 and cell count10,161,776→16,453,232. The added cells are exactly `2^21+2^22`. Existing sequence semantics, field values, lookup tables, AIR constraints and relative column order are unchanged; the two new high-log sequence columns are included in the canonical sorted trace.

Read-only comparison found exactly this preprocessing file changed among310 copied Cairo Rust files and no changed file among333 copied circuits Rust files. The generated Cargo patches route the active Cairo/circuit families to those copies. Comparison of the generated lockfile with the original found no new external `(name,version,source)` package identities. Previous checkouts and verifier binaries remain separate.

`capacity.rs` obtains the original program, component enable set and output count from trusted pinned helpers, replaces the Cairo `ProofConfig` with the operator-selected geometry, and computes the Cairo preprocessing commitment from the actual public columns. It builds the recursive verifier using that complete config, derives its `NoValue` preprocessing, and commits that circuit's public columns independently. No root, topology, column count or security choice is taken from a supplied proof.

The recorded shape has Cairo trace-log22/lifting25; the resulting recursive circuit has trace-log22/lifting24 and45 preprocessing columns. Both roots change relative to the old fixed wrapper; the shape's `matches_original_root` is false. Cairo retains blowup-log3,23 queries, PoW27, fold4 and last-degree-log0; the recursive circuit retains blowup-log2,35 queries, PoW26, fold4 and last-degree-log0. Interaction PoW settings are inherited unchanged. Preserving these parameters is not a fresh theorem about end-to-end concrete security, and no such audit was requested here.

The actual Cairo proof is checked by the fixed verifier circuit before recursive proving. Actual circuit preprocessing must equal the independently generated NoValue preprocessing. Both constructions use the unchanged upstream blinding calls with35 rows per supported gate; the actual seed is derived from the Cairo base commitment exactly as in the pinned wrapper, while NoValue uses a dummy seed only to determine topology. This confirms faithful reproduction of that mechanism, not a new privacy qualification.

One interface defect was identified: the first source allowed LOG20..23 despite the copied variant containing sequences only through22 and requiring22 for its largest preprocessing column. The final source now requires `LOG == linked_variant.max_log_trace_size()`:20 in the preserved helper,22 in the enlarged build. This rejects unsupported operator choices early. The measured binary used the earlier source with LOG22, whose proof semantics are unchanged by this guard. Original measured source and binary identities are archived separately; a later guard-only build must not be substituted silently into the measurement provenance.

The final [argument-guard check](results/bridge-capacity/large/argument-guard.json) confirms that LOG21 rejects before setup or proving. Its binary SHA256 is `9fe600b39694c96d774d9a488bd5a9fa5083c9e931bfe905844bdc86b6b43b73`; this is distinct from the measured binary below.

## Public binding, serialization and compatibility

`capture.rs` compiles the pinned runner modules directly and invokes the normal virtual OS runner; it adds no unchecked execution result. It limits the RPC host to127.0.0.1 and selects the synthetic Sepolia context. `capture.py` runs the existing fixture transport, records fixture/request/binary/PIE identities, and checks the exact message count, class, sender, destination and expected payload. These are operator-selected local fixture identities, not network finality or an independent external chain trust anchor. Their hashes must remain attached to the measured PIE.

The optimized capture records exact expected-message acceptance and PIE SHA256 `be8e5bebc4e5cc5cb806e83e0a36ddd7df5f93452a34c57ddea4c7f962165cd8`. The recorded enlarged command uses that same PIE. Privacy-bootloader replay retains the original program and output encoding; the verifier circuit binds the hash of the entire resulting output preimage. The measured replay records17,557 Blake compressions and no generic or QM31 opcodes. Public hash-batch meaning still depends on the earlier checked account/program/message binding; this is not membership verification.

The final recursive-check code deserializes serialized proof bytes with the reconstructed trusted config, requires complete consumption, and verifies the expected two output-hash coordinates. It includes changed-output, wrong-root, wrong-query-config, truncated and trailing-data controls. **These checks and controls did not execute in the failed enlarged run**, because no proof was generated. The code is an internal capacity harness, not a general deployment-ready proof-envelope API.

The artifact deliberately uses the upstream three-byte envelope but is named `research-proof.bin` and requires newly trusted geometry and roots. The common envelope does not establish original PROOF1 compatibility. `stock.rs` links exclusively against preserved original dependencies using `build.py`'s fingerprint-resolved libraries. It reports acceptance as a JSON boolean and exits successfully even for rejection; the boolean, not the exit code, is the compatibility result. Its positive control accepted a known original proof. No new enlarged artifact exists to give it, so compatibility remains **untested**, rather than either accepted or empirically rejected.

## Capacity evidence and verdict

[The enlarged run summary](results/server-circuit/capacity-prove-log22-optimized/summary.json) records four threads, a96GiB cap,71.2557 seconds elapsed, process high-water RSS95.7859GiB, cgroup peak96GiB, one OOM kill and zero swap. `proof-optimized/` contains only boot metadata, config and output preimage: no completed Cairo claim/proof or recursive proof. The source saves config before `prove_cairo` and the Cairo claim only after that function returns; the retained artifacts are consistent with failure during Cairo proving.

The inverse change is correct and measurably reduces executed work. It does not make this enlarged proof path fit the tested budget. Source approval is limited to the isolated experiment. A successful enlarged wrapper, negative-control result for such a proof, original-verifier compatibility, unchanged PROOF1 acceptance and full membership verification are all unachieved here. No further parameter change or retry is implicitly approved by this report.

## Reviewed identities

SHA256 paths are relative to `bench/m31-private-wrapper/` unless qualified:

```text
bridge-capacity/capacity.rs (final operator guard)
  2dd07bafc05691d2fbab7619ddd725052d911fa40e6ca68af863c0128c825bcb
results/bridge-capacity/large/measured-source.rs
  d6b023ad3360c1388259564c4f322eb5bf0415116a3b9390749390146d4a9daf
bridge-capacity/setup_large.py
  4adf6c5a9235c5239927fbe76049147a4956aeeac95c48ce6800baca6ec972be
bridge-capacity/setup_optimized.py
  1c85305642e42d28813758fbd74f816716567c797b42f00b0f68eb1bdb4892d2
bridge-capacity/stock.rs
  485b2f234c1ee178ff69d3ae34704b6db4ab3acc601bc331203f12e820edc303
bridge-capacity/capture.rs
  86881aa9830e9f4f14f2c148c05db80329c5c165e64b4ef572264d9edd68965e
bridge-capacity/capture.py
  d4c2beb65deaa137507cfa9110a2d3545a8b3ae524a230c744cde964ab108caa
bridge-capacity/build.py
  d9ee4fc65b1b4dec0a70adf792ad7db14f9dc12e4608aca3dd367ae63a32eb71
generated optimized vendor M31 naive.cairo
  d8052bfaac1ce986953212a2c272e2965dd41fdc3bb2183f625763c5e76edf48
generated large Cairo preprocessed_trace.rs
  9ccaf69f6cd20439a078378928f2073ec5fd2aa9245040c7adb82c9519c0a7c7
results/bridge-capacity/optimized/k3-validation/optimized-cairo-validation.json
  9004d6363ed8ba7061842dfa278ed611571e3c8d1a080185e0f55967b7db299c
results/bridge-capacity/large/shape/config.json
  654abcb8e11e955cdd2375d4b02e0081a49979296f38fcdd08646d6a5704726e
results/server-circuit/capacity-prove-log22-optimized/summary.json
  9734bbdd8883245a912901837553cbb260053202a9dc86909174ac83dd475e6d
```

`results/bridge-capacity/large/build-and-input-pins.json` records the measured manifest, lockfile, source, PIE and binary; the measured binary hash is `82a20d8699b0c426dbc8a3888c27507c4664617b1259ba418d3ea5ed33a2eef9`. The generated-source hash records identify the exact isolated files. Only this report was written by the reviewer.
