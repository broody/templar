# Fixed Cairo wrapper stage probe

This harness measures the existing pinned fixed Cairo privacy wrapper. It does not implement a private compact membership circuit and makes no new privacy claim.

`setup.py` copies the frozen bounded-memory source trees into a new directory and applies only `patches/proving-utils-checkpoint.patch`. The original `privacy_recursive_prove_low_memory` is unchanged and is the unsplit parity oracle. The new checkpoint module duplicates its Cairo prefix and exact wrapper suffix; all verifier configuration and preprocessing remain trusted library constants. `build.py` compiles and runs three checkpoint-format tests, archives the command/compiler/source hashes, and freezes the binary. It performs no proofs. Reproduction requires the archived original source trees, cached Cargo dependencies, and `nightly-2026-01-15` (the script records the session's scoped `RUSTUP_HOME`).

From the repository root:

```sh
python3 bench/client-privacy-feasibility/client/setup.py
python3 bench/client-privacy-feasibility/client/build.py
```

The setup refuses to overwrite copies; skip it in the already prepared workspace. Build metadata is under `bench/client-privacy-feasibility/results/build` and the binary is `target/client-privacy-feasibility/bin/fixed-cairo-wrapper`. An optional copy of the old Cargo target directory can accelerate builds; cached build products are not source authority and Cargo still rebuilds changed path dependencies.

Commands, each in a fresh process:

```text
fixed-cairo-wrapper prepare <synthetic-pie.zip> <fresh-output-dir>
fixed-cairo-wrapper wrap <checkpoint.bin> <fresh-output-dir>
fixed-cairo-wrapper unsplit <synthetic-pie.zip> <fresh-output-dir>
fixed-cairo-wrapper verify <proof.bin> <output-preimage.json>
```

Use only `target/client-privacy-feasibility/proving-utils/crates/privacy_prove/test_data/privacy_tx_cairo_pie.zip` for this experiment. Its SHA256 is `9e193692b3f2f26a21dd04f11ca5b44cfb618fdf49d8a042d2030d3c2f9ba354`. The separate circuits repository proof fixture has a different bootloader and is incompatible.

`prepare` runs the unchanged bootloader and Cairo proof stage, then writes a synthetic local-only typed checkpoint and matching output preimage. The checkpoint includes proof auxiliary data, which is required for the verifier circuit; it is not an upload format. Files use `create_new` and Unix mode 0600. Decoding rejects the wrong magic, truncated values, and trailing bytes.

`wrap` accounts for checkpoint read/deserialization, fresh max-domain twiddles, proof conversion, fixed verifier context creation and validation, original commitment-derived blinding and query count, finalization, trusted circuit preprocessing, bounded16 proving, PROOF1 compression/serialization, and proof/output file writes. External measurement also includes summary writing and process teardown. `summary.json` records coarse phases; monotonic tracing timestamps identify the unchanged library's finer phases. Both stages use the reviewed bounded16 storage options with unchanged field, transcript, security settings and output schema.

`verify` runs the native fixed verifier and then adds one to the final public output-preimage felt, requiring rejection. Verification is separate from proving timings. Before reporting results, compare the complete wrapped PROOF1 bytes with `unsplit` on the same PIE and run the preserved original verifier against the resulting public artifact. The original source verification is independent of this duplicated wrapper suffix.
