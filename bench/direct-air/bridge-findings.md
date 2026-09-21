# Synthetic Cairo bridge findings

Status: the library, executable, and Starknet account compile with the generated
synthetic configuration. Both saved proofs pass; nine malformed/altered inputs are
rejected; four serialization/transcript tests pass. Execution inside the pinned V1
virtual OS remains pending. This is a synthetic compatibility experiment, not a private
client-payment protocol. Further disclosure diagnostics are deferred at the user's request.

The client privacy gate is separate and now blocked by a synthetic recovery result; see
`privacy-review.md` and `results/eq-one-thread-8g/proof/summary.json`. In the second
fresh-seed run, query-plus-OOD observations recovered all four coordinates of the private
test value. A server-side zero-knowledge wrapper cannot remove information already
leaked by its client input. This result concerns the diagnostic topology and call pattern;
it is not a claim of extraction from Templar's existing V1 recursion circuit.

## Explicit source boundary

The outer proving family remains pinned: S-two `489a0f3`, stwo-cairo `9b6be27`,
stwo-circuits `5ef951a`, proving-utils `3035dd0`. No outer verifier or proof format is
changed by this bridge. The June 11 Cairo tree lacks the circuit AIR/verifier referenced
by the pinned Rust `circuit_cairo_serialize` crate.

The bridge alone vendors the complete `bounded_int`, `constraint_framework`,
`verifier_core`, `verifier_utils`, and `circuit_air` crates from stwo-cairo
`16700cc9a03fe43a6801ca87b4ff685aeb26339d` (June 25). This is the earliest complete
fixed-circuit executable implementation found in the available upstream history.
`cairo/vendor-source.json` records the original SHA-256 for every source file. The
license declaration, standard Apache-2.0 text, and provenance are included in `vendor/`.

Relative to the old Cairo core, this coherent source includes component metadata,
duplicate-query handling, and a full PCS configuration including lifting. The generic
verification argument was refactored from composition bound to trace bound, related by
`old_composition_log = new_trace_log + 1`; the FRI delta is only a `PartialEq` derive.
The mathematical reviewer reviewed this source choice. No verifier equations were
reimplemented locally.

## Compatibility adaptations

- The exact Cairo source supports ordinary Blake2s, whereas the default Rust circuit
  API uses Blake2sM31. The synthetic client explicitly chooses the existing generic
  `Blake2sMerkleChannel` prover API. This affects the inner artifact only; outer PROOF1
  remains unchanged. The bridge never enables `qm31_opcode` or Poseidon hash features.
- The pinned Rust `CairoSerialize<PcsConfig>` silently omits `lifting_log_size`. The
  local `cairo/serialize_full_config.rs` writes all fields in the June 25 Cairo order:
  pow bits, blowup, last-layer degree, query count, fold step, Option lifting. `Some(x)`
  encodes as `[0,x]`, `None` as `[1]`. Existing query sorting/transposition is reused.
- A tiny topology changes the stable size-sorted order of preprocessed columns.
  `generate_constants.py` regenerates both column symbols and trusted constants from
  a reviewed build-time manifest. It checks all 45 identities, component log sizes,
  fixed lookup-table dimensions, lifting, full security config, and public addresses.
  These two files are the only intended vendor deviations, recorded in
  `generated-config.json`. The verifier never adopts runtime proof-supplied config
  or preprocessing roots as its authority.

The generated synthetic manifest is `cairo/synthetic-config.json`, derived from the
8 GiB diagnostic's summary. The component log sizes are
`[6,10,6,6,6,16,20,8,14,18,16]`; fixed lookup tables still force lifting log 22.
Both executable and contract artifacts were rebuilt successfully with this configuration.

Keep the hash meanings distinct: the inner proof uses ordinary Blake2s; a circuit's
Blake application gadget reduces its output words to M31; the Cairo bridge's final
output commitment is raw Blake2s over raw preprocessing-root words and public QM31
limbs. `cairo/hash-fixtures.json` records an independent Python computation of that
last preimage/digest and of the initial salt/config transcript. No M31 reduction is
applied to the bridge output commitment.

## Entry points and statement shape

`cairo/bridge` exposes `verify_serialized(Span<felt252>)` and an executable taking the
same span. It rejects trailing data after deserializing exactly one complete proof,
then invokes upstream full verification. The result is the upstream Blake2s digest of
`compiled_preprocessed_root || public_output_QM31_words`.

`cairo/statement_account` exposes `SyntheticCircuitStatementAccount::__validate__`
and `__execute__`, both with a proof span. There is no constructor or private input.
Validation requires zero tip and resource prices; execution requires the virtual OS
caller. It emits an L1 message to zero with nine felts: its class hash followed by eight
public values:

1. `DIRECT_AIR_SYNTHETIC_V1`;
2. `SYNTHETIC_CHAIN` sentinel;
3. zero pool sentinel;
4. four little-endian u64 limbs of the verified 256-bit output commitment;
5. reserved zero.

This preserves the harness's message length only. It does not claim the pool's payment
encoding or semantics. The class hash binds the complete compiled verifier identity,
including its topology/config, and the output commitment binds the public outputs.
No deployment or live-chain write has occurred.

## Build and validation

Scarb is explicitly pinned to 2.18.0 locally; otherwise the parent `bench/.tool-versions`
selects 2.14.0. The executable uses gas-disabled compilation. Starknet contracts require
gas enabled, so the statement has a separate package and a `contract` build profile.

Commands from `cairo/`:

```sh
scarb build -p templar_synthetic_circuit_bridge
scarb --profile contract build -p templar_synthetic_statement_account
scarb test -p templar_synthetic_circuit_bridge
scarb execute --no-build -p templar_synthetic_circuit_bridge --arguments-file ABSOLUTE_JSON --print-program-output --print-resource-usage
```

The executable's JSON input is one length-prefixed span `[proof_felt_count, ...proof]`.
`make_mutations.py` prepares changes to security config, lifting, preprocessed root,
public output/count, OOD/query values, truncation, and trailing input. Real acceptance
and mutation execution results must be recorded before interoperability is claimed.

Build logs are in `results/cairo-bridge-build.log` and `results/cairo-statement-build.log`.
The statement artifacts are under `cairo/target/contract/`, named
`templar_synthetic_statement_account_SyntheticCircuitStatementAccount` with the usual
`.contract_class.json` and `.compiled_contract_class.json` suffixes.

Final generated-configuration builds are recorded in
`results/cairo-bridge-final-build.log` and `results/cairo-statement-final-build.log`.
The initial test compilation exposed function-local imports unsupported by Cairo;
moving the imports to module scope fixed compilation without changing the test logic.
All four tests pass in `results/cairo-bridge-tests-fixed.log`.

`validate_bridge.py` executes the second saved proof and nine mutation fixtures under
8 GiB, zero-swap process-group caps. The first saved proof was measured separately.
Both outputs match the independent hash fixture. Altered configuration/lifting,
preprocessing root, output count/value, OOD value, query value, truncated data and
trailing data all fail inside the verifier/decoder, without OOM. Exact results are in
`results/cairo-bridge-validation.json` and `results/measurements.md`.

## Remaining PROOF1 integration boundary

The pinned service's `server/rpc_api.rs::ProvingRpc` accepts only a block ID and an
invoke transaction. It has no state-override parameter. Its
`running/committer_utils.rs::validate_virtual_os_state_diff` forbids contract
deployment, class replacement and declaration in the proven virtual transaction.
Consequently the new statement account must already be available in authenticated
state before this service can prove its invocation. The current experiment has not
declared/deployed it or constructed a separate authenticated local chain fixture.

After that setup, prove the exact saved synthetic payload through the unchanged
service, run the original independent PROOF1 verifier, and compare all nine emitted
message felts against the compiled account identity and expected public commitment.
Record server proving resources separately. The current 2.03–2.12 second Cairo
execution result does not estimate that server proving cost.

The final `sncast` 0.63.0 declaration dry-run against Sepolia succeeds with
account `account-1`, Scarb's `contract` profile and the installed universal
Sierra compiler. Its estimate is 5,246,255,680 L2 gas plus 192 L1 data gas,
totalling 93.282573384211208384 test STRK at the recorded prices. This is a
one-time declaration estimate, not a payment fee or wrapper execution estimate.
No transaction was submitted. The log is
`results/sepolia-declaration-dry-run-final.log`; earlier logs preserve an account
alias typo and a missing compiler PATH entry, both fixed before that final run.
