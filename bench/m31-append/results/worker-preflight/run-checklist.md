# M31-append frozen-build execution checklist

Status: **provisional preflight only**. These commands were derived from the
current source entrypoints and existing repository patterns. This worker did
not run any build, test, prover, benchmark, service, or chain command. Do not
begin timed work until Astra declares the specialist outputs frozen and no
build/test/prover workload is active.

## 1. Freeze and identity gates

- [ ] Astra approves the final source review and declares
  `bench/m31-append/client`, `bench/m31-append/cairo`, and
  `target/m31-append` frozen.
- [ ] Create a final manifest for the frozen sources and only the selected
  binaries/fixtures. The hashes in `inventory.json` are a provisional snapshot,
  not freeze pins.
- [ ] Preserve the unchanged PROOF1 identities:
  - prover: `31fb582d5ec8cfcb028ae7c144f0152acc432f68d5cbfeb4c10e881a00f18db5`
  - verifier: `492e2ea2b2bbc9eef05239407e9f3cbcc39199934b3f3bb02172aba3fd198934`
  - sequencer source: `e6b6fd2e9932909107833579e5b6efd6c75fa0af`
  - proving-utils source: `3035dd00421daa541894297bd754db6e2787807b`
- [ ] Copy or reproducibly rebuild the two binaries before reboot; their current
  paths are under ephemeral `/tmp`.
- [ ] Use explicit tools; do not rely on the old `~/.local/bin` Foundry tools:

```sh
export PATH="/home/broody/.asdf/installs/scarb/2.18.0/bin:/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin:/usr/bin:/home/broody/.cargo/bin:/bin"
SCARB=/home/broody/.asdf/installs/scarb/2.18.0/bin/scarb
SNFORGE=/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin/snforge
SNCAST=/home/broody/.asdf/installs/starknet-foundry/0.63.0/bin/sncast
CLIENT=/home/broody/development/templar/target/m31-append/client-target/release/templar-m31-append
CAIRO_MANIFEST=/home/broody/development/templar/bench/m31-append/cairo/Scarb.toml
```

Recorded versions are Scarb/Cairo 2.18.0, Sierra 1.8.0, snforge/sncast 0.63.0,
and starknet-devnet 0.6.0. Version checks belong in the later execution record;
they were not rerun here.

## 2. Native build and correctness

The checked-in wrapper fixes nightly `2026-01-15`, offline release mode,
`CARGO_TARGET_DIR=target/m31-append/client-target`, and one test thread.

```sh
bench/m31-append/client/build.sh test-build
bench/m31-append/client/build.sh native
bench/m31-append/client/build.sh test
```

Expected from current source: five Rust library tests. Existing
`target/m31-append/build-test.log` records `5 passed`, but rerun only after the
freeze and record a new immutable log; do not treat the mutable log as final.

Fixture/output directories must not already exist. A reproducible synthetic
smoke context already observed in the present fixtures is chain `0x1`, pool
`0x456`:

```sh
RUN_ROOT=/absolute/fresh/result/directory
"$CLIENT" --make-fixtures 0x1 0x456 "$RUN_ROOT/inputs"
"$CLIENT" "$RUN_ROOT/inputs/single-empty-to-one.json" "$RUN_ROOT/single"
"$CLIENT" "$RUN_ROOT/inputs/batch-empty-to-two.json" "$RUN_ROOT/batch"
"$CLIENT" --verify-tests "$RUN_ROOT/single/proof.bin" "$RUN_ROOT/single-negative"
"$CLIENT" --verify-tests "$RUN_ROOT/batch/proof.bin" "$RUN_ROOT/batch-negative"
```

Exact outputs supported by `client/src/main.rs`:

- `--make-fixtures`: five statement JSON files, their five
  `*-transcript.json` files, and `ood-arbitrary.json`.
- fixture proof: `proof.bin`, `proof.json`, `cairo-arguments.json`,
  `cairo-proof.json`, `statement.json`, `public-output.json`, `transcript.json`,
  `ood.json`, and `summary.json`; the summary is also printed to stdout.
- `--verify-tests`: `negative-tests.json`, also printed to stdout. For n=2 the
  report additionally includes `ordered_commitment_swap`; both reports must
  show `omitted_padding_rejected=true` and
  `discarded_multiplicity_rejected=true`.

Acceptance gate: both summaries say `native_verified=true`; proof byte counts
match `proof.bin`; statement/public/transcript files agree; every listed
negative mutation is rejected. This establishes the direct inner S-two native
round trip only.

## 3. Cairo build and direct verification

These package names and entrypoints exist now:

```sh
"$SCARB" --manifest-path "$CAIRO_MANIFEST" build -p templar_m31_append_bridge -p templar_m31_append_ood_probe -p templar_m31_append_transcript_probe
"$SCARB" --manifest-path "$CAIRO_MANIFEST" --profile contract build -p templar_m31_append_statement -p templar_m31_append_pool
"$SCARB" --manifest-path "$CAIRO_MANIFEST" test -p templar_m31_append_bridge
```

The bridge currently has six focused empty-tree tests in source. No final test
result is claimed here. Statement-account and pool contract artifacts are
currently missing and must be pinned after the contract-profile build.

Execute each inner proof with the already length-prefixed argument array:

```sh
"$SCARB" --manifest-path "$CAIRO_MANIFEST" execute --no-build -p templar_m31_append_bridge --arguments-file "$RUN_ROOT/single/cairo-arguments.json" --print-program-output --print-resource-usage
"$SCARB" --manifest-path "$CAIRO_MANIFEST" execute --no-build -p templar_m31_append_bridge --arguments-file "$RUN_ROOT/batch/cairo-arguments.json" --print-program-output --print-resource-usage
```

Expected semantic output: `VerificationOutput.public_values` contains exactly
eight felts and equals the corresponding `public-output.json.public8`. Preserve
stdout, stderr, exit code, resource output, command, tool hashes, executable
hash, and fixture hash. The exact text wrapper produced by `scarb execute` has
not yet been observed for this experiment, so do not hard-code it before the
first untimed correctness run.

### Differential probes (commands supported; extraction files provisional)

For each shape, extract the arrays under `ood.json` into fresh argument files,
then execute the three cases:

```sh
jq '.cairo_arguments' "$RUN_ROOT/single/ood.json" > "$RUN_ROOT/single/ood.args.json"
jq '.cairo_base_mutation_arguments' "$RUN_ROOT/single/ood.json" > "$RUN_ROOT/single/ood-base.args.json"
jq '.cairo_interaction_mutation_arguments' "$RUN_ROOT/single/ood.json" > "$RUN_ROOT/single/ood-interaction.args.json"
"$SCARB" --manifest-path "$CAIRO_MANIFEST" execute --no-build -p templar_m31_append_ood_probe --arguments-file "$RUN_ROOT/single/ood.args.json" --print-program-output --print-resource-usage
```

Repeat the last command for the other two argument files and all three batch
files. Each program output is a QM31 value (four M31 limbs) and must equal,
respectively, `expected_numerator`, `expected_mutated_numerator`, or
`expected_interaction_mutated_numerator`.

For transcript stages 0 through 3:

```sh
jq '.prefix_probe_arguments[0]' "$RUN_ROOT/single/transcript.json" > "$RUN_ROOT/single/transcript-stage-0.args.json"
"$SCARB" --manifest-path "$CAIRO_MANIFEST" execute --no-build -p templar_m31_append_transcript_probe --arguments-file "$RUN_ROOT/single/transcript-stage-0.args.json" --print-program-output --print-resource-usage
```

Repeat for stages 1–3 and for batch. Each output is eight u32 words and must
equal `prefix_checkpoints[stage]`.

Before claiming Cairo correctness, add and execute the required unchanged-proof
mutation matrix from `review.md`. Only the native mutation generator and focused
empty-preprocessing Cairo source tests currently exist; complete Cairo mutation
fixtures/results are a blocker.

## 4. Contract fact-consumption tests

**Blocked/unfinished:** no `local_pool` test files are currently present, so no
test filter or passing `snforge` command can yet be stated. After Astra supplies
and reviews those tests, use the explicit 0.63.0 binary and record the exact
accepted/rejected/atomicity/stale-refresh cases. The eventual command will be of
this form and remains provisional:

```sh
"$SNFORGE" test --manifest-path "$CAIRO_MANIFEST" <reviewed-filter-and-step-budget>
```

Required cases: valid one, valid ordered two, reversed order, replay, stale
root/count, unauthorized/changed commitment, wrong context/program, atomic
rejection, two updates prepared from A with the second rejected after the first,
and successful public regeneration of the second from the new state.

Evidence label: a passing snforge suite that supplies `proof_facts` demonstrates
contract consumption of facts only. It does **not** show that a node validated
or attached the PROOF1.

## 5. Preserved PROOF1 prover and verifier

**Blocked/unfinished:** no frozen statement class/CASM, deployed authenticated
base state, final address/class/program pins, or M31-append PROOF1 request exists.
Do not start the service until those inputs are supplied and the local RPC is
qualified for `starknet_getStorageProof` plus the complete pinned header schema.

The preserved interface from `bench/push-e2e/proving.py` is:

- service environment: `RPC_URL`, `CHAIN_ID`, `PROVER_IP`, `PROVER_PORT`;
- JSON-RPC method: `starknet_proveTransaction`;
- request: `{block_id, transaction}` with an INVOKE v3 to the already deployed
  statement account and calldata `[proof_felt_count, ...proof_felts]`;
- response: base64 `proof`, `proof_facts`, and one L2→L1 message;
- offline verifier command, once a correctly shaped proof directory exists:

```sh
/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/local-verifier /absolute/proof-directory
```

The existing service pattern uses a 16 GiB zero-swap cap, four CPUs, port 31458,
and a 600-second runtime bound. Treat its full systemd/service/request command as
provisional until Astra supplies the final RPC, chain ID, statement address,
class hash, block ID, and public message. A successful handoff must retain the
unchanged binaries, decode `PROOF1`, compare the exact program/public facts and
message payload, verify the binding digest, and record a zero exit status from
the preserved verifier. This is the **original native PROOF1 verifier** evidence
level; the current inner-native smoke summaries do not satisfy it.

## 6. Actual node attachment and local interaction

**Blocked:** the existing probe records that starknet-devnet 0.6.0 returns error
42 for `starknet_getStorageProof`, while the available Katana RPC 0.9 block
header omits commitment/count fields required by the pinned prover. Do not claim
node-level acceptance from direct prover RPC plus offline verification.

If Astra later authorizes and supplies a compatible local node/base state, use
the explicit `SNCAST` 0.63.0 path for local declare/deploy/invoke operations.
No controller CLI, wallet operation, network-chain write, or real key is in
scope. Record separately:

1. the node accepting a transaction with attached PROOF1;
2. the receiving contract consuming runtime-verified facts;
3. resulting root/count/queue state and unchanged state after rejection.

Without item 1, report “full-node proof attachment not demonstrated.”

## 7. Measurements only after all correctness gates

- [ ] No build, test, proof, or other timed workload overlaps a measurement.
- [ ] Fresh process for every sample; preserve failures and cap changes.
- [ ] Native n=1/n=2: one pinned CPU, initial 1 GiB, zero swap, three successful
  runs; separate prove/verify time, RSS, cgroup charge, elapsed time, proof size.
- [ ] Cairo: one run per shape, explicit step budget, 8 GiB cap; record steps,
  builtins, host RSS, and elapsed time.
- [ ] PROOF1: n=1 first, four CPUs, 16 GiB, zero swap; record virtual execution,
  trace/proving/recursion/serialization, then verify in a separate process.
- [ ] Contract: call-level resources only; state whether native verifier cost or
  node-level attachment cost is excluded.

Current smoke `complete_seconds` fields are uncontrolled smoke observations and
must not be promoted to benchmark results.

## Handoff decision

Not ready for execution or measurement handoff yet. The immediate blockers are
the missing freeze, missing statement/pool contract artifacts and tests, missing
Cairo full-proof/differential/mutation results, missing M31-append PROOF1
round-trip, and absent compatible node/base-state support for actual attachment.
