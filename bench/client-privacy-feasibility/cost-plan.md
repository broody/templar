# Client recursion cost inventory and next experiment

Source and archived-result inspection, 2026-09-21. No builds, new proving runs,
or prover edits were performed for this inventory. Earlier archives remain
unchanged. The deferred `bench/direct-air/client` diagnostic was not run.

The next useful experiment is a **fresh-process replay of the unchanged fixed
Cairo recursion stage**, using a public synthetic execution fixture. It can
measure the cost of the existing supported workflow without designing a new
AIR, masking scheme, or verifier. The Math Reviewer approved this narrow cost
scope: preserve the exact fixed topology, parameters, seed handling and existing
blinding call; keep the inner proof local; compare final output bytes against
the unsplit path and use the preserved verifier. This is not qualification of
an arbitrary circuit or of a compact private membership construction.

## What the existing measurements establish

The accepted native path is sequential:

1. Virtual OS execution produces a Cairo PIE.
2. The privacy bootloader runs, then the Cairo execution proof is generated.
3. That proof is converted into a fixed Cairo-verifier circuit assignment;
   existing blinding/finalization runs locally.
4. The circuit execution is proved, serialized and compressed into PROOF1.

The phase-local implementation releases the Cairo tree/pool before preparing
recursion, and drops the typed Cairo proof after constructing the circuit
assignment. Twiddles survive both stages. The circuit context and its values
remain alive while recursion is proved. Native allocators can retain freed
pages, so a sampled RSS value during stage 4 still includes the process's prior
allocation history. See
[low_memory.rs](/home/broody/development/templar/target/bounded-memory/proving-utils/crates/privacy_prove/src/low_memory.rs).

From the preserved [bounded-memory summary](/home/broody/development/templar/bench/bounded-memory/results/summary.json):

| Archived run | Whole-process RSS peak GiB | Sampled Cairo-window RSS GiB | Sampled recursion-window RSS GiB | Both proof stages, seconds |
| --- | ---: | ---: | ---: | --- |
| Ordinary, fresh bounded run | 5.686 | 5.519 | 5.650 | 23.065 |
| Ordinary, three bounded repeats | 6.120 | 5.973 | 6.087 | 22.688–23.084 |
| Controlled, three bounded repeats | 5.910 | 5.787 | 5.811 | 22.817–23.234 |
| ReturnNote, three bounded repeats | 5.836 | 5.825 | 5.789 | 22.734–22.782 |
| Synthetic 8/8/4, three bounded repeats | 6.311 | 6.255 | 6.267 | 23.405–23.917 |

These are four-core native measurements on the larger development machine,
with no swap. Stage columns are sampling windows in a shared process, not
isolated stage peaks and not incremental memory. They must not be added.
All three repeated proofs per workload passed the 8 GiB service cap. The
ordinary 4 GiB run failed while expanding the Cairo base trace before Merkle
hashing, so that failure says nothing conclusive about an isolated wrapper's
minimum cap. Historical ordinary/controlled/return fixtures are previously
funded-flow replays; use the public synthetic PIE below for new work.

Subtracting timestamps from the existing
[fresh ordinary log](/home/broody/development/templar/bench/bounded-memory/results/ordinary-bounded-12g/prover.log)
gives the following phase observations, rather than new timings:

| Logged interval | Seconds |
| --- | ---: |
| Cairo stage preparation through Cairo pool release | 12.830 |
| Cairo proving call through pool release, excluding stage preparation | 12.487 |
| Proof conversion, context construction, validity check, existing blinding and finalization | 0.294 |
| Recursive stage preparation through recursive pool release | 9.735 |
| Recursive proving call through pool release, excluding stage preparation | 8.814 |
| Recursive pool release through proving-complete log | 0.013 |

The separately logged virtual OS execution was 0.525 seconds. Bootloader work,
shared twiddle preparation, small gaps and rounding explain why these intervals
are not an exhaustive breakdown of the 23.065-second proving duration. The
three-repeat log puts recursion preparation plus proof at 9.598–9.714 seconds.
A standalone recursion process must also pay for its own twiddles and loading,
so 9.7 seconds is context for the next experiment, not its predicted latency.

For comparison, the separate public membership
[browser experiment](/home/broody/development/templar/bench/wasm-membership/README.md)
measures 40.93–41.72 seconds per proof and verification with 2.150 GiB linear
memory, with a fresh 4 GiB process-group run at 41.77 seconds. It has a different
AIR and ordinary Blake2s channel. Its proof cannot simply be supplied to the
existing fixed Cairo verifier, and its memory must not be added to a native
wrapper RSS value to estimate a browser total.

## Fixed circuit shape and storage costs

Pinned bases are S-two `489a0f3ee44a59e03944ad9aa4f3e5a91a3d3f08`, stwo-cairo
`9b6be2710e4d7124bc93fe80a5af36556d42ed29`, stwo-circuits
`5ef951a12727e3489a2ee991c580a5b925c59c69`, and proving-utils
`3035dd00421daa541894297bd754db6e2787807b`. The bounded snapshots add recorded
storage/allocation patches; these hashes name their upstream bases.

The accepted [constants](/home/broody/development/templar/target/bounded-memory/proving-utils/crates/privacy_circuit_verify/src/consts.rs)
fix the Cairo proof at log trace 20, 8× blowup, PoW 27, 23 queries, fold 4,
last-layer log 0, lifting 23. The recursive circuit uses log trace 21, 4×
blowup, PoW 26, 35 queries, fold 4, last-layer log 0, lifting 23. Both use
Blake2sM31. Interaction PoW is 24 for Cairo and 20 for the circuit. The circuit
has two output values plus the reserved `u` anchor, fixed output addresses
`[3,4,2]`, and a pinned preprocessed root and 45 preprocessed columns.

The five gate families and six fixed table components below are always included
by [to_component_provers](/home/broody/development/templar/target/bounded-memory/stwo-circuits/crates/circuit_prover/src/prover.rs:37).
Gate log sizes come from the accepted preprocessing constants; trace and
interaction widths come from the corresponding
[component AIR files](/home/broody/development/templar/target/bounded-memory/stwo-circuits/crates/circuit_prover/src/circuit_air/components).
Interaction widths here count base M31 coordinates.

| Component | Log rows | Preprocessed columns | Trace columns | Interaction columns | All three at 4×, MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Eq | 17 | 2 | 4 | 4 | 20 |
| QM31 operations | 21 | 8 | 12 | 8 | 896 |
| Triple XOR | 17 | 5 | 20 | 24 | 98 |
| M31-to-u32 | 18 | 3 | 4 | 12 | 76 |
| Blake G gate | 20 | 11 | 52 | 52 | 1,840 |
| XOR 4 | 8 | 3 | 1 | 4 | 0.03125 |
| XOR 7 | 14 | 3 | 1 | 4 | 2 |
| XOR 8 | 16 | 3 | 2 | 4 | 9 |
| XOR 9 | 18 | 3 | 1 | 4 | 32 |
| XOR 12 | 20 | 3 | 16 | 32 | 816 |
| Range-check 16 | 16 | 1 | 1 | 4 | 6 |
| **Total** | | **45** | | | **3,795.03125** |

The formula is `2^log_rows × (P + T + I) × 4 bytes × 4 blowup`. The XOR-12
component uses a log-20 XOR-10 table with expanded multiplicity columns; its name
does not imply a log-24 table. The combined base-domain values are 948.7578125
MiB. Fully expanded preprocessing, base trace and interaction trees are
522.76171875, 1,543.25390625 and 1,729.015625 MiB respectively.

These totals describe logical arrays if simultaneously retained, not bounded
mode's peak or an RSS lower bound. The current mode retains coefficients and
expands one full tree at commitment/opening, with component-sized composition
work and 16-column FRI regeneration. It also needs Merkle/FRI buffers, context
values and topology, twiddles, lookup buffers and serialization copies.

Even a tiny arithmetic circuit pays for the fixed tables in
[add_fixed_preprocessed_columns](/home/broody/development/templar/target/bounded-memory/stwo-circuits/crates/circuit_common/src/preprocessed.rs:378):
the six fixed components alone account for 216.2578125 MiB of base M31 arrays,
or 865.03125 MiB at 4×. `PreprocessedCircuit` also stores columns as `Vec<usize>`:
all accepted topology columns contain 261.380859375 MiB of native 64-bit `usize`
cells before conversion to M31; the corresponding wasm32 cells are half that
size. This distinction affects porting costs, not proof semantics. No general
browser footprint can be inferred from it.

## Candidate probes and the exact fixture

The smallest convenient benign circuit smoke tests already exist in
[prover_test.rs](/home/broody/development/templar/target/bounded-memory/stwo-circuits/crates/circuit_prover/src/prover_test.rs):
`test_prove_and_stark_verify_permutation_context` uses two public constants;
the Fibonacci test uses 1,030 recurrence values; Blake, XOR and conversion tests
exercise the supported gate families. They use `PcsConfig::default()` and are
useful for compilation/portability smoke tests only. They neither measure the
fixed Cairo-verifier topology nor establish the cost of its blinding path.
Given the fixed-table cost, they are not the highest-value next performance run.

Use this existing public synthetic fixture for the exact workflow:

- [privacy_tx_cairo_pie.zip](/home/broody/development/templar/target/bounded-memory/proving-utils/crates/privacy_prove/test_data/privacy_tx_cairo_pie.zip),
  669,569 bytes, SHA-256
  `9e193692b3f2f26a21dd04f11ca5b44cfb618fdf49d8a042d2030d3c2f9ba354`.
- It is already exercised by
  [test_privacy_recursive_prove_and_verify](/home/broody/development/templar/target/bounded-memory/proving-utils/crates/privacy_prove/src/tests.rs:25)
  behind the existing `slow-tests` feature.
- The existing combined benchmark binary is
  [low-memory-prover](/home/broody/development/templar/target/bounded-memory/bin/low-memory-prover),
  SHA-256 `8eaa1763abd7216f43fff2a935a3646e5643f55763236b41885ee77f5286d471`.
  It has no standalone recursion CLI. Its prior independent verifier is
  [local-verifier](/tmp/templar-stwo-privacy-dtgn6e8l/sepolia-v1-test/local-verifier),
  SHA-256 `492e2ea2b2bbc9eef05239407e9f3cbcc39199934b3f3bb02172aba3fd198934`.

Do **not** use `stwo-circuits/test_data/privacy/proof.bin` as an accepted fixed
wrapper input. Its associated compiled bootloader has 1,169 words, whereas the
accepted proving-utils bootloader has 2,597 different words. The upstream
generic test derives a verifier from that proof and uses default recursive
parameters; it does not establish compatibility with the accepted fixed root.

No matching typed inner Cairo proof plus output-preimage checkpoint was found in
the inspected previous archives. Their accepted `proof.bin` files are final
PROOF1 artifacts, which do not supply that intermediate input. The shortest
preparation is therefore a synthetic-only checkpoint in a **fresh copied**
version of the existing flow, immediately after generating the Cairo proof.
Keep the full typed `CairoProof<Blake2sM31MerkleHasher>` and matching
`Vec<Felt>` output preimage. Existing
[binary serde helpers](/home/broody/development/templar/target/bounded-memory/stwo-cairo/stwo_cairo_prover/crates/cairo-air/src/utils.rs:65)
serialize via bincode and bzip2; their deserialize buffer and codec costs belong
in the fresh wrapper process budget. The helper
`run_privacy_bootloader` is private to `privacy_prove`, so this checkpoint belongs
in the isolated copy of that crate rather than a replacement cryptographic path.

## Concrete staged experiment

1. **Prepare and establish parity.** Run the existing synthetic PIE through the
   accepted bootloader and Cairo parameters, save the typed checkpoint locally,
   and finish the unsplit flow once. Record source/binary/input hashes, final
   proof/output and preserved verifier acceptance. The checkpoint is not a server
   payload. No keys or actual notes are needed.
2. **Cold wrapper process.** Start a fresh native process under a no-swap cgroup.
   Include checkpoint loading/deserialization, trusted configuration and topology
   construction, twiddles, proof-to-context conversion, validity checking,
   unchanged seed extraction/blinding/finalization, circuit preprocessing/tree,
   bounded recursive proving, serialization/compression and local verification.
   Do not preload a Cairo-stage pool or call the combined precompute function,
   which constructs both stages' caches.
3. **Validate the split.** Require the split output to match the unsplit final
   bytes and output preimage, the pinned preprocessing root/column layout to
   match, and the preserved independent verifier to accept. Keep per-phase times,
   RSS, cgroup high-water/OOM/swap counters, and process start-to-finish time.
   Time any verifier outside the cgroup separately and label that exclusion.
4. **Find a useful cap.** Establish one successful wrapper-only baseline, then
   probe 4 GiB and the desired lower client cap, one process at a time. Record
   failures at their last phase; do not shrink the fixed circuit or parameters.
   A one-worker native run is the relevant next bridge toward browser work.
5. **Port only after sizing.** The wrapper's in-memory core can then reuse the
   established Worker/wasm-bindgen measurement approach. Preserve ordinary
   arithmetic and reviewed single-thread scheduling; test actual WASM output
   against the native output. This step is not accomplished by compiling the
   existing native service.

For sequential client stages, elapsed time adds, but memory is
`max_t(total live client memory at t)`, including the retained handoff artifact,
serialization overlap and runtime caches. It is **not** the sum of independent
stage peaks. A shared WASM instance can reuse freed allocations but its linear
memory does not shrink; repeated runs must measure retained capacity. Separate
Workers allow teardown between stages, but the parent-held proof and transfer
copies remain part of the browser budget. Measure the entire browser process
group as well as each instance's linear-memory high-water mark.

The native bootloader currently uses temporary files and Cairo VM execution;
the proof checkpoint avoids those in the wrapper-only probe, not in a future
complete client. Circuit witness generation additionally uses structured Rayon
scopes, lookup buffers, native-width address vectors, and portable SIMD. These
need target-specific compilation and execution checks. Merely passing this cost
probe would establish the price of the supported fixed Cairo workflow on this
host; a supported client privacy route, the complete payment relation, and
consumer-device/browser qualification remain separate prerequisites.
