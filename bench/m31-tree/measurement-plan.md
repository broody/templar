# Measurement plan

Recorded before the first measured prover run. All inputs are synthetic and
public. This is a comparison of arithmetic workloads, not a private payment.

## Workloads

- **Preserved felt252 reference:** the completed two-depth-32-path archive in
  `bench/poseidon-membership` and its matching `bench/wasm-membership` port.
  Keep those files and measurements unchanged.
- **Tree only:** two depth-32 paths, including two M31 leaf encodings and 64
  ordered parents. This is 130 permutations, padded to 256 rows. Leaf hashing
  is additional work relative to the old raw-felt leaves.
- **Mixed:** the same M31 tree plus the ordinary 2-input/2-output reference's
  17 felt252 hash calls / 62 Hades permutations. The original one-felt binding
  root remains independent; this does not define a migrated payment ABI.

Keep Blake2s proof commitments, PoW 27, interaction PoW 24, log blowup 3,
23 queries, fold step 4 and last-layer degree log 0. Derive the lifting domain
from the workload's largest trace. Removing unused tables permits a smaller
domain in pure mode; it does not change the configured query count or grinding.
Report the 128-bit application-hash design target separately from the existing
96-bit PCS convenience metric.

## Run sequence

1. Freeze reviewed native/WASM sources, fixtures and executable/module hashes
   after independent Plonky3 vectors and source-level checks pass.
2. Run each native workload in fresh processes on one pinned CPU, with swap
   disabled. Start tree-only at a 1 GiB process-group cap and mixed at 3 GiB.
   Repeat successful runs three times. Record failures and any cap adjustment.
3. Test mixed under a 2 GiB cap. If it passes, repeat in a fresh process before
   interpreting the result; the earlier felt252 reference passed once and
   failed on repetition at that cap.
4. Run real Chrome WASM proofs in one worker: three successive requests in one
   worker and one fresh-browser request. Start tree-only at a 1 GiB group cap,
   mixed at 3 GiB. The browser group receives four CPU cores for runtime tasks;
   the prover remains single-worker. This is not native/browser timing parity.
5. Compare each browser envelope byte-for-byte against its frozen native
   reference and verify exported browser artifacts using the native verifier.
   Run reviewed changed-statement/proof rejection checks in both runtimes.
6. Run Cairo correctness and resource measurements outside the timed prover
   window. Use identical tree/root-history policy, cold/warm state, and append
   batch sizes 1/2/4/8. Include two-felt node, zero and root storage.

No builds, Cairo resource runs, or other prover benchmarks overlap the timed
prover runs. Normal desktop applications may remain open; this is a controlled
process cap on the development host, not a physical consumer-device test.

## Accounting

Native reporting separates function proving time, fresh-process elapsed time,
peak process RSS, and whole-cgroup peak. Browser reporting separates proof-call
latency, initialization, linear-memory capacity/high-water mark, Chrome process
RSS/PSS, and whole browser-plus-harness cgroup charge. Preserve phase samples,
proof bytes, shape/table counts, swap/OOM events and UI heartbeat observations.
WASM linear memory normally stays grown after allocations are freed; stable
warm repeats do not imply a shrinking buffer or a long-lived wallet guarantee.
Repeated deterministic fixtures also repeat their grinding search. Their times
measure runtime stability for that fixture, not the distribution of proof of
work across different payments; retain phase timings and nonce where available.

Cairo reports use pinned local snforge/Cairo resources. Per-entrypoint charges
must be separated from deployment and warm-state setup. Local L2 gas estimates
are not a live Sepolia fee quote, and storage accounting must state whether it
uses distinct touched cells, net state differences, or charged data gas.

If isolated tree savings disappear in mixed mode, report that directly. A
tree-only format migration is not justified by the isolated memory result alone.
Neither result resolves the separate client privacy-construction requirement
or changes the measured cost of the existing fixed-Cairo recursive wrapper.
