# Browser membership measurements

2026-09-21. Public synthetic two-path membership only. The experiment does not
prove hidden paths, ownership, nullifiers, conservation, output delivery or a
complete private payment. It does not produce PROOF1.

## Results

| Browser process-group cap | Worker state | Prove + verify | WASM linear-memory capacity | Outcome |
| --- | --- | ---: | ---: | --- |
| 8 GiB | Fresh module, proof 1 | 41.719895 s | 2.149963 GiB | Pass |
| 8 GiB | Same module, proof 2 | 41.182520 s | 2.149963 GiB | Pass |
| 8 GiB | Same module, proof 3 | 40.931450 s | 2.149963 GiB | Pass |
| 4 GiB | Fresh browser/module, proof 1 | 41.774450 s | 2.149963 GiB | Pass |

The timed call performs public fixture regeneration, preprocessing, witness
construction, proving, serialization and verification. It excludes module
import/initialization, returning proof bytes to JavaScript, local artifact
upload and the subsequent rejection checks. It is not directly interchangeable
with the earlier native external-harness timer. Module initialization and local
fixture/reference loading are reported separately, not as a network-download
benchmark. All measured runs were exclusive of compilation.

| Whole browser experiment | 3 proofs, 8 GiB cap | Fresh proof, 4 GiB cap |
| --- | ---: | ---: |
| Peak cgroup charge, browser + Node/server harness | 2.226433 GiB | 2.205582 GiB |
| Sampled sum of Chrome-process PSS | 2.194677 GiB | 2.186101 GiB |
| Sampled sum of Chrome-process RSS (includes shared-page double counting) | 2.829006 GiB | 2.815090 GiB |
| Complete Chrome memory samples | 235 / 235 | 84 / 84 |
| Maximum interval of 100 ms page heartbeat | 120.785 ms | 103.680 ms |
| Swap / OOM kills | 0 / 0 | 0 / 0 |

Linear memory grew to 2,308,505,600 bytes and did not grow further during the
same-worker repeats or rejection checks. This is allocated linear-memory
capacity, not live Rust allocation size or physical resident memory. WASM
memory does not shrink when the Rust result is freed; stable capacity shows
reuse across these three calls, not a general absence of leaks.

The Linux cgroup peak is taken from observed `memory.peak` and the final systemd
property, preserving both and using the largest available observation. Final
systemd properties were unavailable in the two successful runs. Chrome PSS/RSS
are sampled about every 500 ms, cover CDP-reported processes, and can miss short
peaks; cgroup sampling is about every 25 ms. These scopes are intentionally
separate. GNU time's child accounting does not reliably encompass Chrome's
process tree here and is not used as the browser peak.

## Correctness and unchanged settings

All four browser envelopes match the archived native envelope byte-for-byte:

`7883c50e7125e608365e7887b50df589ac57bcc91438fe2f1f660caf56a9631e`.

The complete envelope is 334,307 bytes; the STARK itself is 258,621 bytes.
Each proof passed the verifier compiled into WASM. Both browser experiments
also rejected the existing 13 altered-proof/statement cases and passed the
three lookup boundary controls. The preserved native executable imported one
browser envelope, accepted it, and passed those same checks. The four exported
envelopes are one unique artifact, so that native cross-check was not repeated
for identical bytes. See `native-cross-check/command.json` and its output.

The refactored client also builds natively and passes all three release unit
tests. One complete proof from its shared native core verifies and matches
the same preserved envelope. That run is regression validation, not a new
performance sample; see `port-native-parity/validation.json`.

The relation remains two depth-32 paths: 64 parent hashes, 128 Hades
permutations, 126 distinct requests, 128 padded aggregator rows and 768 public
memory lookup terms. Field arithmetic, AIR, lookup closure, transcript,
serialization and the trusted preprocessing definition are unchanged.

The channel is ordinary Blake2s. Parameters remain PoW 27, FRI blowup log 3,
23 queries, fold step 4, last-layer log degree 0, lifting log 23, and interaction
PoW 24. The implementation's convenience metric is 96 bits; this is not an
independent security theorem. Coefficient-backed storage and FRI batches of
16 remain enabled; the latter is not a global 16-column memory bound.

The raw core summary retains a historical `native_verify_seconds` phase key;
for these browser runs it describes the verifier compiled into WASM. The
explicit fields correctly state `execution_target: wasm32`,
`proof_verified_in_runtime: true`, and `native_proof_verified: false`. The
external native acceptance is recorded separately. The inherited scope string
also predates this browser experiment; it does not override the bounded
runtime evidence described here.

## Port and host

- Chrome 153.0.8010.47, headless Linux, one module worker with non-shared memory.
- `wasm32-unknown-unknown`, nightly 2026-01-15, `simd128`, 8 MiB stack,
  4 GiB declared maximum linear memory, wasm-bindgen 0.2.128.
- Emitted WASM: 11,223,495 bytes; SHA-256
  `9e84a321253f36e41930024b9fd0e07ac8f6bb9efcf6b4f939472d31bfcf117f`.
- Current i9-10980XE / 128 GiB-class development host. The browser and harness
  shared a four-core CPU allowance; proving itself used one worker.
- No arithmetic dependency changes. The copied Cairo witness source only
  bypasses its private native thread pool on WASM, executing the same work
  through a one-thread/current-thread Rayon pool. Time, phase reporting and
  fixture/proof IO use platform adapters.

The user-provided Fibonacci demo supplied useful WASM loading conventions.
It has a different historical backend, workload and proof configuration and
is not a resource estimate for this benchmark. See `../demo-reference.md`.

One initial harness attempt stopped before loading the page because this
Chrome launch did not expose `Browser.getBrowserCommandLine`. Reading the
isolated browser process command line supplied the metadata instead. The
failed launch is retained as `chrome-three-runs-8g`; it is not a prover or
memory failure and no proof settings changed to resolve it.

## Decision and remaining uncertainty

The WASM/browser portability milestone passes. The existing public arithmetic
works beyond 2 GiB; the earlier native 2 GiB cgroup OOM was not evidence of an
universal browser cutoff. The engineering target of substantial headroom below
2 GiB remains unmet.

The current source review identifies no turnkey reviewed privacy mode for this
reused Poseidon AIR. A client-local privacy wrapper would need a supported
construction, a verifier for this exact statement, and its own measured cost.
Server wrapping cannot supply privacy for data already sent to that server.
This experiment adds no privacy construction or disclosure diagnostics.

Before extending to full payment features, establish that complete client route.
Fixed range-check table cost and simultaneous expansion remain the principal
memory leads. Preserve the native payment architecture as the reference.
Consumer hardware, non-headless wallet integration, Firefox/Safari, mobile,
worker cancellation, complete private payments and PROOF1 wrapping are untested.
