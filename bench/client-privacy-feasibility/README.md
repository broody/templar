# Client privacy feasibility

2026-09-21. Follow-up to the public [browser membership benchmark](../wasm-membership/README.md).

The source review did **not establish a supported compact client privacy
construction**. The pinned and current upstream code provide a concrete fixed
Cairo privacy workflow. Their circuit blinding helper is not a documented
drop-in masking mode for the direct Poseidon AIR. The reviewed helper remains
unchanged in the current monorepo; upgrading dependencies alone does not close
this gap. This is an applicability and evidence limitation, not a demonstration
that the upstream fixed workflow fails privacy.

The [review](review.md) records the exact revisions, construction boundaries,
and next prerequisites. The [integration inventory](integration-plan.md)
describes the additional work required to verify a custom AIR inside a circuit.
In particular, native host checks over public Merkle paths would need to become
constraints before those paths could be private witnesses. Merely recursively
verifying the current public STARK would not prove that complete relation.

## Cost experiment

The narrowly scoped experiment isolates the **existing fixed Cairo privacy
recursion** in a fresh native process. A public synthetic Cairo PIE is proved
locally once and its typed proof plus output preimage are checkpointed. A new
process loads that checkpoint, rebuilds the exact fixed verifier circuit and
preprocessing, performs the unchanged upstream blinding/proving workflow, and
serializes PROOF1. The checkpoint is synthetic local measurement input, not a
proposed server payload.

The protocol, trusted roots, parameters, transcript, seed derivation and output
binding remain unchanged. The storage mode is the previously reviewed
coefficient-backed implementation with 16-column FRI batches. The specialist
owns the isolated source extraction; the math reviewer checks its equivalence.
Earlier archives and their dependency trees remain unchanged.

Whole-process measurement includes checkpoint deserialization, fresh twiddles,
topology and context construction, blinding, fixed preprocessing, recursive
proving and final serialization. An independent verification process is measured
separately. RSS and cgroup charge are reported separately. Fresh process means
fresh allocations, not a flushed operating-system disk cache.

The [cost inventory](cost-plan.md) explains why earlier recursion-stage RSS
included allocation history from Cairo proving. Stage peaks cannot be added or
subtracted to obtain a private-client budget. Nor can a native wrapper peak be
added to a WASM membership peak to predict a browser's total.

The split passed source review and exact proof parity. **The existing wrapper
alone fails a 4 GiB cap with either one or four workers.** No measured result in
this experiment qualifies a new privacy construction, full private payment,
browser port, or physical consumer machine.

## Measured results

Each row is one fresh process on the same development host, with no swap,
native CPU instructions and the existing bounded16 storage mode. Cap and
CPU/Rayon worker counts are enforced by the recorded systemd invocation.
Wall time includes launch, measured work and teardown; verification is separate.
These are individual observations, not latency distributions.

| Workload | Workers | Cap GiB | Peak RSS GiB | Peak cgroup GiB | Wall seconds | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Synthetic Cairo checkpoint preparation | 4 | 8 | 4.989 | 4.954 | 12.01 | Pass |
| Same fixture, unsplit complete proof pipeline | 4 | 8 | 5.209 | 5.171 | 20.95 | Pass |
| Fresh recursive wrapper only | 4 | 8 | 4.782 | 4.757 | 11.50 | Pass |
| Fresh recursive wrapper only | 1 | 8 | 4.587 | 4.561 | 35.17 | Pass |
| Fresh recursive wrapper only | 4 | 4 | — | 4.000 | 3.25 to termination | OOM |
| Fresh recursive wrapper only | 1 | 4 | — | 4.000 | 8.23 to termination | OOM |

The two failed runs reached recursive proving after circuit construction and
preprocessing. Their logs do not resolve the precise allocation within proving.
Both record one OOM kill and zero swap. Because the 4 GiB cap fails in both
worker configurations, a lower-cap run of this unchanged implementation would
not advance the client-budget decision.

The harness's internal time through artifact writing is 11.42 seconds for
preparation, 20.28 for unsplit, 11.03 for the four-worker wrapper and 34.70 for
the one-worker wrapper. The separate original-library verifier plus three
mutation controls takes 0.44–0.48 seconds per completed artifact, outside the
prover cap/timing. The synthetic checkpoint is 998,918 bytes; final PROOF1 is
235,734 bytes. See [full measurements](results/measurements.json), per-run
commands/logs/resource samples under `results/`, and [host identity](results/host.json).

Removing earlier-stage allocation history helps, but does not bring this fixed
wrapper near the sub-2-GiB engineering target. The native result also motivates
reducing its footprint before investing in a WASM port. It is not a wasm32
lower bound: pointer sizes, allocation behavior and browser accounting differ.
It is likewise not a lower bound for a different compact verifier topology or
a supported directly private AIR.

## Validation and identities

All three completed final proofs—unsplit, four-worker split and one-worker
split—are byte-identical, with matching public output preimages. The preserved
original verifier executable accepts the unchanged artifact. Its legacy test
adapter then fails because it doubles a zero-valued final fact, leaving that
particular control unchanged. This is recorded explicitly, not counted as a
passing mutation suite.

A separately reviewed adapter changes only the two public-field mutations to
addition of one and links the preserved original verifier libraries; no
verifier library is rebuilt or changed. It accepts each of the three outputs
and rejects a changed final public fact, changed program hash and corrupted
proof bytes: nine rejection executions across three identical artifacts. Its
source, build command and original library hashes are archived. Three release
checkpoint-format tests also pass.

| Artifact | SHA256 |
| --- | --- |
| Frozen wrapper executable | `86073d1ee5b6dfae0264aeddedb5e12d17215aa51480a70a03810f5ef8630b0c` |
| Local synthetic checkpoint | `81500ea26cf4ab0ae8f53fe2a1975b8e09522c0f8cbd31bcea5acb702f54d43a` |
| Every completed final proof | `9326c1eaad137c1b865b417b36d041928b1e5d9ec15b363662f0535eed868153` |
| Preserved original verifier executable | `492e2ea2b2bbc9eef05239407e9f3cbcc39199934b3f3bb02172aba3fd198934` |
| Addition-of-one test adapter executable | `b8658ac824cbfe38edd45b35c35d469c5239662a9c305d57713b2dde01b86a28` |

See the [harness reproduction guide](client/README.md). Exact capped commands
are in each run's `command.json`. Run `build_verifier_adapter.py` before
`verify_results.py`; the latter takes `--reference <unsplit-output-directory>`
followed by completed output directories. The independent verifier tests run
after resource measurement. Reproduction uses the frozen original source trees
and scoped compiler/runtime paths recorded in the build metadata. This archive
does not claim standalone portability to a clean machine without those inputs.

## Decision required for compact private proving

Before implementing a new private statement, identify a versioned upstream or
independently reviewed hiding construction whose applicability covers the actual
circuit/AIR family, topology, randomness and all exported information. Then
review the complete payment relation and public output binding, and measure
the full local pipeline. The earlier disclosure/recovery diagnostic remains
deferred; no such diagnostic or new masking construction is part of this work.

The evidence needed for that decision is concrete:

- Which exact source revision and supported circuit family the hiding argument
  covers, including commitment openings, out-of-domain evaluations, lookup
  interactions, FRI and the randomness policy.
- Which values and shape information may be public, and whether the fixed
  topology covers ordinary, controlled and return-note payment statements.
- How all private validity checks are constrained: ownership, membership,
  nullifiers, per-asset conservation, output commitments and delivery bindings,
  controller/return conditions and chain/pool/version/intent binding.
- What the remote wrapper receives and verifies. It may package and bind public
  state, but it must not receive a raw non-private inner proof or become trusted
  to enforce private validity rules.

Closing these questions would remove a major architecture risk. It would still
leave implementation review, full client measurements, recursive integration,
consumer-device qualification and production audit.

No wallet keys, live notes, chain transactions or external messages are used.
