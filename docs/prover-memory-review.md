# Proving memory: desktop first, browser path preserved

2026-09-21. Active engineering priority. This is a measured implementation
experiment under [ADR-0018](adr/0018-stwo-private-proving.md), not a change to
proof security, note semantics, or supported settlement capacity.

The [coefficient-backed experiment](../bench/bounded-memory/README.md) builds on
the [stage-local allocation patch](../bench/prover-memory/README.md) and
[Cairo commitment experiment](../bench/cairo-memory/README.md). All target the
exact V1 privacy pipeline used by Templar's Sepolia references. Native desktop proving remains the immediate target;
**browser/WASM proving is a strategic target, not a current release gate**.

## Budgets and decisions

| Target | Working prover budget | Qualification still required |
| --- | --- | --- |
| 16 GiB desktop | 8 GiB cap, zero swap | Physical consumer machine, wallet plus browser/OS headroom, CPU portability |
| 8 GiB desktop | 4 GiB cap, zero swap | Establish feasibility before promising support |
| Future browser | Aim below 2 GiB live proving memory | Actual linear-memory high-water mark, browser process memory, repeated runs, UI responsiveness and cancellation |

These are engineering targets, not measured minimum hardware requirements. A
cgroup cap on the current 128 GiB-class host does not qualify a smaller machine.

The current experiment uses four proving threads and coefficient-backed storage
in both proving stages. Retaining coefficients allows expanded evaluations to
be discarded and regenerated as needed. Do not reduce blinding, FRI queries, blowup factors, proof-of-work,
verifier identities, or statement checks to meet a device budget.

## Compact client proof pathfinding

The separate [compact-proof experiment](../bench/direct-air/README.md) explores
moving private validity checks into a small client proof and proving its
verification on a server. This is not an adopted architecture change. A server
must receive an already-private proof; wrapping it afterward cannot supply the
missing client privacy boundary.

The synthetic Rust-to-Cairo compatibility step passes: two saved proofs return
the expected commitment, nine altered inputs are rejected, and four focused
serialization/transcript tests pass. Cairo VM verification uses 0.77–0.78 GiB RSS
and 2.03–2.12 seconds. It does not yet produce native PROOF1. The compiled
statement account needs to be made available in authenticated state supported
by the pinned proving service, which has no local state-override argument.

The tiny client baseline was OOM-killed under a 2 GiB cap and completed at
2.61 GiB RSS under an 8 GiB cap. It still carries large upstream lookup tables
and uses baseline allocations, so this is not a lower bound for a custom AIR.
The client privacy prerequisite has not passed; further disclosure diagnostics
are deferred. A real 2-input/2-output depth-32 payment, full server wrapping,
single/four-thread comparison and full private-client WASM remain unmeasured.
The existing memory results below remain the reference for actual payment proving.

The next [public membership benchmark](../bench/poseidon-membership/README.md)
does prove the real felt252/Poseidon arithmetic for two depth-32 paths, without
Cairo CPU/OS execution: 64 parent hashes and 128 permutations. The paths and
intermediate states are intentionally public. Native verification checks their
bookkeeping and binds every requested permutation to the original upstream AIR.
This isolates substantial arithmetic cost without claiming a private payment.

On one core, the baseline peaks at 4.28 GiB. Reusing coefficient-backed storage
and 16-column FRI batching reduces the peak to about 1.97 GiB, with identical
proof bytes. Three fresh runs pass a 3 GiB cap at 14.08–14.14 seconds, versus
8.67 seconds for the matched baseline. The 2 GiB cap passes once and then OOMs
on a fresh repeat, so it is unreliable. All eight completed proofs verify and
are byte-identical; three unit tests and the 13 verifier/three boundary checks
pass. Fixed range-check tables remain a material cost even without the VM.

This does not meet the substantial sub-2-GiB headroom criterion. Further work
should isolate table size and simultaneous expansion before adding full payment
logic; a supported client privacy route is still required. Public-path proving,
the earlier generic circuit probe, and Cairo verification have different
workloads and must not be presented as interchangeable memory measurements.

The [browser membership port](../bench/wasm-membership/README.md) now generates
and verifies four proofs in headless Chrome 153, all exactly equal to the
preserved native envelope. Three successive proofs in one worker take
40.93–41.72 seconds each; a fresh browser under a 4 GiB process-group cap takes
41.77 seconds. WASM linear-memory capacity grows to 2.150 GiB and stays there
across the warm repeats. Browser plus harness cgroup charge peaks at
2.21–2.23 GiB, with zero swap or OOM; those are distinct memory metrics.
The page heartbeat remains active, the browser rejection checks pass, and the
preserved native verifier accepts exported browser bytes.

This passes public arithmetic's browser portability milestone and demonstrates
that 2 GiB is not a universal browser cutoff. It does not meet the sub-2-GiB
engineering target or qualify full private payments, physical consumer hardware,
other browsers or mobile. The existing AIR and proof settings are unchanged;
only CLI/runtime adapters and WASM thread-pool scheduling changed in an isolated
copy. Before extending payment features, establish a supported reviewed client
privacy construction and measure its full cost. The native payment architecture
remains the reference.

## M31 tree hash pathfinding

The [M31 tree experiment](../bench/m31-tree/README.md) asks the follow-up
question directly: does replacing felt252 Merkle hashing with pinned Plonky3
Poseidon2-M31 (width 24, 8 full / 22 partial rounds, two-felt digest encoding)
materially reduce client resources, and at what contract cost? All inputs are
public and synthetic; this is a hash-workload comparison, not a payment proof.

For the isolated public two-depth-32-path tree, the answer is strongly positive.
The native proof completes in **0.480–0.491 seconds with 0.017 GiB peak RSS**
under a 1 GiB cap (three fresh runs, identical bytes), versus the felt252
baseline's 14.08–14.14 seconds and 1.97 GiB. The pure-M31 table drops the large
fixed felt252 range-check tables (lifting log 11 vs a much larger mixed domain).
In headless Chrome the same proof takes **4.19–4.28 seconds** with a WASM
linear-memory high-water of only **19.75 MiB** (browser+harness cgroup ≤ 0.314 GiB)
— far below the felt252 port's 2.150 GiB.

The mixed union workload (the M31 tree plus the ordinary reference's 17 felt252
hash calls / 62 permutations) tells the opposite story for the fixed tables:
native **16.11–16.35 seconds at 1.899 GiB RSS** (passing 3 GiB and, in a fresh
probe, 2 GiB caps), and browser **75.8–77.2 seconds with 1.900 GiB linear memory**
and ≤ 2.168 GiB whole-browser cgroup. Contract cost is also adverse: the
straightforward Cairo M31 tree's warm single-append measures **787.6M L2 gas**
locally versus 5.12M for the felt tree (~154×; cold single 1,571M vs 8.0M);
batch-8 cells failed at the 8 GiB local VM cap and passed at 16 GiB (the passing
cap is not a measured minimum). These are local VM
resources, not fee quotes.

**Decision: no tree-only hash migration.** The isolated saving does not survive
the mixed workload's retained felt252 tables or the contract penalty. The result
is still promising evidence for M31-native client arithmetic. Recommended order:
resolve the supported client privacy construction and full constrained statement
first; then investigate removing the remaining felt252 table overhead — a
separately reviewed smaller-table AIR preserving the hashes, or a broader hash
redesign only with a viable contract-cost plan. Neither is implemented or
approved. The mixed binding keeps its independent one-felt root; no ABI,
protocol, or live-pool change follows. Evidence: [measurements](../bench/m31-tree/results/measurements.md),
including 6 native unit tests, 36 Cairo correctness tests, 16 measured cost
cells, mode-specific rejection checks and byte parity.

## Public append proof integration

The [M31 append experiment](../bench/m31-append/README.md) tests moving tree
updates into a public direct-AIR proof, verifying that proof in Cairo, and
settling its bound root through the unchanged PROOF1 route. The one/two-append
client proofs use about **17–31 MiB RSS** and **192,143/223,098 bytes**. Five
public scenarios verify natively, including a query-collision regression that
also passes complete Cairo verification. This remains public arithmetic
pathfinding; it provides no private-payment or browser qualification.

The [outer attempt](../bench/m31-append/results/outer/summary.md) passes virtual
OS execution at **8,062,701 Cairo steps**, then stops during Cairo proof
generation. A 16 GiB server cap OOMs. With a 64 GiB cap, the process reaches
**29.27 GiB RSS** and panics with `Not enough twiddles!`. The pinned prover and
recursive verifier have fixed domain parameters; more RAM or a larger twiddle
allocation alone does not establish unchanged-verifier compatibility. The
exact oversized component has not been profiled, and trace rows are not a
universal VM instruction-count limit.

No genuine outer proof was produced, so original outer verification and local
contract settlement tests remain unexecuted. The next integration gate is to
profile and reduce the verifier's largest trace components to fit the preserved
capacity, or explicitly evaluate another supported outer route. These failed
server-run peaks are separate from the small public client measurements and
from the earlier 4.59–4.78 GiB isolated fixed-wrapper benchmark. No live protocol
or note format changes follow from this result.

## Client privacy construction and wrapper

The [client privacy feasibility review](../bench/client-privacy-feasibility/README.md)
inspected both the pinned sources and current upstream monorepo. It found a
concrete fixed-Cairo privacy workflow, but did not establish that its five-gate
blinding helper supplies a supported hiding construction for a custom AIR or
arbitrary new verifier circuit. The helper is unchanged in the inspected newer
sources. This is an evidence/applicability gap, not a finding that the existing
fixed workflow fails privacy.

There is a separate statement-completeness requirement: the public membership
benchmark validates path bookkeeping and lookup boundaries in native host code.
Those checks must become constraints if their inputs are private inside a
recursive proof. Wrapping the current STARK alone would not prove the complete
private relation. The next compact-client gate is construction-specific review,
followed by constrained statement integration and full local cost measurement.
The deferred disclosure/recovery diagnostics remain deferred.

The same experiment now measures the existing fixed-Cairo wrapper in a fresh
process, including checkpoint import, twiddles, circuit construction, unchanged
blinding, preprocessing, proving and serialization. Four workers peak at
**4.78 GiB RSS / 11.50 seconds**; one worker peaks at **4.59 GiB / 35.17 seconds**.
Both configurations fail a **4 GiB cap** during recursive proving with zero
swap. The same synthetic fixture's unsplit pipeline peaks at 5.21 GiB / 20.95
seconds. These are individual fresh native runs, not a full-payment/browser
measurement or a lower bound for a different custom circuit.

All three completed final artifacts are byte-identical and accepted by the
original verifier libraries; three mutation controls reject for each artifact.
The preserved executable also accepts the artifact, but its old test adapter's
doubling-zero control is inapplicable to this synthetic output. The separately
reviewed test adapter adds one instead and leaves the original verifier library
unchanged. Detailed evidence is in the new experiment archive. This result
rules out the unchanged fixed wrapper for the target client budget and supports
resolving the compact privacy construction before porting this wrapper to WASM.

## Coefficient-backed evaluations

The optional mode keeps each polynomial's coefficients and exact committed
domain, then discards expanded evaluations after commitment. Components
regenerate the columns they need; FRI input generation uses batches of 16
columns. Sample challenge powers are prepared in the original global order
before batching. Merkle openings regenerate one tree and check that its root
matches the original commitment. Both Cairo and the recursive circuit use this
mode; neither proof equations nor the verifier change.

This is a storage tradeoff, not a whole-prover 16-column bound. Commitment and
opening still materialize **one full tree**, while composition materializes one
component's inputs. Retained coefficients, witness data, twiddles and FRI buffers
also contribute to peak memory. The patch contains a separately tested streaming
Merkle API, but the measured runtime does not yet use it.

The [review](../bench/bounded-memory/review.md) covers domain and offset handling,
global challenge ordering, borrowed caches, root reconstruction, defaults, and
source compatibility. All 80 final focused test executions passed, including
CPU/SIMD full STARK proofs with shifted row accesses. The dependency fork changes
source-level polynomial storage APIs; custom AIR evaluators that assume retained
evaluations need adaptation. Existing proving entry points keep their defaults.

**The 8 GiB prover target now passes for all four fixtures.** Each row below is
three sequential release proofs in one process, using four physical cores,
an 8 GiB cgroup cap, zero swap, and no allocation profiler, extra span tracing,
or native allocator tuning:

| Workload | Peak RSS GiB | Proving seconds | Result |
| --- | ---: | --- | --- |
| Ordinary | 6.12 | 22.69–23.08 | 3 passed |
| Controlled | 5.91 | 22.82–23.23 | 3 passed |
| ReturnNote | 5.84 | 22.73–22.78 | 3 passed |
| Synthetic 8/8/4 | 6.31 | 23.41–23.92 | 3 passed |

A matched fresh-process ordinary comparison in the same binary measured
**9.00 GiB / 16.74 seconds** with the new mode disabled and **5.69 GiB /
23.07 seconds** with it enabled: about 37% less peak RSS and 38% longer proving.
The previous binary independently measured 8.95 GiB / 16.64 seconds. These are
individual paired measurements, not latency distributions. The ordinary bounded
run sampled 5.52 GiB during Cairo and 5.65 GiB during recursion; repeated runs
show the additional effect of retained native allocation capacity.

All **15 completed proofs**, including comparison baselines, match earlier proof
bytes for the same witness/block and pass the original independent verifier.
The verifier rejects 45 altered-proof/fact cases; the invalid-intent fixture is
rejected before proving. Three public-cache boundary tests also pass. Full
measurements and binary/source hashes are in the
[archive](../bench/bounded-memory/results/measurements.md).

The **4 GiB cap still fails** for an ordinary proof. Both the untraced run and
a separate diagnostic traced run were OOM-killed; the latter stopped during
Cairo base-trace extension, before Merkle hashing. The next reduction must bound
evaluation expansion during construction as well as feed streaming commitment
and opening code. A streamed hash API called after full expansion would not
remove this peak.

These caps cover the prover service; the RPC cache, benchmark client and
independent verifier run outside them. RSS and cgroup memory charges are
reported separately. The build uses `target-cpu=native` on the larger i9 host;
portable CPU support and physical consumer desktops remain unqualified.
Three identical requests establish short-run fixture stability, not arbitrary
workload or long-lived service guarantees. The 8/8/4 fixture is synthetic and
does not increase the live pool's 4/4/2 limit. No new chain transactions were
submitted by this experiment.

## Earlier experiment: Cairo commitment recomputation

The [Cairo memory experiment](../bench/cairo-memory/README.md) adds an explicit
storage mode inside the first proving stage. It retains each owned Merkle root
and tree height, rebuilds the original tree when openings are needed, and checks
that the rebuilt root matches. After out-of-domain samples are materialized, it
releases owned polynomial coefficients and barycentric weights. Borrowed caches
are untouched. The recursive circuit stage still uses the existing commitment
implementation.

For the same ordinary witness and block, fresh release runs with tracing disabled
decreased peak RSS from **10.62 to 9.39 GiB** (about 12%), with byte-identical proof
output. Proving took 14.56 seconds with recomputation disabled in the new binary
and 16.14 seconds with it enabled. The preceding baseline independently measured
10.62 GiB and 14.38 seconds. This isolates the effect from the rebuilt dependency
graph. A separate traced run measured 9.27 GiB and 16.88 seconds; it is diagnostic
evidence, not the primary untraced comparison.

Three consecutive release proofs in one process, with tracing and allocator
instrumentation disabled:

| Workload | Tested cap GiB | Peak RSS GiB | Proving seconds | Result |
| --- | ---: | ---: | --- | --- |
| Ordinary | 10 | 9.41 | 15.69–16.31 | 3 passed |
| Controlled | 10 | 9.64 | 15.92–16.06 | 3 passed |
| ReturnNote | 10 | 9.47 | 15.46–16.01 | 3 passed |
| Synthetic 8/8/4 | 11 | 10.00 | 16.27–16.60 | 3 passed |

Synthetic 8/8/4 passed one proof at a 10 GiB cap, then was OOM-killed on the
second. A traced run passed three at an 11 GiB cap with lower measured RSS than
the untraced run. Allocation and tracing variability matters: the successful
sample's peak does not establish a universally safe lower cap. All successful
runs used zero swap. No native allocator tuning was used.

In this earlier mode, the **8 GiB cap failed**: Cairo was OOM-killed while committing the interaction
trace. Its expanded trace, coefficients and two leaf-hashing state buffers alone
total about 7.98 GiB before other runtime allocations. Pruning after commitment
does not eliminate that construction peak. The diagnostic traced ordinary run sampled
8.90 GiB during Cairo and 9.25 GiB during the recursive stage; the latter now sets
the whole-process peak. Disabling Cairo coefficient caching measured 9.25 GiB
overall but took 21.98 seconds to prove, so it is not the preferred configuration.

The [source review](../bench/cairo-memory/review.md) and differential tests cover
root/opening/proof equality, CPU/SIMD, parallel and sequential execution,
coefficient caching and barycentric sampling, borrowed trees, and negative
cases. All **21 completed proofs** passed the original independent verifier,
matched prior proof bytes for the same witness/block, and rejected 63 proof/fact
mutations. The invalid-intent fixture was rejected before proving. The 44 focused
PCS/Merkle test executions and three public-cache boundary tests passed.
This is an experiment with source-level API changes in the dependency
fork; it is not an audited production library or a desktop/browser qualification.

## Earlier experiment: stage-local allocations

The stock service prepares and retains both Cairo and recursive-circuit trees,
then keeps reusable evaluation buffers between requests. The experiment adds an
explicit `privacy_recursive_prove_low_memory(pie, options)` entry point:

1. Execute the same privacy bootloader and prepare only the Cairo tree.
2. Produce the Cairo proof with the pinned parameters.
3. Drop that stage's owned commitment tree and buffer pool.
4. Prepare the recursive circuit tree, including the unchanged ZK blinding,
   and produce the same version-prefixed compressed proof.
5. Drop the recursive tree and buffers before returning.

The existing shared-precompute API is preserved. The low-memory API owns its
phase resources; it does not require `Arc::try_unwrap`, mutate shared caches, or
use environment variables inside the proving library. The benchmark service
chooses its mode once at startup and serializes requests. A caller must still
bound concurrent proofs. No `malloc_trim`, disk spill, native memory mapping,
or platform-specific allocator tuning is part of the optimization.

## Stage-local baseline measurements

The first paired ordinary run reduced peak RSS from **14.07 to 10.72 GiB**
(about 24%). Its proof bytes were identical for the same private request and
base block. Three successive profiled runs of ordinary, controlled and synthetic
8/8/4 workloads remained within a 12 GiB cgroup with zero swap. The 8/8/4 case
still measures synthetic proof generation, not funded settlement at that limit.

**Release qualification found a limitation:** without allocator instrumentation,
the third consecutive 8/8/4 proof in one process exceeded the 12 GiB cap and was
OOM-killed after two valid proofs. Profiled success must not be promoted to a
long-lived release-service memory guarantee. Fresh-process runs and explicitly
native allocator tuning are measured separately in the results. Retained RSS
and fragmentation are part of the device budget, even when live Rust allocation
counts fall after each job.

The uninstrumented 8/8/4 follow-up passed three **fresh-process** runs at
11.18–11.28 GiB RSS. Explicit glibc tuning (`MALLOC_ARENA_MAX=1`,
`MALLOC_TRIM_THRESHOLD_=131072`) passed three requests in one process at
10.92 GiB RSS, but proving took 20.6–20.8 seconds. Fresh-process proving took
15.1–15.5 seconds. These glibc settings are a native-only tradeoff, not part of
the portable allocation change or a browser solution. Prefer an on-demand
native worker lifecycle while investigating the remaining working set.

Uninstrumented release results (all successful rows used a 12 GiB cap and zero swap):

| Workload / release mode | Runs | Peak RSS GiB | Proving seconds |
| --- | ---: | ---: | --- |
| Ordinary, same process | 3 | 11.33 | 13.89–14.40 |
| Controlled, same process | 3 | 11.45 | 13.73–14.58 |
| ReturnNote, same process | 3 | 11.05 | 14.06–14.68 |
| 8/8/4, fresh process each time | 3 | 11.18–11.28 | 15.14–15.50 |
| 8/8/4, same process, glibc tuning | 3 | 10.92 | 20.57–20.84 |

An ordinary proof still failed at both 10 GiB and 8 GiB caps. One thread used
10.60 GiB RSS and took about 47.9 seconds for recursive proving. Disabling Cairo
coefficient caching used 10.48 GiB RSS and about 20.6 seconds of proving, versus
roughly 14–15 seconds for the profiled four-thread staged mode. These are
exploratory samples, not latency distributions. Native release measurements and
all individual runs are in the [measurement table](../bench/prover-memory/results/measurements.md).

The counted allocator recorded about **10.27 GiB peak live requested Rust
memory** for the staged ordinary proof. After completion, roughly 20 MiB of Rust
allocations remained, versus about 9.87 GiB retained by the cached mode. Requested
allocation counts exclude allocator overhead and C-library allocations; they
are distinct from process RSS, cgroup charges and future WASM linear memory.
Allocator-retained RSS can persist after Rust objects have been dropped: the
profiled ordinary process still held about 5.7 GiB after one request and 7.1 GiB
after three. The 20 MiB figure is not an idle process RAM claim. Current native
integration should end the on-demand prover process after a job if it needs that
RAM returned immediately; future browser integration must measure worker and
linear-memory lifetime explicitly.

The Cairo commitment histogram identified **6.898 GiB of expanded field-element
columns alone** for the ordinary fixture. That excludes commitment trees,
coefficient caches, FRI buffers and other state. This motivated the subsequent
coefficient-backed experiment: stage scheduling alone cannot make that retained
representation fit a small browser heap.

The **38 successful proof runs** are checked by the unchanged independent native
verifier, including successful requests before the later 8/8/4 OOM. The verifier also rejects altered message digests, program hashes and
proof bytes. Same-input/block variants are compared byte-for-byte. This is
correctness evidence for the fixtures, not an independent cryptographic audit.
The archive also checks 114 altered-proof/fact rejections, rejects an invalid
intent witness, and verifies that public messages and their proven digests match
the original fixtures. Three tests exercise the public-read cache boundary.
These runs replay local witnesses against public Sepolia state; they do not send
new transactions or establish acceptance of a newly built prover on chain.

## Browser path

The allocation change is portable Rust, but **the full pipeline is not a browser
implementation yet**. Source inspection of the pinned dependencies found:

- The privacy bootloader writes its output preimage through `NamedTempFile` and
  reads it back. Replace this with an in-memory result interface.
- The current service uses native HTTP, Tokio blocking tasks and OS threads.
  Keep the proof core separate; supply authenticated public execution state from
  the browser and run proving in a Worker.
- The pinned S-two backend has wasm32 branches and portable SIMD, but that does
  not establish that the complete virtual OS, Cairo prover, recursive prover,
  randomness and compression dependency graph builds or runs in a browser.
- Qualify entropy, SIMD lowering, compression, worker messaging and cancellation.
  Avoid copying the entire witness/trace across the JavaScript/WASM boundary.
- Test one-thread execution and optionally browser worker parallelism. Native
  Rayon configuration is not itself a browser thread implementation.

Rust's [wasm32 target documentation](https://doc.rust-lang.org/rustc/platform-support/wasm32-unknown-unknown.html)
explains the unavailable native filesystem and thread APIs. A conventional
single-memory wasm32 build has a 4 GiB address-space ceiling, not a safe browser
RAM budget ([V8's implementation explanation](https://v8.dev/blog/4gb-wasm-memory)).
Rust's [wasm64 target](https://doc.rust-lang.org/rustc/platform-support/wasm64-unknown-unknown.html)
is tier 3; using larger addresses would not make a 10 GiB working set practical
on an ordinary desktop. We are not relying on memory64 for initial portability.

WASM memory [grows in pages](https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/JavaScript_interface/Memory/grow).
Dropping Rust values makes allocator space reusable; do not interpret native RSS
reclamation as a shrinking browser memory buffer. Measure both live allocations
and total linear-memory growth across repeated proofs. For optional Rayon
parallelism, the [browser adapter's requirements](https://github.com/RReverser/wasm-bindgen-rayon)
include worker/shared-memory integration and cross-origin isolation.

## Next memory work

1. Bound evaluation extension during initial commitments and reconstructed
   openings. Integrate the tested column-provider Merkle path so full expanded
   trees are never materialized. Preserve domains, column order, hash block
   boundaries and transcript operations. Repeat source review and differential
   proof tests for the integrated path.
2. Recheck component-sized temporaries, recursive witness data, quotient/FRI
   buffers and retained native allocation capacity once the full-tree floor is
   removed. Keep both proving stages in the measurement; the FRI batch size
   alone is not a whole-prover memory bound.
3. Reach the 4 GiB prover budget, then explore the browser budget. Keep the
   8/8/4 fixture in every comparison without increasing live pool limits.
4. Separately compile a minimal proof-core wasm32 entry point and record actual
   dependency failures. Remove filesystem coupling and add Worker execution
   before claiming browser support. No WASM build or browser proof has been run
   in this experiment.
5. Qualify physical consumer desktops and the whole wallet. The present change
   is an isolated implementation candidate; maintained packages and deployed
   proof configuration have not been changed.
