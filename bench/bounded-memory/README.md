# Coefficient-backed proving memory

This experiment extends the [Cairo commitment baseline](../cairo-memory/README.md)
without changing proof parameters, transcript operations, blinding, statements,
serialization, or the verifier. It applies the same memory mode independently to
the Cairo and recursive circuit stages.

## Storage changes

- Keep polynomial coefficients and the exact committed domain. Expanded
  evaluations are optional; an empty evaluation buffer never stands in for a
  nonempty domain.
- Construct and open one complete commitment tree at a time, then release its
  expanded columns. Check the reconstructed root before returning openings.
- Materialize the exact evaluation domain needed by each AIR component. Preserve
  the existing composition mode, offset masks, and accumulator order.
- Regenerate FRI input columns in bounded batches. Prepare challenge powers and
  periodicity once in the original global column order before batching.
- Preserve borrowed caches. Require coefficients before evicting an owned
  preprocessed tree. Do not return evicted evaluations to an unbounded pool.

The first integrated mode still materializes **one full tree** at commitment and
opening time, and all required columns for a component during composition. The
FRI column batch limit is not a whole-prover memory bound. An additive streaming
Merkle API is tested separately and is not enabled in this initial mode.

## Measured result

The **8 GiB prover cap passes** for three consecutive release proofs per
workload, using four physical cores and zero swap. Allocation profiling, extra
span tracing and native allocator tuning are disabled in these primary runs.

| Workload | Peak RSS GiB | Proving seconds | Proofs |
| --- | ---: | --- | ---: |
| Ordinary | 6.12 | 22.69–23.08 | 3 |
| Controlled | 5.91 | 22.82–23.23 | 3 |
| ReturnNote | 5.84 | 22.73–22.78 | 3 |
| Synthetic 8/8/4 | 6.31 | 23.41–23.92 | 3 |

The fresh ordinary comparison in the same binary is **9.00 GiB / 16.74 seconds**
with bounded storage disabled versus **5.69 GiB / 23.07 seconds** with both stages
enabled. The preserved preceding binary independently measures 8.95 GiB /
16.64 seconds. These single matched comparisons indicate about 37% less RAM
and 38% more proving time; repeated rows above show short-run fixture stability,
not latency distributions or long-lived service qualification.

All 15 completed proofs (including baselines) are byte-identical to the preceding
archive for the same request/block and accepted by the original verifier. It
also rejects 45 proof/fact mutations. An invalid intent is rejected before
proving. The source review covers 80 final focused test executions; three public
RPC-cache boundary tests pass separately.

An ordinary proof **fails at a 4 GiB cap**, with one OOM kill and zero swap.
A separate traced diagnostic repeats the failure during Cairo base-trace
extension, before Merkle hashing. The next experiment must bound initial
expansion and regenerated openings, then connect them to the streaming hash
provider; hashing in batches after full expansion cannot remove that peak.

RSS and cgroup charges are recorded separately. Caps cover the prover service,
with the RPC cache, client and independent verifier outside the cgroup. Proving
time excludes virtual execution, verification and wallet work; request timings
are also recorded. This changes neither the live pool's 4/4/2 limits nor its
deployed prover, and makes no new chain submission.

## Artifacts and reproduction

- [Measurements](results/measurements.md), [full results](results/summary.json),
  and [invariant review](review.md).
- Incremental source patches: [S-two](stwo.patch), [Cairo](stwo-cairo.patch),
  [recursive circuit](stwo-circuits.patch), and [service integration](integration.patch).
- Per-build source snapshots and metadata under `results/builds/`; each replay
  records the exact binary hash. Original verifier logs accompany each proof.

`setup.py` copies the preceding experiment's prepared sources, build cache and
public-read cache into `target/bounded-memory`. It leaves both earlier archives
and their working copies unchanged. Private witnesses remain only in the
original local fixture directories. This benchmark makes no chain writes.

```sh
python3 bench/bounded-memory/setup.py
python3 bench/bounded-memory/apply.py
python3 bench/bounded-memory/build.py
python3 bench/bounded-memory/run.py --variant baseline --bounded-stages none --fixture ordinary --cap 12 --block 15391165 --name baseline-new
python3 bench/bounded-memory/run.py --variant staged-release --bounded-stages both --column-batch-size 16 --fixture ordinary --cap 12 --block 15391165 --name bounded-new
python3 bench/bounded-memory/analyze.py
python3 bench/bounded-memory/validate_archive.py
```

Use fresh run names. The pinned historical block needs the previous public RPC
cache because providers prune storage proofs. See the preceding benchmark for
fixture provenance and public/private RPC boundaries. `--bounded-stages` accepts
`none`, `cairo`, `recursive`, or `both`; the library defaults are `None` for both
stages. The experimental service reads `TEMPLAR_BOUNDED_CAIRO_COLUMNS` and
`TEMPLAR_BOUNDED_CIRCUIT_COLUMNS`, with zero or absence disabling each option.
These variables are interpreted outside the proving library.

Builds may use twelve cores on the development host; proving measurements remain
fixed at four physical cores, one request at a time, with hard cgroup memory
limits and zero swap. Never run builds and proving benchmarks concurrently.
`-Ctarget-cpu=native` is a benchmark setting, not a portable shipping binary.
Optional allocator instrumentation has a separate binary and must be reported
separately from release measurements.

## Limits

This mode is validated for the framework-based Cairo and recursive circuit
provers. It is not a universal compatibility claim for every custom S-two AIR;
custom evaluators that directly require retained LDEs need adaptation. The
dependency fork changes source-level representation APIs while keeping the
legacy proving options and proof format unchanged.

Native cap tests on a larger host do not qualify a physical consumer desktop,
the full wallet, or browser/WASM execution. The privacy bootloader and service
still have filesystem and native-runtime dependencies. The browser goal remains
below 2 GiB live proving memory, with actual linear-memory high-water use and
worker lifecycle to be measured separately.
