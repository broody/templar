# Public felt252/Poseidon membership: measured outcome

2026-09-21. One physical core of the i9-10980XE development host, Rayon thread
count one, CPU affinity 0, zero swap. Every proving run starts a fresh process.
This is a public-transcript validity benchmark, not a private wallet, full
payment, physical desktop qualification, WASM build or PROOF1 wrapper.

## Complete-process memory and time

| Mode | Hard cap | Outcome | Peak RSS GiB | Whole elapsed seconds |
| --- | ---: | --- | ---: | ---: |
| Original baseline | 2 GiB | OOM during base commitment | — | 2.45 to failure |
| Original baseline | 8 GiB | 3 fresh passes | 4.282 | 8.58–8.82 |
| Matched baseline in flag-enabled binary | 8 GiB | Pass | 4.282 | 8.67 |
| Bounded storage, first probe | 2 GiB | Pass | 1.970 | 14.19 |
| Bounded storage, fresh repeat | 2 GiB | OOM during STARK proving | — | 12.84 to failure |
| Bounded storage | 3 GiB | 3 fresh passes | 1.96999–1.97012 | 14.08–14.14 |

The bounded mode retains coefficients and regenerates evaluations, with
16-column FRI batching and one-tree commit/open regeneration. It uses the
previously reviewed `set_bounded_memory_mode(16)` API; no proof equations,
parameters, statement checks or dependency source are changed. The comparison
against the same binary's baseline is about **54% less RSS and 63% longer
elapsed time**. Whole elapsed includes the measurement wrapper lifecycle.
The client reports its own phase/complete times separately in each proof
summary; for example the first original baseline reports 8.370 seconds versus
8.580 seconds externally.

The full process includes reading the fixture, regenerating all 128 permutation
states with the independent Rust reference, trusted preprocessing and twiddles,
witness construction, commitments, interaction PoW, STARK proving, serialization,
and native verification. Original Python fixture creation is outside the cap;
the measured client independently regenerates and checks its transcript.
Negative verification checks run separately and are excluded from proving times.

**Do not claim a reliable 2 GiB budget.** One near-cap success is followed by an
OOM kill of the same binary/fixture with zero swap. The cause of this near-cap
variation has not been isolated. Three higher-cap successes do not override the
observed failure. The successful 3 GiB runs charge about 1.968 GiB to the cgroup;
RSS and cgroup accounting are different measurements.

## Proved work and checks

- Two depth-32 paths, 64 exact two-element `poseidon_hash_span` calls, 128 Hades
  permutations. The fixture contains 126 distinct requests, two repeated
  occurrences, 128 padded aggregator rows and 768 public memory-lookup terms.
- Original upstream felt252 Poseidon/round/cube/range constraints are reused.
  Public native verification checks canonicality, ordering, sponge padding,
  indices, chaining and endpoints without recomputing Poseidon. The full STARK
  verifier binds these public requests to all required permutation constraints.
- Three unit tests pass, including independent Rust/Python reference parity.
  The native verifier rejects 13 altered statement/proof cases; three additional
  controls check padding reads, duplicate multiplicities and memory dictionary
  binding. These are correctness checks, not privacy/disclosure diagnostics.
- Eight completed full proof envelopes are byte-identical across both binaries,
  both storage modes and all successful caps. SHA-256:
  `7883c50e7125e608365e7887b50df589ac57bcc91438fe2f1f660caf56a9631e`.
- Bare STARK: **258,621 binary bytes**. Complete envelope: **334,307 binary
  bytes**, including the intentionally public statement. Public statement JSON:
  76,996 bytes. Full envelope JSON: 800,821 bytes.

The exact configuration is ordinary Blake2s, PCS PoW 27, FRI blowup log 3,
23 queries, fold step 4, last-layer degree log 0, lifting LDE log size 23, and
interaction PoW 24. The convenience PCS security metric is 96 bits, not an
independent security theorem. These parameters differ from the earlier tiny
generic circuit probe. Its 2.61 GiB prover result and the separate 0.77–0.78 GiB
Cairo verification result are not same-workload comparisons to this benchmark.

## What sets the cost

The 12-component subset has no Cairo CPU or virtual OS. Its fixed lookup tables
nevertheless include RangeCheck20 with 1,048,576 rows. The range/key tables'
logical values occupy 136.516 MiB at base domains, or 1,092.125 MiB if all trace,
interaction and preprocessing values are simultaneously expanded eightfold.
This is a logical-array accounting, not an unavoidable RSS lower bound: storage
scheduling changes the simultaneous live set. The component inventory gives
the source definitions and exact formula. FFT buffers, commitments, coefficients
and dynamic Poseidon/cube traces add to the measured peak.

The result supports targeted table/storage work, but does **not** provide the
substantial sub-2-GiB headroom needed to justify a full private payment prototype.
Private paths require constrained hidden bookkeeping, ownership/nullifiers,
note construction, conservation and transaction binding. A supported client
privacy construction and its resource cost remain separate requirements. No
additional disclosure/recovery diagnostics, private inputs or chain writes were
used. The accepted fully local native pipeline remains the reference.

## Evidence

`aggregate.json` contains every run and comparison. Per-run folders contain
exact commands, effective cgroup limits, sampled resources, stdout and proof
artifacts. The archived build/test logs and source manifests pin both binaries:

- Baseline: `0ca540ea98f0034face61e4c4628f0aa198fd9f3d2fd399a5249f541b0fd1128`.
- Flag-enabled: `9c44542bd838100722358edc8c92f91e08012c4e59ebbf2b6ea35813c95c8974`.

Both builds use nightly-2026-01-15, `target-cpu=native`, the checked-in standalone
Cargo.lock, and the recorded pinned dependencies with earlier reviewed storage
patches. Native one-thread results do not establish WASM thread/SIMD/linear-memory
support. No benchmark runs overlapped builds.
