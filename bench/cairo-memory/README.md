# Cairo commitment memory experiment

**Result:** ordinary release peak RSS fell from **10.62 to 9.39 GiB** (about 12%),
while proving increased from **14.56 to 16.14 seconds** with identical proof
bytes. Three ordinary, controlled and ReturnNote proofs per process pass under
10 GiB; synthetic 8/8/4 fails on its second proof at that cap and passes three at
11 GiB. The 8 GiB target remains unmet. All 21 completed proofs passed the
original verifier and 63 mutations were rejected. [Interpretation and limits](../../docs/prover-memory-review.md).

This extends the [stage-local baseline](../prover-memory/README.md) with an
explicit Cairo commitment memory mode. It retains a Merkle root and tree height,
rebuilds the same tree when opening it, and releases owned coefficients and
barycentric weights after out-of-domain sampling. Expanded evaluation columns
remain resident. The recursive circuit stage uses the existing implementation.

The mode does not change cryptographic parameters, transcript ordering, tree
hashing, FRI, blinding, proof serialization, statements, or the verifier. Borrowed
precomputed trees are not modified. Rebuilt roots are checked against the
retained roots before openings are returned. This is an isolated experiment;
neither Cargo's pinned source cache nor the original accepted prover is edited.

## Evidence

- [Measurements](results/measurements.md) and [machine-readable summary](results/summary.json).
- [S-two patch](stwo.patch), [Cairo wrapper](stwo-cairo.patch), and
  [benchmark integration](integration.patch).
- [Invariant and API review](review.md), with 44 focused test executions across
  parallel and non-parallel builds.
- Per-run proofs, public facts, original independent verifier logs, process RSS,
  cgroup memory/OOM/swap counters, and optional allocation profiles in `results/`.
- Source, binary and lockfile hashes in build records. `SHA256SUMS` pins the
  completed public archive. Private witness files remain in the original local
  fixture directories and are never copied into this archive.

## Reproduce

Requires the pinned sources, toolchain, build and public RPC caches from the
previous benchmark, plus its locally held private fixtures. These paths are
recorded in [environment.json](environment.json). Setup creates independent
copies under `target/cairo-memory`. Run names must be new; archived results are
never overwritten.

```sh
python3 bench/cairo-memory/setup.py
python3 bench/cairo-memory/apply.py
python3 bench/cairo-memory/build.py
python3 bench/cairo-memory/run.py --variant baseline --fixture ordinary --cap 12 --name baseline-new --block 15391165
python3 bench/cairo-memory/run.py --variant staged-release --fixture ordinary --cap 12 --name recompute-new --block 15391165
python3 bench/cairo-memory/analyze.py
python3 bench/cairo-memory/validate_archive.py
```

The fixed block requires the existing public-read cache because remote providers
prune storage proofs. For a new block, first run a paired baseline without
`--block`, then use its recorded block for comparisons. All private requests go
to a loopback prover; upstream requests are public state reads. No transactions
are submitted by this benchmark.

`--keep-cairo-trees` disables the mode in the new binary for a comparison with
identical build inputs. `--no-coefficients` selects upstream barycentric sampling.
`--requests 3` tests repeated proofs in one process; a one-request run starts a
fresh process. `build.py --profile-allocations` creates a separate diagnostic
binary selected by `--variant staged`; release results use `staged-release`.
Do not overlap builds and proving benchmarks.

The library's legacy API and new options default to cached commitments. This
experiment's service selects recomputation by default when stage-local proving
is selected (`TEMPLAR_LOW_MEMORY=1`); `TEMPLAR_RECOMPUTE_CAIRO_COMMITMENTS=0`
disables it. The library itself does not read environment variables.

## Scope

Measurements use four physical cores on the same larger host, one proof at a
time, a hard cgroup memory cap and zero swap. No allocator-specific workaround
is part of this change. Proving time includes both proof stages and per-request
precomputation; request time also includes OS execution and public RPC reads.
Independent verification and the harness run outside the prover's memory cap.

Ordinary, controlled, and ReturnNote cases replay earlier funded Sepolia flows;
8/8/4 remains a synthetic capacity fixture. Repeated runs use the same witness
and base block. This does not qualify a physical desktop, a whole wallet, live
acceptance of the optimized binary, or browser/WASM proving. The ordinary
expanded evaluations alone still total about 6.9 GiB, so further restructuring
is necessary for a small browser heap.

## Next representation experiment

Source inspection suggests keeping polynomial coefficients and materializing a
bounded number of evaluation columns when each consumer needs them. The largest
ordinary size bucket already contains 2.625 GiB of evaluations, so grouping only
by tree or domain size would not establish a browser-sized bound. At the current
blowup factor the coefficient cells would occupy about 0.86 GiB; that is a design
estimate for those cells, not a predicted whole-prover peak.

The next bounded milestone is a coefficient-backed representation plus
differential tests of exact evaluation subdomains and FRI quotient accumulation.
It must preserve domain/coset metadata, sample/random-power indexing, and
accumulation order. Composition evaluation can then materialize a component's
required columns, subject to a measured cache budget. Merkle construction will
also need incremental leaf hashing with unchanged column order, hash-block
boundaries, and finalization. Recomputing openings must preserve authentication
paths. Buffer pools must respect the same budget instead of retaining evicted
columns. This is a larger prover refactor and needs its own review and measured
time/memory tradeoff before any browser feasibility claim.

The coefficient-cached interaction commitment explains the 8 GiB failure:
6.648 GiB of expanded trace cells plus 0.831 GiB of coefficients and two 0.250 GiB
Merkle leaf-hashing state buffers already total 7.980 GiB before twiddles, other
runtime allocations, or output hashes. The memory mode prunes after that tree is
built. A smaller follow-up could release the previous hash-state buffer earlier
during output conversion, but that alone would not remove the earlier allocation
floor or the recursive stage's peak.
