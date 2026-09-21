# M31 tree benchmark — v2 measurements

2026-09-21. Frozen v2 handoff (`target/m31-tree/measurement-ready.json`, handoff
sha256 `c0e15a02…`); v1 failure evidence preserved (`results/native-tree-1g-r1`,
`results/build-v1`). All inputs public and synthetic. This is a hash-workload
comparison, not a payment proof, privacy qualification, or production migration.

## Verification evidence

- Native unit tests v2: **6/6 PASS** (`results/native-unit-v2/unit-tests.log`).
- Cairo correctness: **36/36 PASS** (`results/cairo-correctness/`): 24 golden,
  4 packing, 2 reject, 1 history eviction, 5 snapshot. `m31_reject_full` and
  `m31_history_eviction` exhaust the snforge default step limit (cold M31 path)
  and pass with the authorized `--max-n-steps 80000000`; original default-limit
  failures preserved alongside.
- Native proofs: 8/8 exit 0, `native_proof_verified=true`. Proof bytes identical
  per mode across repetitions (tree `d8f4881c…`, mixed `d069e307…`).
- Browser: 4/4 runs PASS; all 8 exported proofs byte-identical to native
  references. Rejection tests match handoff: tree 19 mutations + 2 boundary
  controls; mixed 17 + 3 — in-browser and via native `--verify-tests` on one
  exported representative per mode (`results/native-verify-v2-*`).
- Archive integrity: `results/integrity-final.json` passed, no failures.

## Native (1 pinned CPU, no swap, systemd cgroup)

| Workload | Cap | complete_seconds | Peak RSS | Cgroup peak | Envelope / bare STARK |
| --- | --- | --- | --- | --- | --- |
| tree-only ×3 | 1 GiB | 0.480–0.491 | 0.017 GiB | 0.012 GiB | 197,320 / 166,809 B |
| mixed ×3 | 3 GiB | 16.108–16.352 | 1.899 GiB | 1.897 GiB | 464,900 / 404,305 B |
| mixed probe ×2 | 2 GiB | 16.185 / 16.309 | 1.899 GiB | 1.897 GiB | identical bytes |

## Browser (headless Chrome 153, WASM, 1 worker, 4-CPU budget)

| Workload | Cap | Proof latency | WASM linear HWM | Browser+harness cgroup | PSS peak |
| --- | --- | --- | --- | --- | --- |
| tree 3+1 | 1 GiB | 4.19–4.28 s | 20,709,376 B | 0.305 / 0.314 GiB | 0.283 / 0.277 GiB |
| mixed 3+1 | 3 GiB | 75.8–77.2 s | 2,040,070,144 B | 2.168 / 2.150 GiB | 2.138 / 2.124 GiB |

No OOM, no swap, UI heartbeat max gap 118.2 ms. Linear memory stays grown after
frees (warm repeats do not imply shrinking buffers).

## Cairo `append_batch` per-selector L2 gas (snforge 0.63.0, local VM)

| Batch | felt cold | felt warm* | M31 cold | M31 warm* |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 8,000,008 | 5,122,444 | 1,571,243,590 | 787,619,740 |
| 2 | 13,088,672 | 10,180,788 | 2,358,804,480 | 1,575,125,240 |
| 4 | 23,235,680 | 20,267,156 | 3,933,870,870 | 3,150,080,850 |
| 8 | 43,469,056 | 40,379,252 | 7,083,892,870† | 6,299,881,290† |

† M31 batch-8 failed at the initial authorized 8 GiB cgroup cap (OOM failures
preserved in `cairo-final-m31-cold-8`/`cairo-final-m31-warm-8`) and passed at
16 GiB (`cairo-final-m31-*-8-16g`); 16 GiB is a passing cap, not a measured
minimum. All 16 cells now have measured values; no value is extrapolated.

\* warm excludes `seed_snapshot` setup (felt 6,901,390; M31 12,389,010 L2 gas).
Per-selector VM steps (trace extraction): felt cold-1 append 11,299 steps / 128
poseidon builtins; M31 cold-1 append 13,515,671 steps / 2,519,734 range-checks;
M31 warm-1 6,760,704 / 1,260,324. Per-selector counters verified equal to the
reviewed extraction (`results/reviewed-cairo-counters.json`, with trace SHA256s);
trace `gas_consumed` reads 0 under cairo-steps tracking and is not a zero-gas
claim — gas comes from the gas-report logs. Whole-test counters per directory
are not per-call counters. Cold M31 = 130 permutations (65 init + 65 append); warm = 65;
digest stored as 2 felts. Local estimates only — no on-chain fee claim.

## Prior felt252 baseline (separate sessions, kept distinct)

`bench/poseidon-membership` / `bench/wasm-membership`: native 1.97 GiB peak RSS,
14.08–14.14 s; browser 2.150 GiB linear memory, 40.93–41.72 s, browser group
2.21–2.23 GiB.

## Limitations

Deterministic fixtures repeat the same grinding search (latency stability, not a
PoW distribution). 128-bit application-hash design target ≠ configured 96-bit
PCS metric. Mixed is a labeled hash union, not a migrated payment. M31 prefix-8
warm fixture is reference-derived; genuine Cairo snapshot comparisons cover
prefix 1/2 (felt baseline 1/2/8). M31 batch-8 failed at the 8 GiB local VM cap
and passed at 16 GiB in one authorized run per cell (both failures preserved);
16 GiB is a passing cap, not a measured minimum. Gas figures remain
local VM resources, not fee quotes or on-chain executability. Full data: `results/aggregate.json`.
