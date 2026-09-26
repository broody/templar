# Device-proving spike: phases 0 to 2

2026-09-26. Specification: [PLAN.md](PLAN.md). Phases 0 (restore and calibrate), 1 (capture sweep),
1b (a looped QM31 permutation) and 2 (proving sweep) are measured. Phases 3 to 5 have not been run. No chain access of any kind: all state comes from
synthetic authenticated fixtures served on loopback, with no public node and no local pathfinder.

## Phase 0: restore and calibrate

**Binaries.** The stock V1 prover and its verifier lived in `/tmp` and were lost in the 2026-09-24
reboot, so both were rebuilt ([`build.py`](build.py)):
- **Prover:** `starknet_transaction_prover` from `git archive e6b6fd2e` (tag PRIVACY-0.14.3-RC.2).
  - The source is unmodified, and the lockfile hash `2d47ff1c…` matches the ADR-0018 pin.
  - Built with `--features stwo_proving`, nightly-2026-01-15, release, `-Ctarget-cpu=native`, and
    cairo-lang 0.14.3a3 on `PATH`.
- **Verifier:** the original `verify_saved.rs`, reconstructed from
  `client-privacy-feasibility/verify_saved_plus_one.rs`. Its hash matches the archived `eef9af4a…`.

The new binary hashes differ from the archived ones, because the build paths differ. The replay
below shows they are functionally identical: it reproduces the archived proof byte for byte.

The other preserved binaries match their archived records ([binary-hashes.json](results/phase0/binary-hashes.json)):
- `baseline-prover`;
- `low-memory-prover`;
- the V1 `capture` tool;
- `capacity`;
- `state-fixture`.

`blake_sites` has no binary record, but its source matches its build record.

**Calibration** ([calibration.json](results/phase0/calibration.json)). Every run used 4 physical
cores (0–3), zero swap, and a cgroup cap. V1 stock is three runs; the others are one or two.

| Metric | Measured | Reference | Deviation |
|---|---:|---:|---:|
| V1 stock, 589,958-step fixture: virtual-OS steps | 589,958 | 589,958 | 0 |
| V1 stock: proving stage | 27.35–27.97 s | 27.42 s | +0.6% |
| V1 stock: peak RSS | 29.96–30.38 GiB | 29.05 GiB | +3.8% |
| V1 stock: proof | 225,362 B, **byte-identical** to the archive; verified, 3 rejections | same | 0 |
| V1 bounded (full `run.py` environment, 16/16 columns), same fixture | 16.22 GiB, 48.3 s, byte-identical | none for this fixture | 0.54× RSS, 1.75× time vs stock |
| V2 small, same PIE (`prove-small recursive`) | 28.9–29.2 GiB, 27.0 s, verified, 3 rejections | V1 on the same PIE: 30.15 GiB, 27.6 s | −3.7% RSS, −2.1% time |
| V2 small, StarkWare sample transaction (275,933 steps) | 13.1–13.6 GiB, 11.9 s, 236,403 B | ADR-0018 V2 2/2/1: 14.22 GiB, 11.2 s, 231,955 B | −6.3% RSS, +6.1% time |

The ADR-0018 2/2/1 workload itself cannot be replayed: its private request was in `/tmp`. V1 and V2
proofs are deterministic, with the same proof hash across runs.

## Phase 1: capture sweep

**The statement.** [`cairo/`](cairo) holds `CostStatementAccount`, a cost model of the statement,
not a production one.
- It decodes a fixed 1,000-felt witness with canonical M31 checks.
- It runs a prefix of the R0 V5 hash schedule, with its real frame shapes, then `k − prefix`
  compress-format tree nodes. The schedule is 42 sponge permutations, listed in
  `statement.cairo`.
- It computes the `spend5` binding and emits `[class, 'TMPZDP1_COST_V1', chain, pool, binding]`.

Reused code:
- `hash.cairo`, `perm_compact.cairo`, `perm_unrolled.cairo` and `spend5.cairo` are copied
  verbatim from `m31-pool`.
- `perm_qm31.cairo` is the QM31 probe behind the same interface.

**Tools.**
- Capture: the preserved V1 capture tool, which still runs.
- Component claims: V1 `capacity trace`, and `prove-small trace` for V2.
- Blake attribution: `blake_sites`.

**Checks.** Every capture emits the pinned message shape. The bindings of all three variants agree
at every shared `k`, which checks the qm31 port against the felt252 permutation.

| Variant | k | OS steps | + bootloader | Account steps | Blake (OS) | Poseidon | Hashed / executed CASM felts | Largest V2 components (log) | S1 |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| compact | 0 | 338,014 | 537,414 | 29,864 | 4,409 (2,495) | 626 | 18,802 / 2,809 | blake_g 19 | – |
| compact | 64 | 1,379,745 | 1,579,145 | 911,276 | 5,852 (3,938) | 626 | 28,523 / 8,675 | memory_id_to_small 20 | – |
| compact | 102 | 1,868,920 | 2,068,320 | 1,400,451 | 5,852 | 626 | 28,523 / 8,675 | memory_id_to_small 20, add_opcode 20 | – |
| **compact** | **106** | **1,920,413** | 2,119,813 | 1,451,944 | **5,852** (3,938) | 626 | 28,523 / 8,675 | memory_id_to_small 20, add_opcode 20 | **pass** |
| compact | 128 | 2,203,619 | 2,403,019 | 1,735,150 | 5,852 | 626 | 28,523 / 8,675 | + assert_eq_double_deref 20 | – |
| **unrolled** | **106** | **2,306,738** | 2,506,138 | 1,383,447 | **10,073** (8,159) | 626 | 55,646 / 20,190 | blake_g 20 (V1: 21) | **fail** (Blake) |
| qm31 | 32 | 822,411 | 1,021,811 | 224,574 | 7,660 | 626 | 31,694 / 10,732 | blake_g 20 | – |
| qm31 | 64 | 995,763 | 1,195,163 | 396,041 | 7,676 | 626 | 31,801 / 11,300 | blake_g 20 | – |
| **qm31** | **106** | **1,197,155** | 1,396,555 | 597,433 | **7,676** (5,762) | 626 | 31,801 / 11,300 | memory_id_to_small 20, blake_g 20, qm_31_add_mul 19 | **numbers pass; U2** |

The table omits compact at k 8, 16 and 32, and the extra slope captures (unrolled at 0, 8, 16, 64;
qm31 at 0, 8, 16). They are all in [summary.json](results/phase1/summary.json), with one JSON file
per capture. The account's calldata is 1,093 felts in every capture.

**Contract-mode steps per permutation** (account segment, least squares):

| Variant | Sponge-framed (k = 0, 8, 16) | Tree node (k ≥ 64) |
|---|---:|---:|
| compact | 14,047 | 12,873 |
| unrolled | 13,402 | 12,226 |
| qm31 | 6,011 | 4,795 |

## S1 at k = 106

- **compact: pass.**
  - Every component is at most 2²⁰ in both V1 and V2.
  - The two components at 2²⁰ are `memory_id_to_small` (809,780 values, 77% of 2²⁰) and
    `add_opcode` (593,569 rows).
  - Blake is 5,852 and Poseidon 626. The fixed 57-component small recursion accepts the set.
- **unrolled: fail.**
  - Blake is 10,073, above 8,192. `blake_g` reaches 2²¹ in V1.
  - V2's `blake_g` uses 80 rows per compression, against V1's 128, so in V2 it is 2²⁰ and would
    fit the small path's component limit.
- **qm31: the numeric gates pass, but the component set does not.**
  - Numeric gates: 1,197,155 steps, 0.24% under the 1.2M stop; Blake 7,676, which is below 8,192
    but above the decision rule's 7,000 margin; no non-hash component over 2²⁰.
  - Component set: the fixed small recursion does not accept it, because `qm_31_add_mul_opcode` is
    not among its components. This is U2, as expected.

## Phase 1b: looped QM31 permutation

`perm_qm31_compact.cairo` (feature `qm31_compact_perm`) has `perm_compact`'s structure on native
M31 ops: one shared full-round function over a constant table, groups of four partial rounds, and
Plonky3's M4 addition chain. Its binding equals every other variant's at k 0, 8, 16, 32, 64 and 106.

| k | OS steps | Account | OS segment | Blake (OS) | Hashed / executed felts | Largest V2 components |
|---:|---:|---:|---:|---:|---:|---|
| 32 | 731,665 | 249,409 | 482,256 | 6,071 (4,157) | 28,593 / 6,968 | memory_id_to_small 19, blake_g 19 |
| 64 | 929,889 | 445,748 | 484,141 | 6,087 (4,173) | 28,700 / 7,536 | memory_id_to_small 19, blake_g 19 |
| **106** | **1,163,957** | 679,816 | 484,141 | **6,087** (4,173) | 28,700 / 7,536 | memory_id_to_small 20, qm_31_add_mul 19 |

S1 at k = 106:
- The numbers pass: 1.164M steps, under the 1.2M stop by 3%; Blake 6,087, under the 7,000 margin.
- U2 still fails, as for qm31: `qm_31_add_mul_opcode` is not in the fixed small recursion.

The looped form trades bytecode for calls. The OS segment falls by 116k steps (484k against 600k),
but the account rises by 82k (5,573 steps per tree node against 4,795), because each round call
passes the 24-word state. Net: 33k fewer steps than qm31, and 1,589 fewer Blake.

## Phase 2: proving sweep

Tools, all in this directory:
- [`phase2.py`](phase2.py) drives the sweep.
- [`run_v1.py`](run_v1.py) and [`run_v2.py`](run_v2.py) now take `--cpus`. A run fails unless the
  proof's message equals the local capture's, checked as the response messages and facts[8] (V1),
  or the output preimage's digest (V2).
- `prove-small` has two new modes, both calibrated on the 589,958-step fixture:
  - `cairo-only` runs `privacy_prove`'s steps, then verifies natively with the generic Rust
    verifier, which accepts any component set, and rejects a one-byte change to the PoW.
  - `recursion` runs the recursion stage alone, in a fresh process, from a `cairo-only` output.
    Its proof is **byte-identical** to `recursive`'s.

Every run used zero swap and physical cores 0–3 unless stated. Every proof verified and rejected
its mutations: the V1 verifier's 3 controls, `prove-small verify`'s 3 controls, or the native
verifier's PoW control for QM31. Every message matched its capture. Proofs are deterministic:
- V1 bounded equals V1 stock, byte for byte, at every k.
- V2 is identical across 1, 4, 8 and 16 threads, and across `recursive` and `recursion`.

Caps escalated from 16 GiB on OOM. There were 13 OOMs in all, each followed by a pass at the next
cap. One k = 0 V2 repeat (peak 15.8–15.9 GiB) OOMed at 16 GiB; it was rerun at 32.

**Compact** (peak RSS in GiB; proving-stage seconds at 4 cores):

| k | Total steps | Base cells | V1 stock | V1 bounded | V2 small |
|---:|---:|---:|---|---|---|
| 0 (×3) | 537k | 139.7M | 19.5–19.6, 16.1 s | 8.71–8.72, 28.4 s | 15.75–15.92, 14.6 s |
| 16 | 901k | 168.0M | 20.8, 17.4 s | 9.88, 30.5 s | 17.1, 15.5 s |
| 32 | 1.15M | 188.0M | 21.1, 18.1 s | 10.8, 31.0 s | 17.4, 16.1 s |
| 64 | 1.58M | 231.0M | 21.7, 19.8 s | 12.5, 34.4 s | 19.5, 17.6 s |
| **106 (×3)** | 2.12M | 300.6M | **25.6–26.2, 22.4 s** | **15.1, 38.8–39.7 s** | **22.2–22.5, 20.0–20.2 s** |

Proofs are 224–237 kB (V1) and 226–236 kB (V2).

At k = 106 the V2 stages were:
- Cairo stage (`cairo-only`): 20.85 GiB, 14.1 s.
- Recursion stage alone (proxy, stock mode): **8.62 GiB**, 6.7 s. The plan assumed 4.6–4.8 GiB.

**QM31 at k = 106** (V2 Cairo stage, 32 GiB cap):
- qm31: 18.64 GiB, 12.6 s.
- qm31_compact: 16.24 GiB, 10.6 s.
- Both verify natively. The fixed small-path verifier rejects both ("field element value out of
  range").
- U2 negative controls:
  - `recursive` panics building the circuit (aux data 2,696 against 2,695: one extra component);
  - `recursion` fails deserialization (`ValueOutOfRange`).

**Thread scaling, k = 106** (proving seconds / peak GiB):

| Threads (cores) | Compact, V2 small recursive | Speed-up | qm31 Cairo stage | Speed-up |
|---:|---|---:|---|---:|
| 1 (0) | 66.9 s / 22.1 | 1.0 | 44.4 s / 18.6 | 1.0 |
| 4 (0–3) | 19.8 s / 22.8 | 3.4 | 12.7 s / 18.7 | 3.5 |
| 8 (0–7) | 12.5 s / 22.6 | 5.3 | 7.5 s / 18.7 | 5.9 |
| 16 (0–15) | 9.7 s / 23.3 | 6.9 | 5.35 s / 19.0 | 8.3 |

**Memory model** ([model.json](results/phase2/model.json)). Peak RSS is linear in the Cairo
base-trace cells: the sum of every committed column's rows, from `prove-small trace`. Fits on the
statement family (compact and QM31):

| Prover | Peak GiB | r² (max residual) |
|---|---|---|
| V2 small | 9.96 + 4.15 per 10⁸ cells | 0.996 (0.37) |
| V2 Cairo stage | 7.34 + 4.56 per 10⁸ | 0.980 (0.26) |
| V1 stock | 14.03 + 3.85 per 10⁸ | 0.967 (1.26) |
| V1 bounded | 3.20 + 3.97 per 10⁸ | **0.9997** (0.09) |

Steps predict memory poorly: r² is 0.2–0.56 on all points. The Blake fixture sits above the family
line, because of its many big-felt memory values.

**Projected faithful R0 V6.** Take k = 102 and add 5–15% account steps for the relation's selects
and range checks. The 5–15% is an assumption.

| | Base cells | V2 small | V1 stock | V1 bounded |
|---|---:|---|---|---|
| Compact (felt252) | 303–321M | 22.5–23.3 GiB, 20–21 s | 25.7–26.4 GiB | 15.2–15.9 GiB, 39–41 s |
| qm31_compact (needs U1, U2) | 202–210M | 18.4–18.7 GiB, 17 s | – | 11.2–11.6 GiB* |

\* The V1 bounded model applied to the qm31_compact trace, as a stand-in for a bounded V2 small
path, which does not exist.

## Tier verdicts (decision rule; host with cgroup caps, not physical machines)

| Tier | Felt252 compact (measured at k = 106; projected V6) | Native M31 (qm31_compact, projected) |
|---|---|---|
| 16 GiB desktop (≤ 12 GiB bounded) | **fail**: V1 bounded 15.1 GiB (V6: 15.2–15.9) | borderline: 11.2–11.6 GiB, only a projection |
| 32 GiB desktop (≤ 26 GiB) | **pass**: V2 small 22.5 GiB / 20 s *unbounded* (V6: 22.5–23.3); V1 bounded 15.1 GiB / 39 s | pass (projection) |
| Browser (≤ 3.5 GiB, wasm32) | **fail**: the recursion stage alone is 8.6 GiB | fail |
| Phone (≤ 2 GiB) | **fail** | fail |

**S2 passes.** The felt252 run is at most 26 GiB under a 32 GiB cap, both V1 bounded (15.1 GiB) and
V2 small unbounded (22.5 GiB). The 32 GiB verdict still needs phase 3's items: the faithful
statement, uniform shapes, and ZK over the full witness.

## Findings

- **The OS cost is mostly hashing the account's executed bytecode.** Across all 19 captures the OS
  segment's steps fit
  `21.6k + 15.05 × (small hashed felts) + 36.7 × (big hashed felts)`, with a maximum residual of
  1.2k.
  - QM31-opcode instructions carry the opcode extension above bit 63, so each one is a big felt:
    8 Blake words instead of 2.
  - This is why qm31 costs 600k OS steps and 5,762 OS Blake, and why the plan's 0.73–1.0M
    estimate became 1.20M.
  - A looped (compact) qm31 permutation is the obvious lever.
- **Measured steps against the plan's estimates, at k = 106:**
  - compact: 1.92M (estimate 1.6–1.9M);
  - unrolled: 2.31M (estimate 1.9–2.2M);
  - qm31: 1.20M (estimate 0.73–1.0M).
- **Blake is above the plan's estimate** of 3.5–5.3k: compact 5,852, qm31 7,676.

## Reproduce

```sh
python3 bench/m31-device-proof1/build.py prover            # stock V1, 12 cores (6-17), 32 GiB cap
python3 bench/m31-device-proof1/build.py prove-small       # V2 small-path driver
python3 bench/m31-device-proof1/build.py verifier
A=bench/m31-private-wrapper/results; F=b209ce7531787fdeff19146a9cc33b473b9ad03985e106ae23583d79d7b9a677
python3 bench/m31-device-proof1/run_v1.py --variant stock   --fixture $A/blake-state-v1/fixture.json --fixture-sha256 $F \
  --request $A/outer-blake-v1-cap32/public-request.json --expected-response $A/outer-blake-v1-cap32/public-response.json --cap 32 --name NAME
python3 bench/m31-device-proof1/run_v1.py --variant bounded ...same...
python3 bench/m31-device-proof1/capture.py capture $A/blake-state-v1/fixture.json $F $A/outer-blake-v1-cap32/public-request.json OUT
python3 bench/m31-device-proof1/run_v2.py --mode recursive --pie OUT/os.pie.zip --cap 64 --name NAME
python3 bench/m31-device-proof1/run_v2.py --mode recursive --pie target/proving-server/crates/privacy_prove/test_data/privacy_tx_cairo_pie.zip --cap 64 --name NAME
python3 bench/m31-device-proof1/report.py
python3 bench/m31-device-proof1/sweep.py prepare compact unrolled qm31
python3 bench/m31-device-proof1/sweep.py run compact 0 8 16 32 64 102 106 128
python3 bench/m31-device-proof1/sweep.py run unrolled 106      # plus 0 8 16 64 for the slopes
python3 bench/m31-device-proof1/sweep.py run qm31 32 64 106    # plus 0 8 16 for the slopes
python3 bench/m31-device-proof1/sweep.py prepare qm31_compact && python3 bench/m31-device-proof1/sweep.py run qm31_compact 0 8 16 32 64 106
python3 bench/m31-device-proof1/sweep.py summarize
# Phase 2 (after build.py prove-small; never during a build)
python3 bench/m31-device-proof1/phase2.py sweep 0 16 32 64 106
python3 bench/m31-device-proof1/phase2.py stages compact qm31 qm31_compact
python3 bench/m31-device-proof1/phase2.py scaling compact:recursive:32 qm31:cairo-only:32
python3 bench/m31-device-proof1/model.py
```

The runtime directory is `~/.local/share/templar/runs/m31-device-proof1/`. It holds the PIEs,
proofs, fixtures and requests. Build outputs go to `target/m31-device-proof1/`.

## Limits

- The statement is cost-faithful only. It omits the R0 V6 relation's selects and range checks
  beyond the canonical-word decode, and it makes no soundness claim.
- Input 1 is disabled, so its root equality is not exercised.
- Local capture does not enforce U1, and nothing was declared.
- The documentation error the plan lists (`qm31-opcode/README.md:65-66`) is outside this spike's
  file ownership and is not fixed here.
