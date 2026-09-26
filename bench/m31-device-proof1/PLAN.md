# Spike plan: full device-side proving over the M31 pool

Status: **scoped, not run** (2026-09-26). This plan feeds the future device-proving ADR (ADR-0027
decision 6: no prover server; submission still through a relayer).
- It was produced by three research reports and a synthesis. A skeptic then checked it against
  the repository, and its corrections are applied.
- Nothing here touches a chain.

## The question

Can a device run the R0 spend itself in Cairo, inside the pinned virtual OS, and produce Starknet's
**small proof** locally, with no server? Answer for four tiers:
- a 16 GiB desktop;
- a 32 GiB desktop;
- a browser;
- a phone.

## Expected answer (estimates, to be replaced by measurements)

| | Today: M31 emulated in felt252 Cairo | With native M31 (qm31 opcode) |
|---|---|---|
| Poseidon2-M31 permutations per spend | 106 in V5 ordinary, 102 in R0 V6 (`client-port/src/payment5.rs:624-715`) | same |
| Steps per permutation | 12,172 unrolled; about 12,700 with `compact_perm` | about 4,500 (standalone, gas off: `qm31-opcode/README.md:51-60`) |
| Virtual-OS steps per spend | **about 1.6–1.9M** (compact; 1.9–2.2M unrolled) | **about 0.73–1.0M** |
| Blake compressions (working cap 8,192) | about 3.5–5.1k | about 3.4–5.3k |
| Components over 2²⁰ | unmeasured: the P5 bridge profile does not carry over | unmeasured |
| Peak memory, stock prover | **about 64–75 GiB** (central estimate) | **about 34–43 GiB** |
| Peak memory, bounded | roughly 0.43–0.63× the matching unbounded baseline | about 15–27 GiB |

For scale:
- the largest small proof produced under 16 GiB was 196,470 steps at 15.38 GiB, and 223,540
  steps ran out of memory (`bench/native-counted-shapes/results/measurements.md:6`,
  `bench/native-shapes/results/measurements.md:6`);
- the largest ever was 589,958 steps at 29.05 GiB under a 32 GiB cap
  (`bench/m31-private-wrapper/README.md:84-87`).

**Expected verdict:**
- **Today:** infeasible on every consumer tier. On a large host the latency would be comparable to
  the split route (about 55–65 s for 4 cores). Memory is what rules it out.
- **With native M31:** at best the 32 GiB desktop tier; phones and browsers are out.
  - The recursion stage alone peaks at 4.6–4.8 GiB, and bounded mode fails at a 4 GiB cap.
  - A browser would need Memory64, which is capped at 16 GiB and missing in Safari. Re-check that
    before the ADR.

**Upstream blockers for native M31:**
- **U1:** the `qm31_*`/`m31_*` libfuncs are in Cairo's `all.json` but not in `audited.json`, which
  Starknet enforces. No public schedule is known.
- **U2:** the small path's recursion circuit has no `qm_31_add_mul_opcode`. Its 57 components are
  listed in `privacy_circuit_verify/src/consts.rs:72-130`; the large path does have the opcode
  (`all_components.rs:87`). It needs a new circuit with a root Starknet accepts.

**Proof version.**
- The deployed Sepolia gateway accepted V1 small proofs and refused PROOF2 (2026-09-20).
- The upstream gateway defaults in sequencer PR #15122 allow only V2. V1's deprecation is plausible
  but unconfirmed.
- Pool V3's adapter class requires `facts[0] == 'PROOF2'` and pins one statement account
  (`bench/m31-pool/cairo/src/adapter.cairo:60`), and pool V3 has one R0 verifier slot. So a
  device route needs a new adapter class, and a chosen small-proof version. ADR-0027 decision 2 makes
  V6's adapter a routing class, so a device route is added as a route through the timelock, not
  as another R0 swap.

## Plan

**Ground rules**
- No chain access: state comes from a synthetic authenticated fixture on loopback, as in the
  589,958-step run.
- Runtime directories go under `~/.local/share/templar/runs/m31-device-proof1/`.
- Timed runs use pinned physical cores, zero swap, one at a time, and never run during builds.
- Code lives in `bench/m31-device-proof1/`. The statement is cost-faithful, not production, and
  makes no soundness claim.

**Phase 0: restore and calibrate (1 day).**
1. Check binary hashes. Rebuild the **stock** V1 prover and verifier from pinned sources.
   `target/bounded-memory/bin/baseline-prover` is the cairo-memory low-memory build (about
   8.95 GiB and 16.6 s on the ordinary spend), not stock.
2. Take bounded mode's full environment from `bench/bounded-memory/run.py`:
   `TEMPLAR_LOW_MEMORY=1`, `TEMPLAR_RECOMPUTE_CAIRO_COMMITMENTS=1`,
   `TEMPLAR_CAIRO_COEFFICIENTS=1`, and both column settings.
3. Calibrate by replaying the archived, fully local 589,958-step fixture
   (`results/outer-blake-v1-cap32`) with the same binaries. Record a V2 small-path stock baseline
   too. ADR-0018 recorded 14.22 GiB and 11.2 s for 2/2/1.

**Phase 1: capture sweep, no proving (2 days).**
1. A cost-model statement account decodes about 1k witness felts with canonical checks, runs `k`
   Poseidon2-M31 permutations, computes the `spend5` binding and emits the pinned message.
   - The permutation is chosen by feature: `compact_perm`, unrolled, or qm31.
   - The qm31 variant can be captured locally, since local capture does not enforce U1.
2. Sweep compact `k ∈ {0, 8, 16, 32, 64, 102, 106, 128}`, unrolled at 106, and qm31 at
   `{32, 64, 106}`.
3. Per capture, record:
   - virtual-OS and bootloader steps, builtins, and opcode counts;
   - every component's log size, including `memory_id_to_big` and the full `add`/`mul` row counts;
   - Blake by segment, and **hashed (visited) CASM felts**, as opposed to executed felts;
   - calldata felts, and contract-mode steps per permutation for the sponge-framed hashes (42 of
     the 106 go through `hash.cairo:33-65`).
4. **Stop gate S1:** any non-hash component over 2²⁰, Blake over 8,192 or Poseidon over 8,192 at
   `k = 106`. The qm31 variant also stops above 1.2M steps. Check that the fixed small-path
   recursion accepts the resulting component set.

**Phase 2: proving sweep (2–3 days, about 5 h of compute).**
1. Compact at `k ∈ {0, 16, 32, 64, 106}`: V1 stock, V1 bounded, and V2 small, unbounded. Caps step
   up 16, 32, 64, then 96 GiB on running out of memory. Three repeats at the ends.
2. qm31 at `k = 106`: the Cairo stage only, plus the recursion stage measured in stock mode and
   labelled a proxy, since U2 needs a new circuit. Then attempt the full recursive proof and record
   its expected failure as the negative control for U2.
3. Thread scaling at 1, 4, 8 and 16 threads, with explicit physical-core affinity.
4. Every proof is verified, and rejected after a one-byte mutation.
5. Fit memory against padded rows or trace cells, not steps.

**Phase 3: a faithful R0 V6 statement in Cairo (3–4 days).** Run only if gate S2 passes: the qm31
projection, or the felt252 run, is at most 26 GiB bounded under a 32 GiB cap.
- Differential snforge tests against `payment5.rs`, with a zero account and negative controls.
- Four spend kinds, whose component vectors must be uniform or paddable.

**Phase 4: WebAssembly check (1 day).** `cargo check` for wasm32, and for wasm64 with
`-Zbuild-std`, on the prover crates. Inventory the blockers: tempfile, Tokio, threads. Run it only
if the bounded native peak is at most 3.5 GiB.

**Phase 5 (optional): physical 16 GB and 32 GB machines,** only if a desktop tier passes on the
host with cgroup caps.

**Phase 6: the report and the ADR input (1 day).**

**Duration:** 7–10 working days, or 3 days if S1 stops the run and 6 days if S2 does.

## Decision rule

| Tier | Peak memory (bounded, zero swap) | Proving time, 4 cores |
|---|---|---|
| 16 GiB desktop | ≤ 12 GiB under a 16 GiB cap | ≤ 60 s |
| 32 GiB desktop | ≤ 26 GiB under a 32 GiB cap | ≤ 60 s |
| Browser | ≤ 3.5 GiB, wasm32 | ≤ 60 s |
| Phone | ≤ 2 GiB | ≤ 60 s |

Every tier also needs all components at or below 2²⁰, Blake at or below 7,000 (a margin under
S1's hard stop at 8,192), uniform or paddable shapes, and a verified proof.
- **Feasible now:** the faithful felt252 statement passes a tier.
- **Feasible with native M31:** felt252 fails, but the qm31 projection passes a tier. The ADR then
  says "deferred on upstream (U1, U2)".
- **Infeasible:** the qm31 variant fails S1, or exceeds 26 GiB or 60 s.

## Owner's answers (2026-09-26)

1. **Machines:** only the 128 GiB host (M0). The desktop tiers are judged under cgroup caps
   there. Physical 16 GB and 32 GB machines are not available, so the verdict for those tiers
   carries that caveat.
2. **Target:** the **V2 small proof**. V1 is measured as a secondary arm, to learn whether the
   statement would also fit V1's capacity. The phase 2 sweep already runs both.
3. **Upstream (U1, U2):** the owner has asked StarkWare (2026-09-26).

## Future ADR outline

"Device-side small proofs over the M31 pool". Options:
- (a) adopt now for desktops of at least N GiB with felt252 emulation, only if measured;
- (b) defer until U1 and U2, the default expectation;
- (c) reject and keep the split route.

If it is adopted or deferred:
- R0 V6 in Cairo, with the same binding and message shape;
- a device account tag, and a new adapter instance on unchanged pool V3;
- submission still through a relayer.

Small-path zero-knowledge over the full witness is a hard gate. Shapes must be uniform across
spend kinds. The relation is implemented twice, so differential tests and a Math Reviewer are
required.

## Documentation errors found

`bench/m31-private-wrapper/qm31-opcode/README.md:65-66` calls 0.5M steps "the largest PROOF1
(16/16/8)". That case was 196,470 steps. Fix it with the spike.
