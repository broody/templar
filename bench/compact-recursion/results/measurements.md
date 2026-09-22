# Compact-recursion M0 — floor measurement

Recorded 2026-09-22. Single-run floor measurement of the M0 harness in
[client/src/main.rs](../client/src/main.rs): prove a custom AIR (the pinned
`simple_air` squared-Fibonacci example), verify that proof in-circuit via the
generic `stark_verifier` machinery, then prove the verification circuit with
the pinned circuits configuration and natively verify the result.

No privacy claim attaches to any artifact here. This establishes the
client-side floor for the compact-recursion design
([design doc](../client/../compact-recursion-design.md)) — not a privacy
qualification.

## Result

| Metric | Value |
| --- | --- |
| Inner statement | `simple_air` squared-Fibonacci (pinned example) |
| In-circuit verification of inner proof | PASS (`novalue_circuit.check(values)`); topology equality holds |
| Verification-circuit trace log size | **20** (lifting 22 with blowup 2) |
| Dominant components | `verify_bitwise_xor_12`/`xor_10` tables at log 20 (fixed); `blake_g_gate` at log 15 (32,768 rows, scales with inner-proof Merkle work); `qm31_ops` log 15 |
| Outer proof config | pinned circuits config: pow 26, blowup 2, 35 queries, fold 4 |
| Proving wall time | **1.07–1.08 s** (default rayon threads, dev host) |
| Peak RSS | **~2.88 GiB** (3,077,108 KB, `/usr/bin/time -v`) |
| Native verify of the outer proof | 2.7 ms; valid proof accepted |
| Mutation control | trace-root mutation rejected (rejection surfaces at the interaction-PoW check, as expected for a transcript-root mutation) |

Context stats (gates in the verification circuit): 13,121 add, 9,066 mul,
7,928 pointwise_mul, 1,360 sub, 769 guess, 101 inv, 512 eq, 2,048 triple_xor,
4,096 m31_to_u32, 242 blake_updates, 72 permutation inputs.

## Interpretation

1. **The DSL floor is confirmed at ~2.6–2.9 GiB** for any circuit at trace
   log 20 with the pinned config — matching the direct-air tiny-circuit
   measurement (2.605 GiB) and independent of client-gate count. The fixed
   XOR tables (log 20) plus FRI/quotient machinery dominate.
2. **`blake_g_gate` scales with the inner proof's Merkle work** (log 15 here
   for the toy inner proof). The design doc's estimate for the real
   membership inner proof (~5–6k compressions → blake at ~log 20) remains
   the binding projection: **~3–3.5 GiB total** for the real mini-verifier,
   above the 2 GiB browser target but well under the current V1 pipeline's
   5.7–6.3 GiB.
3. Proving cost is ~1 s for a toy inner statement; real-inner scaling adds
   witness-generation time roughly linear in blake rows.

## Environment and reproduction

- Toolchain `nightly-2026-01-15` (rustc 1.94.0-nightly, installed via
  rustup). `RUSTFLAGS="-Ctarget-cpu=native"`, release.
- **PATH note**: `/home/broody/bin/cc` is a Claude Code CLI shim that
  shadows the real compiler driver; all builds must run with
  `PATH="/usr/bin:/home/broody/.cargo/bin:/bin"` (this matches the recorded
  PATH in the repo's historical build metadata).
- Sources: path deps to the pinned trees `target/direct-air/stwo` (rev
  `489a0f3`) and `target/direct-air/stwo-circuits` (rev `5ef951a`),
  unchanged.

```bash
cd bench/compact-recursion/client
PATH="/usr/bin:/home/broody/.cargo/bin:/bin" CARGO_BUILD_JOBS=16 \
  RUSTFLAGS="-Ctarget-cpu=native" cargo +nightly-2026-01-15 build --release
PATH="/usr/bin:/home/broody/.cargo/bin:/bin" /usr/bin/time -v \
  ./target/release/templar-compact-recursion-m0
```

Machine: i9-10980XE (18C/36T), 125 GB RAM, Linux. Single run — not a
latency distribution. Machine-readable summary: [m0-summary.json](m0-summary.json).
