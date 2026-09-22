# Compact recursion — mini-verifier pathfinding

Status: **M0 complete (floor measured); design review gate (M1) before any
blinding integration.** This experiment explores the "compact recursion"
route from [client-hiding/compact-recursion-design.md](../client-hiding/compact-recursion-design.md):
the client proves a compact statement as a custom AIR, verifies that proof
inside a circuit-DSL mini-verifier, and only the (zk-blinded) outer circuit
proof ever leaves the device. Trust level: identical to the V1 pipeline's
blinding class — not a new hiding argument.

## What M0 established

A custom-AIR proof is verified in-circuit end-to-end in the pinned stack
(`stark_verifier` + `simple_statement` adapter), and the verification
circuit itself proves in ~1.1 s at ~2.88 GiB RSS at trace log 20 —
confirming the ~2.6–2.9 GiB DSL floor is independent of client-gate count.
Details: [results/measurements.md](results/measurements.md).

## Next

- M1: Math Review of the design + the membership-AIR `Statement` adapter
  before implementation of the real (felt252/Poseidon) adapter.
- The shared blinding-qualification diagnostic (review conditions) covers
  this route's outer artifact and remains the standing gate.
