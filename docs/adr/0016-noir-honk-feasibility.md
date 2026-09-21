# ADR-0016: Noir/Honk passes the Garaga compatibility benchmark; production scaling remains open

- Status: Superseded by [ADR-0018](0018-stwo-private-proving.md); benchmark retained as evidence
- Date: 2026-09-20
- Deciders: broody (pending)
- Related: ADR-0008, ADR-0014, ADR-0015

## Context

ADR-0015 records the incompatibility between gnark's emulated-field commitment
extension and the evaluated Garaga Groth16 verifier. A Noir felt252-Poseidon
microbenchmark tests whether UltraKeccak-ZK-Honk offers a compatible alternative.

The [benchmark and raw evidence](../../bench/adr16/README.md) establish:

- Two Starknet Poseidon permutations: 81,889 bb gates; a 131,072-point domain.
- Three 32-thread desktop proofs: median 0.653 s, ~207 MiB peak prover RSS,
  9,408-byte proofs. All pass native verification; a changed public input fails.
- Garaga 1.1.0 regenerates the same verifier and accepts a fresh proof in a
  Sepolia fork at block 15,348,508, returning the expected three hash limbs.
- Verification costs approximately 269.9 million L2 gas in snforge. This is
  an execution estimate, not a complete submitted-transaction fee.
- The 128-permutation compile was stopped at ~99.3 GiB RSS after 9m12s;
  no supported larger-circuit proving measurements are available.

The proof's 9.4 KB wire size is not the calldata size: the generated calldata
with hints contains 3,051 felts. Production public inputs also differ from the
microbenchmark's three-limb output.

## Proposed decision

Record Noir + UltraKeccak-ZK-Honk + Garaga as a demonstrated compatibility
option and pursue a bounded scaling experiment before selecting it for M2.
Keep ADR-0015 and the current production circuit intact pending that evidence.
This proposal does not drop M4 or accept the former draft's full-statement
latency projection.

If this stack is selected later, it avoids a new per-circuit ceremony while
retaining the universal KZG SRS trust assumption. It does not eliminate trusted
setup. Pin Noir, bb and Garaga together: their serialized formats are version-specific.

## Alternatives considered

- Continue ADR-0015's custom gnark limb layer: retains the Groth16 path but
  still requires implementation, differential testing, audit and verifier evidence.
- Select Noir/Honk immediately: compatibility is demonstrated, but compiler
  scaling, full-statement proving and transaction costs remain unmeasured.
- Treat the two-permutation numbers as full-statement predictions: rejected;
  domain rounding, memory growth and verifier specialization require measurements.

## Consequences

The compatibility question is answered for the golden-vector circuit. The next
experiment must capture compile/witness wall time and peak memory as well as
prove time, proof/calldata size and verifier execution for increasing sizes.
Investigate the observed compiler memory growth before another 128-permutation run.

A production port still needs the full M2 statement, canonical felt input
constraints, eight scalar public inputs matching the pool interface, adversarial
tests and audit. Larger VKs need their own generated verifier and gas measurement;
the current result does not establish circuit-size-independent verification cost.
