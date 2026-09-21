# ADR-0017: Desktop feasibility favors native BN254 hashing

- Status: Superseded by [ADR-0018](0018-stwo-private-proving.md); production hash migration not adopted
- Date: 2026-09-20
- Deciders: broody
- Related: ADR-0008, ADR-0012, ADR-0014, ADR-0015, ADR-0016

## Context

The user clarified the target as ordinary desktops with standard RAM. The
working envelope is a 16 GB host, preferably ≤4 GiB / maximum 6 GiB client
memory, no swap dependence, and preferably ≤30 s / maximum 60 s payment
preparation. These are product targets; native CLI measurements on a capped
server CPU are not a consumer-machine or browser validation.

The [bounded pathfinding experiment](../../bench/desktop/README.md) compares
Starknet felt252-Poseidon emulation against native BN254 Poseidon2 while keeping
Noir/bb/Garaga and the Keccak ZK-Honk transcript pinned. Compilation is measured
separately as an offline build/distribution step, with a 32 GiB ceiling.

## Evidence

- The ordinary depth-32 2/2/1 native circuit has 12,965 gates; median prove
  0.26 s / 39.2 MiB peak prover RSS, witness 0.12 s / 59.7 MiB. Proof size is
  8,256 bytes. Calldata/hint generation adds roughly 2 s / 104 MiB.
- A 4/4/2 ordinary native variant has 20,336 gates and proves in 0.40 s /
  56.9 MiB. Fixed shape is not the dominant client constraint on this path.
- The emulated 2/2/1 statement and 32-pair hash chain exceed the pinned
  implementation's 32 GiB compile ceiling. No full-statement prover RAM is
  inferred from that failure.
- Cairo native hashing costs much more than the builtin: ~50.5 M versus
  ~0.42 M L2 gas for 32 pair hashes. The integrated ordinary payment costs
  ~396.3 M L2 gas net of setup/funding; a subsequent withdrawal ~271.1 M.
  These are local fork execution deltas, not live transaction fees.
- Two separately keyed wallet fixtures complete deposit → invoice payment →
  withdrawal with real Garaga verification. The sender never receives recipient
  secrets. Replay, withdrawal redirection and invalid witnesses reject.

## Proposed decision

Use native BN254 hashing as the next production-design candidate. Retain the
current production format while specifying and reviewing its replacement.
Do not build custom felt252 limb arithmetic unless further measurements show
native Cairo costs prevent meeting the product's fee/throughput requirements.
Do not prioritize reducing 4/4/2 solely for client memory: both native ordinary
shapes fit the measured budget, although only 2/2/1 has integrated Cairo evidence.

The experiment closes the desktop feasibility question for an ordinary native
statement on this host. Acceptance for release still requires an actual
consumer desktop/runtime run and production transaction cost/limit validation.

## Consequences

A native format needs u256 commitments, roots and nullifiers with canonical
BN254 bounds; modulo-felt252 truncation is not an encoding solution. Matching
sponge parameters, domains, serialization, deposit computation and statement
binding must be versioned together. This is a new pool format, not a drop-in
verifier swap. Honk still inherits a trusted universal KZG SRS.

The prototype is under `bench/desktop`, with no production controllers, fees,
events, bounded root ring or upgrade machinery. Its generated Cairo hashing
requires review and audit. The production tree-mutation and invoice-output
correctness fixes are independent and have already been applied to the current
pool/reference circuit. Controller-signed destinations and the governance trust
model remain separate release blockers.
