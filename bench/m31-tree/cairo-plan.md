# Cairo append-cost comparison plan

Local tool inventory: Scarb/Cairo 2.18.0, Sierra 1.8.0, snforge and sncast
0.63.0, starknet-devnet 0.6.0. Use explicit foundry 0.63.0 executable paths;
the plain shell `snforge` resolves to an older installation. No external account
or chain write is part of this experiment.

The archived push, controlled, ReturnNote and DeFi-return trees and the current
`packages/pool/src/tree.cairo` are byte-identical, SHA-256
`995e89a06f6a73bc1831fcea7586ef49128e5fa6649536ea557f1b4de4080dcf`.
The baseline copy will come from
[ReturnNote tree](/home/broody/development/templar/bench/return-note-e2e/cairo/src/tree.cairo).
It performs a depth-32 append, stores every updated node, lazily initializes
33 empty-tree values, and maintains a 256-root history ring seeded with the
empty root. Each felt252 parent uses `poseidon_hash_span([left,right])`, including
its final padding permutation.

The comparison keeps this tree algorithm and history policy identical. A batch
is the existing append operation repeated within one contract entrypoint; no
frontier-only storage or shared-ancestor batching optimization is introduced.
The M31 digest, encoding, domains, round constants and empty-leaf rules must be
approved by the Math Reviewer and match the native implementation before its
cryptographic code is written. Reference source is Plonky3
`00fe0a985b398d3ef1f10d69543ca2b8f9f236da`.

Planned local measurements for both hashes:

| State before measured call | Batch sizes | Included in measured entrypoint |
| --- | --- | --- |
| Fresh empty contract | 1, 2, 4, 8 | Lazy zeros, all ordered parent hashes, digest conversion/packing, all node/root/count writes and root-history maintenance |
| Warm contract after a fixed real prefix | 1, 2, 4, 8 | Same append path, including storage and history, without lazy initialization |

Warm setup will use a separate named entrypoint so its gas is not confused with
the measured append selector. Declaration/deployment and correctness assertions
also remain distinguishable. Record per-call gas using snforge 0.63.0
`--gas-report` and call traces, plus `--detailed-resources`; test-total resources
include test setup and must be labeled accordingly. Any storage-difference
accounting or L1-data estimates will be reported with the execution scope.

Correctness checks will compare independently generated native golden roots,
empty roots and several insert prefixes; preserve left/right order; test
canonical limb rejection and lossless digest packing; and cover zero-leaf,
capacity and root-ring behavior. A packed digest is an encoding of all digest
limbs, never field reduction or truncation. Its conversion cost belongs in the
contract call.

These are local VM/resource estimates under pinned tool versions. They are not
Sepolia/mainnet fees or production transaction-cost promises. Start with
snforge; a local devnet estimate is optional only if needed to resolve a resource
accounting gap. Builds/tests and native prover measurements must not overlap.
