# Option A: on-chain Poseidon2-M31 note tree, measured

2026-09-23. A pool that appends R0 outputs to an **on-chain M31 tree** (tree-strategy option A),
measured against the reference felt252 pool in the same harness. Both pools do the same state
work: the same guards, 256-root history, nullifier set, delivery digests and events.

## Result

Per call on a warm pool (after 4 deposits and a transfer). L2 gas is measured in-test around the
call, which agrees with snforge's `--gas-report` to within 0.1%. L1 data gas is per call, from test
totals with and without the call. STRK uses Sepolia median prices (below).

| Operation | felt252 reference | M31, single-permutation nodes | M31, sponge nodes |
| --- | ---: | ---: | ---: |
| **Deposit** (1 new note) | 6.27M · 0.130 STRK | 57.69M · **1.197 STRK** (9.2×) | 110.42M · 2.292 STRK |
| **Transfer** (2 in, 2 out) | 11.53M · 0.240 STRK | 101.69M · **2.111 STRK** (8.8×) | 207.14M · 4.299 STRK |
| **Partial withdrawal** (2 in, 1 out + withdrawal) | 6.75M · 0.140 STRK | 51.99M · **1.079 STRK** (7.7×) | 104.72M · 2.173 STRK |
| **Full withdrawal** (2 in, withdrawal only) | 1.41M · 0.029 STRK | 1.84M · **0.038 STRK** (1.3×) | 1.84M · 0.038 STRK |

The M31 rows use frontier storage. Storing every node, as the reference does, adds about 4% L2
gas and roughly doubles L1 data gas: transfer 105.97M, deposit 59.80M. Exact values are in
`results/summary.json`, and raw runs in `results/*.log`.

**Reading it:**
- **Cost follows appends.** Each new note costs 32 permutations with single-permutation nodes,
  or 64 with sponge nodes. A deposit adds 4 more for the on-chain commitment. At about 1.5M L2
  gas per permutation, hashing is over 90% of every call that appends.
- **A full withdrawal appends nothing,** so it costs about the same as the reference (1.84M vs
  1.41M; the difference is hashing nine-word nullifiers into map keys).
- **Every operation fits** well under the 1B-per-transaction limit.
- **L1 data gas is small** next to L2 gas in both pools.

## In STRK, at Sepolia prices

These use gas prices from Sepolia blocks 15,506,259–15,506,308, read through the local node:
- L2 gas: 20.75 gwei-fri, flat across all 50 blocks, apparently Sepolia's floor;
- L1 data gas: about 581 gwei-fri.

The fee is `L2 gas × L2 price + L1 data gas × L1 data price` (`results/fees-sepolia.json`).
It covers the pool call only. A real transaction adds account validation, calldata and the
PROOF2 fact check, roughly the same for both pools apart from R0's longer calldata. Mainnet
prices will differ.

## What was built (`cairo/`)

- `perm.cairo`: the width-24 Poseidon2-M31 permutation (Plonky3 Mersenne31, 8 full + 22 partial
  rounds), fully unrolled with lazy reduction, from the Cairo performance review.
- `hash.cairo`: the client's framed rate-15 sponge (overwrite absorption, as
  `membership::sponge`), both node formats, the note commitment, the 28-bit felt and 16-bit
  amount limbs, canonical digest reading, and lossless two-felt packing.
- `tree.cairo`: a depth-32 append-only tree with the reference's 256-root ring. It has two
  storage modes: every node (`get_node` serves paths) or frontier only. Empty subtrees are
  generated constants (`zeros.cairo`).
- `pool.cairo`: `deposit` computes the commitment from `inner`, then transfers and publishes.
  `apply_spend` checks chain, pool and token, recomputes the R0 V2 binding (the bridge account's
  `TMR0_BIND_V2`), asks the verifier for the verdict, checks the root is known and the nullifiers
  unused, and marks them. It then publishes the active outputs (a zero commitment marks an
  inactive slot) and pays out the withdrawal, if any.
- `baseline/`: an unmodified copy of the reference pool plus `tests/test_cost.cairo`, the same
  measurement for a 2-in/2-out ordinary spend.

## Correctness (36/36 tests)

- **Golden vectors from the Rust client** (`client-port/examples/pool_vectors.rs` → `vectors.json`
  → `gen_cairo.py`):
  - the permutation, plus extreme and random inputs from an independent Python reference
    (`gen_perm.py`) that also agrees with Rust;
  - the empty-subtree chain in both formats, recomputed by `node`;
  - roots after six successive inserts, for both node formats and both storage modes. The Rust
    side checks its frontier roots against a full level-by-level tree;
  - a deposit commitment;
  - lossless packing;
  - the R0 V2 binding of a real partial-withdrawal statement, against the bridge's
    independent Python reference (`binding-statement.json`).
- **Pool behavior:**
  - a spend marks both nullifiers and publishes both outputs;
  - replay and duplicate nullifiers are rejected;
  - unknown roots, changed outputs (binding) and non-canonical digest words are rejected;
  - a spend against a root that later deposits superseded is still accepted;
  - withdrawals pay the recipient, and inactive slots append nothing;
  - a withdrawal without a recipient, a redirected withdrawal and an empty spend are rejected.

## Limits

- These are snforge local VM measurements under Scarb 2.18.0 and snforge 0.63.0, not Sepolia or
  mainnet fee quotes. Fees depend on the L2 and L1 data gas prices at the time.
- Both pools use a mock verifier, so the fact check that authenticates the PROOF2 facts carrying
  the binding is not included. It is the same stand-in in both.
- The measurements cover the pool call only, not the full transaction. Account validation,
  per-transaction overhead and calldata are excluded. R0 calldata is larger: roots, nullifiers
  and commitments are nine words each instead of one felt.
- The two outputs are appended independently. Appending both in one pass shares the upper
  levels and would roughly halve the spend's hashing (Cairo performance review, Q4). That is not
  implemented here.
- The M31 formats are experimental. Single-permutation nodes await review (math review D).
