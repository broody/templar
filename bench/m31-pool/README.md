# Option A: on-chain Poseidon2-M31 note tree, measured

2026-09-23. A pool that appends R0 outputs to an **on-chain M31 tree** (tree-strategy option A),
measured against the reference felt252 pool in the same harness. Both pools do the same state
work: the same guards, 256-root history, nullifier set, delivery digests and events.

## Result

L2 gas per call on a warm pool (after 4 deposits and a spend). Measured in-test around the call,
which agrees with snforge's `--gas-report` to within 0.1%. L1 data gas is per call, from test
totals with and without the call.

| Pool | Deposit L2 gas | 2-in/2-out spend L2 gas | Deposit L1 data gas | Spend L1 data gas |
| --- | ---: | ---: | ---: | ---: |
| **felt252 reference** (`controlled-push-e2e`) | **6.27M** | **11.53M** | 480 | 1,056 |
| M31, single-permutation nodes, frontier storage | 57.69M (9.2×) | **101.58M (8.8×)** | 288 | 768 |
| M31, single-permutation nodes, every node stored | 59.79M | 105.85M | 672 | 1,344 |
| M31, sponge nodes, frontier storage | 110.42M (17.6×) | 207.02M (17.9×) | 288 | 768 |
| M31, sponge nodes, every node stored | 112.52M | 211.30M | 672 | 1,344 |

`results/summary.json` has the exact values, and `results/*.log` the raw runs. Cold and warm calls
cost the same within 0.3%, because the empty-subtree digests are compiled constants rather than
lazily initialized.

**Reading it:**
- Hashing dominates. An append is 32 permutations with single-permutation nodes, or 64 with
  sponge nodes. A deposit adds 4 for the note commitment, which the pool computes on chain.
  At about 1.5M L2 gas per permutation with its digest handling, the permutations make up over
  90% of every M31 call.
- The M31 spend costs **8.8×** the reference with single-permutation nodes, and **17.9×** with
  sponge nodes. Both fit well under the 1B-per-transaction limit.
- Storing every node, as the reference does so wallets can read paths from storage, adds only
  about 4% L2 gas, but roughly doubles L1 data gas: nine-word digests take two felts. Frontier
  storage writes less than the reference, but wallets then need paths from events or an
  indexer.
- L1 data gas is small next to L2 gas in both pools.

## In STRK, at Sepolia prices

These use gas prices from Sepolia blocks 15,506,259–15,506,308, read through the local node:
- L2 gas: 20.75 gwei-fri, flat across all 50 blocks;
- L1 data gas: about 581 gwei-fri.

The fee is `L2 gas × L2 price + L1 data gas × L1 data price` (`results/fees-sepolia.json`):

| Pool | Deposit | 2-in/2-out spend |
| --- | ---: | ---: |
| **felt252 reference** | **0.130 STRK** | **0.240 STRK** |
| M31, single-permutation nodes, frontier | 1.197 STRK | **2.108 STRK** |
| M31, single-permutation nodes, every node | 1.241 STRK | 2.197 STRK |
| M31, sponge nodes, frontier | 2.291 STRK | 4.296 STRK |
| M31, sponge nodes, every node | 2.335 STRK | 4.386 STRK |

These cover the pool call only. A real transaction adds account validation, calldata and the
PROOF2 fact check, the same for both pools apart from R0's longer calldata. Mainnet prices will
differ. The L2 price here appears to be Sepolia's floor.

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
  `apply_spend` checks chain, pool and token, recomputes the R0 binding (the bridge account's
  `TMR0_BIND_V1`), asks the verifier for the verdict, checks the root is known and the nullifiers
  unused, marks them, and publishes both outputs.
- `baseline/`: an unmodified copy of the reference pool plus `tests/test_cost.cairo`, the same
  measurement for a 2-in/2-out ordinary spend.

## Correctness (27/27 tests)

- **Golden vectors from the Rust client** (`client-port/examples/pool_vectors.rs` → `vectors.json`
  → `gen_cairo.py`):
  - the permutation, plus extreme and random inputs from an independent Python reference
    (`gen_perm.py`) that also agrees with Rust;
  - the empty-subtree chain in both formats, recomputed by `node`;
  - roots after six successive inserts, for both node formats and both storage modes. The Rust
    side checks its frontier roots against a full level-by-level tree;
  - a deposit commitment;
  - lossless packing.
- **Pool behavior:**
  - a spend marks both nullifiers and publishes both outputs;
  - replay and duplicate nullifiers are rejected;
  - unknown roots, changed outputs (binding) and non-canonical digest words are rejected;
  - a spend against a root that later deposits superseded is still accepted.

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
