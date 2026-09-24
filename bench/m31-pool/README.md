# Option A: on-chain Poseidon2-M31 note tree, measured

2026-09-23. A pool that appends R0 outputs to an **on-chain M31 tree** (tree-strategy option A),
measured against the reference felt252 pool in the same harness. Both pools do the same state
work: the same guards, 256-root history, nullifier set, delivery digests and events.

## Result

Per call on a warm pool. L2 gas is measured in-test around the call, which agrees with
snforge's `--gas-report` to within 0.1%. L1 data gas is per call, from test totals with and
without the call. STRK uses mainnet median prices (below); Sepolia prices give the same figures
to within 0.5%.

| Operation | felt252 reference | M31, single-permutation nodes | M31, sponge nodes |
| --- | ---: | ---: | ---: |
| **Deposit** (1 new note) | 6.27M · 0.131 STRK | 57.70M · **1.202 STRK** (9.2×) | 110.42M · 2.299 STRK |
| **Transfer** (2 in, 2 out; batched append, average) | 11.53M · 0.240 STRK | 53.34M · **1.111 STRK** (4.6×) | 107.71M · 2.243 STRK |
| **Partial withdrawal** (2 in, 1 out + withdrawal) | 6.75M · 0.141 STRK | 52.03M · **1.084 STRK** (7.7×) | 104.76M · 2.182 STRK |
| **Full withdrawal** (2 in, withdrawal only) | 1.41M · 0.029 STRK | 1.88M · **0.039 STRK** (1.3×) | 1.88M · 0.039 STRK |

The M31 rows use frontier storage. Storing every node, as the reference does, adds about 4% L2
gas and roughly doubles L1 data gas: transfer at an even index 53.98M, deposit 59.80M. Exact
values are in `results/summary.json`, and raw runs in `results/*.log`.

**Reading it:**
- **Cost follows appends.** Each new note costs 32 node hashes on its own. A deposit adds 4
  permutations for the on-chain commitment. A node hash is about 1.53M L2 gas with
  single-permutation nodes, or 3.18M with sponge nodes; hashing is over 90% of every call that
  appends.
- **A full withdrawal appends nothing,** so it costs about the same as the reference.
- **Every operation fits** well under the 1B-per-transaction limit.
- **L1 data gas is small** next to L2 gas in both pools.

## Caller account class and declaration size (measured on Sepolia)

- **The caller's account must be Sierra 1.7 or later.** Otherwise the whole call tree is billed
  in Cairo steps, and the pool costs about 2.7× the figures above: a deposit's pool call is
  155.5M L2 gas on Sepolia from a Sierra 1.4 account. From a Sierra 1.7 account, a transfer's
  `apply_spend` simulates at 52.2M, matching this table. Details in
  [`bench/m31-sepolia`](../m31-sepolia/README.md).
- **Declaring a class costs 40,960 L2 gas per Sierra + CASM felt.** The default pool class is
  3.47B, about 73 STRK on Sepolia. Feature `compact_perm` (`src/perm_compact.cairo`) has one
  full-round function over a constant table and a four-partial-round group. The unrolled form
  has 30 round functions. Both pass all 64 tests.

  | Permutation | Sierra + CASM | Declaration | Deposit | Transfer (index 6) |
  | --- | ---: | ---: | ---: | ---: |
  | Unrolled (default) | 84,613 | 3.47B | 57.70M | 51.81M |
  | `compact_perm` | 43,621 | 1.79B (−48%) | 60.30M (+4.5%) | 54.13M (+4.5%) |

  At 20.8 gwei-fri the compact class saves about 35 STRK once and costs about 0.05 STRK more
  per append. It breaks even at about 700 appending transactions. Rolling every partial round
  separately gave 1.72B, but at +20% gas.

## Batched two-output append

A transfer's two outputs land at adjacent indices `i` and `i + 1`, so their paths to the root
meet and then coincide. `insert_two` hashes both paths while they differ, the meeting node
once, and the shared path once:
- `i` even: the outputs are siblings, so **32 node hashes**;
- `i` odd: `32 + t`, where `t` is the number of trailing 1-bits of `i`;
- over uniform positions: **33 on average**, against 64 for two separate appends.

The root is identical to two `insert_leaf` calls, and only it enters the root history. Clients
and wallets are unaffected.

| Transfer start | Node hashes | Single-permutation nodes | Sponge nodes |
| --- | ---: | ---: | ---: |
| before batching (two appends) | 64 | 101.69M · 2.118 STRK | 207.14M · 4.314 STRK |
| index 6 (even) | 32 | 51.81M · 1.079 STRK | 104.53M · 2.177 STRK |
| index 5 (odd, t = 1) = **the average** | 33 | 53.34M · 1.111 STRK | 107.71M · 2.243 STRK |
| index 7 (`0b111`, t = 3) | 35 | 56.46M · 1.176 STRK | 114.13M · 2.377 STRK |

Golden tests mix single and paired appends over 12 leaves, with pairs starting at indices 1, 4,
7 and 9. They reproduce the client's roots after every step in both node formats and both
storage modes.

## Fees

Fee = `L2 gas × L2 price + L1 data gas × L1 data price`, for the pool call only.

**Mainnet** (`results/fees-mainnet.json`, read through the local mainnet node): 201 blocks
sampled every 100 over 9.4 hours (blocks 15,292,777–15,312,777, Starknet 0.14.3).

| Price | Min | Median | p90 | Max |
| --- | ---: | ---: | ---: | ---: |
| L2 gas, gwei-fri | 20.56 | 20.82 | 21.85 | 27.08 |
| L1 data gas, gwei-fri | 28.8 | 155.4 | 531.8 | 588.3 |

At the window's highest prices the fees above rise by about 30%: a transfer costs 1.45 STRK
(M31, single-permutation nodes) against 0.31 STRK.

**Sepolia** (`results/fees-sepolia.json`): L2 gas at a flat 20.75 gwei-fri, L1 data gas at about
581 gwei-fri. The fees are within 0.5% of the mainnet medians.

A real transaction adds account validation, calldata and the PROOF2 fact check, roughly the
same for both pools apart from R0's longer calldata.

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

## Correctness (40/40 tests)

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

## Policy notes (ADR-0025, experimental)

Spec: [policy-note-spec.md](../../docs/policy-note-spec.md), reviewed before implementation
(`reviews/policy-note-design-*.md`). The implementation has also been reviewed
(`reviews/policy-note-impl-*.md`): the math review gave GO, and the contract review gave a
conditional GO on missing wallet test vectors. Every finding has been addressed:
- the wallet vectors are now pinned (`vectors/policy-wallet-kat.json`, `test_policy_wallet.py`);
- recovery survives a hostile backup, discovery checks each leaf, splits take `x` from the
  event, and there is an acceptance checklist;
- the pool now rechecks the refund shape, caps controller data and emits `PolicyVerifierSet`;
- the native reference rejects unpaired withdrawals and non-canonical felts.

Both reviewers' tests are in the repo: `tests/test_policy_adversarial.cairo` and
`tests/test_policy_e2e_adversarial.cairo` (33 tests), and
`client-port/tests/policy_p1_malicious.rs` (11 malicious-witness tests; `--features tamper`).

- **Relation.** P1 (`client-port/src/policy.rs`) is a separate relation next to R0, which is
  unchanged. A policy note is an ordinary leaf whose receiver is `H(PRECV, H(PNK, cap) ‖ policy)`,
  so a deposit or an R0 output creates one. Settling it proves one committed outcome: fixed, or a
  split with a public `x`. Circuit: 231,512 qm31 rows with single-permutation nodes (R0: 182,947).
- **Bridge and account.** `client-port/cairo-p1` (41 outputs, tag `P1V1`/`P1C1`, binding
  `TMP1_BIND_V1`, message tag `TMPZP1_POLICY_V1`). `Proof2Adapter` now takes its account tag at
  deployment, so the P1 path has its own adapter.
- **Pool.** `apply_policy_spend` (`policy.cairo`) checks the statement. Up to the deadline it calls
  the pinned-class controller's `templar_apply_policy`. After the deadline only the refund
  (outcome 0) settles, without a controller. `policy_escrow.cairo` is the reference escrow: the
  handle is the arbiter, and approvals are keyed by `(arbiter, policy_id)`, written once and stored
  as `outcome + 1`.
- **Wallet.** `policy_note.py` covers policies, spends and the binding. `policy_wallet.py` covers
  the seed derivations, the `M301`/`PB01`/`PS01` plaintexts, the reproducible refund sealed box
  and seed-only recovery. The spending and incoming keys are fixture derivations.

**Local end to end with real proofs** (`policy_e2e.py`,
[results](results/policy-e2e.json)):
1. A depositor creates two escrow notes by deposit.
2. An executor holding only note A's opening proves the arbiter-approved release.
3. The depositor, from the seed alone, recovers note B and proves its refund after the deadline.
4. Each proof goes through the P1 bridge (31/31 cases), the virtual OS (exact message) and PROOF2.
5. Both settle in snforge through the P1 adapter, and the pool's tree ends at the root the
   beneficiary's wallet computed.
6. The beneficiary finds its two notes by trial decryption and proves an ordinary R0 spend of them.

| | Release (A) | Refund (B) |
|---|---|---|
| client proof | 5.3 s, 0.31 GiB, log 18 | 1.9 s, 0.30 GiB, log 18 |
| bridge | 2.02M steps | 1.96M steps |
| virtual OS | 3.41M steps | 3.33M steps |
| PROOF2 | 111.0 s, 257,470 B, 50.9 GiB | 110.8 s, 253,006 B, 51.7 GiB |
| `apply_policy_spend` L2 gas | 52.4M (two notes) | 51.5M (one note) |

The settlement gas excludes the PROOF2 fact check and account validation. The snforge rejection
tests run against real facts: no approval, a cancelled approval, a replay, another proof's facts,
a redirected output, and a rebound deadline.

## Limits

- These are snforge local VM measurements under Scarb 2.18.0 and snforge 0.63.0, not Sepolia or
  mainnet fee quotes. Fees depend on the L2 and L1 data gas prices at the time.
- Both pools use a mock verifier, so the fact check that authenticates the PROOF2 facts carrying
  the binding is not included. It is the same stand-in in both.
- The measurements cover the pool call only, not the full transaction. Account validation,
  per-transaction overhead and calldata are excluded. R0 calldata is larger: roots, nullifiers
  and commitments are nine words each instead of one felt.
- The M31 formats are experimental. Single-permutation nodes await review (math review D).
