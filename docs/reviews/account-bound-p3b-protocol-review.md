# M31 pool V3 (P3b): protocol review

- **Date:** 2026-09-26.
- **Scope:** uncommitted work on `feat/account-bound`:
  - `bench/m31-pool/cairo/src/{pool_v3,tree_v3,spend5}.cairo`;
  - the pool V3 tests;
  - `cairo-r5/pool_e2e`;
  - `results/pool-v3`.
- **Checked against:** spec §8 and §15 P3b.
- **Where I worked:** only in copies under `~/.local/share/templar/runs/review-p3b-protocol/`. Nothing
  under the repository was edited, and nothing was sent on chain.

## Verdict: GO

What holds:
- **Expiry:** `valid_until ≠ 0`, `block ≤ valid_until`, on the Q grid, and `≤ block + E + Q`.
- **Roots.** The current root is always accepted; a replaced root is accepted while
  `block − replacing block ≤ W`. Storage holds the replacing block plus one, so 0 is
  unambiguous. The rule applies on both spend paths and on P1.
- **Bootstrap:** a one-time `initialize`, with every entry gated by `NOT_INITIALIZED` until then.
- **Verifier changes:** timelocked propose/apply/cancel for both kinds, with events and views.
- **Carried fixes:** F17 on both sides of every ERC20 pull, F18, F30 and F19 are all present.
- **No fees and no gating (§8.6):** there is no fee state. Any account deposits, and any account
  submits a proved spend (`any_account_deposits_and_any_account_submits`, and the e2e's third-party
  submitter).
- **Owner powers:**
  - Only the timelocked verifier change can move or freeze funds.
  - `set_shadow_class` is an instant owner lever over `INVOKE`/`COMPUTE` routes only (AB-PV1).
  - `initialize` runs once, on an empty tree.
  - Ownership moves in two steps.
- **Reproduced:** 34/34 pool tests and 8/8 e2e tests pass. CASM is 80,283 felts.
- **Mutations:** I tried three mutants beyond the implementer's 20. Two were killed; one survived,
  which is a test gap (AB-PV4).

Pools cannot be upgraded, so decide AB-PV1 and AB-PV2 before P6 declares the class. Both fit the
CASM budget. Add AB-PV4's test now.

## Findings

**AB-PV1 (low) — `set_shadow_class` (§8.4, §8.6): an instant route gate.**
- **Problem.**
  - After F18, allowlisting a class makes every `INVOKE` to it revert (`INVOKE_TARGET`).
    Un-allowlisting a class makes every `COMPUTE` to it revert (`COMPUTE_TARGET`).
  - Both take effect immediately, and in-flight spends get no notice.
- **Scenario.** The owner allowlists the class of a popular swap adapter. In-flight invokes are
  included as reverted, with their calldata and asset public (the F03 linkage).
- **Scope.** No funds move, and plain withdrawals and transfers are unaffected. But §8.4's "none
  charges or gates users" is not true of this function.
- **Fix, either:**
  - route it through the same propose/apply timelock (measured +824 CASM felts; it fits); or
  - state it in §8.4 and §12 as an owner lever, and have the SDK and relayer re-read the allowlist
    immediately before any invoke.

**AB-PV2 (low) — §8.4 (your Q1): armed proposals never expire.**
- **Problem.**
  - A proposal can be applied at any time after `eta`.
  - Anyone who deposits after `eta` gets no T-long notice before it is applied.
- **Fix.**
  - Allow `apply` only within `[eta, eta + G]`. With G = T this needs no new storage. Measured: +280
    CASM felts, including AB-PV3's event.
  - Make the SDK rule normative: refuse deposits and warn while any proposal is pending or armed.
- **Your Q2.** Owner-only apply is right. A permissionless apply would race the owner's cancel.
  Re-propose with a fresh `eta` is fine.

**AB-PV3 (info) — a replaced proposal emits no event.**
- **Problem.** When a new proposal replaces a pending one, no event marks the old one as gone.
  Indexers have to infer it.
- **Fix.** Emit `VerifierCancelled` for the replaced proposal (included in AB-PV2's +280).

**AB-PV4 (low) — tests: `transfer_ownership`'s owner check is not pinned.**
- **Problem.** With `only_owner()` removed from `transfer_ownership` (my mutant X1), all 34 tests
  still pass.
- **Scenario if it regressed.** Anyone takes ownership (transfer to self, then accept), cancels a
  pending OS-rotation proposal, or proposes a verifier of their own.
- **Fix.** Add a stranger → `NOT_OWNER` test.

**AB-PV5 (info) — your Q3: the payout delta check.**
- Freezing is acceptable, and better than silent last-holder insolvency.
- **Document it in §8.5 and §14:**
  - An upgradeable token that starts taking a sender-side fee, or starts rebasing, freezes that
    asset's withdrawals, invoke budgets and P1 payouts, with no rescue.
  - In-pool transfers continue.
  - Recipient-side fees pass the check, and the recipient bears them.
- **SDK token list.** Flag upgradeable tokens. Share-rounding tokens (stETH-like) are already
  refused at deposit by F17.

**AB-PV6 (low) — your Q4: re-proofs and the root window.**
- **Problem.**
  - `W ≥ E + Q` protects a root and a `valid_until` only when both are taken at the same block.
  - sdk-spec §9.1 re-proves a record "with its identical witness" (SDK-M10). A re-proof that keeps
    the old root but takes a fresh `valid_until` can outlive the root.
- **Scenario.**
  - The root was replaced at block s, so it is valid until s + W.
  - A re-proof about 90 minutes later has `valid_until ≈ L₂ + E + Q > s + W`.
  - It then fails admission late, or lands on `UNKNOWN_ROOT`.
- **Fix (P4).**
  - Every proof, re-proofs included, takes its root, paths and `valid_until` from one `latest`.
    The inputs and the companion stay the same: the root is public, and the nullifiers do not
    depend on it.
  - Server admission also checks `get_root_superseded_at(root) + W ≥ send_deadline`.
- **No other liveness issue.** `max_proof_age = 1,024 < E + Q` only lowers the deadline to
  `base + 1,024` when the queue is short.

**AB-PV7 (info) — §11: the verifier ABI changed.**
- `get_verifier()` and `get_policy_verifier()` are now `get_verifier(kind)`.
- The server's per-job check (`pipeline.rs:95-102`) and the SDK's pin checks must switch to it,
  and should also read `get_pending_verifier(kind)`.
- List this in §11 under prover-server-spec §8 and sdk-spec §8 and §9.2.

**AB-PV8 (info) — deployment parameters and P1.**
- The constructor accepts any nonzero T and allows `W = E + Q` exactly.
- The P6 record and the SDK pins must enforce the policy: T ≥ 7 days on mainnet, and W with sync
  margin (the proposed 4,096).
- P1 statements have no `valid_until`. One on the current root stays valid on a quiet pool, as in
  V2, bounded only by P1's own deadline.

## Your questions

- **Q5, intermediate roots:** acceptable. They are genuine prefixes of the append sequence, so
  membership against them is sound. Each costs one storage write, and the SDK only uses final
  roots.
- **Q6, the e2e:** adequate for P3b. It runs:
  - real proofs;
  - the real statement account, whose bridge verifies them;
  - the real V5 adapter;
  - the pool's own binding;
  - facts laid out as the adapter expects, which the battle test (F31) matched against real
    Sepolia facts.

  Still open for P5: the pinned virtual OS producing that message and those facts with the real
  wallet classes, and PROOF2.
- **Q7, CASM headroom:** AB-PV2 plus AB-PV3 add +280 (headroom 1,357). AB-PV1's timelock adds +824.
  Together they are about +1,100, leaving about 530 (additivity inferred, not measured). A
  multi-OS-program allowlist would belong in the adapter, which is a separate class.

## What I ran

In copies of `bench/m31-pool/cairo` (with `verifier_core` pointed at the absolute path) and of the
`r5-p3b` bridge workspace, using scarb 2.18.0 and snforge 0.63.0:
- the pool tests: 34/34;
- the e2e tests: 8/8;
- `scarb build`, for the CASM count (80,283);
- mutants:
  - X1, `transfer_ownership` open to anyone: **survived**;
  - X2, an unknown root accepted below W: killed;
  - X3, `apply_verifier` keeps the pending proposal: killed;
- CASM builds of AB-PV1 and AB-PV2.

I did not read or print `private-wallet.json`.

## Resolution (implementer, 2026-09-26)

All findings are applied before any commit, since pools cannot be upgraded.

| Finding | Change |
| --- | --- |
| AB-PV1 | The shadow-class allowlist takes the verifiers' timelock. `set_shadow_class` is gone, and `initialize` takes the first allowlist. Test: `shadow_classes_take_the_timelock` |
| AB-PV2 | A proposal applies only within `[eta, eta + T]` (`PROPOSAL_LAPSED`). §8.4 adds the SDK rule. It is narrowed: a pending verifier proposal blocks deposits; a pending shadow-class proposal only warns and stops the routes it would break, since allowlisting cannot move funds. Test: `proposals_lapse_after_a_second_period`, which applies at exactly `eta + T` |
| AB-PV3 | A replaced proposal emits `Cancelled`, asserted in `timelock_for_each_verifier` |
| AB-PV4 | `ownership_moves_in_two_steps`: a stranger's `transfer_ownership` fails `NOT_OWNER`. Mutant X1 is now killed |
| AB-PV5 | Spec §8.5 and §14 |
| AB-PV6 | Spec §11 (sdk-spec §9.1 re-proofs) and §9 admission (the root at `send_deadline`) |
| AB-PV7 | Spec §11 (server §4, sdk-spec §8) |
| AB-PV8 | Spec §8.4, §8.1 and §15 P6 |

**The CASM budget.** The typed timelock with a shadow-class timelock measured 82,203 felts, over
the limit. It is replaced by one generic timelock: `propose(key, value)`, `apply(key)`,
`cancel(key)` and `get_proposal(key)`, where the key is `'R0'`, `'P1'` or a shadow class hash.
The `asset_id` view, which the SDK computes in WASM, is dropped too. Result: **80,052 felts**,
with 1,868 headroom (before the review: 80,283 and 1,637).

The pool tests are now 36/36, and the end to end is 8/8 on the final class. The mutation run
covers 31 mutants, including X1 and X3 (`bench/m31-pool/results/pool-v3/mutation.json`).
