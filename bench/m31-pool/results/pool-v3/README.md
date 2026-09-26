# M31 pool V3 (P3b)

2026-09-26. The pool of [`docs/account-bound-note-spec.md`](../../../../docs/account-bound-note-spec.md)
§8: R0 V5 spends with a public expiry, roots accepted by block height, timelocked owner levers, and
V2's assets, payouts, open notes and policy notes. Code: [`spend5.cairo`](../../cairo/src/spend5.cairo),
[`tree_v3.cairo`](../../cairo/src/tree_v3.cairo), [`pool_v3.cairo`](../../cairo/src/pool_v3.cairo).
Nothing is deployed.

## Result

| | |
| --- | --- |
| Pool tests (snforge, mocked verdicts) | **36/36** ([`tests/test_pool_v3.cairo`](../../cairo/src/tests/test_pool_v3.cairo)); the package's 265 tests all pass |
| Mutants of the V3 rules | **31/31 killed** ([`mutation.json`](mutation.json)); one survived the first run and was fixed in the test |
| Real statement account end to end | **8/8** ([`e2e.json`](e2e.json), `client-port/cairo-r5/pool_e2e`) |
| CASM (limit 81,920) | **80,052 felts**, 1,868 headroom (V2: 76,860) |
| `apply_spend` with the real V5 adapter | 55.27M L2 gas (bound withdrawal), 54.20M (ordinary transfer); V4 transfers measured 53.7–55.2M by tree position |
| V2 classes | Unchanged: `M31PoolV2` and `Proof2Adapter` still hash to the Sepolia-deployed classes |

## What V3 changes from V2

- **Spends** (§8.1, §8.2) take `spend5::Spend`: V4's fields plus `valid_until`, bound by
  `TMR0_BIND_V5`. A spend lands only if `block ≤ valid_until`, `valid_until % Q = 0` and
  `valid_until ≤ block + E + Q`, and `valid_until ≠ 0`.
- **Roots** (§8.3). The 256-root ring is gone:
  - the current root is always accepted;
  - a replaced root is accepted for `W` blocks after the block that replaced it;
  - the constructor requires `W ≥ E + Q`;
  - the policy path uses the same rule.
- **Owner levers** (§8.4):
  - The constructor takes no verifier. A one-time `initialize(r0, p1, shadow_classes)` sets both
    verifiers and the first shadow-class allowlist, and every deposit, hook and spend reverts with
    `NOT_INITIALIZED` until then.
  - Afterwards, the verifiers and the allowlist change only through one timelock:
    `propose(key, value)`, then `apply(key)` from `eta = now + T` until `eta + T`, or
    `cancel(key)`. The key is `'R0'`, `'P1'` or a shadow class hash.
  - Events: `Proposed`, `Cancelled` (also for a replaced proposal), `VerifierChanged`,
    `ShadowClassSet`. Views: `get_proposal(key)`, `get_verifier(kind)`, `is_shadow_class`.
  - Ownership moves in two steps.
- **Carried fixes** (§8.5):
  - F30: the constructor takes no format. The tree carries only the compress node hash and
    empty-subtree table, which also brings the class under the size limit.
  - F17: every ERC20 pull (a deposit, or an open note's proceeds) checks that the payer's balance
    fell by the amount. Every ERC20 payout checks the pool's balance delta.
  - F18: an `INVOKE` target cannot be an allowlisted shadow class.
  - F19: the constructor emits the owner; `initialize` and `apply` emit the verifiers and the allowlist.
- **Not changed:** V2's deposits, asset registry, `held`, receiver hooks, `pay_out` paths,
  `MAX_NOTES = 4`, the nullifier set and the exit rule. The `asset_id` view is dropped, since the
  SDK computes asset ids itself. The adapter class is reused unchanged; the
  V5 instance takes `account_tag = 'TMPZR0_PAYMENT_V5'` and `max_proof_age = 1,024`.

## Pool tests (spec §15 P3b)

| Acceptance item | Tests |
| --- | --- |
| Root rule | `current_root_accepted_after_a_long_idle` (3W idle blocks); `replaced_root_window_boundary` (accepted at `W`, rejected at `W + 1`, never-recorded root); `junk_appends_do_not_age_a_root` (258 appends in one block); `policy_spends_use_the_root_rule` |
| Expiry boundaries | `expiry_boundaries`: lands at `block = valid_until`, not one block later, off-grid, `block + E + Q` accepted and the next grid point rejected (at two blocks), zero at block 0. Also `sdk_valid_until_lands_through_its_window` (five `latest` values, landing at both ends) and `invoke_spends_expire_too` |
| V5 binding | `binding_matches_the_reference`: three vectors from [`gen_binding_v5_kat.py`](../../gen_binding_v5_kat.py), whose Python Poseidon reproduces the four starknet.js bindings in `cairo-r5/kat/kat.json`. `every_field_is_bound`: 17 field changes, each moves the binding. `valid_until_is_bound_at_the_pool` |
| Timelock, both verifiers | `timelock_for_each_verifier`: apply before `eta`, cancel, re-propose, a replaced proposal's `Cancelled`, events, owner-only, address checks. `proposals_lapse_after_a_second_period` (applies at exactly `eta + T`, lapses one second later). `shadow_classes_take_the_timelock` (allow and disallow). `applied_verifiers_decide` |
| Bootstrap | `constructor_checks_its_parameters`, `nothing_enters_before_initialize` (deposit, both spend paths, policy, both hooks, propose), `initialize_once_by_the_owner` (with the first allowlist), `initialize_requires_an_empty_tree` |
| Ownership | `ownership_moves_in_two_steps`: stranger `NOT_OWNER` (AB-PV4), pending owner without rights, accept, cancel by zero, zero caller |
| No fee or gating path | `any_account_deposits_and_any_account_submits` |
| V2's `insert_two` tests | `v3_tree_roots_match_client_{nodes,frontier}` and `v3_batched_roots_match_client_{nodes,frontier}` (the client's golden roots), `compress_tables_match_the_shared_ones`, `empty_nodes_are_compress_zeros` |
| F17, F18, F30 | `fee_on_top_deposit_rejected`, `fee_on_transfer_deposit_rejected`, `fee_on_top_payout_rejected`, `fee_on_top_open_note_funding_rejected`, `invoke_cannot_target_a_shadow_class`; F30 by the constructor and tree tests |
| F28 branches | `spend_guards`: wrong chain or pool, zero nullifier, the same nullifier twice in one spend, intent or identity without invoke, asset range, exit rule, withdrawal shape, binding, holdings; the failed calls leave the nullifier fresh. `execution_guards`: `EXECUTION_INTENT` (two ways), `EXECUTION_EXPIRED`, `EXECUTION_ADAPTER` (pool, zero), `IDENTITY_UNEXPECTED`, `IDENTITY_REQUIRED`, `COMPUTE_TARGET`, `EXECUTION_ASSET`. `tree_full`: an append at index 2^32 − 1, then `TREE_FULL` for a pair and for a single note |
| Open-note paths on V3 | `invoke_funds_an_open_note`, `compute_funds_an_open_note` |

## Real statement account end to end ([`e2e.json`](e2e.json))

[`account_bound_e2e.py`](../../account_bound_e2e.py) builds a wallet state and proves two spends
with `wallet prove5` (added in P3b: `prove4` plus `account` and `valid_until`):
- **Deposits:** a 1,000-unit ERC20 note bound to account `A`, and a 500-unit ordinary note.
- **S1**, bound: `A`'s note pays 400 to a recipient, with 600 in change and a dummy output.
- **S2**, ordinary: the 500-unit note splits into 300 and 200.

Both are proved against the tree after the deposits.

`client-port/cairo-r5/pool_e2e` runs in a built bridge workspace, with this package copied in and
its `verifier_core` pointed at the workspace's byte-identical vendored copy. For each spend:
1. The real statement account runs the proof, as the OS does (caller 0). Its bridge verifies the
   proof. For S1, a mock account at `A` accepts only the SNIP-12 hash starknet.js computed, with
   the fixture's signature.
2. The account's one message, hashed as the OS commits it, becomes the proof facts.
3. A third party submits the pool calldata. The real V5 adapter checks the facts against the
   binding the pool recomputes.

The test asserts that the deployed pool's class hash is the one built here.

| Test | Result |
| --- | --- |
| `bound_withdrawal_then_ordinary_transfer` | Both settle. S2 lands on a replaced root inside the window. The recipient gets 400, and `held` and nullifiers are updated |
| `bound_withdrawal_lands_at_valid_until` | Settles at `block = valid_until` (proof based 11 blocks earlier) |
| `bound_spend_needs_the_accounts_signature` | Another salt: `SIG_NOT_VALID` in the account, so no message |
| `expired_spend_rejected` | `SPEND_EXPIRED` one block after `valid_until` |
| `moved_expiry_rejected` | `valid_until − Q`, rebound: `PROOF_BINDING` (the account's message carries the original) |
| `another_spends_facts_rejected` | S2's facts for S1: `PROOF_BINDING` |
| `redirected_withdrawal_rejected` | `BAD_BINDING` |
| `replay_rejected` | `NULLIFIER_USED` |

The virtual OS and PROOF2 are P5, with the real Ready and Braavos accounts in the pinned OS.

## Review

Protocol: [`docs/reviews/account-bound-p3b-protocol-review.md`](../../../../docs/reviews/account-bound-p3b-protocol-review.md), GO.
All eight findings are applied (spec §17). The code changes are AB-PV1 to AB-PV4.

## Reproduce

```text
cd bench/m31-pool/cairo && scarb build && snforge test          # 265 tests; the e2e needs this build
python3 bench/m31-pool/check_class_sizes.py
python3 bench/m31-pool/gen_binding_v5_kat.py                     # rewrites tests/binding_v5_vectors.cairo
cargo +nightly-2026-01-15 build --release --example wallet        # in client-port
python3 client-port/build_bridge_arith.py results/stwo-client-r5/trusted-config.json RUN/bridge
python3 bench/m31-pool/account_bound_e2e.py RUN/bridge RUN/e2e      # proves S1, S2; runs pool_e2e
```

Runs belong under `~/.local/share/templar/runs` (this one: `r5-p3b`). `RUN/e2e/private-wallet.json`
holds the keys; the committed files hold public data only.
