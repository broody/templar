# Open-note settlement: contract review (M31 pool)

Independent reviewer; did not write the change. Date 2026-09-24, branch `pathfinding/client-zk`
at `03d8955`. No repository code was modified.

## Scope

- `bench/m31-pool/cairo/src/pool.cairo`: `apply_spend_with_invoke`, refactored `apply_spend`,
  `verify_spend`, `pending_outputs`, `publish_outputs`, `append_notes`, `pay_withdrawal`, `start`/`locked`.
- `open_note.cairo` (`hash_intent`, limits, `partial_commitment`/`identity_commitment`), `spend.cairo`
  (V3 `Spend`, `compute_binding`, `delivery_digest`, `IERC20`), `tree.cairo` (`insert_leaf`,
  `insert_two`), `adapter.cairo` (Proof2Adapter), `test_adapters.cairo`, tests.
- Diff `364cad2` and later `bench/m31-pool` commits (`a25f2a4`, `64b40eb`).
- Spec `docs/open-note-spec.md` § "Compact client-proof path (R0 V3)".
- Compared against upstream `privacy.cairo` (`_apply_invoke_and_deposits`, `_deposit_to_open_note`,
  `deserialize_invoke_return_data`), the Ekubo, Vesu and shadow-account anonymizers, and the
  earlier reference `bench/return-note-e2e/cairo/src/pool.cairo` (`execute_returns`).

Method: line-by-line reading, plus 13 throwaway adversarial tests in a copy of the crate outside
the repo (`/tmp/claude-1000/-home-broody-development-templar/scratch-review3`, file
`src/tests/test_review.cairo` and mocks `src/review_mocks.cairo`). The full suite there, 69
existing tests plus 13 review tests, passes: 82/82 with snforge 0.63.0 and scarb 2.18.0.
**D** = demonstrated by a test. **R** = reasoned only.

## Findings

| ID | Sev | Location | Issue | Scenario / failure | Suggested fix | Test in repo? |
|---|---|---|---|---|---|---|
| F1 | Low | `open_note.cairo:81-92`, `pool.cairo:170-178` | Destination fields get weaker checks than `deposit` (`BAD_DEPOSIT`, `pool.cairo:111`) and the reference `execute_returns` (`RETURN_ARGS`: nonzero note_id, token, minimum, inner). All-zero `inner`, `note_id = 0` and `minimum = 0` are accepted. A zero `token` and non-canonical `inner` words are rejected only after the budget has been paid and the adapter has run (`read_digest(dest.inner)` at :177). | **D** (`r_zero_inner_zero_id_zero_minimum_accepted`): a destination with a zero inner is funded and appended, which creates a note that nobody can open, so the funds are burned. A wallet bug that produces non-canonical inner words gives a valid proof that always reverts at settlement, so the user has to prove again. The prover has to authorize all of this, so it cannot be exploited by third parties. | In `hash_intent`, also run `read_digest(d.inner)` with `!is_zero`, and require `token != 0` and `note_id != 0`. Decide on `minimum`: zero is fine as long as `amount != 0` stays. | No |
| F2 | Low (privacy) | `open_note.cairo:97-106`, `pool.cairo:155` | The identity handle is public in calldata (`spend.identity`), so `partial = Poseidon('TEMPLAR_IDENTITY_V1', handle)` is public too. Anyone can compute `Poseidon(partial, nonce)` for every nonce and list all of the user's shadow accounts, including through upstream `get_shadow_accounts(partial, …)`. Upstream keeps `identity_key` and `partial` secret, and binds `dapp_name` and the anonymizer address. Here, nonces give no unlinkability, and scoping to an adapter depends only on the wallet choosing its private `scope`. | **R**: an observer sees handle H in a COMPUTE spend and derives every shadow account under H at nonces 0..N, linking all of them. If the same scope is reused with two shadow anonymizers, their identity commitments are identical. | Have the circuit output `identity_commitment` (with the nonce private, and bound to the adapter) in place of the handle, and pass it through. Otherwise, document that the handle and all its nonces are one public pseudonym. The spec line "links its own actions … not the owner's other notes" understates this. | No |
| F3 | Info | `pool.cairo:151`, `302-315` | The budget recipient is any address the intent names. The reference required `recipient == adapter` and `amount != 0`. With a zero budget the recipient must be zero (`BAD_WITHDRAWAL`). The budget is always `spend.token`, and it is paid before the call. `recipient == pool` strands the funds (already true in `apply_spend`). | **D** (`r_budget_to_third_party`): a budget of 40 A goes to 0x1234 while the adapter funds the open note. The intent authorizes this, and the spec says so. | Document it, or reject `recipient == this`. | No |
| F4 | Info | `pool.cairo:167-179` | Two destinations with the same token are allowed, but upstream anonymizers and the mocks `approve` (overwrite) once per deposit, so the pulls fail. The shadow anonymizer documents "at most one note per token". | **R**: the transaction reverts safely (`INSUFFICIENT_ALLOWANCE`). This is a liveness and UX issue only. | Document it, or reject same-token destinations in `hash_intent`. | No |
| F5 | Info | `pool.cairo:158-164` | Return data is deserialized with no length bound set beforehand. The reference checked `len == 1 + 3n` first. For COMPUTE, the trailing `Span<ContractAddress>` is parsed and then ignored. | **R**: the adapter controls only gas and the user chose the adapter. Strictness holds: **D** (`r_extra_return_data_rejected`) shows trailing felts give `INVOKE_RETURN`. | Optional: bound `ret.len()` before deserializing. | No |
| F6 | Info | `tree.cairo:146-225`, `pool.cairo:275-298` | `append_notes` records one root per `insert_two` or `insert_leaf`. Intermediate roots, for example after only the private outputs, are never recorded. | **D** (`r_append_from_odd_index_matches_sequential`): two outputs plus one open note appended from odd index 1 give the root of sequential `insert_leaf`, and the pre-transaction root stays known. The only effect is on wallets, which must prove against a post-transaction root. The existing `check_batched_roots` already covers pairs at indices 1, 4, 7 and 9 in both storage modes. | None needed. | Partly (tree-level only) |
| F7 | Info | `pool.cairo:132-188`, `200` | During the adapter call, views show nullifiers as spent but the tree before the append (read-only reentrancy). `set_verifier` is not lock-guarded, but it is owner-only. | **R**: no effect on value. The lock covers all three mutating entrypoints. **D** (`r_reentrant_deposit_blocked`): an adapter that calls `deposit` gets `REENTRANCY`. | None. | No |
| F8 | Info | `pool.cairo:149`; `open_note.cairo:42,76` | `TOTAL_NOTE_COUNT` can never fail (outputs ≤ 2 and destinations ≤ 2 are enforced earlier). `nonce` is hashed for INVOKE but not required to be zero. A COMPUTE nonce is a `felt252`, while upstream scanning views use `u64` nonces. `MAX_CALLDATA = 64` may be tight for shadow multicalls (`Array<Call>` plus `Span<OpenNote>`). | **R** | Require `nonce == 0` for INVOKE and `nonce < 2^64` for COMPUTE. Keep or remove the redundant assert. | No |

No Critical, High or Medium findings.

## Checks found sound

- **Lock.** `start()` guards `deposit`, `apply_spend` and `apply_spend_with_invoke`, and each one
  clears the lock on its single exit path. A revert restores the lock. Re-entry from the adapter,
  from budget-token hooks or from pull-token hooks hits `REENTRANCY` (**D** for the adapter case).
- **No allowances granted.** The pool never calls `approve`. An adapter that calls
  `transfer_from(pool, …)` fails with `INSUFFICIENT_ALLOWANCE` (**D**, `r_pull_from_pool_rejected`).
- **Pulls.** `transfer_from(adapter, pool, d.amount)` must succeed. Under-approval reverts (**D**).
  The per-pull balance delta must equal the amount exactly, as a u256: a decreasing balance
  underflow-panics and a surplus fails `==`. A fee-on-transfer token is rejected with
  `OPEN_NOTE_FUNDING` (**D**). A lying or malicious destination token only affects notes committed
  to that same token address, because the commitment includes `dest.token`, so it cannot mint value
  in another token (**R**). Because the check is per pull and runs after the budget is paid,
  refunds in `spend.token` are accounted for correctly (**R**).
- **Matching.** There is exactly one deposit per destination, in order. `note_id` and `token` must
  be equal, and `amount != 0 && >= minimum` (**D** for the zero amount and below-minimum cases).
  Duplicate note_ids are rejected in `hash_intent`. The commitment uses the actual amount, the
  verified `spend.chain`, the pool address and `dest.token`. `delivery_digest` validates the
  ciphertext, and `append_notes` checks that the digest is nonzero.
- **Events.** The `OpenNoteFunded.index` value, `first + created + i`, matches the `NotePublished`
  index, because `first` is `tree_count` before any insert and the appends are sequential.
- **Authorization.** `intent != 0` and `intent == hash_intent(spend, intent)`. The hash covers
  the chain, pool, token, kind, adapter, nonce, budget recipient and amount, expiry, selector,
  calldata and every destination field, including the ciphertext digest. The binding covers
  `intent` and `identity`. The expiry is enforced (**D**). The kind is restricted to 0 or 1, and
  the selector is derived from it. The identity handle is required for COMPUTE and forbidden for
  INVOKE.
- **`apply_spend` regression.** Apart from the new guard, the logic is identical to before
  (`verify_spend` is the old prologue, and `publish_outputs` is the old output block). The new
  guard is `INTENT_NEEDS_INVOKE` for a nonzero intent or an active identity (**D**,
  `r_apply_spend_rejects_intent`). EMPTY_OUTPUT and withdrawal semantics are unchanged, and the
  existing tests pass.
- **Proof2Adapter.** It checks the caller, chain, pool, a proof facts length of exactly 9, the
  version, variant and OS program, base-block age, a message count of 1, and a message hash that
  includes the V3 binding.
- **Upstream compatibility (R).** The Ekubo and Vesu anonymizers work unmodified with
  `kind = INVOKE`: they have no caller check, approve `get_caller_address()` (the pool), return
  `Span<OpenNoteDeposit>`, and are prefunded through budget recipient = adapter. The
  shadow-account anonymizer works unmodified with `kind = COMPUTE` if it is deployed with
  `privacy_contract` set to this pool. Its signature is
  `(identity_commitment, calls, open_notes)`, it returns
  `(Span<OpenNoteDeposit>, Span<ContractAddress>)`, and deposits come back in `open_notes` order.
  The client must serialize the calldata in each adapter's ABI (the pool forwards it verbatim).
  Tokens must expose snake-case `balance_of`, `transfer_from` and `transfer`.

## Test coverage gaps (repository)

`test_open_note.cairo` has only three happy-path tests; its header defers adversarial cases. None
of the following are covered in the repo:
- reentrancy from the adapter;
- under-approval and pulls from the pool;
- fee-on-transfer or lying tokens;
- wrong `note_id`, wrong token, wrong order or wrong count of deposits;
- zero amount and below-minimum amounts;
- trailing return data;
- expiry;
- identity rules (COMPUTE without a handle, INVOKE with one);
- invalid kind;
- adapter equal to the pool or zero;
- `apply_spend` with a nonzero intent;
- duplicate note_ids;
- zero budget with a nonzero recipient;
- a destination token equal to `spend.token` (refund);
- two destinations of the same token;
- F1 and F3 behaviour;
- root equality of mixed private and open appends at an odd start through the pool.

The throwaway tests listed above cover 13 of these and could be ported directly.

## Verdict

**GO for research use.** No finding lets an adapter, a token or a third party create unbacked
notes, move pool funds, bypass the lock, or change what the proof authorized. Before any
production use: fix F1 by validating destinations in `hash_intent`, decide F2 (the identity
commitment design or explicit documentation), and port the adversarial tests.
