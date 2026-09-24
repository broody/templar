# Policy notes — implementation review (contracts and protocol)

Reviewer: independent contract/protocol reviewer (did not write the change). Reviewed commit
`bb04f61` against `docs/policy-note-spec.md` revision 3 (§6, §7, §9, §10). I also read the design
reviews in `policy-note-design-protocol-review.md`. This review covers the Cairo contracts, the
adapter change, the P1 statement account, the tests, and the Python wallet and e2e driver. It
does not replace the Math Reviewer's sign-off on the P1 relation (`client-port/src/policy.rs`)
or the bridge's limb decoding.

## Verdict

**CONDITIONAL GO.**

- **Contracts: GO.** `apply_policy_spend`, `call_controller`, `PolicyEscrow`, the separate P1
  verifier slot and the `Proof2Adapter` change implement §6 and §10 as specified. I found no
  way for a relayer or capability holder to settle something the proof did not bind. I also found
  no way for a controller to break atomicity, re-enter the pool, or block the deadline refund.
  33 additional adversarial tests in a scratch copy all pass, and so do the original 147 (180/180).
- **Condition (§9 wallet).** Add the known-answer test vectors that §9.1 explicitly requires
  "during implementation" (IC-2). Everything else is non-blocking.

## Findings

| ID | Severity | Location | Finding | Concrete scenario | Fix | Blocking |
|---|---|---|---|---|---|---|
| IC-1 | Low | `policy.cairo:112` (`authorization`), `pool.cairo:340` (`PolicySettled`), spec §6 steps 4 and 6, §10 | The felt that controllers approve and that the event reports is `key(policy_id₉) = Poseidon(nine words)`. The spec text just says "`policy_id`". The authorization uses `key(...)` but the event uses `key_or_zero(...)`. The two agree for every real statement (P1 never yields a zero digest), but nothing states the convention. | An arbiter UI or indexer that follows the spec text approves, or looks for, the first word or the nine-word digest. The approval never matches, so the release is lost at the deadline. | In §6 and §10, say that the approved `policy_id` is `key(policy_id₉)` (as `policy_e2e.py` computes it). Use `key` in the event too, for consistency. | No |
| IC-2 | Medium | `policy_wallet.py:1-8` (docstring), `:19-85` (`hkdf`, `m31_9`, `x25519_scalar`, `policy_secrets`), `:120-156` (plaintexts); spec §9.1 l.369 | §9.1 says "Test vectors pin all of this during implementation (F-1 math, F-4 protocol)". There are none. The docstring says the vectors are "the functions' outputs checked in `policy_e2e.py`", but that script draws random seeds and nonces and only checks self-consistency (round-trips between the same functions). Nothing pins the HKDF labels and info layout, the M31⁹ mapping, the clamping, the `M301`/`PB01`/`PS01` byte layouts, or the deterministic refund sealed box. | A second implementation (the production wallet, a Rust or JS port) changes a label byte, the chain/pool width or the chunk endianness. It then derives a different `cap`/`rho_refund`/`esk_refund`, and seed-only refunds of notes created by this wallet silently fail. The funds can then be refunded only by someone who still holds the opening. | Add a fixed-seed, fixed-nonce KAT file: `s_pol`, `cap`, `rho`, `salt`, `rho_refund`, `esk_refund`/`epk`, the 256-byte `PB01` and the refund `M301` plaintexts, the 304-byte refund box and its ten words and delivery digest, and the resulting `o₀`/`policy`/`policy_id`/`cm` for a fixed header. Check it from Python, and from Rust if a Rust wallet exists. | **Yes** (spec-mandated; cheap) |
| IC-3 | Medium | `policy_wallet.py:213-223` (`find_notes`), `:126-139` (`parse_m301`, `ps01`); spec §9.3 | The split receiver path is not implemented. `find_notes` trusts the plaintext amount and never recomputes `cm` against the leaf (§9.3: "The wallet recomputes the commitment and checks it against the leaf at the reported index"). For `PS01` it returns amount 0 (x side) or the full note amount (remainder side) instead of `x` and `amount − x` from `PolicySettled`. No test or e2e exercises a split settlement end to end. | A split beneficiary's wallet records a 0-value note or a note worth the whole amount. Its later R0 spend fails the membership check, or the UI shows a wrong balance. A malicious creator can also send an `M301` whose amount disagrees with the commitment, and it is accepted. | In `find_notes`, recompute `cm = H(NOTE, chain, pool, token, amount, H(INNER, receiver ‖ rho))` and require it to equal the leaf. For `PS01`, read `PolicySettled` (from the pool's address) covering that index, use `x` or `amount − x` by side, then check `cm`. Add a split e2e or unit test. | No (split is not in the escrow milestone), but required before wallets offer split outcomes |
| IC-4 | Low | `policy_e2e.py:125-140`; `policy_note.py:61` (`spend_request`); spec §7.2 (deadline boundary), §9.3 (acceptance checklist) | Wallet-side obligations are not implemented. Nothing refuses a controller-window settlement too close to the deadline. The executor/beneficiary acceptance checklist (leaf in tree, controller class is the reference escrow, deadline margin, own ciphertext against the committed delivery) is not run before proving. | An executor starts a 2-minute PROOF2 wrap 5 blocks before the deadline. The approval is lost (spec P-7), and nothing warned. | Add `check_opening(opening, pool_state, expected_class, margin)` and a margin guard in `spend_request`, and call them in the e2e. | No |
| IC-5 | Info | `pool.cairo:314`; bridge `cairo-p1/bridge/src/lib.cairo:155` | The pool rechecks only "index 0 ⇒ type 1" (as §6 step 5 requires). It does not recheck the rest of the refund shape (`active₀ = 1`, no withdrawal), which P1 enforces (§5 step 6). Scratch test `r_refund_shape_not_rechecked_by_pool` shows that a (mock-verified) withdrawal-only refund settles after the deadline. | Only reachable with a circuit bug. It would let a refund pay out publicly instead of creating the depositor's private note. | Optional defence in depth: `assert(index != 0 \|\| (!is_zero(cm₀) && w.amount == 0))` in the pool and the bridge. | No |
| IC-6 | Info | `pool.cairo:322, 341` | `PolicySettled.first_index` is the next free index even when the outcome published no note (withdrawal only), so it points at a leaf that does not exist yet. | An indexer maps the settlement to the next unrelated note. | Document it, or emit `first_index` only together with the count of notes published. | No |
| IC-7 | Info | `policy.cairo:121-131` | A controller (chosen by the note creator) runs inside the settlement transaction. It can emit events named `PolicySettled`/`NotePublished` from its own address (scratch test `r_controller_fake_event_is_from_controller`). | A scanner that filters by event name only is fed fake notes or settlement data. | State in §9 that wallets and indexers take `NotePublished`/`PolicySettled` only from the pool address. | No |
| IC-8 | Low | `pool.cairo:347-351` | `set_policy_verifier` emits no event (like `set_verifier`). Nothing stops `policy_verifier == verifier`. I checked that such a misconfiguration is still safe: real P1 facts fail an R0-tagged adapter (`r_real_p1_facts_rejected_by_r0_tagged_adapter`), and the binding tags differ. The owner can swap the P1 verifier instantly, which is the same trust as R0. | A key compromise or mistaken swap of the P1 verifier is not visible to monitors. | Emit `PolicyVerifierSet`. Optionally assert `verifier != self.verifier.read()`. | No |
| IC-9 | Low | `bench/m31-sepolia/deploy.py:43, 103-104, 117` | The adapter change is behaviourally backward compatible: with `account_tag = 'TMPZR0_PAYMENT_V3'` the message hash is identical, and every call site (`deploy.py`, `test_adapter.cairo`, `test_open_note_e2e.cairo`, `test_policy_e2e.cairo`) passes the tag. But the `Proof2Adapter` and `M31Pool` class hashes change. `deploy.py` rewrites `source-snapshot.json` unconditionally on every run, even when it resumes with the cached pre-`bb04f61` `classes.json`/`deployment.json`. `--check` now reports the adapter as undeclared. | Rerunning `deploy.py` against the existing run (`m31-sepolia-sn9lwok8`) records post-change sources as the snapshot of contracts deployed from pre-change sources, and `report.py` archives the mismatch as evidence. | Write the snapshot only when deploying, or check each cached class hash against a class hash recomputed from the snapshotted sources. | No |
| IC-10 | Info | `pool.cairo:309` | `data` has no length cap (the design review P-10 suggested one; rev. 3 did not adopt it). The relayer pays, and controllers receive attacker-sized spans. | None beyond gas. | Optionally cap `data.len()`. | No |

## What I checked and found sound

**§6 order and completeness (`pool.cairo:270-344`).**

- The lock is taken first (`start()`).
- Context is checked: chain equals the transaction's chain, pool equals `this`, and the token is
  nonzero.
- Each ciphertext is ten words (`delivery_digest` asserts the length), its digest equals the bound
  delivery, and the delivery is nonzero for an active commitment. An inactive slot needs an empty
  ciphertext and a zero delivery.
- `policy_binding` covers every `PolicySpend` field. I compared it field by field with the bridge's
  `binding` (`cairo-p1/bridge/src/lib.cairo:163-189`): same order, digests as nine words, other
  fields as one felt.
- The P1 verdict comes from `policy_verifier` only (nonzero), and the pool checks the known root.
- A nonzero nullifier is checked against the shared map and marked spent.
- `Poseidon(data) == spend.data`.
- `b ≥ not_before`, and index 0 must have type 1.
- Windows: `b ≤ deadline` goes to the controller; `b > deadline` allows index 0 only, with no
  controller call and no class check.
- Effects: notes are appended with their ciphertexts, and `NotePublished` is emitted for each. A
  withdrawal needs recipient ≠ 0 and ≠ pool, and is paid via `transfer`. With no withdrawal the
  recipient must be 0 and at least one note must exist.
- `PolicySettled` carries `{key(nf), controller, handle, key(policy_id), outcome, x, first_index,
  by_controller}`.

The order differs cosmetically from the spec's numbering (ciphertexts first). This is immaterial,
because nothing external runs before the owner-set verifier, and every assertion reverts the
whole transaction. The R0 entry points are unchanged by the commit (diff is additions only).

**Boundaries.**

- `b == not_before` settles.
- `b == deadline` is still the controller's block, and an unapproved refund at that block is
  rejected.
- `b == deadline + 1` accepts the refund without a controller, even with controller and class
  zero, and reports `by_controller = false`.
- A release settled at the deadline block cannot be followed by a refund of the same note.

**Controller call (`policy.cairo:121-131`).**

- `controller ∉ {0, pool}`.
- The class must be nonzero and equal to the pinned one. An undeployed address fails, and so does
  a controller that replaced its own class via `replace_class_syscall`, after which the deadline
  refund still works.
- The selector is Templar-specific: a contract exposing only `privacy_apply_controlled_transition`
  is unreachable.
- The result is unwrapped with `unwrap_syscall`, and the call must return exactly
  `['TEMPLAR_POLICY_OK']`. A trailing extra word is rejected.
- The authorization is the 16-field layout of §6 step 4.

**Malicious controller.** The lock blocks re-entry into `apply_policy_spend`, `apply_spend` and
`deposit` (and `apply_spend_with_invoke` by the same `start()`). A controller cannot call owner
setters. The tree ABI is view-only, and the adapters reject non-pool callers. A controller cannot
relay the authorization to the escrow, because the escrow sees the controller as caller. Its
revert, or a later failure in the pool (such as the withdrawal transfer), rolls back the escrow's
consumption and the nullifier, and the approval stays usable. Gas griefing and reverts only affect
notes that name that controller before their deadline. The deadline refund never calls it, has no
withdrawal and therefore no token transfer, so neither a hostile controller nor a blocklisting
token can freeze value past the deadline. Open-note adapters and controllers share the one lock,
so neither can nest the other.

**Escrow (`policy_escrow.cairo:69-113`).**

- `approve` is by the caller (the arbiter), write-once per `(arbiter, policy_id)`, stored as
  `outcome + 1`, and bounded to outcomes 0 and 1. A `policy_id` of 0 is rejected.
- `templar_apply_policy` checks `caller == pool`, `len == 16`, the tag, chain, pool and
  `type == FIXED` (so `x = 0`). It checks `approved == index + 1`, which is nonzero, so an unset
  entry never reads as cancel. It also checks the approval is not consumed, then marks it consumed.
- Not checking the token matches §10: `policy_id` binds token, pool, chain and amount.
- Decoys are rejected: another policy id, another handle, index 2/3, the refund when release was
  approved, and an escrow deployed for another pool.
- The key includes the arbiter: two arbiters approving the same id are independent.
- A same-token, same-amount copy of the policy can consume the approval, but only by paying the
  committed outcome with the copier's own funds (N-1, accepted by design).

**Verifier separation.** The adapter message is `Poseidon(statement, 0, 5, class, tag, chain,
pool, binding)`, with the tag now a constructor parameter (nonzero). The R0 and P1 accounts
hardcode `'TMPZR0_PAYMENT_V3'` and `'TMPZP1_POLICY_V1'`, and the binding tags differ
(`TMR0_BIND_V3` and `TMP1_BIND_V1`). With the real vectors:

- the existing test shows R0 facts fail a P1-tagged adapter;
- my test shows P1 facts fail an R0-tagged adapter, even one pinned to the P1 statement address
  and class, while the P1-tagged adapter accepts them;
- the R0 entry point uses only `verifier` (P1 accept + R0 reject → `PROOF_REJECTED`);
- the policy entry point uses only `policy_verifier` (existing test).

The nullifier map is shared in both directions (R0→P1 and P1→R0 reuse rejected). The P1 account
(`cairo-p1/account/src/lib.cairo`) mirrors the R0 account: prove-only validate, OS-only execute,
chain check, own class in the payload.

**Delivery.** The relayer cannot swap or replace ciphertexts: on the real statement, swapping the
two ciphertexts gives `DELIVERY`, and the binding covers commitments and deliveries.
`PolicySettled` gives split receivers `x` and `first_index` (out₀ at `first_index`, out₁ at
`first_index + 1` when published). A split test checks the event and both delivery digests.

**Wallet recovery (§9) in `policy_wallet.py`.**

- HKDF-SHA256 with a 32-zero-byte key, which equals an empty salt under HMAC.
- `s_pol` under its own label, `ctx = chain₃₂ ‖ pool₃₂ ‖ ν₁₆`, a fresh random 16-byte `ν` per note.
- `M31⁹` as 8-byte big-endian chunks mod p. An all-zero result asserts instead of redrawing; the
  probability is negligible.
- RFC 7748 clamping.
- The refund sealed box has libsodium's format (`epk ‖ crypto_box(m, BLAKE2b-24(epk ‖ pk))`), is
  reproducible, and decrypts with stock `SealedBox`; the e2e finds the refund note.
- The `PB01` layout is byte-exact to the §9.2 table (212 bytes + 44 zero), and parsing requires
  zero padding. The `M301` layout is exact.
- `recover` rebuilds the standard refund, `policy` and `cm` and requires `cm` to equal the leaf
  before trusting the backup (§9.2). Gaps are IC-2 to IC-4.

## Scratch tests run

The scratch copy is at `~/.local/share/templar/review-scratch/policy-impl-contract/`, with the
`verifier_core` path made absolute and `.tool-versions` pinning scarb 2.18.0 and snforge 0.63.0.
The home `.tool-versions` otherwise selects snforge 0.54.1, which fails on
`get_execution_info_v3_syscall`. The added files are `src/review_adapters.cairo` (hostile
controllers: `LongReturnController`, `UpstreamOnlyController`, `HostileController` modes 1–5, and
`UpgradableController`), `src/tests/test_review.cairo` and `src/tests/test_review_real.cairo`.

Results: `snforge test` gives **180 passed, 0 failed** (147 original + 33 review).

| Test | Checks | Result |
|---|---|---|
| `r_not_before_boundary_accepted` | settles at `b == not_before` | PASS |
| `r_refund_at_deadline_needs_controller` | unapproved refund at `b == deadline` → `ESCROW_NOT_APPROVED` | PASS |
| `r_refund_after_deadline_zero_controller_and_event` | refund at `deadline+1` with controller and class 0; `PolicySettled` fields, `by_controller = 0` | PASS |
| `r_settle_then_refund_same_note_rejected` | release at deadline, refund at `deadline+1` → `NULLIFIER_USED` | PASS |
| `r_extra_return_data_rejected` | `['TEMPLAR_POLICY_OK', 0]` → `CONTROLLER_RETURN` | PASS |
| `r_upstream_selector_unreachable` | PR #2 selector only → reverts | PASS |
| `r_controller_reenters_policy_spend` / `_apply_spend` | → `REENTRANCY` | PASS |
| `r_controller_cannot_call_owner_setter` | → `NOT_OWNER` | PASS |
| `r_controller_cannot_relay_to_escrow` | hostile controller forwards the authorization → `ESCROW_CALLER` | PASS |
| `r_controller_fake_event_is_from_controller` | fake `PolicySettled` comes only from the controller address (IC-7) | PASS |
| `r_replaced_controller_class_blocks_then_refund` | self-upgraded controller → `CONTROLLER_CLASS`; refund after the deadline still settles | PASS |
| `r_late_failure_rolls_back_consumption` | withdrawal transfer fails after the escrow call → escrow and nullifier untouched; approval reusable | PASS |
| `r_escrow_of_another_pool_rejected` | → `ESCROW_CALLER` | PASS |
| `r_escrow_other_slot_rejected` | approve(1), settle index 2 → `ESCROW_NOT_APPROVED` | PASS |
| `r_escrow_key_includes_arbiter` | two arbiters, same id, independent consumption | PASS |
| `r_escrow_zero_policy_rejected` | → `ESCROW_POLICY` | PASS |
| `r_split_two_notes_event` | split `x = 600`: two notes, deliveries, event `x`/`first_index`/`by_controller` | PASS |
| `r_withdrawal_only_outcome` | no note, withdrawal paid, no `NotePublished` | PASS |
| `r_nothing_produced_rejected` | → `EMPTY_OUTPUT` | PASS |
| `r_recipient_without_amount_rejected` | → `BAD_WITHDRAWAL` | PASS |
| `r_active_output_zero_delivery_rejected` / `r_inactive_output_nonzero_delivery_rejected` | → `DELIVERY` / `INACTIVE_PAYLOAD` | PASS |
| `r_ciphertext_count_rejected` / `r_short_ciphertext_rejected` | → `CIPHERTEXT_COUNT` / `PAYLOAD_LENGTH` | PASS |
| `r_zero_nullifier_rejected` | → `ZERO_NULLIFIER` | PASS |
| `r_refund_shape_not_rechecked_by_pool` | documents IC-5 (settles) | PASS |
| `r_shared_nullifier_r0_then_p1` / `_p1_then_r0` | → `NULLIFIER_USED` both ways | PASS |
| `r_r0_path_uses_r0_verifier` | R0 rejects, P1 accepts → `apply_spend` `PROOF_REJECTED` | PASS |
| `r_real_p1_facts_rejected_by_r0_tagged_adapter` | real P1 facts, R0 tag, P1 statement and class → `PROOF_BINDING` | PASS |
| `r_real_p1_facts_accepted_by_p1_adapter` | control for the above | PASS |
| `r_real_swapped_ciphertexts_rejected` | real release, ciphertexts swapped → `DELIVERY` | PASS |

Tooling note: snforge's `replace_bytecode` cheat swaps the code but leaves
`get_class_hash_at_syscall` returning the old class, so it cannot test class pinning. Use a
controller that calls `replace_class_syscall` itself, as `UpgradableController` does.

## Recommended test additions (to port into the repository)

1. All the scratch tests above, notably the self-upgrading-controller pinning test, late-failure
   rollback, extra return data, the upstream selector, re-entry into `apply_policy_spend` and
   `apply_spend`, the shared nullifier map in both directions, the R0 verifier on the R0 path,
   P1 facts against an R0-tagged adapter, and the `PolicySettled` contents.
2. §9 KATs (IC-2) and a split receive test (IC-3).
3. Still not covered anywhere (needs provers or relation tests, out of this review's scope): a
   real-proof split settlement, and the relation-side items of the §10 list (out-of-range limbs,
   wrapped conservation, index/selector mismatch), which belong to the Math Reviewer.
