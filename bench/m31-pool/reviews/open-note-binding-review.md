# Open-note binding review (R0 V3 compact path)

Independent protocol/binding review. The reviewer did not write the change. It is read-only
except for this file. No builds, tests or PROOF2 were run.

## Scope

Commits `05084b4^..03d8955` (context: `05084b4` V3 statement fields, `e6227f8` zero budget,
`364cad2` pool `apply_spend_with_invoke`, `1321a0f` rename/spec, `a25f2a4`, `b43eb0c` e2e and
Sepolia simulation).

Files reviewed:
- Spec/ADR: `docs/open-note-spec.md`, `docs/adr/0023-…` (amendment), `docs/adr/0024-…` (context).
- Pool: `bench/m31-pool/cairo/src/{open_note,spend,pool,adapter}.cairo`, tests
  `cairo/src/tests/test_open_note*.cairo`.
- Client: `client-port/cairo-r0/bridge/src/lib.cairo`, `cairo-r0/account/src/lib.cairo`,
  `client-port/src/payment.rs` (statement and circuit, identity handle).
- Wallet: `bench/m31-pool/open_note.py`, `bench/m31-sepolia/open_note_flow.py`.
- Upstream (read-only): `privacy.cairo` (`compute_and_invoke`, `_apply_invoke_and_deposits`,
  `_deposit_to_open_note`), `hashes.cairo::compute_identity_key`,
  `shadow_account_anonymizer.cairo`, `ekubo_swap_anonymizer.cairo`.

## 1. What one proof authorizes

The proof reaches the pool as a PROOF2 message
`[statement_class, 'TMPZR0_PAYMENT_V3', chain, pool, binding]`. The adapter checks the whole
message (`adapter.cairo:394-398`). The binding is
`Poseidon('TMR0_BIND_V3', chain, pool, token, root₉, nf₀₉, nf₁₉, cm₀₉, d₀, cm₁₉, d₁, recipient,
amount, intent, identity₉)` (`spend.cairo:390-409` = `bridge/lib.cairo:158-183`). The pool
recomputes it from the submitted `Spend` (`pool.cairo:219-220`). It then recomputes `intent`
from the submitted `ExecutionIntent` (`pool.cairo:134`, `open_note.cairo:254-279`).

| Relayer-supplied field | Bound? | Where |
|---|---|---|
| chain, pool, token | yes | binding and intent; `verify_spend` checks chain and pool against the executing context (`pool.cairo:216-218`) |
| root, nullifiers, output commitments, output ciphertexts | yes | binding (ciphertexts through `delivery_digest`) |
| budget recipient and amount (withdrawal) | yes | binding and intent (`open_note.cairo:261`) |
| kind, selector | yes | intent; `selector_of` rejects any kind other than 0 or 1 (`open_note.cairo:242-249`) |
| adapter | yes | intent; also required to be nonzero and not the pool (`pool.cairo:137`) |
| nonce | yes | intent (`open_note.cairo:261`) |
| expiry (block number, inclusive) | yes | intent; `get_block_number() <= expiry` (`pool.cairo:135`) |
| calldata (length and felts) | yes | intent, length-prefixed, at most 64 felts |
| destinations: count, note_id, token, minimum, inner₉, ciphertext | yes | intent, count-prefixed; inner length asserted to be 9; ciphertext through `delivery_digest` (fixed 10 words, range-checked) |
| identity handle | yes | **binding** (not intent). Pool requires it for COMPUTE and forbids it for INVOKE (`pool.cairo:139-143`) |
| COMPUTE identity commitment | derived | pool computes `Poseidon(partial(identity), nonce)` and prepends it (`pool.cairo:154-156`) |

Not bound, and why it matters:
- **Adapter return data** (actual amounts, and the associated addresses returned by COMPUTE). The
  adapter decides these. The pool only enforces the count, the order, note_id and token equality,
  `0 < amount`, `amount >= minimum`, and the exact balance change of each pull
  (`pool.cairo:165-176`). Associated addresses are parsed and then discarded (`pool.cairo:160-163`).
  Upstream behaves the same way, apart from screening.
- **Submission timing**. The relayer chooses when to submit, anywhere up to
  `min(expiry, base + max_proof_age)`. It can also resubmit after a revert (see L3).
- **Note indices and append order**. These are not bound, but the code fixes them: private
  outputs come first, then open notes in destination order (`pool.cairo:146-181`). This is the
  same as for ordinary spends.
- **Transaction envelope**. The relayer can put other calls before or after the pool call in the
  same multicall (sandwiching). Only `minimum` limits the effect.

The identity handle is outside `intent`. That is fine, because the binding covers `intent` and
`identity` together.

## 2. Findings

| ID | Sev | Location | Issue | Concrete scenario | Suggested fix |
|---|---|---|---|---|---|
| M1 | Medium (privacy) | `payment.rs:19-21,766-767`; `spend.cairo:331-332`; `open_note.cairo:282-291`; spec l.76-78 | The identity handle `H(IDENTITY, sk₀‖scope)` is published in plaintext in `Spend.identity` calldata, and it is independent of the nonce. Anyone can compute `partial = Poseidon('TEMPLAR_IDENTITY_V1', handle₉)`. Upstream keeps `identity_key` and the partial commitment off-chain; its docs say the "preimage is off-chain only and unrecoverable from on-chain data" (`shadow_account_anonymizer.cairo:111-112`). | An observer takes the handle from one COMPUTE transaction and calls the public view `get_shadow_accounts(partial, 0, 1024, false)`. This lists **every** shadow account (every nonce) the owner has under that scope, deployed or not, and so links positions that upstream keeps unlinkable. The same fixed handle also links every future COMPUTE spend with that scope. | Fold the nonce into the proven handle, for example `handle = H(IDENTITY, sk₀‖scope‖nonce)`, and use a fixed upstream nonce (0). Alternatively publish only a per-account value. At minimum, correct the spec's "not the owner's other notes / links its own actions" claim and list the handle as public. |
| M2 | Medium (qualification) | `cairo/src/tests/test_open_note.cairo` (3 positive tests), `test_open_note_e2e.cairo` (2 positive) | There are no negative tests for any guard: `EXECUTION_INTENT` (tampered calldata, destination, adapter, expiry or kind), `EXECUTION_EXPIRED`, `IDENTITY_REQUIRED/UNEXPECTED`, `INTENT_NEEDS_INVOKE`, `DUPLICATE_NOTE_ID`, trailing `INVOKE_RETURN`, count/ID/token/amount mismatches, `OPEN_NOTE_FUNDING` (fee-on-transfer), `TOTAL_NOTE_COUNT`, reentry. ADR-0023's amendment itself defers the math review and adversarial tests. | A regression in any guard would go undetected. For example, dropping `spend.intent != 0` or the identity checks. | Add the adversarial suite, including an invoke proof settled through `apply_spend` and the reverse, and do the Math Reviewer pass before calling this qualified. |
| L1 | Low | `pool.cairo:151`; upstream `ekubo_swap_anonymizer.cairo` (no caller check, no storage) | The pool does not relate the budget (recipient and amount) to the adapter or its calldata. Upstream's Ekubo anonymizer is permissionless and spends its own balance. | A wallet authorizes a budget of 300 to the anonymizer with calldata `in_amount = 250` (or a route that refunds). Fifty tokens stay in the anonymizer, and anyone can take them with their own `privacy_invoke(… in_amount=50 …)`. The owner authorized both values, so this is a wallet-validation failure, not a relayer attack. | Wallet: require `budget == calldata in_amount` and `recipient == adapter` for known INVOKE adapters. Optionally add a pool-side INVOKE policy `recipient ∈ {0, adapter}`, and state it in the spec. |
| L2 | Low | `open_note.cairo:266-277`; `pool.cairo:167-178` vs `deposit` (`pool.cairo:111`) and spec l.87-88 | Destinations are not required to have nonzero `inner`, `token` or `minimum`. `deposit` rejects a zero `inner`. Upstream rejects a zero token. | A buggy wallet authorizes `inner = 0`. The pool pays the budget and appends a funded note that nobody can spend, because it would need a preimage of zero, so the value is burned. With `minimum = 0`, the adapter can return 1 unit. | Add `assert(!is_zero(inner) && token != 0)` in `hash_intent`, and either require `minimum > 0` or document that zero is allowed. |
| L3 | Low | `pool.cairo:135`; `adapter.cairo:389-392` | Timing and replay after a revert. Every effect reverts, including the nullifiers, so a proof that fails (for example on `minimum`) can be resubmitted until the expiry or the proof age is reached. The relayer controls ordering and can sandwich the swap down to `minimum`. It cannot change any parameter. | A relayer holds the transaction, moves the Ekubo price until output ≈ `minimum`, then submits. Upstream has the same exposure. | The wallet sets a tight `minimum` (both the Ekubo `minimum_received` and the destination minimum) and a short `expiry`. Document the resubmission semantics. |
| L4 | Low (trust) | spec l.46-48; upstream `ShadowAccountAnonymizer` (`ReplaceabilityComponent`, `upgrade_delay: 0`, `shadow_account_class_hash`) | Using upstream's anonymizer "unchanged" means Templar deploys its own instance, with `privacy_contract = Templar pool`, a governance admin and a shadow-account class. Its governance can replace the class immediately. The anonymizer controls `shadow_account.execute`. The pool pins no adapter class hash. | A compromised or malicious anonymizer governance upgrades the class and drains every persistent shadow-account position, or returns deposits while keeping proceeds. Only `minimum` limits the latter. | Deploy with governance renounced or a non-zero upgrade delay, have the wallet check adapter, anonymizer and shadow class hashes before signing, and record the trust in ADR-0023. |
| I1 | Info | `open_note.cairo:226`, `payment.rs:19` | For INVOKE, the "nonce zero" rule is only a comment. It is still bound, so security is unaffected. The nonce is a felt, while upstream's scan views take `u64`, so a nonce ≥ 2^64 is not recoverable through `get_shadow_accounts`. | — | Assert `nonce == 0` for INVOKE and `nonce < 2^64` for COMPUTE. |
| I2 | Info | `payment.rs:341,766`; upstream `compute_identity_key(user, sk, contract_address)` | Nothing binds the handle to the anonymizer or dapp. Upstream's identity key includes the anonymizer address and a `dapp_name`. Templar relies on the wallet choosing a distinct scope per application. It is also derived from input 0's `sk`, so a wallet that holds notes under several keys gets different shadow sets. | Reusing a scope across two anonymizers links them, because the same handle is public (see M1). | Derive the scope from (secret, adapter address, dapp), and document the input-0 key rule. |
| I3 | Info | `pool.cairo` (no intent nullifier) | An `intent` is not single-use. The owner could prove it twice with different inputs, producing two notes with the same `inner` (the same `rho`) and identical ciphertexts, which are publicly linkable. The positional nullifiers do not collide. | Only reachable through wallet misuse. | The wallet never reuses a destination `inner` or `note_id`. |
| I4 | Info | `pool.cairo:167-178`; upstream anonymizer l.469-472 | Two destinations with the same token revert through the shadow anonymizer, because a second `approve` overwrites the first. This affects liveness only. | — | Reject duplicate destination tokens for COMPUTE in the wallet. |
| I5 | Info | `open_note.py:28-39` | The Python `hash_intent` matches Cairo field by field: domain, chain, pool, token, kind, adapter, nonce, recipient, budget, expiry, selector, `len(calldata)`, calldata, `len(d)`, then per destination note_id, token, minimum, inner₉, delivery digest. It lacks the duplicate-note_id check and range checks for felt < P, u128 and u64. Any divergence only makes the proof fail to settle. `identity_commitment` (`poseidon_hash_span([p, n])`) equals `HashState.update(p).update(n).finalize()`, and a test covers this (`test_open_note_e2e.cairo:26`). | — | Mirror the Cairo asserts in the wallet. |

No Critical or High findings.

## 3. Sound by construction (verified)

- **Ordinary vs invoke cannot be swapped.** `apply_spend` requires `intent == 0` and an inactive
  identity (`pool.cairo:125`). `apply_spend_with_invoke` requires `intent != 0` and
  `intent == hash_intent(...)` (`pool.cairo:134`). Because the binding covers `intent`, changing
  it breaks `BAD_BINDING`. The bridge also rejects an identity without an intent
  (`bridge/lib.cairo:140`), so a proof with an identity but no intent cannot be settled anywhere.
- **INVOKE vs COMPUTE.** The kind and its selector are in the intent. The identity must be present
  for COMPUTE and absent for INVOKE, and it is in the binding. A proof for one kind cannot be
  settled as the other.
- **Cross-pool, cross-chain, cross-token.** These are in the binding and the intent. The pool
  checks chain and pool against the executing context, and `Proof2Adapter` checks chain, pool,
  statement class and message tag.
- **V2 to V3.** V3 has a distinct statement tag (`R0V3`/`R0C3`), a pinned circuit hash, the binding
  domain `TMR0_BIND_V3`, and the message tag `TMPZR0_PAYMENT_V3`.
- **Zero budget.** When the budget is zero, the recipient must be zero, both on chain
  (`pool.cairo:311-313`) and in the bridge (`bridge/lib.cairo:135`). The recipient is also in the
  intent. `pay_withdrawal(produced=true)` is correct, because `hash_intent` requires n ≥ 1. Because
  the bridge requires at least one output or withdrawal, a zero-budget invoke must re-issue value
  as private change. This leaks nothing new. A nonzero budget goes only to the recipient the
  owner authorized.
- **Encoding is injective.** The intent has a fixed-width header, a length-prefixed calldata, and
  a count-prefixed list of fixed-width destinations (inner length asserted to be 9; the delivery
  digest takes exactly 10 range-checked words). The integer widths (u8, u64, u128) embed in a felt
  without collisions. Each domain word is the first element of its own Poseidon span:
  `OPEN_EXEC_V1`, `TMR0_BIND_V3`, `CTRL_DELIVERY_V1`, `TEMPLAR_IDENTITY_V1`. The bridge limbs are
  canonical (`felt_from_limbs` rejects values ≥ p). In M31 the identity kind `IDENTITY=9` differs
  from AUTH, NK, OWNER, INNER, NOTE, NODE, NF and NODE1.
- **Shadow addressing.** The circuit computes the handle from the same `sk[0]` variable that
  derives input 0's `ak` and `nk` (`payment.rs:663,766`). `id_active` is constrained to a bit
  (`merkle.rs:13-23`). The pool prepends the commitment itself, so the calldata cannot shift it. The
  anonymizer accepts only the configured privacy contract as caller. Routing through an adapter,
  a token or a shadow account changes the caller and so fails. Only someone who knows
  `(sk₀, scope)` can address a given shadow account. The nonce is bound.
- **Funding integrity.** The deposit count must match exactly and in order, with note_id and token
  equal. Each pull must change the pool's balance by exactly the amount (which rejects
  fee-on-transfer tokens). Trailing return data is rejected. The pool grants no allowances. The
  lock blocks re-entry into the pool. Any failure reverts every effect.
- **Replay.** Nullifiers prevent reuse. After a revert, only the identical authorized execution can
  be resubmitted.

## 4. Spec/code mismatches

1. The spec says (l.76-78) that a shadow account "links its own actions by design, not the owner's
   other notes", and its list of public data omits the handle. In the code the handle is public and
   links every shadow account and COMPUTE spend under one scope (M1).
2. The spec says (l.27, l.46-47) that the handle is per application. Nothing binds it to the
   adapter or dapp (I2).
3. The code comment "nonce: zero for INVOKE" is not enforced (I1).
4. The first-reference section (l.87-95) says "token, minimum and inner are nonzero" and describes
   "one withdrawal of the exact input amount to the adapter". The compact path enforces neither
   nonzero `minimum`, `inner` or `token`, nor a budget recipient equal to the adapter, nor a budget
   equal to the calldata amount. The compact section does not say these rules were relaxed (L1, L2).
5. The ADR-0023 amendment says math review and adversarial tests are pending. This is confirmed:
   no negative open-note tests exist (M2).
6. Everything else in the compact-path section matches the code: expiry uses the block number, the
   adapter is nonzero and not the pool, the identity rules, the order of verification, budget,
   call, match and pull, commitments computed on chain, private-before-open append order,
   `OpenNoteFunded`, the limits 2, 4 and 64, and no allowances.

## 5. Privacy and recovery (question 6)

The public sees the adapter, the full calldata (route, pool key, `minimum_received`, note_id), the
budget and its recipient, destination tokens and amounts, timing, and the link between the
transaction and its change output (same transaction, index adjacent to the open notes). The public
also sees the two nullifiers, which are unlinkable to their source notes under the existing model.
For COMPUTE it additionally sees the handle, from which it derives the partial commitment, and
from that every shadow account (M1). Upstream discloses the same execution data except the handle:
there only the identity commitment appears.

A destination's `note_id` is only a public tag. It is not bound to the owner, but reusing it across
executions links them. The wallet should use fresh random values, as the Sepolia flow does
(`open_note_flow.py:86`). Reusing `inner` links notes (I3). Recovery works: the ciphertext's
delivery digest is bound, and the amount comes from `OpenNoteFunded` and `NotePublished`.

## 6. Unverified

- Soundness of the circuit beyond the lines cited. The review assumed the bridge's pinned circuit
  hash matches `payment.rs`.
- Whether `poseidon_hash_span([p,n])` equals the upstream `HashState` result. This relies on the
  cited test; it was not re-run.
- Behavior of the deployed Sepolia anonymizer and Ekubo class hashes.
- Shadow-account class internals (`starkware_accounts::shadow_account`).

## Verdict

**CONDITIONAL GO for research use.** The binding is sound: every parameter the relayer submits is
proof-bound. Invoke and ordinary spends, and the two kinds, cannot be interchanged. Only the key
owner can address a shadow account. Conditions: resolve or explicitly document M1 before claiming
shadow-account unlinkability equivalent to upstream; add the adversarial tests and the math review
(M2) before calling the path qualified; add wallet validation of the budget and calldata and of the
destination fields (L1, L2).
