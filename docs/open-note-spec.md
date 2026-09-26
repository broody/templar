# Open notes — atomic external funding

Status: accepted architecture under [ADR-0023](adr/0023-return-notes-and-adapter-compatibility.md).
**Renamed from "return notes" on 2026-09-24** (ADR-0023 amendment). Sections below the compact-path
section describe the first reference, on the client-side Cairo pipeline, where the construction is
called `ReturnNote`.

Executable references:
- first reference (client-side Cairo pipeline, `ReturnNote`):
  [bench/return-note-e2e](../bench/return-note-e2e/README.md);
- compact client-proof path (R0 V3): [bench/m31-pool](../bench/m31-pool/README.md), and the client
  relation in `bench/m31-private-wrapper/client-port`.

Production encoding and maintained-package integration remain pending.

## Compact client-proof path (R0 V3)

An open note is a transaction-local funding destination: a note of a declared token for a committed
owner, funded by one external call in the same transaction. The final note is ordinary. Upstream's
open note must also be filled in its creating transaction (`UNDEPOSITED_OPEN_NOTES`); upstream
writes an empty stored note and fills it, while Templar appends the funded commitment, which is the
natural form on an append-only M31 tree whose commitment includes the amount.

**Client statement (R0 V3).** V2's statement plus two public fields:
- `intent` (a felt): the execution the spend authorizes, `0x0` for an ordinary spend. The circuit
  carries it verbatim, so the proof commits the owner to exactly that execution.
- `identity` (nine M31 words): `H(IDENTITY, ak₀ ‖ scope)` under a private flag, zero otherwise,
  where `ak₀ = H(AUTH, sk₀)` is computed in the circuit from input 0's key, never guessed or
  copied. (ADR-0027 amends ADR-0023: this is the handle of R0 V5 and R0 V6 on pool V3. R0 V3 and
  V4 on pool V2 publish `H(IDENTITY, sk₀ ‖ scope)`.)

The execution's budget is the statement's withdrawal (possibly zero); its recipient is part of the
intent and may be any address except the pool (usually the adapter). A zero budget needs a zero
recipient, as for any withdrawal. An identity requires an intent. Binding: `TMR0_BIND_V3`. Tags: `R0V3`, `R0C3`. Account message tag: `TMPZR0_PAYMENT_V3`.

**Intent.** `ExecutionIntent { kind, adapter, nonce, expiry, calldata, destinations }`, with each
destination `OpenDestination { note_id, token, minimum, inner (9 words), ciphertext }`. `nonce` is
reserved and must be zero (see *Shadow accounts*). Each destination's `note_id`, token and minimum
are nonzero, its `inner` is a canonical nonzero digest, and `note_id`s are distinct; all are checked
before any external effect.

```
intent = Poseidon('OPEN_EXEC_V1', chain, pool, token, kind, adapter, nonce,
                  budget_recipient, budget, expiry, selector, |calldata|, calldata…,
                  |destinations|, (note_id, token, minimum, inner₉, delivery_digest(ciphertext))…)
```

- `kind = INVOKE`: selector `privacy_invoke`, calldata passed as is (upstream Ekubo and Vesu
  anonymizers).
- `kind = COMPUTE`: selector `privacy_invoke_with_computation`, calldata
  `[identity_commitment] ++ calldata`, where
  `identity_commitment = Poseidon(partial, 0)` (upstream `commitment_from_partial` at nonce 0) and
  `partial = Poseidon('TEMPLAR_IDENTITY_V1', identity₉)`. Only the owner of `sk₀` can produce a
  handle, since the circuit derives `ak₀` from `sk₀` (knowing `ak₀`, as a full viewing key does,
  is not enough), so only they can address their shadow accounts. Upstream's shadow-account
  anonymizer is used unchanged, configured with the Templar pool as its privacy contract.

**`COMPUTE` targets.** Upstream contracts trust the calldata prefix of
`privacy_invoke_with_computation` as the output of their own `privacy_compute`, run over the
user's secret in the client proof; they check only that the privacy contract is the caller. The
compact path has no such client-side computation: the prefix is always the pool's identity
commitment, followed by user calldata. That is exactly the shadow anonymizer's compute output, but
any other target would read user-chosen data as proven output. The pool therefore calls only
contracts whose class the owner has allowed (event `ShadowClassSet`). On pool V3 the owner allows
or removes a class through the timelocked `propose(class_hash, value)` and `apply(class_hash)`
(ADR-0027; `docs/pool-v3-spec.md` §8); pool V2's `set_shadow_class` is immediate. An
upgrade of an anonymizer changes its class and disables `COMPUTE` to it until the new class is
reviewed and allowed. General `privacy_compute` is not supported (ADR-0023).

**Shadow accounts.** The handle `H(IDENTITY, ak₀ ‖ scope)` is public, and anyone can compute
`Poseidon(partial, n)` from it for every `n`. A public nonce would therefore let anyone enumerate
every shadow account under one handle; the pool requires it to be zero. A wallet separates accounts
through the private `scope` instead, nine M31 words derived from a wallet secret and the context:

```
scope_i = Poseidon('TEMPLAR_SHADOW_SCOPE_V1', seed, chain, pool, anonymizer, dapp, index, i) mod (2³¹−1)
```

(`bench/m31-pool/open_note.py`, `shadow_scope`). Handles for different scopes are unlinkable without
`ak₀` and the seed; all executions under one scope share its handle and its shadow account.

**Settlement (`apply_spend_with_invoke`)**, under the pool's lock:
1. Recompute `intent`; check expiry (block number); the adapter is nonzero and not the pool; the
   identity handle is present for `COMPUTE` and absent for `INVOKE`; a `COMPUTE` adapter's class is
   allowed.
2. Verify the spend: context, binding, fact verdict, known root, fresh nullifiers.
3. Pay the budget to its recipient.
4. Call the adapter. Deserialize `Span<OpenNoteDeposit>`; for `COMPUTE`, optionally followed by the
   associated addresses. Nothing else may follow.
5. Require exactly one deposit per destination, in order: same `note_id` and token, amount nonzero
   and at least `minimum`.
6. Pull each amount from the adapter with `transfer_from` and check the pool's balance increased by
   exactly that amount.
7. Compute each commitment on chain, `commitment(chain, pool, token, amount, inner)`, as `deposit`
   does.
8. Append all of the transaction's new notes (private outputs, then open notes) in `insert_two`
   pairs (only the root after each pair is recorded as known; intermediate roots are not). Emit `NotePublished` for each, and `OpenNoteFunded { note_id, index, token, amount }` for
   each open note.

Any failure reverts every effect. The pool grants no allowances.

**Limits.** One adapter call and one input token per transaction; at most 2 destinations, 4 new
notes in total and 64 calldata felts.

**Recovery.** The destination ciphertext carries the owner's opening except the amount, which comes
from `OpenNoteFunded` and `NotePublished`. A wallet trial-decrypts `NotePublished` exactly as for
deposits.

**Public.** The adapter, calldata, budget and its recipient, destination tokens and amounts, and
(for `COMPUTE`) the identity handle and shadow account are public, as upstream. All executions under
one scope are linked through the handle by design; different scopes are not linked to each other or
to the owner's notes (see *Shadow accounts*).

**Trust in the adapter.** The pool relies only on the pulled balance and the destination checks;
the adapter itself is trusted for the price it gets. Upstream's Ekubo and Vesu anonymizers are
stateless with no caller check, so a budget left in one after a failed or partial fill can be taken
by anyone; the transaction must consume it (the minimum enforces the fill). Upstream's shadow-account
anonymizer checks its caller but is governance-upgradeable: whoever controls its upgrades controls
the shadow accounts' future behavior.


## Types and lifecycle

`ReturnNote { note_id, token, minimum, inner, ciphertext }` is a transaction-local
destination. `note_id` is an opaque handle, not a Merkle leaf, receiving address,
nullifier or globally reserved identifier. The `inner` value binds recipient
ownership and fresh randomness using the ordinary-note construction. The handle
must be nonzero and unique within the execution. Token, minimum and inner are
nonzero; minimum and actual amount are u128. Controller and policy are zero.

`ExecutionIntent { adapter, amount, expiry, calldata, notes }` authorizes one
external call. Its selector is fixed to `privacy_invoke`. The experimental cap is
64 calldata felts, one to four ordered return destinations, one withdrawal of the
exact input amount to the adapter, and four combined private/return note outputs.
The ordinary spend remains at 4 inputs / 4 outputs / 2 withdrawals; this path
restricts withdrawals to one funding leg. At least one return is required.

The pool consumes the private spend, calls the prefunded adapter, and decodes
exactly `Span<OpenNoteDeposit>` with `OpenNoteDeposit { note_id: felt252,
token: ContractAddress, amount: u128 }`. It checks the total response length before
deserializing. Responses must match the authorized destinations in count and
order, with identical identifiers/tokens and sufficient amounts. Trailing data
and upstream extensions carrying other metadata are unsupported.

For each return, pull the specified tokens from the adapter, verify the pool's
exact per-pull balance increase, construct the ordinary commitment using the
actual amount, and atomically publish its leaf and authenticated receipt. The
per-pull check occurs after the initial spend, allowing input-token refunds and
repeated return tokens without confusing withdrawals with incoming funding.
The reference tests these mechanics; deployed protocol support is narrower.

All operations execute under the pool lock in one transaction. A failure in a
later return rolls back earlier returns, input funding, change, nullifiers and
external execution. Network gas remains payable. A plain `apply_spend` rejects a
nonzero intent, and setting it to zero changes the proven spend binding.

## Authorization

The experimental intent is Starknet `poseidon_hash_span` of:

```text
RTN_EXEC_V1, TEMPLAR_RETURN_POC1, chain, pool, input_token,
adapter, input_amount, expiry_block, selector(privacy_invoke),
calldata_length, calldata...,
return_count,
(note_id, token, minimum, inner, ciphertext_digest)...
```

The intent hash enters the spend binding and is recomputed by the pool from the
actual call. The private ownership statement verifies that binding; it does not
predict AMM execution or an output price. Each token amount is accounted in its
own units: the private spend funds the input leg, and external token receipts
fund the returned notes. The system never equates units of different tokens.

The pool has no adapter/router allowlist in this reference. The wallet must
validate its supported route and token assumptions before authorizing the exact
call. Callers cannot substitute those parameters under the original proof.
The pool grants no adapter allowance on its existing token holdings.

## Receipt and recovery

The isolated reference uses `RTN_*` domains and `templar/return-poc1` key derivation
scoped by chain/pool; it never reinterprets previous experimental notes.

The existing 256-byte ordinary plaintext uses version 2 and contains an exact
amount. A return template uses version 3 with the same ownership/context fields
and zero amount bytes. Both seal to 304 bytes. The version-3 template is prepared
locally; the final positive amount comes from settlement.

```text
commitment = H(RTN_NOTE_V1, chain, pool, token, actual_amount, 0, 0, inner)
digest     = H(RTN_RETURN_V1, actual_amount, ciphertext_digest)
```

`NotePublished(index, commitment, digest, settled_amount, ciphertext)` carries
the public return amount. Ordinary publications use zero metadata and the normal
ciphertext digest. The pool stores the delivery digest at the immutable leaf
index. The wallet validates the authenticated digest, decrypts and validates the
receipt, combines the actual amount, and recomputes the funded commitment. It
then holds the same `Note` type and derives the same positional nullifier as for
an ordinary receipt within this deployment.

Full viewing and seed restoration require retained ciphertext and authenticated
history. A missing payload is incomplete recovery, not a complete zero balance.
Ciphertext decryptability is not established by the proof; wallet construction
and address authentication remain required.

## Upstream compatibility and scope

The adapter boundary retains upstream `OpenNoteDeposit` serialization, while
Templar uses `ReturnNote` internally. Adapters receive an opaque `note_id`, execute
their public protocol, approve their caller to collect proceeds, and return
funding instructions. They need no knowledge of Templar's tree or ownership keys.
Pin source and check deployed class hashes; matching an ABI alone is not security
qualification.

The imported Ekubo adapter supports a full exact-input single hop. The current
live route has no extension and uses synthetic assets in deployed Sepolia Ekubo.
The imported Vesu adapter supports supply/redeem; local mock-vault tests do not
qualify live positions, borrowing, partial fills or arbitrary tokens.

Calls, amounts and the return deposit are publicly linked. Recipient identity and
earlier private input membership remain subject to the existing privacy model.
There is no persistent pending balance, partial funding, asynchronous claim or
controller requirement in this reference. Production token behavior, wallet
submission, privacy transport, memory and scalable synchronization remain open.
