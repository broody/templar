# Return notes — atomic external funding

Status: accepted architecture under [ADR-0023](adr/0023-return-notes-and-adapter-compatibility.md).
Executable reference: [bench/return-note-e2e](../bench/return-note-e2e/README.md).
Production encoding and maintained-package integration remain pending.

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
