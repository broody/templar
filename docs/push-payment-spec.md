# Templar push payments — current architecture specification

Status: **Accepted architecture, production encoding not frozen** (2026-09-21),
under [ADR-0021](adr/0021-push-only-payments.md) and the S-two selection in
[ADR-0018](adr/0018-stwo-private-proving.md). The executable controlled/ordinary reference is in
[bench/controlled-push-e2e](../bench/controlled-push-e2e/README.md), under
[ADR-0022](adr/0022-controlled-push-payments.md). The ordinary-only reference and
its separate live evidence remain in [bench/push-e2e](../bench/push-e2e/README.md).
[Return notes](open-note-spec.md), accepted by [ADR-0023](adr/0023-return-notes-and-adapter-compatibility.md), extend ordinary spends with atomic external funding.
The primary packages are not yet integrated with these formats.

## Payment and authority model

A wallet shares a reusable shielded receiving address containing chain/pool
context, a receiving identity, and an independent encryption public key. A payer
selects the token and amount, chooses fresh randomness, constructs the recipient's
commitment, and encrypts its opening. Receiving does not require a response or
state shared with the payer. The same process creates change.

The controlled-push reference uses canonical Starknet `poseidon_hash_span` over felt252:

```text
ak       = H('CTRL_AUTH_V1', sk)
nk       = H('CTRL_NK_V1', sk)
receiver = H('CTRL_OWNER_V1', ak, nk)
inner    = H('CTRL_INNER_V1', receiver, rho)
cm       = H('CTRL_NOTE_V1', chain, pool, token, amount, controller, policy, inner)
nf       = H('CTRL_NF_V1', nk, cm, leaf_index)
```

Ordinary notes require zero controller and policy. Controlled notes bind a
controller contract and policy commitment and require approval to spend. Amounts are nonzero u128 values. Keys, receiving identities, and
randomness must satisfy the reference's canonicality and nonzero checks. Indices
are bounded to 32 bits and must be the same indices authenticated by membership.

A payer knows an output opening but lacks `sk` and `nk`. Spending requires `sk`:
the statement derives both `ak` and `nk`, checks ownership and membership, and
recomputes the nullifier. A full viewing export contains incoming-decryption
authority, `ak`, and `nk`, but not `sk` or the seed. Import checks their consistency
against an independently authenticated expected address. Incoming-only viewing
does not expose nullifiers and cannot determine an authoritative unspent balance.

Spending and incoming keys are derived with separate labels and chain/pool
context. The fixture seed derivation and serializations are not a final wallet
backup or address standard. Independent review is required for the cryptographic
construction before freezing production encodings.

## Delivery contract

The reference plaintext is 256 bytes: a four-byte version, seven 32-byte fields
(chain, pool, token, receiver, randomness, controller, policy), a 16-byte amount,
and twelve zero padding bytes, all canonically encoded. Libsodium sealed boxes
produce a 304-byte payload using the recipient's X25519 public key and a fresh
ephemeral sender key. Ciphertext integrity does not authenticate sender identity.

Encode those bytes as nine 31-byte big-endian felts and one 25-byte felt. Reject
wrong lengths and out-of-range words; do not reduce arbitrary bytes modulo the
field. The digest is:

```text
delivery = H('CTRL_DELIVERY_V1', 304, ciphertext_words[0..10])
```

Each output publishes `(index, commitment, digest, ciphertext)` atomically. The
reference pool stores an immutable digest at the same leaf index so archive
payloads can be checked against contract state. The note root alone does not
authenticate ciphertext. Production storage and authenticated history transport
may be optimized only while preserving this delivery and recovery contract.

The receiver decrypts, validates context and ownership, recomputes the commitment,
and confirms the funded canonical leaf before crediting a note. Encryption
correctness is not proved; an undecryptable output is not evidence of receipt.

## Pool and statement

The pool uses a depth-32 append-only Poseidon tree, a 256-root history, and a
spent-nullifier map. Two funded leaves with identical commitments have different
positional nullifiers; repeated delivery of one leaf must count only once.
Randomness must still be fresh because identical commitments are linkable.

`deposit(token, amount, controller, policy, inner, ciphertext)` requires no proof. The pool computes
the commitment from its own chain/pool context, actual token/amount, supplied
controller/policy fields, and the supplied inner value. It transfers funds from
the caller and publishes the encrypted note with the commitment in one operation.

A spend supports 1–4 inputs, 0–4 outputs, and 0–2 withdrawals, with at least one
output or withdrawal and exactly one public token. The statement proves ownership,
membership, correct nullifiers, output openings, amount bounds, and conservation:

```text
sum(input amounts) = sum(output amounts) + sum(withdrawal amounts)
```

The reference public bundle contains version, chain, pool, root, token, binding,
controller, deadline, nonce, transition digest, signature, ordered nullifiers, output commitment/ciphertext pairs, and recipient/amount
withdrawal pairs. Its binding is:

```text
H('CTRL_BIND_V1', version, chain, pool, root, token,
  controller, deadline, nonce, transition_digest,
  input_count, nullifiers_padded_to_4,
  output_count, (commitment, delivery_digest)_pairs_padded_to_4,
  withdrawal_count, (recipient, amount)_pairs_padded_to_2)
```

Pairs are flattened and unused slots are zero. The pool recomputes digests from
actual ciphertext and binds actual withdrawal destinations. The statement exports
`[version, chain, pool, root, controller, deadline, transition_digest, binding]`.
The protocol identifier is `TEMPLAR_CONTROL_POC1`. Ordinary spends require zero
controller, deadline, nonce, transition digest and signature fields.
No separately supplied generic action hash or public discovery ID is used.

Native PROOF1 verification checks the proof; the adapter pins virtual OS identity,
statement address/class, chain/pool, public message layout, and base-block age.
The pool checks context, binding, accepted root, unused nullifiers, and token
transfers. Ciphertext publication, nullifier writes, withdrawals, and pool fees
are atomic. The fee is paid separately by the public transaction caller; it is
outside private value conservation. Network gas is also separate.

## Controlled authorization

Each input commitment binds its controller and policy, and each output must have
that same controller. Ordinary and controlled inputs cannot mix in one operation.
Owners cannot strip the controller. The authorizer decides which output policies
are acceptable; the fixture preserves its one configured policy commitment.

The controller sees scoped transition legs, not spending keys, receiving identities,
input commitments/openings or Merkle paths. It sees amounts and policies that are
private from general observers. Its address is public on controlled spends.

```text
transition_digest = H('CTRL_TRANSITION_V1', version,
  chain, pool, root, token, controller, deadline, nonce,
  input_count, (nullifier, amount, policy)_triples_padded_to_4,
  output_count, (commitment, amount, policy, delivery_digest)_quads_padded_to_4,
  withdrawal_count, (recipient, amount)_pairs_padded_to_2)
```

The private statement computes that digest from the actual proven notes and
withdrawals. Counts and padding match the controller's encoding. Both the full
digest and public operation enter the statement binding. This prevents obtaining
a different valid proof for an unapproved withdrawal destination while reusing
an approval. Nonzero deadline, nonce and transition are required.

The fixture `SignatureController` holds an immutable Stark-curve public key. Its
ECDSA message is the low 251 bits of the digest, with identical masking in Python
and Cairo. It rejects zero and out-of-order signature scalars. The pool requires
a valid signature and `current_block <= deadline`, then consumes nullifiers
atomically. The nonce scopes requests but does not implement revocation.

The off-chain fixture checks context, expiry, policy, amount conservation, and
withdrawal destination/limit before signing. It is not a complete policy engine.
Controller unavailability can freeze funds; seed recovery does not bypass it.
There is no escape, key rotation, revocation or upgrade in this controller.
Approved public withdrawals release value from the note condition.

Recovery returns the controller and policy for every owned note. Reported unspent
value is distinct from currently authorized spendable value. A full viewer can
inspect these conditions and spent status without spending authority.

The distinct version, domain tags and key-derivation labels apply only to a fresh
pool. Ordinary POC2 proofs, keys and commitments cannot be reinterpreted as this
format. Independent review and primary-package integration remain outstanding.

## Recovery and disclosure

Restore requires the seed plus backup version and chain/pool metadata, canonical
commitments and positions, encrypted historical payloads, and spent status at one
checkpoint. The seed recreates keys, not payer-chosen randomness. Rebuild and
check the root, verify delivery digests, decrypt receipts, deduplicate by position,
and use nullifiers to compute the balance as of that checkpoint.

Missing payloads yield an incomplete result even if known unspent value is zero.
Conflicting data must be rejected. Reorgs require rebuilding from a canonical
checkpoint. The current two-provider RPC agreement is an explicit trust model,
not a consensus or state-proof verifier. Candidate-nullifier queries expose
wallet access patterns. Scalable private synchronization remains to be designed.

Full viewing reveals received notes and their spent status for its address; it
does not identify every sender, outgoing destination, or input/output pairing.
Exports are sensitive, optional, and not revocable once copied. Secure backup,
export, rotation, and address authentication are production requirements.

## Scope and evidence

Push payments are the sole receiving model. Persistent delivery channels and
invoice features are outside the initial product. Controlled notes are an optional
authorization condition within the push model. [Return notes](open-note-spec.md) add a proof-bound external call and atomic
funding of ordinary notes. Persistent or asynchronous external positions remain
outside this reference.

The [Sepolia results](../bench/push-e2e/README.md) demonstrate offline receipt,
full viewing, fresh-process seed recovery, recovered-note spending, public
withdrawals, and ciphertext/proof/replay rejection. They do not establish an
audited format, scalable history retrieval, physical-desktop qualification,
production token compatibility, or mainnet readiness. Existing deployed note
formats must retain their original nullifier rules; this specification does not
authorize reinterpreting old leaves.

The [controlled run](../bench/controlled-push-e2e/README.md) additionally validates
real signatures, controlled receipt/recovery/re-spending, withdrawal approval,
ordinary regression, and rejection of missing/wrong/expired approval, replay and
a changed destination with a valid new proof but the original signature. Native
execution rejects controller-key substitution and removal of committed conditions.
