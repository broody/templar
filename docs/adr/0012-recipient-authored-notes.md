# ADR-0012: Recipient-authored notes (invoice flow); channel machinery cut

- Status: Superseded by [ADR-0021](0021-push-only-payments.md)
- Date: 2026-09-20
- Deciders: broody
- Amends: spec §3.1 (`note_secret`, `note_id`), §3.3 (delivery/discovery
  rewritten as the invoice protocol), §4 (channel storage removed), §8
  (`packed_value`, `ViewingKeySet` removed).

## Context

The unified note format (ADR-0009) binds `owner_private_key` into
`note_secret` and thence into the commitment, to make nullifiers receiver-only.
A consequence the spec never stated: **only the recipient can compute a note's
commitment**, because the sender lacks `owner_private_key`. With hash-only
derivations there is no escape — any format that let the sender compute the
commitment would let them derive the nullifier and creator-spend. (The
alternative — binding an owner *public* key and checking key derivation
in-circuit — adds non-native EC ops to the circuit.) Upstream never faced this:
no tree (sender-computable `note_id` sufficed as a storage key), and the
trusted prover supplied the owner key at spend time.

So third-party sends were already implicitly recipient-shaped. Meanwhile the
channel machinery inherited from upstream (`channel_key` derivation, ECDH
channel-info delivery, subchannels, `recipient_channels` / `outgoing_channels`
storage, the `public_key` registry) existed to **deliver sender-generated
secrets to recipients**. Under recipient-authored notes there is nothing to
deliver — the recipient generated the secrets.

## Decision

1. **Recipient-authored notes ("invoice flow")**. To be paid, the recipient
   picks `salt`, derives `note_secret = H(NOTE_SECRET_TAG:V3, salt,
   owner_private_key)`, `inner = H(NOTE_INNER_TAG:V3, note_secret)`, and
   `note_id = H(NOTE_ID_TAG:V3, note_secret)`, then sends an invoice `{token,
   amount, inner, note_id}` (optionally `controller`, `policy_commitment`) to
   the sender off-chain. The sender's spend bundle inserts
   `commitment = H(COMMITMENT_TAG:V3, token, amount, controller,
   policy_commitment, inner)` — computable by the sender from public fields
   plus the invoiced `inner` (ADR-0011), but never openable by them.
2. **`channel_key` is removed from `note_secret`**; the preimage shrinks to
   `(salt, owner_private_key)`. The recipient needs nothing from the sender to
   author notes.
3. **Channel machinery is cut**: no OpenChannel/OpenSubchannel/SetViewingKey
   entry points, no `recipient_channels` / `outgoing_channels` /
   `channel_exists` / `subchannel_*` storage, no `public_key` registry, no
   `ViewingKeySet` event, no `packed_value` in `NoteCommitted`. Discovery is
   local matching of `NoteCommitted` events against self-issued invoices
   (by `note_id`, with `commitment` recomputation as the trustless check).
4. Push payments are replaced by **receive boards**: recipients pre-publish
   single-use invoices (pseudonymously, or via their wallet service) — an
   SDK/discovery-layer concern, not protocol surface.
5. Voluntary disclosure (ADR-0002) is out-of-band: hand over the
   `owner_private_key` or per-invoice openings.

## Alternatives considered

- **Receive-key redesign** (publish `R = H(owner_private_key)`; `note_secret`
  binds `R`; nullifier additionally binds `owner_private_key`): restores
  sender-authored push payments at the cost of ~2 extra in-circuit permutations
  per note, an identity↔receive-key registry, another §3.1 revision, and the
  delivery machinery staying load-bearing. Rejected; receive boards approximate
  push UX without protocol weight.
- **Keep channels as an organizational layer**: they no longer enable anything
  — creation is recipient-shaped regardless — and per-counterparty organization
  becomes SDK-local invoice metadata. Rejected.

## Consequences

- Spec §3.3 shrinks to the invoice protocol; the discovery-spam risk (review
  §D.2) is structurally reduced — recipients match commitments they authored.
- Invoices are un-underpayable: the commitment pins token/amount/controller;
  the sender's only freedom is to pay the invoice or not.
- Unsolicited payments die at the protocol level (receive boards approximate
  them); change notes and self-deposits are non-interactive throughout.
- Circuit: shorter `note_secret` preimage (−~1 permutation per note);
  `CHANNEL_KEY_TAG:V1` upstream compatibility dropped (the V2 tags had already
  diverged).
- New golden vectors together with ADR-0011.
