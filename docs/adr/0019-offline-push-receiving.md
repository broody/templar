# ADR-0019: Explore offline push receiving with separate delivery and spending keys

- Status: Superseded by [ADR-0021](0021-push-only-payments.md), which accepts push-only architecture; this prototype and its evidence are preserved
- Date: 2026-09-20
- Deciders: broody
- Would amend: ADR-0012 (mandatory recipient invoices), ADR-0018 §3 (preserved note semantics), and the note/discovery portion of the pool specification
- Evidence: [push-receive experiment](../../bench/push-receive/README.md)

## Problem and recommendation

A recipient currently has to prepare a single-use invoice before another person
can pay them. Pre-published invoice boards still require inventory, discovery,
coordination between simultaneous payers and recovery of invoice secrets. They
do not provide the same experience as sharing an address once and receiving an
arbitrary payment while offline.

Restore this experience as a protocol capability. Keep invoices as an optional
application flow. Start with independently encrypted notes to a reusable address;
evaluate persistent channels as a later discovery/throughput optimization. The
upstream channel/subchannel maps are not required to make the first payment work.
These are note-delivery channels, not offchain balance/payment channels: every
payment still settles through the pool and requires a spend proof.

ADR-0012's broad claim that hash-only ownership cannot permit sender-authored
notes is not generally correct. Its own alternative describes a hash-derived
public receiving key with a secret-keyed nullifier. The expensive non-native
arithmetic and fixed-circuit assumptions no longer apply under the selected
local Cairo/Stwo architecture. Encryption, discovery, recovery and privacy
engineering remain necessary; Stwo does not solve those automatically.

## Product acceptance target

1. Bob publishes an authenticated receiving address once; no channel-opening
   transaction or per-payment response is required.
2. Alice and Carol independently send different amounts while Bob is offline,
   without sharing a counter or reserving an invoice.
3. Bob restores from his backup, obtains authenticated public pool history,
   decrypts his receipts and spends them. Neither payer learns his spending key.
4. Observers see commitments and fixed-size encrypted payloads, without a public
   stable recipient/channel identifier. The sender cannot compute the recipient's
   spending nullifier from the opening it created.
5. Incoming viewing authority can be shared without granting spending authority.

This does not promise that counterparties forget payments they made, prevent
amount/timing inference, conceal network queries, or hide public withdrawals.
An address's offchain publication may identify its owner. Recipient identity
must remain inside private note data, not an indexed onchain address field.

## Candidate ownership construction

This is an experimental construction requiring independent cryptographic review,
not an audited standard. `H` is canonical Starknet `poseidon_hash_span`; every
line has a distinct domain tag, shown in the implementation. The ordinary-note
prototype sets controller and policy to zero.

```
receiver = H(owner_domain, spending_secret)
inner    = H(inner_domain, receiver, fresh_note_randomness)
cm       = H(note_domain, chain, pool, token, amount, controller, policy, inner)
nf       = H(nullifier_domain, spending_secret, cm, leaf_index)
```

An address carries protocol/network/pool context, `receiver`, and an independent
encryption public key. The sender knows these public values and chooses note
randomness; it can construct the commitment but cannot derive `nf`. Spending
proves the receiving-key preimage, opening, depth-32 membership at `leaf_index`,
canonical nullifier, amount bounds and conservation. This path needs no elliptic
curve arithmetic inside the spend statement. Encryption is performed by the
wallet outside the proof.

The leaf index is taken from the same bounded index used by the membership path.
It allows two separately funded leaves containing identical commitments to
remain separately spendable. Re-delivery of an event for the same index must
not double-credit a wallet. A duplicate input at the same index is rejected;
the onchain spent-nullifier check prevents replay. Including position in the
new nullifier is an explicit format decision, not a change to existing V3 notes.
Fresh randomness is still necessary for privacy: duplicated commitments are
publicly linkable even though their funds remain spendable.

The public outer commitment preserves the proofless-deposit principle: the pool
computes token/amount/context binding from the actual funded amount plus `inner`.
The chosen receive key is hidden behind fresh randomness in `inner`.

## Delivery and recovery

The prototype uses libsodium sealed boxes through PyNaCl: X25519 with
XSalsa20-Poly1305, ephemeral sender keys, and 48 bytes of overhead. A fixed
256-byte plaintext produces a 304-byte encrypted payload. This primitive
authenticates ciphertext integrity, **not sender identity**. No sender signature,
memo or forward-secret channel ratchet is implemented. See
[libsodium's specification](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes)
and [PyNaCl's API](https://pynacl.readthedocs.io/en/latest/public/).

The plaintext includes version, chain, pool, token, amount, receiving key,
randomness and controller/policy, with canonical lengths/ranges and zero padding.
After decryption the wallet checks context, ownership identity and recomputed
commitment against the authenticated pool event. Encryption-key and receiving-key
substitution must be prevented by address authentication (QR/contact exchange
or an authenticated directory); no global identity registry is cryptographically
required. An unauthenticated directory can substitute an entire address.

The new public binding covers each `(commitment, ciphertext_digest)` pair and
each `(withdrawal_destination, amount)`. The digest hashes length-prefixed
31-byte chunks using a separate Poseidon domain, without reducing arbitrary
byte strings modulo the field. A production pool must recompute this digest
from the supplied payload, require exactly one payload for each output, and
publish the bytes atomically with insertion. A relayer must not be able to
replace/drop delivery data while retaining the same valid proof.

The proof **does not establish correct encryption** or that the recipient ever
receives the data. A malicious payer can create an undecryptable output and
lose their own money. A wallet must not treat that as a successfully received
payment. Proving encryption correctness is a separate cost/product choice.

Recovery needs both seed/key material and available encrypted history. A
ciphertext digest or a storage URL alone cannot restore a lost payload. The
first production candidate should publish ciphertext with the onchain output;
measure actual transaction size, data gas and historical retrieval behavior.
Offchain delivery alone would introduce a new availability assumption. The
prototype's local event list demonstrates the required data contract, not
Starknet event availability or mainnet economics.

The wallet must authenticate event source/index and handle finality/reorgs before
crediting a payment. Incoming scanning in this experiment consumes a trusted
local event stream; it is not a light client, RPC privacy solution or production
indexer. Full scans avoid address-specific queries but transfer all ciphertexts.

## Key separation and disclosure

The prototype derives independent spending and incoming-decryption secrets from
a seed with different labels. The seed derivation is an experimental fixture
scheme, not a final wallet backup/address standard. Sharing the incoming key
reveals incoming note data, including amounts, without supplying the spending
secret.

**Incoming view is not full view.** This construction does not give an incoming
viewer the nullifiers required to identify later spends, so it cannot report an
authoritative unspent balance. Do not solve that by disclosing the spending key.
If watch-only balances are a launch requirement, choose and review a separate
nullifier/viewing-key construction before freezing the format. Existing shielded
systems explicitly distinguish these authorities; [ZIP 310](https://zips.z.cash/zip-0310)
is useful for specifying expected disclosure properties, not a claim that this
prototype implements Sapling.

This supersedes neither accepted disclosure policy nor production keys yet;
ADR-0012's suggestion to share `owner_private_key` must not become a wallet's
"view-only" feature. X25519 delivery is not post-quantum, and compromise of a
long-lived decryption key exposes old published ciphertexts. Key rotation,
old-address receipt, diversified/contact addresses and backup scan ranges require
a wallet design. A stolen seed grants full wallet authority by definition.

## Independent notes versus persistent channels

| Property | Independent encrypted note | Persistent delivery channel |
|---|---|---|
| First payment | Address is enough; no setup transaction | A channel invitation/establishment rule is required, which can be piggybacked |
| Concurrent payers | Independent randomness; no recipient counter | Needs per-sender separation and robust sequence/nonce handling |
| Discovery | Trial decrypt all outputs in the simple baseline | Can use derived tags/indexing; query/tag linkability requires analysis |
| Cost | Per-note public-key encryption and 304 bytes here | May amortize key exchange and reduce payload/scan work; unmeasured |
| Recovery | Seed and complete encrypted output history | Also recover channel establishment, derivation state and rotation/ratchet history |
| Metadata | No stable public recipient/channel ID | Public maps, repeated IDs and recipient counts can reveal relationships |

Prefer independent notes for the first implementation. Preserve the option of a
channel transport that delivers the same canonical note plaintext without owning
funds or changing spend authorization. Require measurements before adding stateful
channel machinery. A channel is not automatically more private or more recoverable.
Spam/dust filtering and unsolicited-note coin-selection policy are required for
either design; the protocol should not force consolidation of every received note.

## Compatibility and implementation gates

This requires new domains and statement identity. It is not a verifier-only
upgrade to the existing pool: ownership/nullifiers, output data, binding and
discovery change together. The experimental `TEMPLAR_PUSH_POC1` version and
tags are intentionally distinct from V3. No production package or accepted ADR
is changed by this proposal.

If a migration is required, old inputs must retain their **old nullifier rule**.
Reinterpreting an old leaf with the new positional nullifier could permit an
already-spent note to acquire a different nullifier. Use an explicitly reviewed
versioned spend/migration path, or a fresh pool with a funded exit/redeposit path.
Do not install this experimental statement into the existing verifier slot.

Before adoption:

1. Review ownership, nullifier uniqueness, canonical encoding and key separation;
   decide incoming-only versus full viewing, address authentication and recovery.
2. Implement the output ciphertext field, digest/action binding and emission in
   an isolated pool, retaining deposit funding checks, known roots, nullifiers,
   token/fee rules and atomic rollback. Add controlled-note semantics separately.
3. Qualify the new statement with the exact V1 virtual OS/prover/verifier and
   adapter; complete offline receive → sync → spend on Sepolia. The earlier
   standalone proof harness is not a substitute for this network test.
4. Measure marginal payload/data gas, full transaction fees/limits, cold sync and
   recovery, and proving RAM on an actual consumer desktop. The existing live
   baseline is roughly 14 GiB RSS; a small change in Poseidon count is not a
   promise of small end-to-end proving RAM.

## Other old tradeoffs to revisit separately

- ADR-0006 external controller signatures: local deterministic policies no longer
  inherently disclose openings to an operator. External authorities and mutable
  state still require authorization and settlement-time freshness checks.
- ADR-0014 fixed 4/4/2 and single-token bundles: measure useful batching and
  consolidation under Cairo; keep bounded resource use and unambiguous per-token
  conservation. Their limits stay unchanged in this experiment.
- ADR-0010 private invokes: the virtual-OS overhead argument has changed, but
  arbitrary pool-authorized dispatch remains an independent security concern.
  Evaluate a narrowly scoped integration only after ordinary payment UX.

The shared anonymity set, no mandatory auditor/screener, local proving,
receiver-exclusive spend authority, action binding and funding conservation
remain requirements regardless of the delivery mechanism.
