# ADR-0020: Full viewing authority and recoverable push notes

- Status: Superseded by [ADR-0021](0021-push-only-payments.md), which adopts viewing/recovery capabilities; production key-format review remains pending
- Date: 2026-09-20
- Deciders: broody
- Builds on: proposed ADR-0019; preserves ADR-0002's voluntary disclosure policy
- Would amend: the proposed push-note key model and wallet recovery contract
- Evidence: [view-recovery experiment](../../bench/view-recovery/README.md)

## Recommendation

Include optional full viewing authority in the push-note design before freezing
the address format. A user should be able to restore from their seed and public
encrypted history, or share a capability that watches the same address's balance
without giving away spending authority. Keep incoming-only disclosure available.
No viewing key is given to an operator or auditor by default.

The local experiment establishes feasibility with modest extra Cairo work. It
does not establish cryptographic security, production chain authentication or
historical data availability. Adopt only after reviewing those separate issues.

## User-visible capabilities

Bob receives 100, sends 60 to Carol, and receives 40 back as change. His history
contains two notes to his address, for 100 and 40. Adding those receipts gives
140, but the first note has already been spent. His available balance is 40.

| Capability | What it can learn or do |
|---|---|
| Public receiving address | Create a payment to Bob |
| Incoming viewing key | Decrypt Bob's received notes; sees 100 and 40 |
| Full viewing key | Also derive their nullifiers; identifies the spent 100 and unspent 40 |
| Seed / spending wallet | Recreate the keys, recover the 40, and authorize spending it |

"Full" is deliberately scoped: this prototype reveals the received notes and
their spent status for one receiving address. It does not recover all outgoing
destinations, sender identities or memos. When multiple inputs and outputs share
a transaction, it does not reveal a unique private input-to-output mapping.
An outgoing viewing key or encrypted transaction journal would be additional
functionality. [ZIP 310](https://zips.z.cash/zip-0310) is useful prior art for
distinguishing incoming, outgoing and full viewing privileges; this construction
does not implement Sapling or inherit its security analysis.

## Candidate key and nullifier construction

This is a new, unaudited construction. `H` is Starknet `poseidon_hash_span`;
each operation below has its own versioned domain tag in the implementation.

```
ak       = H(authority_domain, spending_secret)
nk       = H(nullifier_key_domain, spending_secret)
receiver = H(owner_domain, ak, nk)
inner    = H(inner_domain, receiver, note_randomness)
cm       = H(note_domain, chain, pool, token, amount, controller, policy, inner)
nf       = H(nullifier_domain, nk, cm, leaf_index)
```

The wallet derives an independent X25519 decryption secret from the seed. Both
spending and decryption derivations include the network and pool: exported key
material is not reused across those contexts. Software context checks alone
cannot limit the authority of an exported raw secret. The
receiving address includes protocol/network/pool context, `receiver` and the
encryption public key. The full viewing export contains the incoming capability,
`ak` and `nk`, with its address and format metadata. It contains neither seed nor
spending secret. The spending statement still requires the spending secret and
derives both `ak` and `nk` before checking ownership, membership and nullifier.
Knowing the viewing material should not let a viewer recover that secret under
the required hash preimage assumptions; substituting each viewing component for
it fails the tested Cairo ownership checks. Those tests are not a security proof.

Binding `nk` into `receiver` is significant. If an owner could export an arbitrary
unbound nullifier key, a viewer could be shown false nullifiers and mistake spent
notes for unspent ones. Import therefore verifies both the decryption-key/public-
key pair and `H(owner_domain, ak, nk) == receiver`. It also requires the expected
address to be authenticated independently. A self-consistent viewing export for
another address is not evidence about Bob's known address.

As in ADR-0019, the index is the same bounded leaf index authenticated by the
membership path. Duplicate deliveries of one leaf are deduplicated; two separately
funded leaves with identical commitments have distinct nullifiers. Output
encryption stays outside the spending statement. Ordinary notes only are modeled.

`TEMPLAR_PUSH_POC2`, V2 hash domains, plaintext version 2 and new seed-derivation
labels deliberately distinguish this experiment from POC1 and the deployed V3
format. This is not a wallet-only change. Old notes must retain their old spending
and nullifier rules; applying new nullifiers to old leaves could reopen spent
funds. Migration and statement/version dispatch require separate review.

## Recovery contract and trust boundary

A seed recreates keys; it does not recreate random note data chosen by payers.
Recoverability therefore needs available ciphertext, canonical commitments and
positions, and the current spent-nullifier state. Store backup format/derivation
version and network/pool discovery metadata with the seed. Future account indices,
address rotations and scan bounds need an explicit backup/discovery standard.
The deterministic derivation here is a fixture scheme, not that standard.

The prototype separates two inputs:

1. A **trusted checkpoint** containing network/pool/version, canonical block
   identity and height, tree root/count, an ordered commitment/delivery-digest
   receipt manifest and the spent-nullifier set at that block.
2. An **untrusted archive** carrying encrypted payloads and event indices.

The trusted checkpoint currently comes from the local reference ledger. A real
implementation must obtain equivalent information from authenticated chain
data or an explicitly trusted node. A block hash supplied by the same hostile
archive is insufficient. The experiment does not verify Starknet consensus,
receipt inclusion, state proofs, finality or RPC authenticity.

Recovery rebuilds the commitment tree and compares the checkpoint root, checks
every payload against the checkpoint receipt at its index, decrypts matching
notes, recomputes their commitments, and marks them spent using the checkpoint's
nullifiers. A root authenticates the commitments and positions; it does **not**
authenticate encrypted bytes. The expected delivery digests must additionally
come from authenticated transaction/receipt data. Self-consistent ciphertext and
digest returned by a hostile archive are not sufficient.

The result is explicitly **as of the checkpoint block**. A valid old snapshot is
a historical balance. A minimum height rejects known-stale checkpoints but does
not independently prove current canonical status. A reorg replaces the checkpoint
and rebuilds state in this prototype; no incremental database rollback is claimed.

## Missing data must be visible

If a payload is missing at any canonical position, return a list of missing
positions and an incomplete result. A full viewer may display known unspent
notes, but must not label that number as the complete balance. In particular,
"no known unspent notes" must not silently become "balance zero". Until the
missing payload is retrieved and decrypted, the wallet cannot tell whose it is.

Reordered events and identical duplicate deliveries are accepted. Conflicting
duplicates, unexpected positions, changed commitments, changed ciphertexts,
changed delivery digests and inconsistent checkpoint manifests are rejected.
Retrying against a complete archive restores the missing note. The prototype
requires all output payloads; efficient selective discovery is future work.

This completeness guarantee is limited to **recoverable protocol-published notes
for the supplied receiving address**. It does not prove that a person disclosed
every address or all their finances. The statement still does not prove correct
encryption. A payer can publish an authenticated but undecryptable ciphertext,
including one that does not match the committed note. A scanner cannot always
distinguish such a failed intended payment from an output for another recipient.
Wallets must only credit successfully decrypted, commitment-matching notes.

Publish ciphertext atomically with outputs and retain historical bytes, as
proposed in ADR-0019. A digest alone cannot recover lost data. Actual Starknet
payload costs, retrieval guarantees and archive redundancy remain unmeasured.

## Disclosure and compromise

Full viewing is optional and sensitive. For the same long-lived address, its
holder can inspect past published receipts and future receipts, and correlate
their nullifiers with spends. Sharing it is broader than sharing incoming view.
It should not be advertised as a limited-time or revocable grant: deleting an
export does not erase copies. Rotate both receiving and encryption key material
and publish a new authenticated address to limit future disclosure; old history
and any later payments to the old address remain exposed to the old viewer.

A stolen incoming key leaks receipt contents; a stolen full viewing capability
also leaks spent status; a stolen seed grants spending authority. Key-export
encryption, user consent screens, secure storage, address authentication and
rotation discovery are not implemented. The prototype serializes only synthetic
public fixture keys to test import consistency. Real key transfers must not use
its plaintext test-export workflow.

## Evidence and next gate

- 48 Python tests cover the note model, key separation, export consistency,
  recovery, incomplete/corrupt history, stale checkpoints and reorg rebuilding.
- Five valid Cairo vectors and 17 rejected witnesses cover ownership, membership,
  nullifiers, conservation, output/delivery binding and old-version rejection.
  Substituting incoming, authority or nullifier key material for the spending
  secret fails. A false nullifier still fails with a recomputed public binding.
- The two-input/two-output/one-withdrawal case increases from 179 to 187 Poseidon
  instances and from 7,981 to 8,199 standalone Cairo steps. The key model adds
  four Poseidon instances per input; payload size stays 304 bytes per output.
- The evidence directory records standalone recursive proofs, verifier checks,
  public-output comparisons, process time and memory separately from Cairo counts.
  These use the earlier ADR-0018 staged harness, not the live V1 virtual OS.

The next useful gate is an isolated implementation of the ciphertext data contract
and authenticated recovery against the current V1/Sepolia flow, after independent
review of the proposed key/nullifier construction. Exercise offline receipt,
watch-only balance, loss of local wallet data, restore and spend. Measure full
history download/tree reconstruction and marginal onchain data cost. Qualify on
the actual target desktop: this key design does not remove the roughly 14 GiB
RSS previously observed for live V1 proving. Persistent delivery channels remain
an optional discovery optimization, not a prerequisite for these capabilities.
