# ADR-0004: Sparse commitment tree + nullifier ring state model

- Status: Accepted — §4 (controlled-map exemption) superseded by ADR-0009
- Date: 2026-09-19
- Deciders: broody

## Context

Upstream stores notes in `Map<note_id, Note>` and establishes ownership via storage
reads inside the trusted prover's virtual block. That only works while the prover
may see secrets (ADR-0005 removes that). Note *existence* must become provable
without reading all storage; upstream already has the sound half — the nullifier
map with `WriteOnce` double-spend protection (`privacy.cairo:102`, `953-958`) — and
no Merkle tree at all.

## Decision

TemplarPool state model:

1. **Ordinary (account) notes** become tree leaves: `cm = H(TREE_TAG, note_secret,
   token, amount, salt)`, stored in a sparse Merkle tree implemented over Starknet
   storage maps (`Map<index, cm>`), with the root in storage and the root emitted in
   every spend event.
2. **Root history ring**: `root_history: Map<felt252, bool>` over a bounded set of
   recent roots, so a circuit proof can reference a root that was current when the
   user built it, without race conditions against concurrent deposits. Ring bound is
   a config constant (start: 256).
3. **Nullifier set**: kept verbatim from upstream (`Map<felt252, bool>`, WriteOnce,
   nullifier formula `hashes.cairo:229-236`).
4. **Controlled notes** (ADR-0006) do **not** enter the tree: their `note_id` is
   public at creation, so the spend's opening check reads
   `controlled_notes[note_id]` from public storage inside the outer block without
   learning secrets. Tree membership is only needed where the identifier itself is
   secret.

   > **Superseded (ADR-0009)**: this exemption is unsound under the blind-operator
   > model — the storage binding must enter the inner proof's public inputs, which
   > links every spend to its creation. Controlled notes are tree leaves too.
5. Hash layouts and domain-separation tags are frozen in
   `docs/pool-v2-spec.md` (M1 spec) before circuit work starts (M2) — the contract
   and the inner circuit must agree byte-for-byte.

## Alternatives considered

- **Keep map-only state, prove storage inclusion inside the virtual block**: this
  is exactly upstream's model; it requires the prover to see openings (rejected by
  ADR-0005).
- **Append-only dense tree with on-chain insertion circuit**: stronger succinctness
  than sparse, but adds insert-proof machinery per deposit; sparse-over-storage gets
  the same security for far less contract complexity.
- **Zcash-style incremental tree with on-chain root updates in-circuit only**:
  rejected for now — Starknet storage ops inside `apply_actions` are cheap and
  auditable; revisit if insertion cost dominates.

## Consequences

- The SDK must maintain the tree locally (leaves via discovery or own node) and
  produce Merkle paths as circuit witnesses.
- Discovery service gains a "get leaves[i..j]" endpoint; it stays zero-trust since
  leaves are commitments.
- ~log2(N) Poseidon hashes per spend in the circuit (≈ 40 × 3 for 10^12 leaves) —
  measured context: the whole client-phase workload is ~75 Poseidon/transfer
  (bench-results.md), so paths roughly double per-spend hash cost; acceptable.
