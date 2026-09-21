# ADR-0009: Note-type unification (single format, optional controller authorization); open notes cut

- Status: Accepted; ownership/nullifier derivations and initial ordinary-note scope amended by [ADR-0021](0021-push-only-payments.md); open-note exclusion superseded by [ADR-0023](0023-return-notes-and-adapter-compatibility.md)
- Date: 2026-09-19
- Deciders: broody
- Supersedes: ADR-0004 §4 (controlled-map exemption), ADR-0006 §2 (verbatim PR
  derivations + bearer spend semantics); see also the spec revision it drives.

## Context

Asked whether Templar could support *only* controlled notes (dropping ordinary and
open notes), analysis found three things:

1. **The bearer-spend path cannot be removed, only relabeled.** A plain private
   transfer has no application to authorize it. Controlled-only forces a "null
   controller" (mandatory signing infrastructure + key-custody risk for every
   basic transfer), a self-controller (redundant with the spend capability), or
   `controller = 0` meaning no authorization — which is an ordinary note under
   another name. Ordinary notes are the degenerate case of controlled notes.

2. **A flaw in ADR-0004 §4 and the draft spec (§3.2/§7.3), found via this
   exercise.** The draft stored controlled notes in a public map and skipped tree
   membership, on the grounds that `note_id` is public at creation. Under the
   blind-operator model (ADR-0005) that storage binding must enter the inner
   proof's *public inputs* (stored commitment or note_id) — both are public at
   creation — so **every controlled-note spend would link back to its creation**.
   The map trick only works while the prover is trusted (upstream PR #2 hides
   note_id inside the trusted execution). Tree membership — proving the note
   exists *somewhere in the set* without naming it — is required for unlinkable
   spends under a blind prover, for **both** note types.

3. **The real simplification is unification, not deletion.** One note format, one
   tree, one nullifier domain, one circuit with an authorization bit.

## Decision

1. **Single note format** (channel machinery retained — receiver-only spend
   capability requires receiver-only secret material):

```
note_secret = H(NOTE_SECRET_TAG, channel_key, token, index, salt, owner_private_key)
note_id     = H(NOTE_ID_TAG, channel_key, token, index, salt)          // discovery key
commitment  = H(COMMITMENT_TAG, note_secret, token, amount, controller, policy_commitment)
nullifier   = H(NULLIFIER_V2_TAG, note_secret)
```

   `controller = 0` and `policy_commitment = 0` for ordinary notes. Binding
   controller/policy into the commitment makes the authorization requirement
   immutable on-chain: a note created as controlled can never be spent as ordinary.

2. **Both types are tree leaves.** No `controlled_notes` map. One root history
   ring, one nullifier set, one spend circuit with
   `authorization = NONE | Controller(transition_commitment)`.

3. **Controlled semantics change vs PR #2**: bearer `spend_key` is replaced by
   owner-keyed notes (the nullifier includes `owner_private_key`, so the note
   *creator/sender* can never spend a note they delivered — this also removes the
   creator/recipient double-spend race inherent to bearer openings). Transferring
   a controlled note = spend + create under the same controller in one transition.
   The ADR-0006 core redesign is retained unchanged: the controller validates
   off-chain and signs the transition commitment, verified in the outer block.

4. **Open notes are cut from v2.** Their single job (external contracts funding
   notes mid-proof — the Ekubo/Vesu anonymizer callback flow) is deferred; the
   re-add path is app-specific controllers or withdraw-and-redeposit. This drops
   the callback deposit-parsing machinery, `deposit_to_open_note`, and the
   open-note event family.

## Alternatives considered

- **Controlled-only** (the question that prompted this ADR): rejected — see (1);
  it relocates the ordinary-note semantics into a mandatory no-op authorization
  path while keeping all its complexity.
- **Keep bearer `spend_key` in the unified format**: rejected — creator always
  knows the opening of notes they create, so creator and recipient race to
  nullify; avoiding that is exactly why receiver-only material (`owner_private_key`)
  must be in the nullifier preimage.
- **Keep the map for controlled notes and accept spend-linkability**: rejected —
  some applications are fine with linkable escrow spends, but the protocol default
  must be unlinkable; apps wanting linkability can emit their own events.

## Consequences

- The delta from PR #2 is larger than "adopt with a redesign": the note *format*
  is v2-native (unified), the PR's `hashes.cairo` controlled-note derivations and
  bearer semantics are not carried over. The PR's protocol shape (creation debits
  private balance, one controller per tx, invoke-must-target-controller,
  signature-over-transition authorization, staleness receipts) is carried over.
- The M2 circuit gets *smaller* than the draft spec (no dual schemes, no
  open-note handling) but the tree path cost now applies to controlled inputs too.
- Discovery keeps upstream compatibility: `note_id` remains public at creation as
  the matching key; spends emit only nullifier (+ controller), so create↔spend
  stays unlinkable; the controller address is public at creation (accepted in
  ADR-0006).
- Upstream anonymizer packages (`ekubo_swap_anonymizer`, `vesu_lending_anonymizer`,
  `shadow_account_anonymizer`) and the open-note callback interface are out of v2
  scope.
