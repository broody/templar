# ADR-0006: Adopt controlled notes with out-of-prover controller authorization

- Status: Accepted — §2 note format & bearer semantics superseded by ADR-0009;
  the out-of-prover controller redesign (§1) is retained
- Date: 2026-09-19
- Deciders: broody

## Context

PR [broody/starknet-privacy#2](https://github.com/broody/starknet-privacy/pull/2)
adds contract-governed private value: a `ControlledNote` (`{hiding commitment,
controller}`) whose creation debits private balance and whose spends require
authorization from the bound application contract. Public events are commitment-only
(`ControlledNoteCreated {note_id, controller, commitment}`, `ControlledNoteUsed
{nullifier, controller}`); create↔spend unlinkability holds (nullifier =
`H(note_id, blinding(spend_key))`; note_id hides sender behind a spend-key nonce).

The one architectural mismatch: upstream runs the controller's
`privacy_validate_controlled_transition` **inside the proven execution**. Under the
blind-operator model (ADR-0005) that would pipe the transition — openings, spend
keys, recipients — into the prover→controller path, defeating blindness.

## Decision

Adopt controlled notes as a first-class note type in TemplarPool, with one
redesign:

1. **Controller authorization moves out of the proving trust set.** The controller
   validates the transition off-chain and returns a **signature over the
   transition commitment** `H(ControlledTransition)`. The inner circuit proves:
   commitment-opening correctness, nullifier derivation, value conservation, and
   the controller-signature check. The outer block stays blind.
2. Keep verbatim from the PR: note-id/commitment/nullifier derivations
   (`hashes.cairo` additions), one-controller-per-tx, invoke-must-target-controller,
   void-return apply ABI with pool-caller authentication, bearer spend semantics,
   epoch/nonce-in-receipt staleness guidance.
3. **Data minimization**: controlled transactions carry only controlled openings +
   deposits + withdrawals. Upstream's `ControlledTransition` also feeds ordinary
   `UseNote` nullifiers/amounts and `CreateEncNote` recipients to the controller —
   mixing an unrelated private transfer into a controlled tx must not leak it.
   Per-item disclosure, if ever supported, is explicit user consent surfaced by the
   SDK.
4. Drop the PR's `proof-interceptor` hunk with the screener (ADR-0003); no
   dependency on the auditor (ADR-0002) exists in the design.

## Alternatives considered

- **Keep in-prover controller validation**: capability-equivalent from the
  controller's perspective, but forces the operator to see controlled transitions
  and adds the controller's Cairo code to the outer proof trace.
- **Run controller logic in-circuit**: arbitrary application policy inside the SNARK
  is not expressible for general controllers; would restrict policy to a fixed DSL.

## Consequences

- The controller is now a party the *user* chooses to talk to, not a party the
  *prover* talks to — controller trust is scoped and visible.
- Replay/partial-replay of a signed transition is prevented by the WriteOnce
  nullifier plus commitment binding; stale-authorization handling follows the PR's
  epoch/nonce guidance.
- Escrow deadlock property is inherent (dead controller ⇒ locked value); SDK must
  surface it, policy-encoded deadline is the partial mitigation.
- Controller address is public at creation; anonymous controllers require fresh
  contract deployments per pool (documented, not solved).
- The PR's own remaining work carries into M1/M2: policy-revocation recheck at
  apply, mock void-return ABI alignment, live devnet validation.
