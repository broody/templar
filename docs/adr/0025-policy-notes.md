# ADR-0025: Policy notes (bounded, capability-spent, controller-gated)

- Status: Proposed — design reviewed (GO, revision 3); implemented experimentally with a local
  real-proof end to end; implementation reviewed (math GO, contract conditional GO, findings
  addressed);
  supersedes, once accepted, ADR-0022 and ADR-0009 §3, and ADR-0006's off-chain signer
- Date: 2026-09-24
- Deciders: broody
- Specification: [policy-note-spec.md](../policy-note-spec.md)

## Context

Templar's "controlled notes" (ADR-0006, ADR-0009 §3, ADR-0022) are owner-keyed notes whose spends
also need an off-chain policy service's signature. That is a co-signed ordinary note, not an
application-controlled asset: the owner must be present for every spend and the signer is a
trusted service. Upstream PR #2 (broody/starknet-privacy, `edf2f1e`) intended something else: a
note spent with a per-note bearer capability, validated privately by the controller's own Cairo
during proving and applied atomically on chain. Escrow, vesting, conditional payment and auction
collateral need that shape: fund, hand the note to an executor, go offline.

The compact client proof (ADR-0024) is a fixed arithmetic relation and cannot run controller Cairo
privately, so PR #2 cannot be reproduced as is.

## Decision

1. **Policy notes replace controlled notes.** A policy note is an ordinary-format leaf whose
   receiver is `H(PRECV, H(PNK, cap) ‖ policy)`: spent with a per-note capability `cap`, into one
   of up to four outcomes committed in `policy`.
2. **Bounded policy (tier 1).** Outcomes are fixed at creation (receivers, amounts, deliveries,
   an optional withdrawal), or a split whose public amount is chosen at settlement. A separate
   client relation (P1) proves the spend matches the selected committed outcome; R0 V3 is
   unchanged.
3. **Controller at apply time.** Before the committed deadline, the pool calls the pinned-class
   controller's `templar_apply_policy` with a pool-built authorization from proven fields,
   atomically. The authorization carries a public `policy_id` derived from the note's policy, and
   controllers authorize on it, never on the creator-chosen handle alone. After the deadline the
   pool alone allows the refund outcome. The selector is deliberately not PR #2's
   `privacy_apply_controlled_transition`, whose controllers trust its arguments as their own
   privately validated receipt.
4. **Creation is unauthorized and private**: any R0 V3 output or deposit with a policy receiver.
5. **Seed-recoverable refunds.** The creation ciphertext is a standard-size sealed box whose
   plaintext is a policy backup; with the wallet seed it recovers the note and its standard refund.
6. **Process.** The design is reviewed before implementation, as `AGENTS.md` requires. Revision 1
   was reviewed independently (math: conditional go; protocol: no go); revisions 2 and 3 respond to
   the findings and re-reviews; both reviewers signed off on revision 3
   (`bench/m31-pool/reviews/policy-note-design-*.md`). The implementation gets its own review,
   including the malicious-witness tests.

## Alternatives considered

- **Keep ADR-0022's co-signed notes.** Needs the owner online and a trusted signer; not an
  application-controlled asset. A co-signing design can return later as its own decision.
- **Per-application circuits now (tier 2).** General, but each application ships and gets reviewed
  a circuit; deferred until demand.
- **Client-side Cairo (PROOF1) for policy spends.** Full PR #2 parity at 6–9 GiB on the client;
  contradicts ADR-0024.
- **Controller-only refunds.** A broken, paused or upgraded controller could freeze value forever;
  rejected for a pool-enforced deadline refund. Applications that want indefinite authority choose
  a far deadline.
- **Controller authorization of creation (PR #2).** Unneeded for safety (a note only restricts its
  creator's funds) and it would make creation public; applications register notes themselves.
- **Owner-keyed nullifier (ADR-0009 §3's reason for rejecting bearer keys).** The creator/holder
  race it avoided is acceptable here because no unconstrained spend path exists: every holder can
  only cause committed outcomes, and the controller's state arbitrates between them.

## Consequences

- Escrow, per-tranche vesting, conditional payments and controller-pinned splits (arbitration)
  are expressible without a signer. Auction collateral is not: a controller cannot verify a
  bidder's note before settlement, which needs a creation attestation (deferred). Decisions over
  private data, private remainders and multi-token settlement are not expressible either.
- New relation, bridge, statement account, verifier adapter and pool entry point; no change to
  ordinary notes, open notes or shadow accounts.
- ADR-0022's experiment (`bench/controlled-push-e2e`, `TEMPLAR_CONTROL_POC1`, its own pool) is kept
  as history; there are no production controlled notes to migrate.
- Controllers become security-critical application code: they must authenticate the pool and
  check every authorization field they rely on.
- Real value remains gated on the compact proofs' hiding argument.
