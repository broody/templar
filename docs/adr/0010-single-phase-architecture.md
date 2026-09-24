# ADR-0010: Single-phase architecture — on-chain inner-proof verification; operator removed; private invokes cut

- Status: Accepted; proof transport, verification and milestone choices partially superseded by [ADR-0018](0018-stwo-private-proving.md); external-invoke exclusion superseded by [ADR-0023](0023-return-notes-and-adapter-compatibility.md); wrapping service role added by [ADR-0024](0024-compact-client-proofs-and-server-wrapping.md)
- Date: 2026-09-19
- Deciders: broody
- Supersedes: [ADR-0001](0001-two-phase-proof-facts-architecture.md) (two-phase
  proof-facts architecture), [ADR-0005](0005-proving-architecture.md) (blind
  operator; client-side Stwo staging). Amends forward-looking language in
  [ADR-0006](0006-controlled-notes.md) (controller signature verified "in the
  outer block" → on-chain) and [ADR-0008](0008-inner-proof-system.md) (the
  Groth16 verifier runs on-chain, not inside an outer block).

## Context

ADR-0001 kept upstream's two-phase virtual-block architecture, and ADR-0005
staged proving toward a blind operator, on the strength of what the outer block
buys: a flexible proven client phase and **private invokes** — arbitrary
external contract calls executed with the pool's authority mid-transaction.
Everything else the outer block does (inner-proof verification, controller
signature checks, action compilation) is replicable in a single-phase contract.

Reassessment after the M1 freeze found:

1. **Private invokes are not worth their cost.** They hide *who* acted, never
   *what* (the DeFi call is public — the spec §8 `ExternalContractInvoked`
   event exists precisely because of this). Curated DeFi integrations via
   app-specific controllers (ADR-0006) deliver the same user-visible property —
   "my address never appeared; the app acted" — with no outer block, at the
   cost of generality (an app must exist per protocol), atomicity (escrow
   timing between legs), and controller transition metadata (already accepted
   in ADR-0006). A handful of dominant protocols makes "curated" cover most
   real demand. Keeping general invokes means keeping M3 wholesale: the
   client-phase program (a new TCB), operator infrastructure (~2.7 GB Stwo
   frame per transaction, paid via fees forever), proof-facts gating, L1
   message machinery, re-added open-note callbacks — plus the largest remaining
   exploit surface (arbitrary external dispatch with pool authority).
2. **M1's verifier seam makes the outer block optional.**
   `apply_spend` authorizes state changes via
   `IVerifier.verify(proof, public_inputs)`; a Garaga-class Groth16 verifier
   contract behind that seam gives the same authorization security as
   proof-facts gating of an outer block that itself only verified the same
   inner proof. ADR-0001's stated reason for rejecting direct on-chain
   verification — "adds per-tx gas and a new verifier dependency without
   removing the need for a state model change" — expired: the state model
   change landed (ADR-0004/0009) and the verifier dependency exists either way.
3. **A privacy pool's product is its anonymity set.** Shipping without the
   operator milestone starts growing the set earlier; every exotic on-chain
   flow shape also fragments the set. The operator was the last non-user party
   with a liveness role; removing it makes the pool trustless at circuit
   completion (M2) rather than after an operator pipeline (old M3).

## Decision

1. **Single-phase architecture.** A spend is one transaction: the SDK builds
   the bundle *and* the server actions off-chain and generates the inner
   Groth16 proof; `apply_spend` recomputes the statement binding over public
   inputs and actions, verifies the proof on-chain via `IVerifier`, verifies
   the controller signature on-chain via `ISigVerifier` when `controller ≠ 0`,
   and zip-checks (§7.4) and applies the actions atomically. No client phase,
   no virtual block, no proof facts, no L1 message path, no operator. The 1:1
   action zip (already load-bearing in M1) is what makes SDK-built actions safe
   without a proven client phase.
2. **Private invokes are permanently cut** — not deferred. No invoke action,
   `ExternalContractInvoked` event, or open-note callback machinery is retained
   for a future re-add. Curated DeFi integrations ship as app-specific
   controllers: transition request → off-chain authorization → withdrawal leg
   to the app contract → batched public execution → proceeds re-enter as notes
   (invoice-supplied commitment). If general invokes are ever wanted, they are
   a new design, not a reactivation.
3. **Milestones redefined.** Old M3 (blind-operator pipeline) and M6
   (client-side Stwo absorption) are deleted. Their still-required contents —
   upstream Roles/AccessControl governance, the Groth16 ceremony, the real
   Stark-ECDSA `ISigVerifier` — move to a redefined **M3: mainnet readiness**
   (plus audit and fee re-measurement on a production sequencer). M2 gains the
   on-chain verifier contract deliverable; M4/M5 unchanged in substance.
4. `proof_validity_blocks` (outer-proof recency window) is removed from the
   spec storage table and the contract; there is no outer proof whose recency
   needs gating.

## Alternatives considered

- **Keep the outer block for future invokes (M3 warm)** — rejected: it delays a
   trustless launch past the point where the anonymity set should already be
   growing, keeps an operator liveness assumption, and retains the largest
   exploit class for a feature with no demonstrated demand that controllers
   cannot serve.
- **Keep two-phase without invokes** — rejected: with invokes gone the outer
   block buys nothing; it adds operator liveness, ~500k steps of in-block
   Garaga verification plus a multi-GB Stwo frame per transaction, and an
   M2→M3 verifier migration, for zero user-visible gain over on-chain
   verification.
- **In-operator privacy (encrypted calldata, MPC proving)** — rejected in
  ADR-0005 already; nothing changes.

## Consequences

- The pool is trustless at M2: no party with a live protocol role exists
  besides the user and Starknet. The threat model's "operators" entry
  disappears because the role does.
- On-chain Groth16 verification gas lands on every spend; it must be measured
  on a production sequencer and priced into the fee model (review §E) — new
  M2/M3 deliverable.
- The inner circuit, note format, tree, nullifier domain, statement binding,
  action zip, and the `apply_spend` ABI are unchanged; the M1 contract needs no
  structural edits (seam docs and the `proof_validity_blocks` member only).
- Governance (single owner → upstream components) and the Stark-ECDSA sig
  verifier are explicit launch blockers in the redefined M3.
- The Groth16 trusted-setup ceremony (ADR-0008) becomes the single remaining
  launch-gating trust event; PLONK with an inherited public SRS remains the
  documented zero-new-ceremony fallback.
- The controller-based integration pattern (above) should be written down as a
  template when the first integration lands (spec §9.7).
