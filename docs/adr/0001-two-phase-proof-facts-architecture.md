# ADR-0001: Keep the two-phase proof-facts architecture

- Status: Superseded by [ADR-0010](0010-single-phase-architecture.md)
- Date: 2026-09-19
- Deciders: broody

## Context

Upstream starknet-privacy splits every private transaction into a **client phase**
(the pool account contract compiles `(user_addr, user_private_key, client_actions)`
into server actions, `packages/privacy/src/privacy.cairo:195-245`) and a **server
phase** (`apply_actions`), gated by proof facts that bind the actions to a STARK
proof of a "virtual Starknet block". The contract validates only the proof *facts*
— program variant, block recency, message hash (`privacy.cairo:808-843`) — and the
proof itself is verified by the sequencer.

The apparent problem: the proof is produced by a centralized operator who sees all
secrets. The tempting fix is to replace the whole proving model with a Tornado-style
on-chain SNARK verifier.

Key observation: **the contract cannot tell who ran the prover.** Proof facts carry
no prover identity. The operator is a convenience, not a cryptographic role.

## Decision

Keep the two-phase architecture and the proof-facts gating verbatim. Treat the
operator as a replaceable component (see ADR-0005). All trustlessness work happens
in (a) who produces proofs and (b) what data they see — not in the on-chain
execution model.

## Alternatives considered

- **Clean-room Tornado contract** (fixed denominations, on-chain zkSNARK verifier,
  no virtual blocks): smallest trusted surface, but discards the channel/subchannel
  note model, encrypted-note delivery, private DeFi invokes, and the paymaster path.
  Kept as fallback only (PLAN.md §5.2 Option C).
- **Modify `apply_actions` to verify SNARKs directly on Starknet** (Garaga): adds
  per-tx gas and a new verifier dependency without removing the need for a state
  model change (ADR-0004); revisitable later.

## Consequences

- Nothing in the existing sequencer/proof-facts plumbing changes — the day users can
  prove locally, the contract accepts their proofs with zero protocol changes.
- The virtual-block trace remains the outer proven artifact; its ZK properties are
  governed by ADR-0005.
- The client-phase calldata privacy problem (plaintext `user_private_key` to the
  prover) must be solved out-of-band — it is not solved by this architecture, it is
  what ADR-0005 addresses.
