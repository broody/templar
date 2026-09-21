# ADR-0005: User-generated inner proofs; blind operator; client-side Stwo as end state

- Status: Superseded by [ADR-0010](0010-single-phase-architecture.md)
- Date: 2026-09-19
- Deciders: broody

## Context

The single largest trust hole (H2): the operator-side proving service receives
`user_addr`, `user_private_key`, and every action in plaintext per proof request
(`sdk/src/internal/proof-invocation-factory.ts:121-195`) and can link
deposits↔withdrawals across requests. ADR-0001 keeps the two-phase architecture, so
the question is only *who proves what, and what do they see*.

Measured context (bench-results.md): Stwo proving cost is dominated by a fixed
AIR frame (~4 s, ~2.7 GB) independent of workload; the pool's own client-phase
crypto is negligible (~2.4 k steps, 6 EC-muls, 75 Poseidon per transfer). Mobile is
blocked by memory, not compute. Stwo is transparent — *not zero-knowledge by
default* — so publishing a user-proven full virtual-block proof would leak trace
secrets via FRI query openings.

## Decision

Three-stage adoption, all inside the ADR-0001 architecture:

1. **Now — blind operator (Option B)**: the user generates a small, ZK inner proof
   locally of the spend statement (ADR-0008): note membership (tree root, ADR-0004),
   nullifier derivation, value conservation, controlled-transition authorization
   (ADR-0006). The outer virtual block *verifies the inner proof* (Garaga-class
   Cairo verifier) and applies only public state transitions. The operator sees
   exactly what a chain observer sees: commitments, nullifiers, roots.
2. **Interim — self-proving users**: because proof facts carry no prover identity
   (ADR-0001), a power user may prove their own virtual block on a laptop and
   submit directly; the operator role becomes competitive infrastructure.
3. **End state — client-side Stwo (Option A)**: when Stwo ships a ZK mode and
   mobile-class traces (Kakarot CairoM targets 10 MHz on phones), the inner proof
   is re-expressed as a Cairo program proven client-side inside the same virtual
   block. Nothing in the contract changes.

## Alternatives considered

- **MPC/distributed prover holding the secrets**: removes the single operator but
  adds an MPC stack and a committee; committee collusion reconstructs everything.
  Complexity without a clear win over (1).
- **Encrypted mempool to the operator (prove over ciphertexts)**: requires FHE or
  MPC on ciphertexts inside the circuit; far beyond current feasibility.
- **Clean-room Tornado, no virtual blocks**: smallest surface but discards the note
  model (ADR-0001); fallback only.

## Consequences

- The SDK gains a local proving step (WASM/native); proof generation targets are
  < 10 s on phone-class hardware for the inner statement (M4).
- The outer block grows by a Groth16/PLONK Cairo verification (~500 k steps class)
  — fixed cost amortized across the tx's actions; benchmark before M3.
- Trusted-setup choice for the inner system is ADR-0008 (open).
- The operator's remit shrinks to *proving public logic*; multiple operators are
  allowed and encouraged from day one.
