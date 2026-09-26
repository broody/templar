# ADR-0003: No on-chain screening; opt-in ZK association sets

- Status: Accepted; would be superseded by [ADR-0028](0028-deposit-admission-and-screening.md) (proposed)
- Date: 2026-09-19
- Deciders: broody

## Context

Upstream enforces deposit screening on-chain: `apply_actions` requires a fresh
(≤300 s) SNIP-12 signature from the `screener_public_key` over the tx's screening
subject — derived from the proven actions (`privacy.cairo:921-943`), supplied by an
Elliptic AML service behind the proof-interceptor sidecar, with fail-open defaults
in the prover config (`proof-interceptor/README.md:47-54`).

Screening-by-identity is definitionally incompatible with a private pool: the
screener learns every depositor address with timestamps, and the enforcement hook
gives a governed key veto power over all deposits (H3).

## Decision

1. Delete all screening machinery from TemplarPool: `screener_public_key`,
   `_verify_screening`, `open_note_depositor_screening_policies`, the
   `ScreeningAttestation` calldata suffix, and the interceptor/proxy services.
2. Replace the legitimate use case (compliance attestation) with **opt-in
   zero-knowledge association-set proofs** (Privacy-Pools/0xbow pattern): a user
   who wants attestability proves in ZK that their value's source set is contained
   in a published set AS_k. No identity, no linkage, no veto.
3. Open notes remain the *deliberately public* on-ramp (depositor visibility is
   inherent to `transferFrom`); document them as such.

## Alternatives considered

- **Keep screening as a deploy-time option**: two privacy classes of pools
  fragment the anonymity set; every "compliance" deployment would be a de-facto
  backdoored pool with the same key-veto surface.
- **Off-chain-only screening (no on-chain enforcement)**: still funnels every
  depositor address through a screening operator; solves nothing.

## Consequences

- `apply_actions` loses its screening tail; SDK loses
  `ScreeningRejected`/`ScreeningUnavailable` error mapping and the
  `screening-calldata` suffix packing.
- Relying parties (exchanges, funds) gain a verification job (check attestation)
  instead of a veto job (gate deposits).
- Association-set membership circuits are new work (M5) and must not be mandatory
  for pool participation.
