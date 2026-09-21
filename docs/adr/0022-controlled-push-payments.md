# ADR-0022: Controlled push payments with exact transition approval

- Date: 2026-09-21
- Status: Accepted experimental architecture; production format and integration pending
- Extends: [ADR-0021](0021-push-only-payments.md)
- Reference: [controlled push experiment](../../bench/controlled-push-e2e/README.md)

## Decision

A controlled note uses the same reusable receiving address, encrypted publication,
viewing and seed recovery as an ordinary push payment. It additionally commits to
a controller contract and policy. Spending requires both the owner's proof and
that controller's authorization. The authorizer cannot replace ownership.

All inputs and outputs in one operation have the same controller. The controller
approves policies for actual input/output legs. Ordinary notes have zero controller
and policy and require no signature. Public withdrawals need authorization of
their actual destination and amount and release tokens from the note condition.

The proof recomputes a canonical transition from input nullifiers, amounts and
policies, output commitments, amounts, policies and delivery digests, and public
withdrawal destinations/amounts. Version, chain, pool, root, token, controller,
block-number deadline and nonce scope it. Counts and zero padding are explicit.
The full transition enters the statement binding. A new proof for altered outputs
or withdrawals does not make an old controller approval valid.

The controller learns those scoped legs without spending keys, receiving identities,
note randomness or Merkle paths. Its identity is public on controlled spends and
its privileged visibility into amounts/policies is an explicit disclosure.

## Executable boundary

`TEMPLAR_CONTROL_POC1` uses distinct domain tags and key derivation in a fresh pool.
Existing notes retain their original format and nullifier rules. The fixture
controller verifies real Stark-curve ECDSA against an immutable public key; the
message is the low 251 bits of the transition hash with explicit signature scalar
bounds. Its off-chain policy permits a configured policy and withdrawal destination
and limit. Exact encodings are in [the current specification](../push-payment-spec.md).

The pool enforces expiry and nullifier consumption. The nonce is not a separate
revocation registry. The reference permits no unilateral escape, controller
upgrade, key rotation or approval revocation. Application policy, availability
and escape design remain separate decisions. Controller refusal can freeze value.
Recovery preserves that condition and reports unspent value separately from
whether approval can currently be obtained.

## Qualification

Local tests cover ownership, preserved controller conditions, real signatures,
canonical encoding, ordinary regression and maximum statement shape. The live
harness exercises controlled offline payment, viewing, fresh seed recovery,
approved re-spending and withdrawals with native PROOF1. It also attempts missing,
wrong and expired approval, replay, and redirecting a withdrawal using a new proof
with the original approval. Public outcomes and receipts are recorded by the
experiment's `results/summary.json` and `results/evidence.json`.

This is not independent cryptographic review or production-wallet qualification.
Primary packages, secure key storage, policy service operation, private scalable
synchronization and physical-desktop proving remain outstanding.
