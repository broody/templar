# ADR-0007: Public event minimization rules

- Status: Accepted; push publication metadata amended by [ADR-0021](0021-push-only-payments.md); return publication metadata amended by [ADR-0023](0023-return-notes-and-adapter-compatibility.md)
- Date: 2026-09-19
- Deciders: broody

## Context

Even with the auditor removed, upstream leaks linkable data publicly. Every event
field is a policy decision; today's defaults leak by accident:

- `Deposit.user_addr` is a plaintext indexed field (`events.cairo:33-34`) — every
  deposit is attributed to an address, defeating the nullifier's unlinkability.
- `Withdrawal {to_addr, token, amount}` — recipient/amount public (inherent), but
  only the *link to the deposit* must be hidden.
- `OpenNoteDeposited.depositor`, `get_num_of_channels` (per-recipient counts,
  `privacy.cairo:1078-1080`), `ViewingKeySet` identity↔key binding.
- No freshness check on withdraw `random` → identical `enc_user_addr` ciphertexts
  link a user's withdrawals (`actions.cairo:191-201`).

## Decision

Event and view policy for TemplarPool:

1. `Deposit` emits `(commitment, token, amount)` — **no depositor identity**. The
   ERC20 `transferFrom` still attributes the deposit at the token layer; users who
   need deposit-privacy start from a relayed/mint path (documented UX).
2. `Withdrawal` keeps `(to_addr, token, amount)` — inherent, as in Tornado; the
   unlinkability guarantee lives in the spend step (nullifier + tree), not here.
3. `EncNoteCreated`/`NoteUsed` semantics preserved (salted masked amounts,
   nullifier-only spends).
4. Controlled-note events stay commitment-only per ADR-0006.
5. Remove `get_num_of_channels` (or return an encrypted count); do not add views
   that aggregate per-address activity.
6. Any new event must pass the rule: *does this field help an observer link two
   actions that the nullifier/tree model intends to unlink?* If yes, it needs an
   ADR exception.
7. All randomness consumed in derivations that become public (salts, ephemeral
   keys) is enforced-fresh on-chain where replay is possible.

## Alternatives considered

- **Encrypt amounts on withdrawal too**: breaks composability with ERC20
  `transfer` (amount is visible at the token contract anyway); no gain.
- **Encrypted deposits**: deposit amount must match the on-chain `transferFrom`;
  hiding it requires fixed denominations — rejected for flexibility reasons
  (PLAN.md non-goals), revisitable via UX-level denomination wrappers.

## Consequences

- Chain-observer visibility drops to: commitments, nullifiers, withdrawal
  recipients/amounts, token-level transfers — the Tornado floor, plus flexible
  amounts.
- The SDK must warn users about the token-layer attribution of deposits
  (relayer/paymaster patterns are already supported upstream).
