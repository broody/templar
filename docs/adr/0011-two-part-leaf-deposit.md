# ADR-0011: Two-part commitment leaf and standalone proofless deposit

- Status: Accepted
- Date: 2026-09-20
- Deciders: broody
- Amends: spec §3.1 (commitment format), §5 (new `deposit` entry point), §7
  (deposits leave the spend statement). Resolves m1-invariant-review §D.1.

## Context

The M1 review (§D.1) accepted a real weakness: deposit legs inside
`apply_spend` bundles pull `transferFrom(depositor, …)` where `depositor` is
unproven calldata — any third party who can build a valid (balanced) bundle can
route someone's standing allowance into notes they control. Unlike upstream —
where the trusted client phase gated deposits behind the depositor's private
key — v2 had no depositor authorization at all.

The blocker for a proofless standalone deposit: the commitment hides the
amount, so the contract cannot check that the deposited amount equals the
committed amount — an unproven deposit would let anyone mint unbacked notes
(deposit 1, commit 100, withdraw 100). Tornado got away with proofless deposits
only because fixed denominations bind the amount per pool instance.

Key observation: at deposit time, `token` and `amount` are public anyway (the
ERC20 `transferFrom` reveals them), and ordinary deposits have
`controller = policy_commitment = 0`. The only secret part of the commitment is
the note-secret side. Splitting the commitment into a public outer hash over a
secret inner hash lets the **contract compute the leaf itself**.

## Decision

1. **Two-part commitment** (spec §3.1 revision):

```
inner      = H(NOTE_INNER_TAG:V3, note_secret)                    // hiding, depositor-supplied
commitment = H(COMMITMENT_TAG:V3, token, amount, controller, policy_commitment, inner)
```

   Note-family tags bump to V3 (preimage layouts change);
   `TRANSITION_COMMIT_TAG` / `TX_BIND_TAG` stay V2.
2. **New entry point**
   `deposit(token, amount: u128, controller, policy_commitment, inner, note_id)`:
   pulls `amount` from `get_caller_address()` via `transfer_from`, computes the
   commitment on-chain, inserts the leaf, emits `Deposited` + `NoteCommitted`.
   No proof required: the amount binding is by construction, and a garbage
   `inner` only strands the depositor's own funds (an unspendable leaf).
3. **Deposits leave the spend statement**: `SpendPublicInputs.deposits`,
   `ServerAction::Deposit`, `MAX_DEPOSITS`, and the deposit zip leg are
   removed. Conservation becomes `Σ private_in = Σ private_out + Σ withdrawals`
   per token.
4. Controlled-note funding uses the same entry point (`controller ≠ 0`) — e.g.
   auction escrow top-up in one plain transaction.

## Alternatives considered

- **Small deposit proof** (bind public `(token, amount)` into the commitment
  in-circuit): keeps the old format, but costs a second circuit and a second
  ceremony artifact for a property achievable by construction. Rejected.
- **Keep in-bundle deposits with `depositor` as a proven public input**: keeps
  atomic deposit+spend, but allowance pulls remain possible unless
  `depositor == caller` is enforced, which breaks relayer submission of
  bundles. Rejected.
- **Fixed denominations**: proofless without format changes; kills arbitrary
  amounts. Rejected.

## Consequences

- Shielding is a plain transaction — no proving.
- Review §D.1 is resolved by construction: the depositor is always
  `msg.sender`; no allowance can be pulled by third parties.
- The spend circuit loses deposit legs and their zip (smaller, simpler).
- Duplicate-leaf inserts are harmless: one nullifier per `note_secret` bounds
  spendability regardless of how many leaves commit to it.
- Atomic deposit+spend bundles disappear; two transactions are required (and a
  deposit had to land before its note became spendable anyway, for the
  membership root to exist).
- New golden vectors (`tests/test_hashes.cairo`); the M2 circuit must reproduce
  the V3 derivations byte-for-byte.
