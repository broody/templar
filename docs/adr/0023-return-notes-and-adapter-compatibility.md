# ADR-0023: Open notes (formerly return notes) with upstream-compatible external settlement

- Date: 2026-09-21
- Status: Accepted architecture; experimental integration and production qualification tracked separately
- Deciders: broody
- Partially supersedes: ADR-0009's removal of open-note funding and ADR-0010's exclusion of external invokes
- Extends: ADR-0021's push-payment scope and ADR-0018's native proof architecture
- Amends: ADR-0007 publication metadata and ADR-0014 operation binding/output accounting for this execution path
- Specification: [open notes](../open-note-spec.md)
- Amended: 2026-09-24 (rename; compact client-proof path; shadow accounts), see below
- Reference: [upstream adapter integration](../../bench/return-note-e2e/README.md)

## Context

A wallet that keeps funds private needs a way to convert assets and return the
proceeds to private payments. Withdrawing to a fresh public account remains a
useful exit path. Automatic, atomic return removes the separate account and
redeposit steps when the user intends to continue using the pool.

The earlier DeFi experiment demonstrated native proof authorization, an unknown
output amount, actual funding, fresh recovery and spending on Sepolia. It used a
Templar-specific swap adapter. Upstream's Ekubo and Vesu adapters instead expose
`privacy_invoke` and return `OpenNoteDeposit { note_id, token, amount }` while
approving their caller to collect the proceeds. Those adapters do not inspect
the caller's note storage or proof system.

The old exclusion of open-note funding no longer defines the desired product
scope. Controller authorization alone does not supply external execution or
atomic funding. Return notes require no controller.

## Decision

Adopt **ReturnNote** as an explicit, transaction-local funding primitive. It
specifies a public opaque identifier, expected token, minimum amount, ownership
commitment and encrypted recovery payload. The exact output amount is determined
by public execution. A return destination is not spendable or a stored empty leaf.
Verified funding creates an ordinary `Note` in the existing commitment tree.

Use **return note** in architecture prose and `ReturnNote` in implementation.
Retain `OpenNoteDeposit` only at the upstream compatibility boundary. These names
are intentionally different: upstream fills a stored open note; Templar appends
the final funded commitment. “Cloaked address” remains receiving terminology;
no additional cloaking terminology is required in contract types.

An owner proof binds an `ExecutionIntent` covering the external adapter, fixed
entry point, exact calldata, input budget, expiry and ordered return destinations,
including each recovery payload. Chain, pool, version and input token scope the
intent. Settlement verifies the spend, funds the adapter, invokes it, validates
the returned deposits and actual token receipts, and publishes the funded notes
under one reentrancy lock. Any failure reverts all these effects; gas is charged.

Implement the upstream `privacy_invoke` and `Span<OpenNoteDeposit>` wire interface.
The boundary resolves each returned `note_id` against the destinations authorized
for that execution, rejects missing/extra/duplicate or mismatched returns, and
enforces minimum amounts. The pool pulls proceeds from the adapter and checks its
actual balance increase. It grants no external token allowances.

Keep the scope bounded: one prefunded external call, one input token, ordinary
ownership, and at most four total note outputs including private change and
returns. All destinations must be funded once before completion, in authorized
order. Existing payment limits are not increased by this ADR. There is no
persistent partially funded destination, asynchronous claim, arbitrary lending
position or automatic controller integration.

## Receipt and privacy contract

Prepare ownership and recovery information before execution. Authenticate the
actual settled amount together with the ciphertext, then reconstruct and validate
the final funded commitment during local discovery. Seed restoration and full
viewing must recover the same ordinary note that can subsequently be spent.
Retain ordinary encrypted delivery for payments with privately known amounts.

Public execution reveals the call, tokens, amounts, timing and return-deposit
linkage. Return notes do not make an AMM trade private. Input membership and
recipient identity remain protected within the existing proof, encryption and
anonymity assumptions. Sender/gas metadata, correlation, and RPC access patterns
remain separate privacy concerns. No new auditor or screening role is introduced.

## Consequences and alternatives

- A reusable funding interface replaces protocol-specific return handling in the
  pool. Existing adapter implementations can be imported at a pinned revision;
  compatibility and deployment behavior must still be tested.
- One funded-note ownership/nullifier/spending model remains. Two receiving cases
  must be supported: an encrypted known amount and an authenticated public amount
  determined at settlement.
- Adapters and public token execution remain part of the security boundary. The
  wallet must construct and validate the intended route, budget, return destination
  and supported token/protocol behavior. Signing a bad intent does not make it safe.
- The unchanged upstream Ekubo adapter accepts a router in calldata; unlike the
  earlier Templar-specific adapter it does not pin a router or caller. The exact
  calldata is proof-bound, and prefunding/execution/collection must stay atomic.
- A separate permanent spendable note type and mutable tree placeholders add no
  demonstrated benefit here. Persistent or asynchronous funding is deferred.
- An exit-only wallet could omit this capability, but would require a separate
  return flow for users converting assets before private payments.

## Qualification and integration

The earlier [DeFi prototype](../../bench/defi-return-e2e/README.md) is retained
unchanged. The new reference uses distinct `TEMPLAR_RETURN_POC1` domains and a fresh
pool. Its local tests distinguish real statement checks, mock-verifier settlement
checks and unchanged upstream adapter execution. The new reference passed
two native spends on Sepolia: an unchanged Ekubo adapter against deployed Ekubo
funded a 999-unit return, fresh seed/full-view recovery found it, and a private
payment spent it. Six on-chain rejections preserved pool/token state; native
execution rejected a tampered intent. Local checks passed 11 Python and 24 Cairo
tests. See the reference for receipts, source hashes, measurements and limits. Vesu mock-vault tests
do not qualify live Vesu or borrowing.

This accepts the architecture, not production readiness. Canonical package/SDK
integration, independent format and security review, production tokens, supported
route policies, reliable submission, bulk synchronization and desktop memory
qualification remain required. No improvement in proving memory or anonymity is
claimed from introducing this abstraction.

## Amendment (2026-09-24): open notes on the compact client-proof path

- **Name.** "Return note" becomes **open note**, matching upstream and the `OpenNoteDeposit` wire
  type. Semantics are unchanged: upstream also requires every open note to be filled in its creating
  transaction. Templar appends the funded commitment instead of filling a stored placeholder. The
  first reference keeps its `ReturnNote` type names.
- **Compact path.** ADR-0024's R0 relation gains a public execution `intent` and an optional identity
  handle (R0 V3). The M31 pool gains `apply_spend_with_invoke`; see the
  [specification](../open-note-spec.md#compact-client-proof-path-r0-v3). The budget is the
  statement's withdrawal and may be zero; the intent names its recipient.
- **Shadow accounts.** A bounded form of upstream's `ComputeAndInvoke`: the client proves the
  identity handle `H(IDENTITY, sk₀ ‖ scope)`, and the pool derives upstream's identity commitment
  from it. This supports persistent pseudonymous positions through upstream's shadow-account
  anonymizer. General `privacy_compute` (arbitrary application logic on private data) needs
  per-application circuits and remains out of scope.
- **Limits.** 2 destinations, 4 new notes, 64 calldata felts, one adapter call and one input token
  per transaction.
- **Process deviation.** At the user's direction, the independent math review and the adversarial
  test suite follow implementation rather than precede it, contrary to the default order in
  `AGENTS.md`. The implementation is not qualified until both are done.
