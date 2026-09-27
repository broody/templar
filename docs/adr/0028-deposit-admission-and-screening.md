# ADR-0028: Deposit admission, sanctions screening and gated value entry

- Status: Proposed. Not implemented: pool V3 has no admission gate. Would supersede
  [ADR-0003](0003-remove-onchain-screening.md) and amend
  [ADR-0023](0023-return-notes-and-adapter-compatibility.md) (adapters).
- Date: 2026-09-27
- Deciders: broody
- Keeps: [ADR-0002](0002-remove-mandatory-auditor.md) (no auditor key; voluntary viewing keys)

## Context

Templar must operate within the law and must not be treated as a mixer by regulators, exchanges
or chain-analytics vendors. ADR-0003 removed screening and proposed opt-in association-set proofs
instead. Working that design through showed four problems:

- **Opt-in leaves the pool open to bad actors.** Anyone can deposit, move value and withdraw
  without a certificate. For them the pool behaves like Tornado Cash, and the certificate only
  helps if exchanges penalize every uncertified withdrawal.
- **Merged notes rule out Privacy Pools' withdrawal-time check.** Spends are 2-in-2-out, so a
  note's value can descend from many deposits. Per-note deposit labels either forbid merging,
  which breaks payments, or grow without bound. They also tell a recipient which deposit paid
  them, and leave the recipient stuck if that deposit is flagged later.
- **Opt-in proofs of innocence are the larger build.** They need a new relation (forward
  propagation through spends), a registry, status-aware coin control, and a payer's cooperation
  at every hop.
- **Comparable projects hold every deposit.** Research on 2026-09-27
  ([compliance-enforcement-research.md](../reviews/compliance-enforcement-research.md): Railgun, Privacy Pools
  (0xbow), Nocturne, STRK20, Tornado Cash, Samourai) found that each project with institutional
  traction enforces its control by default in some layer. They also hold every deposit for a
  while (Railgun one hour; Privacy Pools and Nocturne hours). Nocturne's deposit manager had a
  screener delay, a global hourly cap, a per-deposit maximum and a per-address daily cap.

The auditor key is a different matter. It lets someone decrypt a user's private history and stays
removed (ADR-0002). Deposit screening sees only public data (the funding address, asset and
amount), which the chain already shows.

## Decision

1. **Gate at deposit.** A deposit is **pending**: the pool holds the funds and records the
   depositor, asset, amount, commitment and time, but does not insert the note. A **list
   provider** admits deposits, and admitted commitments enter the tree in batches.
   - A pending or rejected deposit can **always be refunded, only to the address it came from.**
   - Changes to the list provider's key go through the pool's timelock.
   - Notes already in the tree are never delayed: spends and withdrawals of admitted notes work
     as today.
2. **Every way value enters is gated.**
   - `deposit()` and the ERC721/ERC1155 receiver hooks go through admission.
   - `INVOKE` accepts only **allowlisted adapters**, pinned by address and class hash and
     changed through the timelock. Today any contract can be an adapter (`pool_v2.cairo:220`).
     An arbitrary adapter could return outside value as open-note proceeds and bypass the gate.
   - `COMPUTE` returns above what the pool has sent to that shadow account (per asset, plus a
     margin for yield) are treated as pending deposits. Anyone can send tokens to a shadow
     account.
3. **Admission policy** (off-chain, run by the list provider, published). The values are policy
   settings, not contract constants.
   - Sanctions screening of the funding address against OFAC's SDN list, including the Ethereum
     sender of deposits bridged through StarkGate.
   - A maintained blocklist of exploit and incident addresses. With no paid risk-scoring vendor,
     this is what makes the hold effective.
   - A hold of at least **1 hour for deposits under $10k** and **3 hours at or above**, per
     deposit. ERC721 and ERC1155 deposits are priced off-chain (quantity × a price from real
     sales); unpriced items get 3 hours.
   - A **global admission rate limit**, like Ethereum's staking queue. At most R dollars are
     admitted per hour, R is the larger of a floor and a share of the pool's value, and the queue
     is first come, first served and public. A deposit is admitted when its hold has passed and
     its turn has come.
   - A published admission log, and the current expected wait for depositors.
4. **Fair-value adapters** (amends ADR-0023). An adapter's proceeds may not exceed the fair value
   of its budget.
   - **Ekubo:** only the pool may call it; routes are fixed at deployment; exact-input single hop;
     a full fill or a revert; and `out ≤ TWAP × (1 + ε)` from Ekubo's on-chain oracle. The
     user's `minimum` remains the lower bound.
   - **Vesu:** `out ≤ convertToAssets(shares) × (1 + ε)`, plus a limit on how fast the share
     price may rise since its last observation, which blocks donation inflation.
   - Each adapter has an independent review before it is allowlisted.
5. **Operated services.**
   - The prover server, relayer, front end and vault fallback refuse sanctioned withdrawal
     recipients and connected wallets.
   - IP geoblocking for comprehensively sanctioned jurisdictions, at the front end and the OHTTP
     relay, without storing IP addresses.
6. **Unchanged.** R0, P1, the note format and the large-proof path. ADR-0002's no-auditor-key rule
   and voluntary per-account viewing keys.
7. **Positioning.** Public material presents Templar as operating within the law: screened
   deposits, voluntary disclosure, and no auditor key. It never presents the absence of
   compliance controls as a feature.

## Alternatives considered

- **Keep ADR-0003: opt-in association sets with forward-propagated proofs of innocence.**
  Rejected. Bad actors can still use the pool uncertified; it needs a new relation, a registry
  and coin control; one payer who does not opt in breaks the chain for everyone downstream.
- **Privacy Pools labels checked at withdrawal.** Rejected. This requires notes that never merge.
  The only gain is retroactive exclusion, and the costs to recipients are above.
- **An auditor key (STRK20).** Rejected by ADR-0002.
- **A paid risk-scoring vendor (Elliptic or TRM).** Deferred. About $50–100k a year for Elliptic
  (AWS Marketplace listing). The incident blocklist stands in until volume justifies one.
- **Paying the relayer from spend outputs.** Rejected. It does not remove the relayer, which
  exists for unlinkable submission; it mirrors Tornado's relayer fees; and it would make the
  operator's revenue mixer-exposed. Blind tickets stay.

## Consequences

- **A new pool deployment.** The anonymity set starts again; pool V3 notes remain in pool V3.
- **Pending deposits.** A pending deposit cannot be spent. The SDK needs a pending status, a
  refund action and a display of the expected wait.
- **Provider veto.** The list provider can veto deposits. The refund bounds this: it can delay a
  deposit and return it, but cannot take funds or see private data.
- **Known limits.**
  - There is no retroactive removal: an admitted deposit that is flagged later has already mixed.
  - Late sanctions designations are not covered.
  - Stolen funds split below $10k enter after 1 hour when the queue is empty.
  - The queue can be filled and then refunded to delay others. The cost grows with R.
- **Less opt-in machinery.** Every admitted note is clean by construction, so the opt-in
  proof-of-innocence machinery (relation, registry, coin control, attestations) is not needed.
- **Unaffected.** Policy notes and applications such as auctions need no change. Organizers can
  add their own KYC through controller credentials.
- **Documents.** The GTM strategy, README and guide were updated to this model on 2026-09-27.

## Open items

1. Who operates the list provider, and whether several independent providers should be able to
   admit.
2. Ekubo oracle coverage and depth for the intended pairs, and its interface and time-window
   semantics.
3. An optional on-chain per-asset rate cap in token units, so that a compromised provider key
   cannot admit faster than the cap.
4. Owner powers beyond the timelock, and a path to freezing the core.
5. Counsel, in particular:
   - the relayer's money-transmitter status, free versus paid;
   - separating a developer entity from an operating entity;
   - whether serving the vault counts as control;
   - the list provider's role;
   - the $10k threshold and structuring;
   - EU AMLR from July 2027.
