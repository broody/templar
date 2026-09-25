# ADR-0026: Account-bound notes for existing wallets, expiry and a permissionless M31 pool V3

- Status: Proposed. Design revision 4, a simplification. Its re-review gave math GO and
  protocol CONDITIONAL GO; the conditions (AB-P28, AB-P29) and the other findings are applied in
  the specification.
- Date: 2026-09-25
- Deciders: broody
- Specification: [account-bound-note-spec.md](../account-bound-note-spec.md)

## Context

The compact client proof (ADR-0024) is a fixed arithmetic relation, so it cannot run a Starknet
account's `is_valid_signature`. So existing wallets (Ready, Braavos) could not authorize Templar
spends. Upstream Starknet Privacy supports them through a proving service that sees keys, amounts,
recipients and every action. Existing-wallet support is the way most users would first reach the
pool.

The P0b spike (2026-09-25, `bench/wallet-sig-spike/`) showed three things:

- the prover server's statement account can call a real account's `is_valid_signature` in the
  virtual OS, on live Sepolia state;
- Ready X and Braavos sign SNIP-12 typed data, and their accounts accept it;
- an inline Stark signature check leaves PROOF2 in the same leaf bucket, at the same cost.

PROOF2 for the real account call is inferred from its virtual-OS counts (at most 172k steps and
1.2k Blake). P5 measures it.

The hidden-asset battle test also left fixes that change the relation or the pool:

- no expiry on plain spends (F07);
- a flushable root ring (F02);
- an owner who can swap the verifier without delay or event (F01, F19).

Every relation change forces a lockstep cutover of both products, so they are batched.

Revision 3 also carried a private relayer fee output, protocol fees and a signature-derived seed.
Revision 4 removes all three (decisions 4, 6, 7 and 8) to simplify the relation, the pool and the
wallet.

## Decision

1. **Two products on one pool.**
   - Existing wallets use the compact client proof in the browser with **account-bound notes**.
     The prover server's statement account checks the owner account's signature inside the proven
     execution.
   - The server learns which account made which spend, and cannot move funds.
   - The Templar wallet keeps ADR-0024's boundary.
2. **Account-bound receiver** `H(OWNER, H(WAUTH, account ‖ sk) ‖ H(NK, sk))`.
   - A new hash kind, `WAUTH = 16`.
   - One mode bit per spend, fully constrained to `account ≠ 0`.
   - Spending needs the Templar key and the account's `VALID`, always.
3. **No escape path.** A path that lets the Templar key alone spend after a timeout would turn a
   leaked backup phrase or device store into theft. Without it, a leaked seed is privacy only
   (spec S4). It would also add distinguishable spends and on-chain state. P0b removed the reason
   for it: wallet signatures verify reliably.
4. **A random seed for product 1.**
   - 28 bytes, backed up as a 21-word mnemonic whose length marks its origin, confirmed at setup.
   - The account is in every key's derivation context.
   - A change of the account's keys never changes the seed.
   - Stark-key signers only at launch; guardian and multisig accounts are refused at setup.
5. **The spend message** is SNIP-12 revision 1, built entirely from statement fields.
   - The binding is salted, so wallet vendors and guardians cannot match in-pool transfers to the
     chain.
   - `valid_until` is authorized through the salted binding and not displayed.
6. **R0 V5 = R0 V4 plus a published `account` and `valid_until`.**
   - 35 QM31 outputs, V4's two outputs and V4's conservation gadget.
   - The pool checks `valid_until` (F07).
   - Identity handles are computed over the selected authorization key, so a leaked key cannot act
     through a bound wallet's shadow accounts.
7. **M31 pool V3**, a fresh deployment, **permissionless and free**.
   - It carries the V5 binding and expiry rules.
   - Roots expire only a window after being replaced (F02).
   - Every verifier change goes behind a timelock with events (F01, F19), bootstrapped by a
     one-time initializer.
   - It has no protocol fee, no fee collector and no gating of deposits or spends.
   - The V5 adapter uses a smaller proof-age window (1,024 blocks).
8. **Templar's service is paid off-chain with blind tickets.**
   - The prover server checks tickets before proving, and the relayer submits every spend the
     server proves.
   - Tickets are publicly verifiable blind RSA signatures (RFC 9474), unlinkable to their purchase.
   - At launch they are claimed with a soulbound Templar Pass NFT. A token can be added later under
     the same issuer keys.
   - A full withdrawal of a priced asset at or above its minimum costs no ticket. Dust, NFTs and
     unpriced assets pay one ticket, or exit by self-hosting.
   - Self-hosters prove and submit for free. A non-owner fallback submitter covers relaying.
   - The job carries the full pool calldata, so the service settles what it proves and chooses
     when, up to the statement's deadline.
   - The pass, the issuer and the costs are specified in P7 (`docs/relayer-spec.md`).
9. **Process.** The design is reviewed (math and protocol) before any implementation, as
   `AGENTS.md` requires. Each implementation phase gets its own review.

## Alternatives considered

- **Upstream-style trusted prover** (the server receives keys and builds the proof). Simplest for
  existing wallets, but the server sees everything. Rejected for a server that learns only
  account ↔ spend.
- **Local Cairo proof (ADR-0018 PROOF1) calling `is_valid_signature` on the device.** No server
  learns the account. But it needs:
  - 6–15 GiB on a desktop;
  - a felt252 pool, which splits the anonymity set;
  - the account call to fit PROOF1's fixed capacity (8,192 Blake compressions), which is untested.

  Kept as a possible later desktop tier.
- **Signature check inside the client circuit.** Non-native Stark or P-256 arithmetic, an
  estimated 4–16× today's rows (unmeasured). Rejected for the browser.
- **An escape path** (Templar key alone after a timeout: request → wait → execute). It gives
  liveness against wallet failures, but costs extra on-chain state and distinguishable spends.
  Rejected after P0b.
- **Keep pool V2 and cut over with `set_verifier`.** No new pool. But expiry would be checked only
  against the proof's base block, and F01, F02 and F19 would stay.
- **A relayer fee output** (revision 3: a third private output paying the relayer in the hidden
  asset). Rejected in revision 4 because it:
  - cannot pay for NFTs or unpriced assets;
  - shows a paid relayer the asset;
  - needs a third output, a wider conservation gadget and about 5–8% more L2 gas per spend.
- **Protocol fees in the pool** (revision 3: capped percentages and flat STRK fees, timelocked,
  accrued in the pool). Rejected in revision 4: the pool is free, and revenue comes from the
  service. Fees added attack surface (F59-style hook arguments, collector blocking). Pools cannot
  be upgraded, so a fee later needs a new pool.
- **A pass-gated pool** (deposits or spends require the pass). Rejected:
  - a spend gate can freeze exits;
  - a deposit gate turns away self-hosters, who add to the anonymity set and TVL.
- **A signature-derived seed** (revision 3: HKDF over a deterministic SNIP-12 derivation
  signature). Rejected in revision 4 because:
  - any site can ask for that signature, and it reveals every bound note;
  - a key change changes the seed, which needed a sweep;
  - it is multi-device by nature, which needed deterministic companions;
  - it depends on wallets signing deterministically.
- **A standard paymaster instead of a relayer.** Rejected: the user's account would be the
  transaction's account.
- **A token at launch instead of the pass.** Deferred until the legal picture is clear. The issuer
  keeps one key per period for every payment source, so a token can be added without changing
  tickets.

## Consequences

- **Existing wallets.** Ready and Braavos users can hold and spend private notes with their wallet,
  without an add-on, in the same anonymity set as Templar-wallet users. On-chain data does not
  reveal the mode.
- **Server boundary.** ADR-0024's boundary gains a mode in which the server learns the account.
  - The server must scrub accounts and signatures, and publish what it learns.
  - Retained signatures are third-party-verifiable evidence of account ↔ spend.
- **RPC and gateway.**
  - The web app's RPC node learns the account, unless reads are batched with decoys or the user
    runs a node.
  - Whether the PROOF2 object hides the account from the gateway operator depends on PROOF2's own
    hiding (an open ADR-0024 gate).
- **Freezes.** Bound notes freeze in two cases:
  - the account changes in a way the prover cannot satisfy (a guardian cosignature, a new signer
    type, an unsupported class upgrade);
  - the random seed is lost from every device and from its backup.

  A compatibility matrix, setup checks, a confirmed backup and warnings mitigate this.
- **Revenue and the service.**
  - Revenue depends on the service, not the pool. Anyone can use the pool for free by running
    their own prover and submitter.
  - The relayer learns no asset or fee.
  - The ticket issuer learns which pass claimed how many tickets and when, not which spends they
    paid for.
  - A free full withdrawal tells the server that the spend empties its inputs.
  - Pass holders are public on chain, so the pass should sit in an account other than the owner
    or depositing account.
- **Deployment.** New relation, bridge, statement account, adapter instance and pool. Notes in
  pool V2 move by withdrawal and deposit (Sepolia test tokens only).
- **Gates.** Real value remains gated on ADR-0024's hiding and review gates.
