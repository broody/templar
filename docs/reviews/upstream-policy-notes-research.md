# Policy notes on upstream starknet-privacy: research

- Date: 2026-09-27
- Status: research, not a decision; nothing here is built. Templar development is paused
  ([README](../../README.md)). Legal remarks are input for counsel, **not legal advice**; see
  [compliance and enforcement research](compliance-enforcement-research.md).
- Upstream reviewed: [`starkware-libs/starknet-privacy`][up] at `b40bf10` (0.14.3-rc.8,
  2026-09-15), still the newest commit on 2026-09-27, and the transaction prover in
  `starkware-libs/sequencer` (`crates/starknet_transaction_prover`). Line references below are to
  `packages/privacy/src/` at `b40bf10` unless stated.

[up]: https://github.com/starkware-libs/starknet-privacy/tree/b40bf109c8e5b97d9d6e8ec6db48b16b9d10a106

## Summary

- **The question.** After the internal compliance review, Templar stopped work on its own pool. We
  started Templar because upstream had no controlled or policy note. Can policy notes be added to
  upstream through its existing hooks, so that we operate no pool?
- **Yes, without upstream changes, through a *policy account*.** Upstream authorizes a spend by
  calling the note owner's contract inside the proof, and that call receives the whole private
  transaction. An owner contract whose "signature check" is a policy is an escrow contract whose
  funds stay as encrypted notes in upstream's pool (§4).
- **Why Stake Wars' Beacon auction (Whisper) is custodial.** Spending an upstream note needs the
  owner's private key, a contract cannot keep a secret key, and the pool gives applications no
  say over how a note is spent. So Whisper's vault is a privacy account the operator owns (§1).
- **Rejected:** a Templar side pool attached to upstream (it is a pool again, depends on
  StarkWare in three places, and "funded only through upstream" cannot be enforced today), and
  bridging the existing Templar pool (it keeps every service we operate). Upstream-native
  controlled notes ([broody/starknet-privacy#2][pr2]) remain the long-term proposal (§3).
- **Main costs of policy accounts:** everyone holding a case key sees that case; upstream's
  auditor, proving service and discovery service see what they see for any upstream user;
  wallets can fund an account but cannot settle as one; each private transaction pays upstream's
  flat pool fee (§4.5, §4.6).
- **A sealed-bid auction with a third-party auctioneer** becomes non-custodial with one policy
  account per bid, keeping one-action bidding. The auctioneer still sees bids early (§5). The
  RSW time-lock in the [vdf repo][vdf] can remove that too, but publishing each bid account's key
  exposes who funded it (§6).
- **Next step:** a one-day spike on upstream's devnet (§9).

[pr2]: https://github.com/broody/starknet-privacy/pull/2
[vdf]: https://github.com/broody/vdf

## 1. Why the Beacon auction is custodial

Whisper (`stake-wars/vendor/whisper`, [`docs/PROTOCOL.md`](https://github.com/broody/whisper),
"Why this is escrow, and why it is custodial") holds bids in a STRK20 privacy account controlled
by the operator's backend. The operator can see bids early, can spend the vault's notes and is
responsible for refunds. Whisper's contract checks the bid openings and the Vickrey result, but
the pool does not enforce payout recipients, and bidders have no permissionless way to reclaim.

The upstream reasons:

1. **Note ownership is possession of the owner's private key.** `use_note` derives the owner's
   public key from the supplied private key and checks the note's subchannel (`privacy.cairo:587`).
   A contract cannot keep a secret key.
2. **Applications cannot restrict how a note is spent.** An open note lets an application fund a
   note, but once funded it is spent like any other.
3. **Open notes must be filled in the transaction that creates them**
   (`UNDEPOSITED_OPEN_NOTES`, `privacy.cairo:907`), so an application cannot hold a pre-created
   note to fill later.
4. **Sealed bids need someone to keep amounts secret until the close.**

The custom signature path used in §4 has existed since 2026-06-22 (upstream #822), before
Whisper's design. It solves 2 but not 1 or 4: whoever settles still needs the key, and the key
opens every note the account holds. That is why §5 uses one account per bid.

## 2. The upstream hooks that matter

| Hook | What it does | Where | Since |
|---|---|---|---|
| Owner authorization inside the proof | `__execute__` compiles the client actions, then calls `assert_valid_signature(user_addr, calls, tx_info)` with the same `calls`. It accepts if **any** check passes: `is_custom_signature_valid(calls, [], signature)` when the owner advertises it through SRC5; `is_valid_signature` over the transaction hash; or over the SNIP-12 `CallSet` hash. `calls` is `compile_actions(user_addr, user_private_key, client_actions)`. | `privacy.cairo:195–213`, `utils.cairo:371–418` | #822, 2026-06-22 |
| Registration | `SetViewingKey` writes the public key once and encrypts the private key to the auditor's key; the event publishes the address and public key. | `privacy.cairo:319` | — |
| Channels | `OpenChannel` requires both parties registered. `Append` publishes the recipient's address; the channel info encrypts the channel key and the sender's address to the recipient's key. | `privacy.cairo:362`, `:417`; `objects.cairo` (`EncChannelInfo`) | — |
| Invokes | At most one `InvokeExternal` or `ComputeAndInvoke` per transaction, after withdrawals. The target returns `Span<OpenNoteDeposit>`, optionally followed by addresses to screen. | `actions.cairo:304`; `utils.cairo:586` | — |
| Compute-and-invoke | The target's `privacy_compute` runs inside the proof with `identity_key = H(tag, user_addr, user_private_key, target)`; its result prefixes the calldata of the on-chain `privacy_invoke_with_computation`. | `privacy.cairo:547`; `hashes.cairo:57` | #844, 2026-06-25 |
| Open-note screening | An open-note deposit is screened by the depositor's policy: `Required` (default, the depositor), `Exempt`, or `Delegated` (addresses the invoke returns). The admin sets it. | `privacy.cairo:991`; `objects.cairo:116` | #944, #946, 2026-08-19/20 |
| Withdrawals | The `Withdrawal` event publishes `to_addr`, token and amount; the user's address is encrypted to the auditor. | `privacy.cairo:507`; `events.cairo:17` | — |
| Replay protection | Every transaction needs at least one write-once action (a nullifier, a note, a registration). | `privacy.cairo:309` | — |
| Proof freshness | `base_block < current ≤ base_block + proof_validity_blocks`. The SDK proves against finalized state at least 10 blocks old. | `privacy.cairo:808`; SDK README | — |
| Fee | A flat fee per `apply_actions`, taken from the caller. The STRK20 guide measured 4 STRK on mainnet in July. | `privacy.cairo:845` | — |

`apply_actions` has no caller restriction: any account can submit a proven transaction, including
inside a multicall.

## 3. Options

| Option | Amounts | What we would run | Needs from StarkWare | Verdict |
|---|---|---|---|---|
| Policy accounts | Encrypted in upstream's pool | A contract class and an SDK | Nothing | **Recommended** (§4) |
| Escrow anonymizer | Public, in the contract's balance | A contract | A screening policy or attestations for its releases | Only where a contract must verify funding |
| Templar side pool | Hidden inside it | A pool contract | Funding binding, wallet support, exit attestations | Rejected (§3.1) |
| Bridge the Templar pool | Hidden inside it | Pool, prover server, relayer | Exit path | Rejected (§3.2) |
| Upstream-native controlled notes | Encrypted in upstream's pool | Nothing extra | Accept and audit the change | Long term (§3.3) |

**Escrow anonymizer.** Locking is an unshield plus `privacy_invoke` in one private transaction;
release is `ComputeAndInvoke` gated by an identity commitment, into an open note (the
shadow-account pattern). Owners stay hidden, amounts are public, and other contracts can check
funding on chain, which is what auction collateral needs. Releases are open-note deposits, so
under the default policy each needs a screener attestation over the contract's address, or an
admin exemption. The Wallet API does not offer dapps `ComputeAndInvoke`.

### 3.1 Templar side pool (rejected)

A Cairo contract with its own commitment tree. Every operation is an upstream private
transaction: entry is an unshield to the side pool plus an invoke, spends run the side pool's
`privacy_compute` inside upstream's proof (membership, nullifier, policy, value conservation),
and exit is `CreateOpenNote` plus `ComputeAndInvoke` returning an `OpenNoteDeposit`. It would need
no prover of ours, port P1 almost directly, give each party its own keys derived from the identity
key, and allow proving "this note holds at least X" without spending it.

If side-pool keys derive only from the identity key, upstream's auditor, which holds every user's
private key, could trace the side pool too. The blockers:

1. **"Funded only through upstream" cannot be enforced today.** The invoked contract sees only
   its token balance. Any account can send `token.transfer(side_pool, X)` and then
   `apply_actions(withdraw 1 to side_pool, invoke claiming X + 1)` in one multicall, bringing
   unscreened funds in behind a tiny screened withdrawal. The fix is an upstream change: pass
   the proven withdrawals to the target into the invoke (for example a new `InvokeWithFunding`
   action). Upstream's DeFi anonymizers have the same blind spot, harmlessly.
2. **StarkWare could freeze it** by pausing or upgrading upstream, or by refusing to attest its
   address for exits. A public emergency exit removes that risk but breaks "upstream only".
3. **Wallets cannot drive it.** Spends and exits need `ComputeAndInvoke`, which the Wallet API does
   not offer dapps; the SDK exposes it only for the sub-account anonymizer, in a release
   candidate. Users would have to export their upstream key to our app.
4. **It is a pool:** our contract holding pooled funds with its own anonymity set, which is what
   the compliance review stepped back from.

### 3.2 Bridging the existing Templar pool (rejected)

An upstream transaction carries one set of proof facts, so a Templar spend cannot be verified
inside an upstream transaction. Exits would go through a parking contract and a second upstream
transaction with public amounts, and we would keep running the prover server (PROOF2 about 64 s
and 30 GiB per spend) and the relayer.

### 3.3 Upstream-native controlled notes

[broody/starknet-privacy#2][pr2] (open since 2026-09-06, 44 files) adds a controlled note whose
spends need its controller's approval, validated inside the proven execution. Its own open items:
the outsourced prover receives note openings, and policy revocation. It needs StarkWare's buy-in
and an audit. Propose it once policy accounts work, drafted as an issue in `broody/templar` first.

## 4. Policy accounts

### 4.1 How it works

A policy account is an owner contract that implements SRC5 and `is_custom_signature_valid`. Notes
are sent to its address like to any registered user. To spend them, a key-holder proves a
transaction *as* the account. Inside the proof the pool asks the account to approve, and the
account accepts only if the outputs match an outcome its rules allow at the proof's base block.
The key lets you try; the contract decides.

It is an escrow contract that never holds tokens:

| | Normal escrow contract | Policy account |
|---|---|---|
| Funds | Its own public token balance | Encrypted notes owned by its address |
| Who moves them | The contract, when a condition is met | A key-holder's private transaction, which it approves or refuses |
| Where its rules run | On chain, in public | Inside the proof: terms, decisions and amounts stay hidden |

In exchange, it cannot act on its own, cannot keep state (its check runs inside the proof and
writes nothing), and other contracts cannot see its balance.

### 4.2 An escrow (buyer B, seller S, arbiter A)

1. **Create.** B's app generates a case key and deploys a `PolicyAccount` holding the pool
   address, the key's public key and a hash of the policy (token, release → S, refund → B, A's
   public key, deadline). The key is encrypted to S and A with their upstream public keys.
2. **Register.** A transaction as the account containing only `SetViewingKey`, allowed only if the
   key matches the stored public key.
3. **Fund.** B's wallet sends an ordinary private transfer to the account's address. S decrypts
   with the case key and checks the amount before shipping.
4. **Decide.** A signs "release" off chain.
5. **Settle.** Anyone with the key proves: spend the account's notes, create a note for S. The
   signature field, free-form and hidden in the proof, carries the policy preimage and A's
   signature. The account checks the preimage, the signature, and that every output goes to S.
6. S's wallet finds the note like any other.

Refund: after the deadline, or with a signed "refund" from A or S, settle to B. A path where B and S
both sign the exact transaction covers anything else.

### 4.3 What the account must enforce

- **Structure:** exactly one call, to the pinned pool, selector `compile_actions`, user address
  equal to itself.
- **Actions:** an allowlist. Channels only to the outcome's recipients, spends of its own notes,
  notes only to those recipients, withdrawals only if the outcome allows them. Refuse invokes,
  compute-and-invoke, deposits and open notes.
- **The other paths:** `is_valid_signature` returns 0. The pool accepts any of three checks, and
  implementing it avoids relying on a missing entry point failing cleanly.
- **Immutability:** no admin, no class replacement; refuse ordinary transactions.
- **Decisions:** signed messages domain-separated by chain, pool, account and outcome, and final.
  On-chain decisions must be write-once, because proofs read state at least 10 blocks old.
- **State** comes from notes: vesting checks that the change note back to the account holds at
  least the unvested amount. The account can decode input amounts with the key; output amounts are
  in the actions.
- **An escape hatch:** the all-parties signature over the exact calls survives an upstream change
  to the action format that would otherwise make the parser refuse everything.

### 4.4 The P1 review problems

| P1 issue | With policy accounts |
|---|---|
| Decoy notes naming a victim's controller (PN-1, P-1) | Gone: the policy is the account, not creator-chosen metadata |
| Split payouts undeliverable (P-3) | Gone: outputs are created at settlement with their real amounts |
| No collateral assurance (P-4) | Key-holders can check by decrypting; a contract still cannot |
| Our relation, bridge, prover and relayer | Replaced by one Cairo class and SDK glue |

### 4.5 Who sees what

Funding needs only the account's address and registered public key. Each payer's transfer goes
over their own channel, encrypted to the account's key: a payer sees only their own payment.
The case key opens everything. With the key held only by a third party that created and
registered the account itself:

| Who | Sees |
|---|---|
| The key holder | Every amount, every payer's address, when funds move |
| Each payer | Their own payment |
| Each payout recipient | The note they receive, sent from the account's address |
| Upstream's auditor | Everything: registration encrypts the key to it, as for every upstream user |
| Upstream's proving service | Each settlement it proves (the SDK sends the key and the transaction); avoidable by proving yourself (§7) |
| The prover's blocking-check service, if the hosted prover uses one | The same transactions (§7) |
| Upstream's discovery service | The account's notes, since it is given the key; avoidable by running it (`crates/discovery-service`) |
| The public | The account's class, address and public key; channel openings to it (about how many payers); a payout recipient's address if their channel is new. Never amounts |

Whoever runs the registration knows the key, so a payer who sets up the case sees everything.

**Several payers.** If each payer must be able to refund themselves, give each payer their own
account; every account reads the same on-chain decision. A non-paying key holder (arbiter,
operator) who settles for everyone also works, but must stay online. Rules on the combined total
across payers (a crowdfund threshold) need either one party who sees all accounts or amounts that
become public at a deadline.

### 4.6 UX and cost

- **Wallets:** only Ready supports STRK20 (Xverse in progress). Funding works through the Wallet
  API; settling as an account needs our app with upstream's SDK, the account's address and a
  custom signer.
- **Per case:** deploy, register, fund, settle: three private transactions, about 12 STRK in pool
  fees at 4 STRK, plus gas. Wallets sponsor gas, not the pool fee. That rules out small escrows.
- **Latency:** notes mature about 10 blocks after creation, each private transaction waits for the
  previous one to finalize, and settlement sees a decision about 10 blocks late.
- **Races:** any key-holder can settle an allowed outcome; the first wins.
- **Key custody:** lose the key and another party must settle; leak it and privacy is lost, not
  funds.

### 4.7 To verify before building

1. **Time.** The prover runs the virtual block with the base block's `block_info` and passes the
   base block's header commitments (`running/runner.rs:244`, sequencer checkout at `625929a`),
   which suggests the OS binds the timestamp to the base block hash. Confirm in the OS; until
   then, deadlines use signatures or write-once on-chain flags.
2. Whether StarkWare's hosted prover accepts unknown owner classes.
3. Whether the SDK's signer can return arbitrary signature felts.
4. Whether a paymaster will sponsor `apply_actions` for our settlements; otherwise the settler's
   public account pays and is linked.
5. Step cost of parsing the actions inside the check.

## 5. Sealed-bid auction with a third-party auctioneer

Whisper made non-custodial: one policy account per bid, keys held by the auctioneer and the bidder.

1. **The auctioneer prepares bid accounts in advance:** it deploys and registers them and pays
   those fees. Each account's rule reads its terms from the auction contract's record for its
   address.
2. The bidder gets an account and its key from the auctioneer's API.
3. **The bid is one wallet action:** a private transfer of the amount to the account plus
   `submit_bid(account, commitments)` in the same transaction; the commitments cover the refund
   address and the winner payload.
4. **Acceptance:** the auctioneer decrypts the account, checks the amount and calls `accept` as an
   ordinary public call (no replay-protection notes, unlike Whisper's acceptance).
5. **Close:** the auctioneer computes and posts the Vickrey result.
6. **Settlement:** the auctioneer or the bidder settles. A losing bid refunds to the committed
   address; the winning bid pays the clearing price to the seller and the change to the refund
   address.
7. **Fallback:** after the abort deadline, or if the bid was never accepted in time, the bidder
   reclaims with their key.

| | Whisper today | Per-bid policy accounts |
|---|---|---|
| Custody | The operator's vault | Nobody |
| Operator can redirect or withhold funds | Yes | No |
| Operator sees bids early | Yes | Yes |
| Other bidders see bids | No | No |
| Refund if the operator vanishes | None | The bidder reclaims |
| Bidder's wallet steps | 1 | 1 |

Still trusted: the auctioneer keeps bids secret until the close; it accepts only funded bids (a
bond or an attestation, where the bid account proves its note amount to the auction contract,
removes this); and the result is correct. For the result, either post every opening so the
contract checks the Vickrey computation (losing amounts become public, as in Whisper), or post
only the winner and price and trust the computation.

## 6. Time-lock integration ([vdf repo][vdf])

The vdf repo's design note separates **custody** (who can move funds) from **reveal timing**
(when bids become readable). Policy accounts solve the first; the RSW time-lock solves the second.
Combined: each bidder funds their own bid account and posts a commitment, the puzzle and a
ciphertext of the bid, a salt, the account's key and the policy terms. After the close anyone does
the T squarings, decrypts, posts the opening, and settles. The Wesolowski proof is needed only in a
dispute.

From the vdf repo's TODO: the controller now sees the price paid (policy accounts see outputs); the
note deadline becomes the account's abort path; collateral can be checked by anyone once keys are
public, but a contract still needs a bond or an attestation step; censorship near the close is
still open.

**The new problem.** Settlement by strangers needs the account's key in the ciphertext, and the key
decrypts the account's incoming channel data, including the funder's address. After the close,
every bidder's funding address is public. Options: fund each bid through a throwaway account
(deployable from inside a private transaction; about two more private transactions, roughly
8 STRK) or give the key to the auctioneer with a longer-delay time-locked copy as backup.

State of the vdf repo: the Cairo verifier runs (8.5M steps at 512 bits, 53.9M at 2048 bits); the
optimized traces are not yet proven (the last attempt hit stwo-cairo#1733); on-chain verification
is not built; `dabba07` has had no independent review. A first version can skip on-chain proofs:
bidders can always open their own bid, solvers open bids for absent bidders, and a bid with no
valid opening by the reveal deadline loses its bond.

The time-lock keeps something secret until about time T; it cannot enforce deadlines, which must
still come from chain state. drand/tlock fills the same slot without compute, trusting the drand
operators instead.

## 7. Proving and the blocking check

Upstream's README describes an operator-side proving service; the starknet-privacy repo does not
document proving yourself. Its SDK accepts any endpoint (`ProvingServiceProofProvider(url)`), and
the prover is open source in `starkware-libs/sequencer`: created as `starknet_os_runner` on
2025-12-18 (#10888), renamed `starknet_transaction_prover` on 2026-03-05 (#12980), with external
developer docs and a Docker quickstart since 2026-03-11 (#13129). We have not run it against the
pool. The STRK20 integration guide calls this "self-hosted proving" and notes it does not bypass
deposit screening.

The prover has an optional **blocking check** (`src/blocking_check.rs`): in parallel with proving it
sends each transaction to an external `starknet_checkTransaction` service that can block it. It
has defaulted to failing closed since 2026-07-01 (#14671). A privacy transaction's calldata holds
the user's private key and all its actions, so if the hosted prover uses the check, that service
sees them. We do not know the hosted configuration. A self-hosted prover leaves it off unless
configured; on-chain deposit screening applies either way.

## 8. Legal shape, for counsel

Input for counsel, not conclusions; see
[compliance and enforcement research](compliance-enforcement-research.md).

| Option | What we would operate or hold |
|---|---|
| Policy accounts | A published contract class and an SDK. No pool, prover, relayer or custody. Upstream's deposit screening and auditor apply unchanged. |
| Escrow anonymizer | A contract holding each case's funds in public, released into upstream notes under StarkWare's screening. |
| Templar side pool | Our contract holding pooled funds with its own anonymity set: a pool again. |
| Bridged Templar pool | The pool, prover server and relayer the review stepped back from. |
| Third-party auctioneer (§5) | Acceptance and settlement of other people's bids, without custody. The research's relayer discussion (coordination without custody treated as money transmission in Samourai) is the question to put to counsel. |

## 9. Next step

A one-day spike on upstream's devnet: a policy account registered, funded and settled, answering
§4.7 items 1–3. Then the escrow template with rejection tests (wrong recipient, forged decision,
the fallback signature paths), an independent Math/Protocol review, and a bid-account demo against
a mock auction.

## Sources

- `starkware-libs/starknet-privacy` at `b40bf10`: `packages/privacy/src/{privacy,utils,actions,objects,events,hashes}.cairo`;
  `packages/shadow_account_anonymizer`; `sdk/README.md`; `README.md`.
- `starkware-libs/sequencer`: `crates/starknet_transaction_prover` (`src/running/runner.rs`,
  `src/blocking_check.rs`, `README.md`) and the commit history cited in §7.
- Whisper `docs/PROTOCOL.md` (vendored in `stake-wars/vendor/whisper`, `0525042`).
- vdf repo `README.md`, `TODO.md`, `skill/references/whisper-integration-design.md` (`dabba07`).
- STRK20 privacy-integration guide (`starkience/strk20-agent-skills`): Wallet API scope, pool fee,
  note maturity, SDK sub-account support, self-hosted proving.
- [broody/starknet-privacy#2][pr2]; [ADR-0006](../adr/0006-controlled-notes.md),
  [ADR-0025](../adr/0025-policy-notes.md) and the policy-note reviews in
  `bench/m31-pool/reviews/`.
