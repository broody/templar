# Hidden-asset spends and NFT notes: protocol and contract design review (pre-implementation)

Independent reviewer; did not write the design. Date 2026-09-24, branch `docs/guide-refresh` at
`a5d2e54`, reviewing the uncommitted `docs/hidden-asset-spec.md`. Nothing is implemented, so every
finding comes from reasoning (**R**) or from reading third-party source (**V**, verified in
source); none is demonstrated by a test. I modified no code or docs other than this file.

## Scope

- **Spec.** `docs/hidden-asset-spec.md` in full, with the focus on §3, §5, §6, §7 and Q1, Q3, Q7,
  Q8. §4 (the relation) is under separate soundness review; I note only its contract and protocol
  consequences (HA-P3, HA-P4, and Q2 in passing).
- **Pool.** `bench/m31-pool/cairo/src/pool.cairo` (`deposit` :150-163, `apply_spend` :165-172,
  `apply_spend_with_invoke` :174-237, `apply_policy_spend` :277-357, `verify_spend` :376-394,
  `append_notes` :436-459, `pay_withdrawal` :463-476, `start` :478-481), `spend.cairo`,
  `open_note.cairo`, `policy.cairo`, `adapter.cairo`, `hash.cairo`, `tree.cairo` (depth 32, 256
  roots).
- **Bridges.** R0 `client-port/cairo-r0/bridge/src/lib.cairo` (:24-25 `ADDRESS_BOUND`, :118-140
  liveness checks) and account; P1 `client-port/cairo-p1/bridge/src/lib.cairo` (:143-154).
  The R0 witness rules are in `client-port/src/payment.rs` (:289-335).
- **Specs.** `docs/open-note-spec.md`, `docs/policy-note-spec.md` (§4.2 split l.136-139,
  constraint 8 l.225-236, §9.3 l.449-453), `docs/push-payment-spec.md` (delivery contract).
- **Wallet.** `bench/m31-pool/open_note.py`, `policy_wallet.py` (`m301`, `find_notes` :234-262,
  the backup validity check :229).
- **OpenZeppelin Cairo (V).** Read in `~/.cache/scarb/.../openzeppelin_token-3.0.0`:
  - `erc1155/erc1155.cairo`:
    - :218-234: `safe_batch_transfer_from` requires `from == caller` or
      `is_approved_for_all(from, caller)`. There is no per-id approval.
    - :186-197: `safe_transfer_from` is the batch path with length 1.
    - :607-619: `update_with_acceptance_check` credits balances **before** the receiver hook, and
      uses the single hook when the length is 1 and the batch hook otherwise.
    - :702-721: `_check_on_ERC1155_received` accepts `to` if it supports `IERC1155_RECEIVER_ID`
      through SRC5 and returns that id, or else if it supports `ISRC6_ID`. Otherwise it fails
      (and a `to` without SRC5 fails the call).
  - `erc721/erc721.cairo`:
    - :180-194: `transfer_from` asserts `from == previous_owner`, and the caller must be
      authorized (:661-691, :825).
    - :154-166: `safe_transfer_from` is `transfer_from` plus the check.
    - :839-852: the receiver check has the same shape as ERC1155's.
    - :677: a transfer clears the per-token approval.
  - The interface ids are identical in `openzeppelin_token-0.20.0/src/{erc721,erc1155}/interface.cairo:9-10`
    and `openzeppelin_interfaces-2.2.0`: `IERC1155_RECEIVER_ID = 0x15e8…515e`,
    `IERC721_RECEIVER_ID = 0x3a0d…10bc`, `ISRC6_ID = 0x2cec…c1cd`.
  - **Not verified:** OZ releases before 0.18 (none cached), Cairo 0 era collections (camelCase
    entry points), and dual-case receiver fallbacks. Those are treated as "non-standard" below.
- **Upstream Starknet Privacy** (`packages/privacy/src`):
  - It is ERC20 only (`OpenNoteDeposit.token` is "the ERC20 token contract",
    `objects.cairo:128-135`).
  - Deposits and withdrawals publish the token (`privacy.cairo:486-530`).
  - Encrypted notes store `token = 0` and carry the token encrypted (`objects.cairo:92-100`).
  - There is no registry and no NFT support to compare against.
- **Ran (read-only).** The existing pool suite, `snforge test` with scarb 2.18.0 / snforge 0.63.0
  in `bench/m31-pool/cairo`: **181 passed, 0 failed**. The default scarb 2.14.0 does not build the
  crate (`get_execution_info_v3_syscall` is missing). This is a tooling note, not a finding.

## Verdict

**CONDITIONAL GO.** Resolve HA-P1 (High) and HA-P2, HA-P3 and HA-P5 (Medium) in the spec before
implementation. The Low and Info items can go into the spec during implementation.

The hidden token, the uniform shape and the pool-side exit rule are consistent with each other
and with the relation as specified. The pool-side checks in §5.2, together with V3's checks, are
complete for pure transfers. A pure V4 transfer runs no token-dependent code in the pool, so gas
and events do not depend on the asset. The ERC1155 expected-receipt hook cannot be spoofed,
replayed or left set by anyone other than the token contract itself (see "Checks found sound").

The design has four problems:

1. **Per-identifier solvency assumes identifiers are independent.** That is false for one
   contract deposited through two standards (hybrid and dual-ledger tokens). Another user's
   deposits and withdrawals can then make NFT notes unbacked (HA-P1).
2. **"Replace the V3 entry points in the same pool" presupposes an upgrade path.** The pool has
   none, and commitments bind the pool address (HA-P2).
3. **The V4 bridge's liveness checks are unspecified.** The existing V3 checks would reject every
   pure transfer (`token ≠ 0`) and admit inactive outputs (HA-P3).
4. **The ERC1155 pull deposit requires a collection-wide, standing `ApprovalForAll`** to the pool,
   and the hook contract is under-specified (HA-P5).

## Findings

### HA-P1: High. One contract under several standards breaks per-identifier solvency

**Location:** spec §3 "Per-asset solvency invariant" (l.77-80) and "Registry" (l.68-75); §5.1
(l.150-159); §5.2 open-note rule (l.180-181).

**Problem.** Identifiers are independent only if their on-chain backings are independent.
Several legitimate token designs couple them:

- ERC20/ERC721 hybrids (ERC-404/DN-404 style), where fungible balance moves mint or burn NFTs;
- one contract exposing ERC721 and ERC1155 views over a shared ledger;
- ERC20 facades over ERC1155 ids.

The pool accepts the same contract `C` through `deposit` (identifier `C`), `deposit_erc721`
(`H(721, C, id)`) and `deposit_erc1155` (`H(1155, C, id)`). Each of these assumes it alone moves
the pool's holdings of `C`. The sentence "A malicious token contract can only affect notes of its
own asset identifiers" is literally true. It hides the case that matters: an *honest* hybrid
lets users of one identifier destroy the backing of another identifier of the same contract.

**Scenario (R).**

1. `C` is an ERC-404-style hybrid in which ERC20 transfers that drop a holder's balance below a
   whole unit burn one of that holder's NFTs.
2. Alice deposits NFT #7 through `deposit_erc721` and gets a note `H(721, C, 7)`.
3. Bob deposits `10.5e18` units through `deposit`, spends in-pool, and withdraws `0.6e18` through
   the ERC20 path.
4. The pool's `C` balance crosses a unit boundary, and `C` burns the pool's last-acquired NFT,
   which is #7.
5. Alice's withdrawal fails at `owner_of(7) == recipient` forever.

A variant: if `C.transfer_from` returns `bool` and treats small values as token ids, `deposit(C,
7)` through the ERC20 path moves NFT #7 while crediting an ERC20-style note of amount 7. That
note can then be merged, split and withdrawn against other users' holdings.

**Required spec change.**

1. Add `contract_standard: Map<ContractAddress, u8>` (ERC20, 721 or 1155):
   - write it on a contract's first deposit through *any* path, including `deposit` and
     open-note destination funding;
   - reject deposits and open-note destinations that use a different standard for a recorded
     contract.

   This costs one storage read per ERC20 deposit and one write per new contract. It is not a
   write per deposit, and it does not change identifiers (Q1).
2. At NFT registration, also require SRC5 support of the matching token interface (`IERC721_ID`
   or `IERC1155_ID`). This screens accidents only; a malicious contract can claim anything.
3. For migration (HA-P2), backfill `contract_standard = ERC20` for every token with pre-V4 notes
   before the first NFT deposit.
4. Restate §3: solvency is per *contract ledger*, not per identifier. Facades at *different*
   addresses that share a ledger cannot be detected on chain. They are a listing or allowlist
   decision for a production pool, which the spec should mention.

### HA-P2: Medium. Migration "in the same pool" has no mechanism; retiring V3 must be atomic

**Location:** spec §5.2 (l.171-172), Q8 (l.259-260); `pool.cairo` (no `replace_class`; grep);
`hash.cairo:325-333` (`cm` binds `pool`).

**Problem.** Note commitments bind `pool₉`, so V4 can spend pre-V4 notes only at the *same
address*. The reference pool has no upgrade entry point, and its binding domain
(`TMR0_BIND_V3`, `spend.cairo:106`) and `Spend` layout are compiled in. Swapping the adapter with
`set_verifier` does not help. The options are:

- **(a)** Add an owner-controlled `replace_class`. That is a new trust assumption: the owner can
  take all TVL. Under HA-P5 it also reaches every user's ERC1155 holdings covered by a standing
  `ApprovalForAll`.
- **(b)** Deploy a new pool. Pre-V4 notes stay in the old pool, and users must withdraw and
  re-deposit publicly.

The spec picks neither.

If V3 and V4 entry points coexist, even briefly:

- V3 spends of V4-created notes publish the token those notes hid;
- V3 in-pool transfers stay distinguishable, which splits the anonymity set;
- a V3 spend of an NFT-identifier note reaches `IERC20.transfer` on a hash address and reverts.
  That is safe but leaves a confusing failure.

**Required spec change.**

- State the mechanism. For the reference pool, recommend a fresh deployment. For a production
  pool, specify the upgrade authority explicitly if one exists.
- Specify that V3 entry points are removed in the same class change that adds V4 and the
  registry.
- Specify that the `nullifiers` map, `root_history`, tree and `delivery_digests` storage keys are
  preserved unchanged (nullifier formula unchanged, so there is no cross-version double spend).
- Specify the HA-P1 backfill.
- Specify that in-flight V3 proofs fail after the switch and must be re-proved; no value is lost.

See Q8.

### HA-P3: Medium. The V4 bridge and account checks are unspecified; V3's would reject every pure transfer

**Location:** spec §4.2-4.4 (l.94-144), §5.2 (l.174-178); R0 bridge `lib.cairo:118-137`; R0
account `account/src/lib.cairo` (tag `'TMPZR0_PAYMENT_V3'`).

**Problem.** The V3 bridge does three things that conflict with V4:

- it asserts `token != 0` ("zero context") and `token < 2^251` ("address range");
- it allows inactive outputs (`(d ≠ 0) == active`);
- it requires "some output or withdrawal".

Copied into V4, the first check rejects every pure transfer, whose `token_out = 0`. The second
admits a statement with a zero commitment. The pool's §5.2 check would catch that, but only the
pool. The spec says the bridge, account, tag and adapter are "new classes". It does not list what
they check.

**Required spec change.** List the V4 bridge liveness checks:

- `token_out` may be zero, and there is no address-range check on it (see HA-P4);
- both commitments are nonzero, and both deliveries are nonzero;
- nullifiers are nonzero and distinct (as V3);
- `recipient ≠ 0 ⇔ w_amount ≠ 0`, with `recipient < 2^251`;
- identity ⇒ intent;
- the exit rule `token_out ≠ 0 ⇔ (w_amount ≠ 0 ∨ intent ≠ 0)`. It is cheaper here, inside the
  proven execution, and the pool keeps it as defense in depth.

Also name the account tag (for example `'TMPZR0_PAYMENT_V4'`) and the `binding` field order,
already given in §4.4.

For the math reviewer: the pool rule exists only to reject a voluntary reveal. Constraining
`x = [w_amount ≠ 0 ∨ intent ≠ 0]` in the relation would remove the need for it.

### HA-P4: Low. Asset identifiers do not fit the `ContractAddress`-typed fields and the P1 bridge

**Location:** spec §3 table (l.59-65), §5.4 "P1 is unchanged"; `spend.cairo:31`,
`policy.cairo:27`, `pool.cairo:105,110,134` (`token: ContractAddress` in `Spend`, `PolicySpend`,
`OpenNoteFunded`, `Withdrawn`, `Deposited`); P1 bridge `lib.cairo:144`
(`address(statement.token)`, `< 2^251`); `policy_wallet.py:229` (`0 < token < ADDRESS_BOUND`).

**Problem.** `Poseidon(...)` is uniform below `p = 2^251 + 17·2^192 + 1`. A fraction of about
`2^-55` of identifiers is `≥ 2^251`. Such an identifier:

- fails `ContractAddress` deserialization in `Spend` and `PolicySpend`;
- fails the unchanged P1 bridge's range check, so a policy note of that asset cannot settle at
  all, *including the refund*;
- fails the wallet's backup check.

The owner of an ERC1155 contract can grind an id into that range in about 2^55 hashes. The harm
falls on anyone who accepts such a note, and the refund guarantee of P1 is lost.

**Required spec change.**

- Registration rejects `a ≥ 2^251`, so every identifier is a valid `ContractAddress` and P1 really
  is unchanged. The (contract, id) pair is then undepositable, with probability `2^-55`.
- Rename the V4 `token_out` and event fields to `asset: felt252` (or keep `ContractAddress` under
  the rule above).
- Make `Withdrawn` carry the asset identifier. Standard, contract and id are recoverable from
  `AssetRegistered`.

### HA-P5: Medium. The ERC1155 pull deposit needs a standing `ApprovalForAll`, and the hook contract is incomplete

**Location:** spec §5.1 (l.151-155, 161-165); OZ `erc1155.cairo:229-232, 607-619, 702-721`.

**Problem.**

- **(a) Standing approval.** ERC1155 has no per-id approval (V). For the pool to call
  `safe_transfer_from(caller, pool, …)`, the user must `set_approval_for_all(pool, true)`. That
  approval covers every id of the collection, for as long as it stands. Any future pool bug that
  lets `from ≠ caller`, or any upgrade (HA-P2 (a)), can then drain the user's *wallet*, not only
  the pool. The `ApprovalForAll(user, pool)` event is also a lasting public marker (see HA-P8).
- **(b) The hook predicate is under-specified.** The spec lists caller, id, amount and operator.
  It omits:
  - `from == depositor`;
  - the exact return value, which OZ compares to `IERC1155_RECEIVER_ID`, not a selector (V);
  - that the record is consumed by the hook;
  - that `supports_interface` must answer true for `ISRC5_ID` and `IERC1155_RECEIVER_ID` and false
    for `ISRC6_ID` and `IERC721_RECEIVER_ID`;
  - `amount ≠ 0` and nonzero `inner` for both NFT deposit entry points, as `BAD_DEPOSIT` checks
    for ERC20.
- **(c) Receipt semantics.** OZ credits the balance *before* calling the hook (V). The hook
  therefore proves nothing about receipt. The spec's post-call balance delta is the only
  authoritative check, and it should be stated as such, with the balance read *before* the call.

**Scenario (R).** A user approves the pool for all ids to deposit one. A later pool class (or a
bug in a new entry point) calls `safe_transfer_from(victim, attacker, id, balance, [])` for every
approved victim and every id.

**Required spec change.** Prefer a **push deposit**: the user calls
`C.safe_transfer_from(user, pool, id, amount, data = inner₉ ‖ ciphertext₁₀)`, and the pool's
`on_erc1155_received` takes the lock and does the following:

- requires `!locked`, `operator == from` (or accepts any operator);
- credits `H(1155, caller, id)` from the data;
- checks `balance_of(pool, id) ≥ held[a] + value`, then sets `held[a] += value` (per-asset
  internal accounting, which also helps HA-P11);
- returns `IERC1155_RECEIVER_ID`.

This needs no approval, and the trust in `caller` is the same as the balance check's today. If
the pull model is kept, specify (b) and (c) and document the approval's scope in §6.

### HA-P6: Low. Withdrawal to the pool is not rejected "as today"; for ERC721 it strands the token permanently

**Location:** spec §5.3 (l.194); `pool.cairo:463-476` (`pay_withdrawal` checks only
`recipient ≠ 0`). The invoke path (`:199`) and P1 (`:341`) do check it.

**Problem.** `apply_spend` today accepts `recipient == pool`. For ERC20 that leaves a surplus. For
ERC721 under §5.3, `transfer_from(pool, pool, id)` succeeds, `owner_of(id) == recipient` passes,
the note is gone, and the NFT can never be deposited again, because `deposit_erc721` requires
`owner_of ≠ pool`. For ERC1155 the pool's own hook reverts the payout.

**Required spec change.** `pay_out` asserts `recipient ≠ 0 ∧ recipient ≠ pool` for every standard
and every caller (V4 and P1). Correct "as today".

### HA-P7: Low. ERC1155 payouts fail for recipients without SRC5, which blocks fixed P1 outcomes

**Location:** spec §5.3 (l.188-189), §5.4; OZ `erc1155.cairo:702-721`.

**Problem.**

- A recipient that neither registers `IERC1155_RECEIVER_ID` nor `ISRC6_ID` through SRC5, or has
  no `supports_interface` at all, makes `safe_transfer_from` revert (V). Examples: plain
  contracts, custodial deposit contracts, Cairo 0 era accounts that answer only camelCase
  `supportsInterface`.
- For a V4 withdrawal this only needs a retry to another address. For a P1 **fixed** outcome the
  recipient is fixed at creation, so that outcome can never settle, and only the refund after the
  deadline remains.
- A recipient hook runs under the pool's lock. It can burn the submitter's gas or revert on
  purpose, which lets a relayer or executor be griefed.

**Required spec change.**

- In §6 and in the policy acceptance checklist (policy spec §9.3): check that an ERC1155 recipient
  supports SRC5 and one of the two ids before building a withdrawal or accepting a policy
  opening.
- Relayers and executors simulate first.
- State in §5.4 that ERC1155 outcomes inherit the recipient's liveness.

### HA-P8: Low. §7's privacy and analytics claims are overstated or incomplete

**Location:** spec §1 (l.17-18), §7 (l.218-238).

**Problem.**

1. **The anonymity set is not every note in the pool.** Several things shrink it:
   - it is bounded by the leaf count at the chosen `root` (root age also fingerprints the
     wallet's sync policy);
   - dummy leaves inflate the count but are never spent;
   - the asset of the spent note has an informed prior. Every deposit, V3 output, funded open
     note and policy output has a *public* token. Only V4 transfer outputs hide it. Hiding
     improves only as V4 outputs accumulate, and pre-V4 leaves (Q8) all have public tokens.
2. **Missing from "still public":**
   - the **set of NFTs held by the pool at every block** (`owner_of`/`balance_of`), and so each
     NFT's dwell time in the pool;
   - `Approval`/`ApprovalForAll` events naming the pool (HA-P5);
   - the PROOF2 facts' base block, which gives the proof time;
   - fee settings and the fee payer.
3. **RPC leaks.** Registry lookups are addressed, but these are not:
   - wallet reads of token metadata (`token_uri(id)`, `name`, decimals);
   - `owner_of` and `balance_of` reads for display;
   - `get_nullifier_spent` and `get_delivery_digest` polling.

   Each reveals interest in an asset or a note to the RPC provider.
4. **The TVL formula is wrong.** "Deposits minus withdrawals" ignores open-note budgets and
   fundings, P1 withdrawals and unsolicited transfers. Holdings and flows are each public, but
   they are not equal.
5. **Wallet fingerprints.** Every implementation-dependent choice partitions the anonymity set by
   wallet: dummy construction (HA-P9), root selection, whether input 1 is real, fee resource
   bounds.

**Required spec change.** Rewrite §7 with these items. Replace "every note in the pool" with "every
leaf at or before the spend's root, weighted by public asset knowledge". Add a wallet rule for
metadata, caching and privacy-preserving RPC.

### HA-P9: Low. Dummy ciphertexts must be real sealed boxes; random bytes are distinguishable

**Location:** spec §6 (l.209-211).

**Problem.** The spec says "a sealed box of a random 256-byte plaintext to a fresh random X25519
key", which is correct. It is not normative against the obvious shortcut of 304 random bytes. A
sealed box starts with the ephemeral X25519 public key, a curve u-coordinate whose top bit is
always clear and which lies on the curve rather than the twist. Uniform bytes fail both tests
about half the time, so a lazy or alternative wallet marks its dummies, and through them its
users.

**Required spec change.** "MUST" produce dummy ciphertexts with the same libsodium
`crypto_box_seal` call as real ones, with a freshly generated key pair and CSPRNG plaintext, and
draw dummy `sk`, `rho`, position and receiver from a CSPRNG independent of seed-derived counters.
Add a wallet test that checks the byte layout (the ephemeral key's high bit) for real and dummy
outputs.

### HA-P10: Info. Registry interface and Q1 guards

**Location:** spec §3 (l.68-75), §6 (l.212-214).

- Add the views `get_asset(a) -> AssetInfo` and `asset_id(standard, contract, id)`. Controllers
  compare the authorization's `token` (now an identifier) against an expected asset, and tests
  and integrators need the derivation on chain.
- Add two cheap Q1 guards:
  - `deposit` (ERC20) asserts `!registered(token)`;
  - registration asserts `get_class_hash_at_syscall(a) == 0` (no contract deployed at the
    identifier; confirm that the syscall returns zero for undeployed addresses).
- `AssetRegistered` can be spammed: each registration costs one real deposit of an
  attacker-minted id. Wallets bulk-sync this event and must read it only from the pool address.
  State the expected growth, and let wallets sync lazily from a snapshot.

### HA-P11: Info. Unsolicited transfers and hook-less mints

**Location:** spec §5.1 (l.161-167).

- An ERC721 sent to the pool by plain `transfer_from` is held without a note, and it also blocks
  any later `deposit_erc721` of that id (`owner_of == pool`). The loss is permanent, not merely
  "never credited".
- ERC1155 "unsolicited transfers are rejected" holds only for standard safe transfers and
  `mint_with_acceptance_check`. A contract that credits balances through its internal `update`
  (no acceptance check) can still add balance.

Neither affects solvency: all checks are deltas or ownership. Optionally, per-asset accounting
(`held[a]`, HA-P5) would allow an owner-only rescue of un-noted NFTs and ERC1155 surplus without
touching note backing.

### HA-P12: Info. Supported token ABI

**Location:** spec §5.1, §5.3.

The pool calls snake_case `transfer_from`, `owner_of`, `balance_of` and `safe_transfer_from`.
Cairo 0 era and other camelCase-only collections revert safely at deposit. Receivers built with
old dual-case dispatchers may expect `onERC1155Received`. Document the supported ABI (OZ ≥ 0.20
interface ids, verified identical in 0.20.0 and interfaces 2.2.0), and decide whether the pool
also exposes a camelCase `onERC1155Received`.

The ERC20 `deposit` still trusts `transfer_from` without a balance delta (`pool.cairo:156-159`),
while the NFT paths check deltas and the open-note path already does (`:223-225`). Aligning them
would be cheap. This is pre-existing.

## Answers

**Q1: ERC20 addresses versus hashed identifiers.** The separation is adequate, and ERC20 should
not move to a tagged hash.

- **Tagging ERC20 would break pre-V4 notes.** `cm` binds `token₉`, so a tagged hash would make
  every pre-V4 note unspendable, and that decides the question given Q8.
- **The collision risk is negligible.** Both sides are attacker-controllable: deployable
  addresses (`pedersen`-based derivation, grindable by salt and class) and registrable
  identifiers (own ERC1155 contract, any id). A generic collision therefore costs about 2^125
  (birthday), and it harms no one: the attacker owns both colliding assets. Hitting someone
  else's asset needs a second preimage (about 2^251).
- **The real risk is elsewhere.** It is not identifier collision but one contract under several
  standards (HA-P1). The fix is per contract, and it gives ERC20 an explicit registry entry
  without changing its identifier.
- **Add the two guards** in HA-P10 and the range rule in HA-P4.
- **The u256 id encoding** `(id.low, id.high)` is unambiguous. `standard` in the preimage makes
  721 and 1155 identifiers of the same pair distinct by construction. Chain and pool are not
  needed in the preimage, because `cm` binds them.
- **Write-once is safe.** The pool computes `a` from the stored triple, so an entry cannot be
  inconsistent. A reverted first deposit rolls back its registration.

**Q3: split outcomes for ERC721 policy notes.** No pool rule is needed.

- P1 requires `1 ≤ x ≤ amount` (`x ≠ 0` through the `z` gadget; policy spec l.136-139, 225-236).
  For amount 1, that forces `x = 1`: out₀ receives the NFT note, and out₁ is unpublished
  (`nz_r = 0`).
- The spec's "`x ∈ {0, 1}`" (l.201) is wrong: `x = 0` is rejected.
- The split therefore degenerates to one fixed outcome ("to out₀"). No capability holder has any
  choice, and there is no withdrawal. That is harmless.
- The pool *could* reject it, because the token is public at P1 and the registry gives the
  standard, but that adds a check for no safety gain.
- Recommend that wallets refuse to create split outcomes for ERC721 notes, and that §5.4 say so.
- Real NFT-specific P1 hazards are HA-P4 (identifier range versus the unchanged P1 bridge, which
  can block the refund) and HA-P7 (ERC1155 recipient liveness for fixed outcomes).

**Q7: receiver hooks, payout, reentrancy, non-standard contracts.** The design is sound for
standard OZ contracts, with the gaps listed in HA-P5, HA-P6, HA-P7, HA-P11 and HA-P12.

- **Spoofing.** The hook requires `caller == contract`, so only the token contract (or code it
  calls) can reach it, and a lying contract affects only its own identifiers, subject to HA-P1.
- **Replay and leftover state.** The record lives in pool storage. A pool-frame panic reverts the
  whole transaction, and a caught failure of the pool call reverts the pool's writes, so the
  record cannot outlive the deposit. The hook also requires the lock.
- **Batch bypass.** OZ routes a length-1 batch to the single hook and a longer batch to the batch
  hook, which reverts (V). A length-1 batch inside the pool's own call is exactly the expected
  receipt.
- **Reentrancy.** All three flows run under `start()`. Token `before_update`/`after_update` hooks,
  recipient hooks and controllers cannot re-enter any mutating entry point. In both V4 and P1,
  effects (nullifiers, appends) come before `pay_out`. A recipient hook that sends tokens back
  hits the pool's hook and reverts, so the payout delta cannot be perturbed except by the token
  itself.
- **Lying views.** A lying `owner_of`/`balance_of` affects only that contract's identifiers
  (HA-P1 aside).
- **Missing SRC5.**
  - On the recipient side it reverts the ERC1155 payout (HA-P7).
  - On the pool side, OZ ERC721 `safe_transfer_from` to the pool reverts, because the pool
    supports neither `IERC721_RECEIVER_ID` nor `ISRC6_ID` (V). That is as the spec intends.
  - ERC721 deposits use `transfer_from`, which does no receiver check (V). OZ checks
    `from == previous_owner` (V), so nobody can deposit someone else's approved NFT.
- **Fee-on-transfer analogues and rebasing ERC1155** fail the exact delta and revert.

**Q8: migration.** It is safe only if all of the following hold (HA-P2):

1. **Same contract address.** `cm` binds the pool, so this needs an upgrade path the reference
   pool lacks, or else a fresh deployment with public withdraw and re-deposit.
2. **Shared state preserved.** The same `nullifiers`, `root_history`, tree and delivery-digest
   storage are kept. The nullifier formula is unchanged, so a note spent under V3 is spent under
   V4.
3. **V3 retired atomically** in the same class change.
4. **Backfill** of the HA-P1 contract-standard map for tokens with pre-V4 notes.

**Does anything tie a note to its creating version?** Not for spending. The commitment, the
`M301` plaintext and the delivery digest are identical, and V4 accepts any leaf.

**For privacy, yes.** The creating transaction publicly shows whether the leaf's token is known:

- V3 outputs, deposits, open notes and policy outputs have a public token;
- V4 transfer outputs do not.

So pre-V4 leaves never gain asset privacy retroactively (HA-P8 item 1). Two smaller effects:

- V3 required two nonzero real inputs (`payment.rs:293`) and nonzero outputs (:313). Pre-V4
  wallets never created zero-value leaves, so all zero-value leaves are V4's. That is not an
  observable distinction, because amounts are hidden.
- P1 and open-note intent formats are unchanged. For exits, V4's `hash_intent` over `token_out`
  equals V3's over `token`. Cross-version replay is prevented by the distinct binding tag and
  account tag.

## Checks found sound

- **Exit rule and relation (R).** Relation 8 forces `x = 1` for any withdrawal or intent, and
  `token_out = x·token`. The pool rejects `token_out ≠ 0` without an exit. Together these give
  `token_out = token` for every exit and `token_out = 0` for every pure transfer. Payout, open-note
  `hash_intent` and P1 always see the spent notes' real asset.
  - Input 0 is a real leaf, and every append path yields a nonzero identifier: ERC20 `BAD_DEPOSIT`,
    NFT Poseidon, open-note `OPEN_NOTE_TOKEN` (`open_note.cairo:247`), and inherited outputs.
    So `token ≠ 0` holds without Q2's constraint. Adding it is cheap defense in depth.
- **Pool checks in §5.2 (R).** Together with V3's inherited checks, they are complete for pure
  transfers:
  - chain, pool, binding, verdict, known root;
  - fresh nullifiers, including `nf₀ ≠ nf₁`, which `verify_spend` catches because the second
    lookup sees the first write (`pool.cairo:385-393`), and which the bridge also asserts;
  - `INTENT_NEEDS_INVOKE`;
  - both outputs active with digests;
  - the exit rule.

  V3's `EMPTY_OUTPUT` becomes vacuous, and that is sound: `amount₀ ≠ 0` and conservation mean
  value always goes somewhere.
- **Uniformity at the pool (R).** A pure V4 transfer does:
  - 2 nullifier reads and writes;
  - one `insert_two`;
  - 2 digest writes;
  - 2 `NotePublished` events and 2 `NullifierSpent` events.

  It does no registry read and no token call. Gas varies only with the tree position, which is
  public and independent of the spend. Calldata sizes are fixed. The PROOF2 facts have a fixed
  layout. `MAX_NOTES = 4` still allows 2 outputs plus 2 open-note destinations.
- **Payout ordering (R).** In V4 the order is verify, then append, then `pay_out`. In P1 it is
  nullifier, then controller, then append, then `pay_out`. So any external code in `pay_out` sees
  final pool state under the lock (read-only reentrancy only, as accepted in open-note review F7).
- **ERC721 payout (V/R).** `transfer_from(pool, recipient, id)` is authorized as owner, needs no
  approval from the pool (the pool never approves; grep) and runs no recipient hook. The
  `owner_of == recipient` post-check is correct. Merged ERC721 notes with amount > 1 cannot arise
  from a standard contract, because a second deposit of a held id fails `INVALID_SENDER` and the
  `owner_of ≠ pool` precheck. `pay_out` rejects them anyway.
- **Solvency across flows (R), apart from HA-P1.**
  - Deposits credit exact deltas or ownership.
  - V4 conserves a single asset.
  - Dummy inputs carry 0.
  - Dummy outputs carry 0 and are unspendable, so they are value-neutral.
  - Open-note executions are ERC20-only on both sides.
  - P1 conserves its token and pays through `pay_out`.
- **Upstream comparison.** Upstream hides the token of private transfers in the same spirit
  (encrypted `token`, `token = 0` on encrypted notes). It publishes it on deposit and withdrawal,
  and it is ERC20-only, so the NFT registry and hook design have no upstream precedent to align
  with.

## Re-review of revision 2

Same reviewer, same day. I read revision 2 of `docs/hidden-asset-spec.md` in full, then the
math review (`hidden-asset-design-math-review.md`, now readable). This is still reasoning only
(**R**) plus OpenZeppelin source (**V**); nothing is implemented, and I modified nothing but this
file. Additional OZ facts checked for the push design:

- ERC721 `safe_transfer_from` = `transfer_from`, then the receiver check
  (`openzeppelin_token-3.0.0/src/erc721/erc721.cairo:154-166`). `safe_mint` = `mint`, then the
  check, with `from = 0` (:620-631).
- ERC1155 credits balances before `_check_on_ERC1155_received` (:607-619, as before).
- `IERC721_ID` (`0x33eb…d943`), `IERC1155_ID` (`0x6114…1b52`) and `ISRC5_ID` (`0x3f91…a055`)
  exist and are stable in `openzeppelin_token-0.20.0` / `openzeppelin_introspection-0.20.0` /
  `openzeppelin_interfaces-2.2.0`.

### Verdict

**GO.** Every prior condition (HA-P1, HA-P2, HA-P3, HA-P5) is resolved in the spec, and so is
every Low/Info item. Four new items follow (HA-P13–P16): one Low and three Info. None blocks
implementation; they are one-line clarifications to carry into the spec or the implementation
tests.

### Status of prior findings

| ID | Status | Where | Note |
|---|---|---|---|
| HA-P1 | **Resolved** | §3.2, §3.3, §5.1-5.2 | A `contract_standard` map is written on first use through every path (ERC20 `deposit`, both hooks, open-note funding), a cross-standard deposit is rejected, NFT registration needs SRC5 screening, and solvency is restated per contract ledger with facades named as a listing decision. The ERC-404 scenario now fails at the second standard. A standard OZ ERC721 cannot be recorded as ERC20 through `deposit`: its selector-compatible `transfer_from` returns unit, so `IERC20Dispatcher` bool deserialization panics. An ERC20 never calls a receiver hook. First-use squatting remains only for hybrids (HA-P13). |
| HA-P2 | **Resolved** | §5.6 | Fresh deployment, no upgrade authority, and no V3 in the new pool, so no coexistence window and no backfill. The old pool's notes remain spendable under V3. This also removes the pre-V4-leaf privacy caveat. |
| HA-P3 | **Resolved** | §4.5 | Lists the bridge checks: `token_out` may be zero with `< 2^251` at exit, the exit rule in the bridge, both commitments and deliveries nonzero, distinct nonzero nullifiers, recipient pairing and range, identity ⇒ intent, tags `R0V4`/`R0C4`, `TMR0_BIND_V4` and `'TMPZR0_PAYMENT_V4'`. V3's `token ≠ 0`, "delivery ⇔ active" and "some output" checks are explicitly dropped. The pool repeats what it can see. |
| HA-P4 | **Resolved** | §3.1 | Identifiers are `< 2^251` by a registration rule, so they fit `ContractAddress`, the unchanged P1 bridge and the wallet's backup check. V4 fields are `asset: felt252`, and `Withdrawn` carries the identifier. |
| HA-P5 | **Resolved** | §5.1 | Push deposits need no approval; the reasoning is under "Push deposits" below. |
| HA-P6 | **Resolved** | §5.3 | `pay_out` requires `recipient ∉ {0, pool}` for every caller. |
| HA-P7 | **Resolved** | §5.3, §5.4, §6 | Recipient liveness is documented; the wallet, the policy checklist and relayers check or simulate. |
| HA-P8 | **Resolved** | §7 | Root-bounded, weighted anonymity set; public-asset leaves; dummies; the full-viewer caveat (HA-M7b); NFT holdings and dwell time; RPC polling; base block and fee metadata; corrected TVL and flows; wallet fingerprints. Approval events are moot under push deposits (ERC20 approvals are as today). |
| HA-P9 | **Resolved** | §6 | Normative `crypto_box_seal` for dummies, CSPRNG randomness independent of the seed, and a layout test. |
| HA-P10 | **Resolved** | §3.1, §3.2, §6 | `get_asset` and `asset_id` views; ERC20 `deposit` rejects registered identifiers; `class_hash_at(a) == 0` at registration (still to confirm for undeployed addresses, as the spec says); lazy and bulk sync. |
| HA-P11 | **Resolved** (accepted) | §5.1 | Unsolicited plain ERC721 transfers and hook-less ERC1155 mints are lost, with no rescue path. This is a deliberate trade against owner power, and I agree with it. |
| HA-P12 | **Resolved** | §5.1, §5.5 | ERC20 deposits check an exact balance delta; the supported ABI and interface ids are documented; no camelCase hooks. |

### Push deposits (§5.1), checked

- **Lock.** Each hook requires `!locked`, takes the lock and releases it before returning.
  - Every pool-initiated token call happens under the lock: the ERC20 `deposit`, open-note
    funding and `pay_out`.
  - So a hook re-entered from any of these reverts. That covers a payout recipient's hook pushing
    tokens back, a controller or adapter pushing NFTs, and a hybrid's ERC20 `transfer_from`
    calling a hook.
  - A revert inside the hook, or in C after it returns, reverts the whole deposit, so the lock
    cannot stay set.
  - Code that C runs after the hook returns sees an unlocked pool. It can only make ordinary new
    calls.
- **Caller trust.** The identifier is `H(std, get_caller_address(), id)`, so a contract that calls
  the hook directly can create notes only of its own identifiers. Such a contract also answers
  `balance_of`/`owner_of` itself, which is the same trust as the revision-1 delta check.
  - Since `held[a]` is incremented cumulatively, a buggy C that calls the hook twice for one
    transfer fails the second `≥` check unless the pool holds a surplus.
  - `operator`, `from` and minting (`from = 0`) do not matter for solvency. An approved operator
    that pushes a user's token with its own `inner` could equally have taken it.
- **Balance and ownership checks.** OZ credits before the hook (**V**), so the checks are
  `balance_of(pool, id) ≥ held[a] + value` and `owner_of(id) == pool ∧ held[a] == 0`. These are
  the right post-conditions.
  - `≥` rather than `=` is necessary: an exact check would let one hook-less mint brick an id
    forever. It is safe, because only C can reach the hook and a standard C reaches it only after
    crediting `value`.
  - A surplus is never claimable except through C itself.
  - A contract that calls the hook before crediting fails the check and reverts, which is the safe
    direction.
  - For ERC721, `held[a] == 0` together with OZ's `from == owner` rule means an id already held
    (noted or unsolicited) cannot be credited again.
- **Batch rejection.** OZ routes a length-1 batch to the single hook (**V**). That is a real
  transfer and is correctly accepted. Longer batches reach `on_erc1155_batch_received`, which
  reverts.
- **SRC5 answers.** The pool answers true for `ISRC5_ID`, `IERC1155_RECEIVER_ID` and
  `IERC721_RECEIVER_ID`, and false for `ISRC6_ID`. That is exactly what OZ's receiver check needs
  (**V**, `erc1155.cairo:702-721`, `erc721.cairo:839-852`).
  - Safe transfers with malformed `data` revert.
  - Plain ERC721 `transfer_from` bypasses the hook, as §5.1 documents.
- **Re-entrancy from payout hooks.** `pay_out` runs last (nullifiers, appends, then payout) under
  the lock. An ERC1155 recipient hook cannot re-enter any mutating entry point, including the
  deposit hooks. ERC721 payouts use `transfer_from` and run no recipient hook.
- **Approvals.** None are needed for NFTs. HA-P5's standing `ApprovalForAll` exposure is gone.

### New findings

#### HA-P13: Info. First use of `contract_standard` can be squatted for hybrid contracts

**Location:** §3.2.

For a contract that genuinely implements two standards, the first depositor fixes its standard for
the lifetime of the pool. Anyone can front-run a new hybrid's first deposit and lock out the
standard users wanted.

This is liveness only: the chosen standard's notes stay fully backed. As shown above, standard
single-standard OZ contracts cannot be mis-recorded. With a fresh pool and no owner, there is no
remedy short of redeployment.

**Spec change:** one sentence in §3.2 stating this, and that hybrids are a listing decision like
facades.

#### HA-P14: Low. `held[a]` needs its type, update order and exact claim pinned

**Location:** §3.3, §5.1-5.3.

1. **Type.** `held` sums many u128 amounts. An 18-decimal ERC20 with a large supply can approach
   2^128 in aggregate. Specify `u256`, or argue the bound.
2. **Update order.** `pay_out` "decrements `held[asset]`". Specify a checked subtraction, done
   *before* the external call (checks-effects-interactions). A violation then panics instead of
   wrapping, and views read during a recipient hook are consistent.
3. **Exact claim.** "`held[a]` never exceeds what the contract reports the pool owns" is enforced
   only when a deposit or payout runs. A pausing, seizing or rebasing contract can make it false
   in between. State it as "checked at every deposit and payout of `a`".
4. **Test.** Invariant I and `held` are what the pool relies on for solvency. Add an
   implementation test that runs each append and payout path (ERC20 deposit, both hooks,
   open-note funding and budget, V4 withdrawal, P1 withdrawal) and asserts
   `held[a] = Σ unspent note amounts of a`.

#### HA-P15: Info. State the push hooks' assumptions about the token contract

**Location:** §5.1.

The hooks rely on four things:

- **Credit before the hook.** This holds for OZ and for EIP-1155/721 semantics. Otherwise the
  deposit fails safely.
- **Re-entering C's views mid-transfer.** The hook calls `balance_of`/`owner_of`, and on first
  registration `supports_interface`. A contract whose views are behind a reentrancy guard fails
  safely.
- **Mints to the pool.** `mint_with_acceptance_check` and `safe_mint` with well-formed `data`
  create backed notes. That is fine, but worth saying.
- **The IDs.** The screening IDs are `IERC721_ID`/`IERC1155_ID`, which OZ components register in
  their initializers. Contracts built without SRC5 registration of these IDs cannot be deposited.

**Spec change:** add these to §5.5.

#### HA-P16: Info. List the new pool's entry points

**Location:** §5 opening ("only V4 spend entry points"), §5.3, §5.4.

§5.3 and §5.4 route P1 settlements through `pay_out`, so pool V2 also has `apply_policy_spend`.
That needs its own P1 adapter instance, bound to the new pool address. Pool V2 also has the
owner setters.

**Spec change:** enumerate V2's full external surface:

- `deposit`;
- the two hooks and the batch hook;
- `supports_interface`;
- `apply_spend`, `apply_spend_with_invoke` and `apply_policy_spend`;
- the views;
- the owner setters, with no upgrade.

Then an implementer cannot drop P1 or add an unlisted entry point that bypasses `held` and
invariant I.

### Relation (§4), contract-level consequences only

§4.3.1 constrains `token ≠ 0`. §4.3.3 removes V3's unconditional root equality. §4.5 moves the
exit rule into the bridge and keeps `token_out < 2^251`. Together with invariant I, these close
every contract-level dependency I raised on the relation. Canonicity of `token` rests on input 0's
membership plus the bridge's `felt_from_limbs` at exit, which is consistent with how the pool
computes leaf limbs (`hash.cairo:303-311`).
