# Policy notes: protocol and contract design review (pre-implementation)

Independent reviewer; did not write the design. Date 2026-09-24, branch `pathfinding/client-zk`
at `cb4f296` with the uncommitted `docs/policy-note-spec.md` and `docs/adr/0025-policy-notes.md`.
Nothing is implemented, so every finding here comes from reasoning (**R**), not from tests. I did
not modify any code or docs.

## Verdict

**NO GO as written. CONDITIONAL GO once P-1, P-2 and P-3 are resolved in the spec.**

The note format, the cross-spend separation, the nullifier rules, the proof binding and the
deadline refund are sound. The spec does not hold together at three points:

1. The controller callback does not identify which note or which destination it is approving. With
   unauthorized creation, anyone can use up a controller's approval with a note they made
   themselves. The reference escrow can be robbed for about the cost of gas (P-1).
2. The "refund from the seed alone" property does not fit the fixed 304-byte delivery format. It
   also needs the refund ciphertext's exact bytes, and those cannot be derived from the seed (P-2).
3. Split outputs cannot be delivered. Their ciphertext is fixed at creation but their amount is
   chosen at settlement, so the receiver cannot recompute the commitment (P-3).

Once those are fixed, the Medium findings should go into the spec before implementation starts,
because they fix interfaces that are expensive to change later: the selector, the P1 binding tag
and the rules for handling callback failures.

## Findings

| ID | Sev | Location | Finding | Concrete scenario | Recommended fix | Blocking |
|---|---|---|---|---|---|---|
| P-1 | **Critical** | spec §6 step 4 (authorization, l.197-203), §4.1 "several notes may share a handle" (l.96), §7 "Creation is unauthorized" (l.232-235), §10 escrow (l.264-267) | The authorization identifies the case only by `(handle, outcome index, type, x, withdrawal, key(nf), …)`. It does not contain the output commitments, the deliveries, the outcome digest, the policy digest or anything the controller could have registered in advance. Outcome indices mean whatever the note's creator chose. Creation is unauthorized, so the pool will call a controller for any note that names it, with any handle, any token and any menu. A controller can check that the fields are authentic (they are proven), but it cannot check that they belong to the note the application cares about. PR #2 avoided this by giving the controller the full private transition, including output recipients and amounts (`objects.cairo:174-220`), during validation. | Attacker M deploys a worthless ERC20 and calls `deposit(junk, 1, H(INNER, recv_p ‖ rho), ct)` (`pool.cairo:119-132` accepts any nonzero token). The policy is (EscrowController, its class, victim handle `h`, deadline, o₀ = refund to M, o₁ = pay M 1 unit). When the arbiter calls `release(h)`, M settles o₁ first. The escrow sees `h` in RELEASED with outcome 1, and moves `h` to SETTLED. The executor's settlement of the real note N1 then reverts, and after the deadline N1 refunds to the depositor. The seller has shipped and gets nothing. The depositor can do the same thing with a second note of their own. The mirror case (settling o₀ on CANCELLED) freezes the depositor's refund until the deadline. Any controller that keeps per-handle state (claim budgets, "settled" flags, counting auction bids) is affected the same way. | (a) Add the two output commitments (or their `key`s) and delivery digests to the authorization. Also consider a new public field for the selected outcome digest or the policy digest (9 limbs, which pads the statement to 164 limbs / 41 QM31). None of these reveals anything that settlement does not already publish or that an opening holder does not already know. (b) Make the escrow bind each case to one note. `open(handle, arbiter, expected)` should register the release outcome digest, the policy digest, or the release commitment key. Apply should check that value, `token`, `outcome type == 1` and a zero withdrawal. (c) State a rule in §7: *a controller must treat every callback as coming from a possibly adversarial note, and may advance shared per-handle state only for a registered note.* (d) Add a rejection test: "a note made by a third party with the same controller, class and handle but a different token or outcome cannot consume the case". The test list in §10 covers only direct invocation. | **Yes** |
| P-2 | High | spec §9 (l.253-256); `push-payment-spec.md` l.50-61; `spend.cairo:58-73` (`delivery_digest` asserts 10 words) | "Enough to refund from the seed alone" is not achievable with the current delivery contract. (i) Size: the plaintext is a fixed 256 bytes of fixed fields. The spec wants it to carry the amount, the header (controller, class, handle and deadline, about 110 B), the full refund preimage (two outputs of receiver, rho, amount and delivery, plus a withdrawal, about 250 B), the refund output's 304-byte ciphertext, and three outcome digests (about 110 B). That totals roughly 800 B. (ii) Determinism: o₀ commits to the refund ciphertext's digest, and step 2 of §6 needs the exact ciphertext bytes. Sealed boxes use a random ephemeral key, so those bytes cannot be regenerated from the seed. (iii) The other outcome digests depend on the beneficiaries' receivers, their rho values and their random sealed boxes, so they cannot come from the seed either. (iv) Deposits and R0 V3 outputs accept only the 10-word ciphertext, and the design says R0 is unchanged. | A depositor loses their device after funding the escrow and restores from the seed. The wallet finds the leaf and derives `cap` and `rho` from the counter. It cannot rebuild `policy`, so it cannot prove membership of `recv_p`, and it has no bytes for o₀'s ciphertext. The refund after the deadline is impossible unless the executor still has the opening and cooperates. | Specify a policy backup payload. It is an encrypted blob of variable length, published in a new unbound event field on `deposit` and on policy-note outputs. It checks itself: the wallet recomputes `cm` from `cap` plus the decrypted policy and compares it with the leaf, so the proof need not bind it. It must include the refund ciphertext bytes and all four outcome digests. Alternatively, derive the refund output's sealed-box ephemeral key from the seed, restrict o₀ to one private output to the creator, and store the remaining digests in the blob. Either way, give the size and format in §9, and add a restore-from-seed refund to the acceptance scenario. | **Yes** (it is a stated property) |
| P-3 | High | spec §4.2 split (l.113-116), §5 constraint 6, §8 (l.241-243); `push-payment-spec.md` l.50-52, 69-70 | The ciphertext of a split output is fixed at creation, but its amount (`x`, or `amount − x`) is chosen at settlement. The delivery plaintext carries the amount, and the receiver "recomputes the commitment … before crediting". With a creation-time ciphertext that recomputation fails, so the output is never credited. §8 is also wrong: a split reveals `x` but not the note amount, because the change commitment hides `amount − x`. The note amount is revealed only when `x = amount`. | An auction winner's note settles with `x = 70` to the seller. The seller decrypts a ciphertext written before the auction, which holds some placeholder amount. `H(NOTE, …, amount, …) ≠ cm₀`, so the wallet discards the note and the funds are effectively lost until someone tells the seller `x` out of band. | Define delivery semantics for split outputs. Either the plaintext marks the amount as "settlement x / remainder" and the pool emits `x` with the indices of the new notes (`PolicySettled { …, x, first_index }`) so wallets can recompute, or split is removed from tier 1. Correct §8. | **Yes** for split; escrow with fixed outcomes can proceed without it |
| P-4 | High | ADR-0025 Consequences (l.58-60), spec §7 last bullet (l.232-235) | Split is not enough for auction collateral. At bid time the auction cannot check that the note exists, its amount, its deadline, its controller and class, or that out₀ pays the seller. P-1 (a) fixes only the destination, at settlement. A bidder registers "collateral" that does not exist, has a deadline before the auction ends, or has less value than the bid. At settlement the bidder simply does not settle. The same holds for any application that needs collateral assurance. | A bidder registers bid 1000 with a claimed note whose deadline is the block before the auction closes, or with no note at all. The bidder wins, never settles, and the auction has no remedy. | Remove "auction collateral" from the ADR's claims for tier 1, or design a registration statement. That would be a P1-style membership proof that publishes `key(nf)` or the policy digest and proves `amount ≥ A`, `deadline ≥ D` and the controller and class, without spending. The controller then registers that nullifier and binds settlement to it (P-1). | No for the escrow milestone; yes for the auction claim |
| P-5 | Medium | spec §6 step 4 (l.195-204), ADR decision 3; `interface.cairo:10-34`; `mock_note_controller.cairo:88-99`; precedent `open-note-spec.md` "COMPUTE targets" and `pool.cairo:150-158` | The design reuses PR #2's selector `privacy_apply_controlled_transition` with different trust semantics. In PR #2 the `public_authorization` is the controller's own receipt, returned by its own private validation, and apply trusts its layout, as the mock does with `[AUTHORIZATION, epoch]`. Here the pool builds the span from fields the creator chose. An upstream-style controller deployed against this pool would read `'TEMPLAR_POLICY_V1', chain, …` as its own receipt fields. This is the same class of bug as the COMPUTE-target finding the pool already fixed with `set_shadow_class`. | An upstream controller whose receipt is `[bid_id, amount, epoch, …]` and whose validation step never runs here. Any note creator can call it through the pool, and it parses attacker-shaped fields as its validated receipt. | Use a new selector and interface, for example `templar_policy_apply(authorization, data)`, so that only controllers written for this contract can be called. Alternatively, add an owner allowlist of controller classes. Do not describe it as "PR #2's apply interface". | No, but decide it before implementation |
| P-6 | Medium | spec §4.1 `controller_class` (l.94), §7 "Controller upgrade" (l.225-228) | Pinning the class hash pins the code at one address. It does not pin behaviour when (a) the controller is a proxy whose implementation lives in storage and is reached by `library_call`, (b) the pinned class has admin setters (arbiter or state overrides) or a `replace_class` path, or (c) the class goes A→B→A: upgrade to B, rewrite storage, return to A, after which the check passes on manipulated state. The property "an upgraded controller blocks every gated outcome" holds only for (b) with a changed class, and only while the class stays changed. A zero class with an undeployed address fails only indirectly, when the call fails. | An upgradable escrow's owner upgrades to B, sets `state[h] = RELEASED`, and upgrades back to A. The executor's o₁ settles against a release the arbiter never gave. For a proxy controller, the pin gives no assurance at all. | In §7, say that pinning fixes code, not state or admin, and that assurance requires a class with no upgrade, no proxy and no admin path over case state. Make the reference controllers non-upgradable with no owner. Have the pool reject `controller == 0`, `controller == pool` and `controller_class == 0` in the controller window, as `pool.cairo:148` already does for adapters. | No |
| P-7 | Medium | spec §6 steps 3-5 (l.194-205), §7 "Settle/refund race" (l.222-224) | A controller approval counts only if the settlement is *included* by `deadline`. At `deadline + 1` the refund needs nothing, whatever the controller's state. Proving is slow (client proof plus a PROOF2 wrap on the server), and the sequencer, the relayer or a congested block can delay inclusion. The depositor holds `cap` and can refund at `deadline + 1`. The race is decided by timing, not by the controller, and §7 does not say so. | The arbiter releases at `deadline − 20`. The executor's PROOF2 wrap takes longer than 20 blocks, or the relayer delays submission. The depositor refunds at `deadline + 1` and keeps both the goods and the money. | Document in §7: "approved but unsettled outcomes are lost at the deadline". The escrow should refuse `release` (or `open` should require) a registered note deadline of at least `now + margin`. With P-1 (b) the escrow can register the deadline together with the policy. Executors should settle through their own account, not a third-party relayer. | No |
| P-8 | Medium | spec §10 (l.264-266) | The escrow is underspecified in ways that matter. (a) Anyone can call `open(handle, arbiter)` once per handle. If the note exists before `open`, a front-runner who sees `open(h, A)` pending registers `open(h, M)`. M then controls release on a note already committed to `h`, and can release to the seller before delivery. (b) The allowed transitions of `release` and `cancel` are not given. If the arbiter can flip RELEASED and CANCELLED, the state the executor proved against can change underneath it. | (a) As described. The depositor's funds go to the seller without the goods being delivered, or the case is squatted until the deadline. | Derive the handle from the opener (`handle = Poseidon(caller, salt)`, computed by the contract), or require `open` before note creation and record the opener. `release` and `cancel` run only from OPEN and are final. Apply also checks `caller == pool`, token, type, withdrawal and the P-1 registration. | No (reference-controller spec) |
| P-9 | Medium | spec §5 table, §6 step 1 (l.189-191); `adapter.cairo:65-69`; `spend.cairo:106`; R0 account `cairo-r0/account/src/lib.cairo:35-39` | Separating the P1 verifier is stated but not specified. The spec does not give the P1 binding formula or its domain tag, the P1 account's message layout, how the pool stores the second adapter (a new storage slot and owner setter), or the P1 bridge's liveness checks. The separation now rests only on the adapter's `(statement, statement_class, tag)` triple. A binding domain tag distinct from `TMR0_BIND_V3` is the defence in depth against a misconfigured adapter. | An implementer reuses `self.verifier` or `set_verifier` for P1, or deploys the P1 adapter with the R0 account's address and class. If the binding tags are also shared, an R0 message could satisfy a P1 check. Today that fails only because of a hash mismatch nobody has specified. | Specify `binding = Poseidon('TMP1_BIND_V1', chain, pool, token, root₉, nf₉, cm₀₉, d₀, cm₁₉, d₁, w_recipient, w_amount, controller, controller_class, handle, deadline, not_before, index, type, x, data[, policy/outcome digest])`. Specify a P1 account that pins the P1 circuit hash for the pool's single tree format and checks the `P1V1`/`P1C1` tag, a `policy_verifier` slot with its own setter, and bridge checks: `index ≤ 3`, `type ∈ {1,2}`, `x = 0` iff fixed, an active output iff its delivery is nonzero, a withdrawal recipient iff an amount, at least one output or withdrawal, and address ranges. | No, but it must be in the spec |
| P-10 | Medium | spec §6 (l.186-211) | Rules for handling callback failures are not written down. Starknet can report an inner call's failure as `Err` with the callee's state reverted. An implementation that matches on the result, or ignores it, settles *without* the controller's state change. The spec also does not say that `start()` must run before verification, what return value is expected, or how long `data` may be. | `let _ = call_contract_syscall(controller, …);` passes review as "call the controller". A controller that reverts, whether by design or because it is out of gas, then fails to block settlement. | State the rules: the pool takes the lock first (`pool.cairo:349-352`), `unwrap_syscall()`s the callback, requires empty return data (or a fixed magic value), and caps `data.len()` (as `MAX_CALLDATA`). Nullifier, then controller, then outputs and withdrawal, all under one lock. Add a test where the controller reverts and a test where it reenters (calls `deposit` or `apply_policy_spend` and gets `REENTRANCY`). | No, but it must be in the spec |
| P-11 | Low | spec §5 constraints (l.165-180), §4.1 (l.93) | §5 does not constrain `version = 1` and `kind = 1` (only §4.1 states them), and does not state `type ∈ {1,2}` or that `active` is boolean. If a later tier (kind 2) reuses `PRECV` receivers, P1 could spend a kind-2 note under menu semantics. | A future tier-2 note is spent with P1 by treating its outcome slots as a menu. | Add them to the constraint list. | No |
| P-12 | Low | spec §4.3 (l.125-129), §7 "cannot freeze value past the deadline" | That guarantee assumes o₀ can be executed. The relation cannot force it, because creation is private. An o₀ that is a zero slot, that withdraws to the pool (rejected at §6 step 6), or that withdraws to a recipient a token can blacklist, freezes the note permanently. | A wallet bug sets o₀'s withdrawal recipient to the pool address. No outcome is ever possible after the deadline. | Require in the relation that o₀ has no withdrawal (only private outputs), and have wallets and executors check that o₀ is live before funding or accepting a note. State the precondition in §7. | No |
| P-13 | Low | spec §6 step 5, §7 | Refunds in the refund window do not notify the controller, so its per-handle state stays stale (OPEN or RELEASED) indefinitely. That is correct for liveness, but applications counting value per handle will be wrong. | An escrow UI shows a case as RELEASED and unpaid after the note was refunded. | Document that the deadline is terminal for applications. `PolicySettled` (which has the handle and outcome) is the signal applications should index. | No |
| P-14 | Info | spec §1, §5, §11 | The design has no settlement-time relayer fee. Outcomes are fixed at creation, so any fee must be a fixed withdrawal committed at creation, or else the executor pays gas publicly, which links its account to the handle. There is also no freshness bound on a settlement proof except the PROOF2 `max_proof_age`. | A relayer holds a proof and submits it later when a non-monotonic controller state allows it. | Document the fee model. Controllers with non-monotonic state should require an expiry in `data`. | No |

## What I checked and found sound

- **Cross-spending and the note format (§3).** `recv_p = H(PRECV, pnk ‖ policy)` and
  `H(OWNER, …)` are domain-separated hash kinds under the same framed sponge (`hash.cairo:67-72`).
  Neither relation can open the other's leaves without a collision. Commitment, inner and
  nullifier constructions are unchanged, so creation through `deposit` or an R0 V3 output needs no
  new code and is indistinguishable on chain.
- **One nullifier per note.** `nf` depends only on `pnk`, `cm` and the position, so every holder of
  the capability derives the same nullifier, and the pool's nullifier set (`pool.cairo:256-264`)
  makes outcomes mutually exclusive. Replay and double claims are covered.
- **Binding and relayer tampering.** Commitments, deliveries, withdrawal, `x`, `data`, header and
  outcome index are all public fields covered by the binding, and the pool recomputes the binding
  from calldata as `compute_binding` does. The relayer cannot change any of them. Chain, pool and
  token appear in both the leaf commitment and the statement, and outputs inherit the input's
  context. Reuse across chains and across pools fails at `WRONG_CHAIN` / `WRONG_POOL` and at the
  adapter (`adapter.cairo:52-53`).
- **Freshness of authorization.** No receipt is stored. The controller decides at apply time from
  its own state, which removes PR #2's stale-receipt problem (`README.md` l.71-74).
- **Delivery binding against executor and relayer.** Each output's delivery digest is committed
  in the outcome at creation and checked against the supplied ciphertext. The executor and relayer
  can neither redirect nor corrupt delivery, although the creator can. For fixed outcomes that is
  sound. Split outputs are covered by P-3.
- **Direct controller invocation.** `caller == pool` in the controller, plus the pool's lock, stops
  direct calls and reentry into `deposit`, `apply_spend` and `apply_spend_with_invoke`. The pool
  never `approve`s tokens (grep), so a controller cannot pull pool funds. The views a controller
  can read mid-settlement show only the nullifier already spent, the same read-only reentrancy
  accepted in the open-note review (F7).
- **Separating R0 and P1 in principle.** The R0 account emits
  `[class_hash, 'TMPZR0_PAYMENT_V3', chain, pool, binding]` (`account/src/lib.cairo:35-39`) after
  checking a pinned circuit hash and tag (`bridge/src/lib.cairo:86, 99-100`). The adapter hashes
  its configured statement address, class and tag into the expected message
  (`adapter.cairo:65-69`). A P1 account with its own pinned circuit and tag, behind a distinct
  adapter instance, rejects R0 proofs and the reverse holds too. Only one message is allowed per
  transaction (`MESSAGE_COUNT`). P-9 asks that this be written into the spec.
- **Window arithmetic.** `b ≥ not_before` in both windows, the controller at `b ≤ deadline`, and
  only o₀ (fixed, per constraint 7) at `b > deadline`, together form a partition with no gap and
  no overlap. The refund window skips the class check and the controller call, so a reverting,
  upgraded or self-destructed controller freezes value only until the deadline. That holds if o₀
  can be executed (P-12).
- **Moving to bearer notes (ADR-0009 §3).** Once P-1 is fixed, a depositor who keeps `cap` can
  only cause outcomes that were committed at creation and that the controller currently allows.
  The race ADR-0009 avoided becomes harmless. Without P-1, the controller does not actually decide
  between holders.
- **Vesting.** Per-tranche notes, with `not_before` enforced by the pool and a controller that only
  holds a `revoked` flag, keep no per-handle budget. Notes made by third parties with the same
  grant handle can then only move their creators' own funds, so this pattern is safe even before
  P-1. Chaining into a fixed next note works. A beneficiary must claim before each note's deadline,
  or the tranche refunds to the employer (P-7). If a vesting controller tracks claimed totals per
  grant, P-1 applies to it.
- **Conservation and split bounds (§5).** These are stated correctly as integer checks. The Math
  Reviewer should confirm that the limb gadgets check `1 ≤ x ≤ amount` and the three-term u128 sum
  with carries rather than field comparisons. The R0 gadgets can be reused.

## Method

I read `docs/policy-note-spec.md` and `docs/adr/0025-policy-notes.md` in full. I compared them
against PR #2 `edf2f1e` (`interface.cairo`, `objects.cairo`, `mock_note_controller.cairo`,
`README.md` "Controlled notes") and against the current pool (`pool.cairo`, `spend.cairo`,
`adapter.cairo`, `open_note.cairo`, `hash.cairo`, `tree.cairo`), the R0 statement account and
bridge (`bench/m31-private-wrapper/client-port/cairo-r0/`), `open-note-spec.md`, the delivery
contract in `push-payment-spec.md`, and ADR-0022 and ADR-0009. I built no tests. Every scenario
above is reasoned (**R**) and should become a rejection test during implementation.

## Re-review of revision 2

Same reviewer, same day. I read revision 2 of `docs/policy-note-spec.md` and of
`docs/adr/0025-policy-notes.md`, and then the math review (`policy-note-design-math-review.md`),
which I was now allowed to read. This is still reasoning only (**R**); nothing is implemented.

### Verdict

**NO GO as written. CONDITIONAL GO once N-1 and N-2 are fixed.** Both need only a few lines in
the spec.

Revision 2 fixes most of revision 1. It adds a public `policy_id`, the Templar selector with a
required return value, an escrow keyed by the arbiter, the seed backup in a standard ciphertext,
split delivery through `PS01`, and the P1 plumbing. Two gaps remain:

- **N-1.** `policy_id` does not commit to the token. Anyone who holds an opening, such as the
  buyer in an escrow, can settle a copy of the note in a worthless token and use up the approval.
  This brings back the decoy attack.
- **N-2.** The escrow check `approved[(policy_id, handle)] == outcome`, read with storage defaults,
  lets the depositor refund early without the arbiter.

### Status of revision-1 findings

| ID | Status | Reason |
|---|---|---|
| P-1 | **Partially resolved** | `policy_id` goes into the statement, the binding and the authorization (§4.1, §5, §6 step 4), together with `key(commitment₀/₁)`. §7.1 says controllers must authorize on `policy_id` and never on `handle` alone. That stops decoys that use a *different* policy, which covers any third party who does not know `policy`. It does not stop a *same-policy* copy in another token: see N-1. |
| P-2 | **Resolved** (see N-3) | The `PB01` layout fits exactly: 4+32+16+32+32+32+8+36+8+4+52 = 256. The `orest` restructuring means a refund needs one digest. `cap`, `rho`, `rho_refund`, the refund receiver and the ephemeral key all come from the seed, so o₀, and with it `policy` and `cm`, can be rebuilt and checked against the leaf. A deterministic `esk` gives a stock libsodium-format box that can be reproduced byte for byte. Constraint 3 (`orest = w_rest` when `b₀ = 1`) matches this. |
| P-3 | **Resolved** (see N-4) | The `PS01` plaintext carries the note amount and a side flag. `PolicySettled` carries `x` and `first_index`, so each receiver can recompute its commitment. §8 now correctly says a split reveals only `x`. |
| P-4 | **Resolved** | §1 and ADR Consequences say auctions are unsupported and defer creation attestations (§11). |
| P-5 | **Resolved** | The pool calls `templar_apply_policy`, unwraps the result and requires the return `['TEMPLAR_POLICY_OK']` (§6 step 4). The ADR explains why PR #2's selector is avoided. |
| P-6 | **Resolved** | §7.2 says pinning fixes code, not state, proxies or upgrade round trips. Reference controllers are immutable, with no proxy and no admin. The pool rejects `controller ∈ {0, pool}` and a zero class, and an undeployed address fails. |
| P-7 | **Resolved** (documented risk) | §7.2 "Deadline boundary" states the loss, requires wallets to refuse settlements too close to the deadline, and says the beneficiary should hold the capability. The protocol cannot enforce a margin, and the escrow does not know the deadline when it approves. That is acceptable. |
| P-8 | **Resolved**, but see N-2 | With `handle` as the arbiter address and cases keyed by `(policy_id, arbiter)`, there is no `open` step and no squatting. Only the arbiter can write its own key. `approve` is write-once, so release and cancel cannot race. |
| P-9 | **Mostly resolved** | The spec now fixes a separate `policy_verifier` slot, the `TMP1_BIND_V1` binding over every §5 field, the `TMPZP1_POLICY_V1` account tag, the P1 statement class, and distinct circuit and statement tags. Still missing: the bridge's liveness checks (see N-5). |
| P-10 | **Resolved** | The lock, `unwrap_syscall`, the exact magic return, the nullifier before the call, and outputs and withdrawal after it are all specified, and a revert or a wrong return rolls everything back (the §10 tests cover this). Minor: `data.len()` still has no stated bound. |
| P-11 | **Resolved** | `version` and `kind` are circuit constants, `type ∈ {1,2}` is boolean-decomposed, `active` is boolean, and one-hot selection is in §5 constraints 1-8. |
| P-12 | **Partially resolved** | P1 now forces o₀ to be fixed with `not_before = 0`, and wallets build a standard refund with no withdrawal. The relation still allows a nonstandard o₀ that withdraws to the pool or to a blockable recipient, which freezes the note permanently. The §9.3 checklist does not tell a counterparty to check that o₀ can be executed. Low: add it to the checklist, or have P1 require that o₀ has no withdrawal. |
| P-13 | **Resolved** | §7.1 says the deadline is terminal. `PolicySettled` carries `policy_id`. |
| P-14 | **Resolved** | Relayer fees are declared out of scope (§6). |

### New findings

| ID | Sev | Location | Finding | Concrete scenario | Recommended fix | Blocking |
|---|---|---|---|---|---|---|
| N-1 | **Critical** | spec §4.1 (`policy`, `policy_id`, l.96-100), §7.1 (l.266-273), §10 (l.391-398) | `policy` commits to controller, class, handle, deadline and the outcomes, but not to chain, pool or **token**. The token is only in `cm`, so the same `policy` (and therefore the same `policy_id`) can back notes in any token. Creating a note needs only the 9-word `policy` digest and a `cap` of one's own. Settling it needs the selected outcome's preimage. Every holder of the opening has both: the depositor, the executor and the beneficiary. Fixed-outcome conservation fixes the note's amount *in units of its own token*. §7.1 asks controllers to "check `authorization[0..4]` (… token)", but the escrow registers no token to check against, since `approve(policy_id, outcome)` takes none. | Buyer B (the depositor) funds note N: 100 USDC, o₁ pays seller S. Arbiter A calls `approve(pid, 1)` once S has delivered. B deploys a junk ERC20 and calls `deposit(junk, 100, H(INNER, H(PRECV, pnk′ ‖ policy) ‖ rho′), ct)`, then settles that copy at index 1 with o₁'s known preimage. The escrow sees `(pid, A)` approved for 1 and not consumed, marks it consumed, and S receives 100 junk tokens. N's own settlement now reverts, and after the deadline B refunds N from the seed. B keeps both the goods and the USDC. A vesting employer can do the same to each tranche's `policy_id`. | Bind the context into the identifier the controller approves: `policy_id = H(POLICY_ID, chain₉ ‖ pool₉ ‖ token₉ ‖ policy)`. P1 already has all three as public inputs, so the change is small. Alternatively, add the token to the policy header. As defence in depth, the escrow's `approve` can also take the token and `apply` compare it. Add a rejection test: "same policy in another token cannot consume the approval". A copy in the *same* token is harmless: conservation forces the same amount, so it pays S the committed outcome with the copier's own money. | **Yes** |
| N-2 | **High** | spec §10 (l.391-396) | `apply` checks `approved[(policy_id, handle)] == outcome`, and outcome `0` means cancel. Starknet storage reads 0 for unset keys, so an implementation that follows the text allows outcome 0 (the refund) for *every* `policy_id` the arbiter never approved. Writing `approve` as write-once needs a "set" marker anyway, but the apply check as worded skips it. | B funds N and hands it over. Before the arbiter decides, B settles o₀ within the controller window. The unset `approved[(pid, A)]` reads 0, which equals outcome 0, so the settlement is accepted. The escrow never actually held the funds. | Store `outcome + 1` (0 meaning unset), or keep an explicit `approved_set` flag, and require it in `apply`. Add a rejection test: "unapproved policy_id, outcome 0, before the deadline". | **Yes** (one-line spec fix) |
| N-3 | Medium | spec §9.1 (l.331-345) | The seed derivation is ambiguous in a way that reuses keys. `n` is counted "per chain and pool", but the HKDF info (`'TEMPLAR_POLICY_*' ‖ n`) and `s_pol` include neither chain nor pool. So note `n` on two pools gets the same `cap`, `rho`, `rho_refund` and `esk_refund`. `epk = X25519(esk_refund)` is the first 32 bytes of the refund ciphertext, so two refunds publish the same `epk` and are linked to one wallet. If the incoming key does not change per pool, they also share the same box key and nonce (`BLAKE2b(epk ‖ pk)`), which reuses the XSalsa20 keystream. The same happens within one pool if `n` is ever reused: a retried or abandoned creation, or two devices on one seed. | A wallet creates policy note 0 on the Sepolia pool and policy note 0 on another pool, and both refund. Observers see the same `epk` in both refund ciphertexts. | Put chain and pool into the HKDF info (or make `n` global per seed). Make `n` strictly monotonic and never reused, including for failed or abandoned creations. Say how multiple devices reserve counters, for example by scanning `PB01` backups before allocating. | No (before wallet work) |
| N-4 | Low (privacy) | spec §9.3 (l.377-380) | Both `PS01` plaintexts carry the **note amount**. The `out₀` receiver needs only `x`, which is in `PolicySettled`. Giving it the note amount reveals the counterparty's total to it, for example the buyer's full balance in an arbitration split. Only `out₁` (the remainder) needs the note amount. | In an arbitration split, the seller's ciphertext reveals the buyer's full note amount, not just the settled `x`. | For the `x` side, set the amount field to 0 and flag it as "amount = x from the event". Keep the note amount only in the remainder side's plaintext. | No |
| N-5 | Low | spec §5, §6 step 1 | The bridge's liveness checks and the pool's cross-checks are still unlisted. The bridge should check `index < 4`, `type ∈ {1,2}`, `(type = 1) ⇔ (x = 0)`, `delivery ≠ 0` iff `commitment ≠ 0`, a withdrawal recipient iff an amount, a nonzero nullifier, the address range for controller and recipient, and a zero padding limb. The pool should assert `index = 0 ⇒ type = 1`. These duplicate circuit rules, but they are cheap defence in depth, and the R0 bridge sets that precedent. | A circuit bug in the one-hot selection or the type decomposition goes unnoticed because nothing outside the circuit repeats the check. | List the checks in §5/§6 (math review PN-3 and PN-9(2) already specify them). | No |
| N-6 | Low (privacy) | spec §4.1 (l.113-114) | The claim that `policy_id` "reveals nothing … whose `rho` values are secret" holds only when some outcome has a random `rho`. A menu of withdrawal-only outcomes with a nonstandard o₀ has low entropy, so `policy` and all its outcomes can be brute-forced from the public header. Revision 2 did not add the salt the math review suggested (PN-8(c)). Once N-1 is fixed, this is privacy only. | A withdrawal-only escrow with predictable recipients and amounts: an observer who sees `policy_id` confirms the entire menu. | Add a 9-word random `salt` to the policy header (seed-derived for recovery, stored in `PB01` padding), or require every policy to contain at least one active private output. | No |
| N-7 | Info | ADR-0025 decision 6 (l.41-43) | "Revision 2 addresses every finding" is premature. | — | Update the wording after this re-review. | No |

### Checked in revision 2 and found sound

- **Decoys with a different policy.** Any note whose policy differs has a different `policy_id`.
  Its creator cannot make `(policy_id, arbiter)` approved without the arbiter's key, and the handle
  is inside `policy`, so it cannot be moved to another arbiter.
- **Selector, return value and unwrap.** An upstream PR #2 controller has no
  `templar_apply_policy`, so it cannot be reached. A controller that returns anything other than
  the magic value, or fails in a way that can be caught, reverts the settlement.
- **Seed-only refund path.** From `PB01` plus the seed, the wallet rebuilds o₀ with its
  deterministic delivery, recomputes `policy` (with `orest` as a witness), recomputes `cm`, checks
  it against the leaf, and then proves index 0 after the deadline without the controller. The
  refund ciphertext's plaintext is fully determined (chain, pool, token, own receiver,
  `rho_refund`, zero controller and policy, amount), so the box can be reproduced exactly.
- **Split delivery.** Each receiver can recompute its commitment from `x`, `first_index` and its
  `PS01` side flag. When `x = amount`, only one note is appended, which matches `first_index`.
- **P1 and R0 separation.** They use separate adapter slots, statement classes, account tags,
  binding tags and pinned circuits, and each transaction carries one fact message.
- **Escrow keyed by arbiter.** Writes are scoped by the caller, `approve` is write-once, and
  consumption is recorded. Once N-1 and N-2 are fixed, the only remaining escrow risks are the
  documented deadline boundary and the arbiter's own honesty.

## Final pass (revision 3)

Same reviewer. I read revision 3 of `docs/policy-note-spec.md` in full, and the status and
process lines of ADR-0025. This is still reasoning only (**R**).

### Verdict

**GO for implementation**, from the protocol and contract side. Both blocking items (N-1, N-2)
and every earlier partial that mattered (P-1, P-12) are resolved. What remains is Low or Info,
and can be handled during implementation.

This does not replace the Math Reviewer's sign-off on the P1 relation. The review of the
implemented code that the nested STWO `AGENTS.md` files require after implementation also still
applies.

### Status of open items

| ID | Status | Reason |
|---|---|---|
| N-1 | **Resolved** | `policy_id = H(POLICY_ID, chain₉ ‖ pool₉ ‖ token₉ ‖ amount₈ ‖ policy)` is computed in the relation from the public context and the private amount (§4.1, §5 step 5). A copy in a junk token, another pool or another amount gets a different `policy_id`, and so does a split copy with a different amount. The only copy with the same `policy_id` is one in the same token and amount. It pays the committed outcome with the copier's own funds, so it cannot be used to steal. The §10 tests cover both kinds of copy. |
| N-2 | **Resolved** | Approvals are stored as `outcome + 1`, and `apply` requires `== outcome + 1`. A never-approved outcome 0 is a listed rejection test. |
| N-3 | **Resolved** | Each note draws a random 16-byte `ν`. Every derivation uses `ctx = chain ‖ pool ‖ ν`, and `ν` is stored in `PB01`. The byte budget still totals 256 (4+32+16+32+32+32+8+36+16+4+44). Retries, several devices and several pools can no longer reuse `cap`, `rho`, `salt` or `esk_refund`. |
| N-4 | **Resolved** | The `x` side's `PS01` amount field is zero. Only the remainder side carries the note amount. |
| N-5 | **Mostly resolved** | The bridge checks and the binding encoding are now specified (§6 step 1), and the pool asserts that index 0 has type 1 (§6 step 5). Still missing: bridge-level repeats of `index < 4`, `type ∈ {1,2}`, `(type = 1) ⇔ (x = 0)`, `delivery ≠ 0` iff `commitment ≠ 0`, a withdrawal recipient iff an amount, a nonzero nullifier, and the address range for controller and recipient. The circuit already enforces all of them. The R0 bridge repeats its equivalents, so P1 should too. Low; add them during implementation. |
| N-6 | **Resolved** | A seed-derived 9-word `salt` is in the policy header and recoverable from `PB01`. |
| N-7 | **Resolved** | The ADR status now says "re-review in progress", and decision 6 says acceptance waits for both reviewers. |
| P-1 | **Resolved** | Through `policy_id` plus N-1. |
| P-9 | **Mostly resolved** | As N-5. |
| P-12 | **Resolved** | P1 requires o₀ to be fixed, with `not_before = 0`, an active `out₀` and no withdrawal (§4.4, §5 step 6). A refund always produces a private note. The checklist asks counterparties to confirm the refund can be executed, for example that its committed delivery matches a ciphertext they have. |

### Remaining notes (non-blocking)

| ID | Sev | Location | Note | Suggested handling |
|---|---|---|---|---|
| F-1 | Low | §5 step 8 (l.223) | "`r`'s bit `z_r` is `active₁`" conflicts with "`active₀ = active₁ = 1`" in the same step if `active₁` means the preimage flag. The intended meaning is surely *the second output's public activity*. Getting it wrong does not break soundness: setting the preimage flag to `z_r` changes the outcome hash, so the proof fails. But `x = amount` would become unprovable, or the `active₁ = 1` constraint could be dropped. | Reword: "`z_r` gates commitment₁ and delivery₁; the preimage's `active₁` stays 1". |
| F-2 | Info | §7.1 (l.287-288), §10 (l.428) | The escrow "checks the token", but `approve(policy_id, outcome)` registers no token and the constructor takes only `pool`, so there is nothing to compare against. `policy_id` already binds the token, so this is redundant, not a gap. | Either drop the phrase or add `token` to `approve`. |
| F-3 | Info | §9.3 (l.415-417) | The example "a withdrawal to the pool, say, never settles" is out of date, because o₀ can no longer carry a withdrawal. Refunds can still fail to execute through a committed delivery with no known ciphertext. | Replace the example. |
| F-4 | Info | §9.1 (l.354) | The encoding of `ctx = chain ‖ pool ‖ ν` inside the HKDF info is not given. | Fix each field to 32 bytes, big-endian, as in the delivery plaintext. |
| F-5 | Info | §9.3 (l.414), §10 | The checklist item "confirm the controller has registered this `policy_id`" comes *after* the checklist in the escrow flow: the seller verifies, then the arbiter approves. | Reword to "before relying on settlement". |

### Checked in revision 3 and found sound

- **`policy_id` with amount and salt.** With the salt, publishing `policy_id` reveals nothing about
  the amount or the outcomes. The arbiter's approval rests on a `policy_id` that the protected
  party verified from the opening (§10), and the arbiter needs no chain lookup.
- **Byte-exact refund plaintext.** With the plaintext pinned byte for byte (§9.2), the seed-only
  refund is fully deterministic: `ν` from `PB01`, then `cap`, `rho`, `salt`, `rho_refund` and
  `esk`, then o₀, `policy` and `cm`, checked against the leaf.
- **Unchanged surfaces.** The pool-side items from revision 2 did not change, and I re-checked them
  against the revision-3 text: the Templar-only selector, the magic return and unwrap, the
  `controller ∉ {0, pool}` and nonzero-class checks, the separate `policy_verifier` slot with its
  `TMP1_BIND_V1` and `TMPZP1_POLICY_V1` tags, and the deadline and pinning text in §7.2.
