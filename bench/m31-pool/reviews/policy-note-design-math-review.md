# Math review: policy notes (ADR-0025, P1 relation), design stage

2026-09-24. Independent Math Reviewer. I did not write this design and received no implementer
reasoning. Nothing is implemented; this reviews the design only.

## Scope

- Primary: `docs/policy-note-spec.md` (all of it), `docs/adr/0025-policy-notes.md`.
- Context: `bench/m31-private-wrapper/client-port/src/payment.rs` (hash framing, `native_sponge`,
  `commitment`, `node`, `nullifier`, `statement`, `statement_limbs`, `build`, the amount and
  conservation gadgets), `src/membership.rs` (`sponge`, `sponge_lanes`), `src/merkle.rs`
  (`guess_bits`), `cairo-r0/bridge/src/lib.cairo`, `cairo-r0/account/src/lib.cairo`,
  `bench/m31-pool/cairo/src/{pool,spend,hash,adapter}.cairo`, ADR-0009 §3, ADR-0022,
  `docs/push-payment-spec.md` (delivery contract).
- I ran nothing: there is no code to run.

## Verdict

**CONDITIONAL GO.** The cryptographic core is sound: the new hash kinds are domain-separated,
policy notes and ordinary notes cannot be cross-spent, the nullifier is unique per leaf, and the
relation can be built from R0's gadgets without new assumptions. Implementation should still wait
for four spec revisions:

- **PN-1** (Critical): as specified, the controller cannot tell which note is settling. Anyone can
  make a decoy note with the same handle and use up the controller's case. This breaks the
  escrow reference scenario (§10): a buyer can take back a released payment.
- **PN-2** (High): §5 does not require range checks and well-formedness on the outcome preimage
  or on the split remainder. An implementation that hashes the preimage as raw words lets a
  note's creator inflate supply.
- **PN-3** (High): §5 does not specify how the outcome index selects a slot, nor that type,
  version and kind are pinned values. If this is done wrong, a proof can settle one outcome while
  the controller authorizes another.
- **PN-4** (Medium): the §9 recovery plan does not fit the fixed 304-byte ciphertext that the
  pool enforces. If the fix changes the policy layout, decide it before P1 is frozen.

These are spec edits, not a redesign. PN-5 to PN-11 can be handled during implementation.

## Findings

| ID | Severity | Location | Finding | Concrete attack / failure | Recommended fix | Blocking |
|---|---|---|---|---|---|---|
| PN-1 | **Critical** (protocol soundness) | spec §4.1 l.95-96 (`handle`, "several notes may share a handle"), §6 l.197-203 (authorization), §7 l.222-231, §10 l.264-267 | The authorization gives the controller `handle`, `outcome index`, type, `x`, `key(nullifier)`, not_before, deadline, the withdrawal and a note count. It gives nothing that ties the settling note to the policy the application agreed to. `handle`, `controller` and `controller_class` are chosen by the creator, and creation is unauthorized. Anyone can therefore create a note whose policy names a victim's controller and handle, with outcomes that pay themselves. The controller can only read "outcome i" as its application meaning if it knows that this particular note's slot i is that outcome. It never learns that. | Escrow (§10). Buyer B opens case H with arbiter A and funds the real note N (outcome 1 pays seller S). A releases H. B (or any griefer) has already created a decoy note N′ from B's own funds: 1 unit, policy `(controller=Escrow, class, handle=H, deadline, o₀, o₁ = pay B)`. B back-runs A's `release` with a P1 settlement of N′ at index 1. The pool calls `Escrow.apply(H, 1, …)`, the state is `RELEASED`, and the case moves to `SETTLED`. N's settlement at index 1 now reverts. After the deadline, B refunds N (refund window, no controller). S has delivered and is never paid; the attack costs B only fees. The same attack works on auctions: a decoy split with the winner's handle and `x = price` pays the decoy's own `out₀`. §7's "Bearer semantics" and "Settle/refund race" arguments assume the controller arbitrates *this note's* outcomes. That assumption fails. | Make the policy identifiable to the controller. Two options. **(a)** Add `policy_id = H(POLICY_ID, policy)` (9 limbs) to the P1 statement, the binding and the authorization. The statement grows to 163 limbs (41 QM31). Controllers register the expected `policy_id` per case (escrow `open(handle, arbiter, policy_id)`) and require equality in apply. Add a random 9-word `salt` to the policy header so `policy_id` cannot be brute-forced when every outcome is low-entropy (see PN-8). **(b)** Change nothing in the relation, but make the reference controller register `key(nullifier)` per case after funding, and check it in apply. This works for escrow but not for cases registered before the note's position is known. Either way, state normatively in §6/§7 that `handle` and `outcome index` are **unauthenticated creator input**, and that a controller must bind each case to a policy or note before relying on them. Add the decoy scenario to §10's rejection tests. | **Yes** |
| PN-2 | **High** (value soundness; Critical if missed in code) | spec §4.2 l.108-116, §5 constraints l.167-178 | §4.2 describes preimage well-formedness as definitions, and §5 lists "all words canonical" and "`amount ≠ 0`". §5 never requires: (i) 16-bit range checks on the preimage's `amount₈` limbs of `out₀`/`out₁` and `w_amount₈`; (ii) a range-checked private remainder `r = amount − x` for splits; (iii) that the limbs hashed into the outcome digest are the same variables used in conservation and in the output commitments; (iv) `active ∈ {0,1}`, with an inactive slot all zero (36 words); (v) for a split, `active₀ = active₁ = 1`, preimage amounts zero, withdrawal fields zero, and nonzero receivers and rhos; (vi) `x = 0` and `r = 0` are handled as described below. "Canonical M31" is not a 16-bit bound. The conservation gadget (`payment.rs:566-604`) proves integer equality only if every limb is below 2^16. | **Creator inflation.** A fixed outcome on a note of 100 sets `out₀.amount` limb₀ = 1100 and `out₁.amount` limb₀ = p − 1000 (active), with w = 0. Limb 0 gives 100 − 1100 − (p−1000) ≡ 0 (mod p) with carry 0, so conservation passes. `out₀` is a canonical, R0-spendable note of 1100; `out₁` is unspendable. Net: 1000 minted. Using o₀ with `deadline = 0` needs no controller, so any depositor can do this. **Split over-draw.** If `r` is not range-checked, an unregistered-collateral bidder settles `x > amount` with r ≡ amount − x (mod p): `out₀` receives more than the note held. | Add to §5, normatively: every amount-like limb in the preimage, plus `r`, goes through `amount_unchecked` (bits), and those same `Var`s feed the OUTCOME hash, the NOTE hashes and conservation. Every flag is `guess_bits(…,1)`. Enforce inactive ⇒ all 36 slot words zero, and active ⇒ receiver, rho and amount nonzero (R0's `nonzero_vector_if`/`nonzero_if`). Enforce the split preimage rules in (v). Fixed conservation is `[amount] = [out₀, out₁, w]`; with one input the carries stay in {−2,…,1}, so R0's gadget applies unchanged. Split conservation is `[amount] = [x, r]`, plus `x ≠ 0`. Choose `z = [r = 0]` soundly in both directions: `r_sum·inv = 1 − z` and `r_sum·z = 0`, where `r_sum` is the limb sum (< 2^19, so zero iff r = 0). Then commitment₁ = `z ? 0 : H(NOTE,…r…)` and delivery₁ = `(1−z)·delivery₁`. Add malicious-witness tests: a negative limb, x > amount, an inactive slot with nonzero words, and `z` forced to 1 with r ≠ 0. | **Yes** (spec text) |
| PN-3 | **High** (authorization binding) | spec §5 item 2 l.168-170, item 4 l.173, item 7 l.179; §4.1 l.93 | (a) Selection. The index must select the slot through one-hot boolean bits `b₀..b₃` with `Σbᵢ = 1`, `index = Σ i·bᵢ`, and `slotᵢ = bᵢ·o_sel + (1−bᵢ)·wᵢ`. The spec says only "the digest at the public outcome index is recomputed". If index and slot are decoupled (say a free index plus a separately chosen slot), a prover publishes index 1, which the controller authorizes, while recomputing slot 3. (b) `type` is only required to equal the selected outcome's. Nothing constrains it to {1,2}, and the circuit's branch selectors (`s = type − 1`) assume a boolean. (c) `version` and `kind` are witnesses. Nothing says they are circuit constants. If they are free, a later tier's policy (`kind = 2`, different semantics, same `PRECV` receivers) could be spent under P1's rules. (d) Rule 7 (index 0 ⇒ fixed) is enforceable as `b₀·(type − 1) = 0`, but only given (a) and (b). | Index 1 is authorized (`RELEASED`), and the proof settles slot 3 (for example "pay the executor") under index 1. Or a creator writes a tier-1 note with `kind = 2` so a future tier-2 relation also accepts it, a cross-tier spend of one leaf under two semantics. The two relations would still derive the same nullifier, so this is not a double spend, but it lets the holder pick which semantics apply. | Specify (a) exactly. Encode type as one boolean `s` (`guess_bits`) with `type = 1 + s`. Hash `version = 1` and `kind = 1` as circuit constants, not witnesses. Keep `b₀·s = 0`. The bridge should also check `index < 4`, `type ∈ {1,2}` and `(type = 1) ⇔ (x = 0)`, and the pool should assert `type = 1` whenever `index = 0` (defence in depth). Add tests: index/slot mismatch, type 0/3, version or kind ≠ 1. | **Yes** (spec text) |
| PN-4 | Medium (recovery, hiding) | spec §8 l.239 vs §9 l.253-256; `spend.cairo:58-73` (`delivery_digest` requires exactly 10 words = 304 bytes); `push-payment-spec.md` l.50-54 (256-byte plaintext) | §9 has the creation ciphertext carry the amount, the policy header (controller, class and handle felts, deadline, version, kind), the refund preimage *including its 304-byte ciphertext*, and three 9-word digests (≈105 bytes). That cannot fit in the 256-byte plaintext of the only format the pool accepts (`deposit` and R0 outputs both go through `delivery_digest`). A larger policy ciphertext would need a pool change and would make creation distinguishable, which contradicts §8. The refund ciphertext must also be reproducible byte for byte at settlement, since the pool checks its digest against the committed `delivery`, and a libsodium sealed box uses a random ephemeral key. | A depositor loses their device. The seed gives `cap` and `rho`, but the header, the other digests and the exact refund ciphertext are gone. The refund, the depositor's only escape, cannot be proven. Alternatively, wallets emit oversized creation payloads that mark policy notes on chain. | Fit the recovery data into the existing envelope. (1) Restructure the policy as `H(POLICY, header ‖ o₀ ‖ o_rest)` with `o_rest = H(OUTCOMES, o₁‖o₂‖o₃)` (a new kind), so recovery needs one digest, not three. (2) Derive from the seed everything that can be derived: `cap`, `rho`, the refund `rho_r`, the refund receiver, and the refund ciphertext's ephemeral key. The last needs a deterministic sealed-box variant; a stock `crypto_box_seal` will not do. (3) Define a versioned 256-byte "policy note" plaintext and show the byte budget. Decide (1) before P1 is frozen, because it changes the relation. | Yes, for the policy layout; otherwise before any wallet work |
| PN-5 | Medium (application safety) | spec §1 l.15-19, §4.2 l.118-120, §7 l.229-231, §9 | Nothing in the relation stops a creator from committing outcomes that look right but fail the counterparty: a garbage `delivery` ciphertext (the beneficiary's note cannot be opened), `not_before > deadline` (the outcome can never settle), a selected outcome that does not conserve against the note amount, a malformed or zero `o₀`, or a withdrawal recipient or token that reverts. The spec has no verification checklist for the beneficiary or executor. There is also a deadline boundary: after `deadline`, a depositor can refund a note the controller had already released but nobody settled. PROOF2 latency and `max_proof_age` shrink the usable window further. §7's claim "a controller cannot freeze value past the deadline" holds only if `o₀` is well-formed. | Seller S is shown a note whose outcome 1 "pays S". The attached ciphertext decrypts under S's key, but the committed delivery is for a different ciphertext. After release, S receives a leaf they cannot open. Or the executor goes offline, the deadline passes, and B refunds. | Add a normative "accepting a policy note" checklist to §9/§10. The counterparty must: recompute `cm` and find it in the tree; recompute `policy` from every outcome relevant to them; check `version`, `kind`, the controller, class, handle and deadline; check the relevant outcome's conservation and `not_before ≤ deadline`; decrypt their output ciphertext and check its digest equals `delivery`; and confirm the case is registered to this policy (PN-1). Recommend that the beneficiary also holds `cap` and settles with a margin of at least PROOF2 latency plus `max_proof_age` before the deadline. Wallets check `o₀` at creation. | No |
| PN-6 | Medium (spec wording) | spec §5 l.182, §7 l.229-231; ADR-0025 alternatives l.52-54 | "`x` and `data` are the only values the **executor** chooses." In fact **every** capability holder chooses them, the depositor included. Any holder can front-run the executor's transaction with the same outcome and different `x`/`data` (same nullifier, so the first transaction wins). The bearer argument therefore needs: (i) the controller pins `x` and treats `data` as adversarial input; (ii) at any time the controller permits at most one outcome per note, or the application is indifferent among those it permits. | The auction controller checks `x ≥ reserve` instead of `x == winning bid`. The depositor (the bidder) front-runs with `x = reserve`. Or a controller that reads a fee recipient from `data` pays whoever lands first. | Reword §5 and §7. State (i) and (ii) as controller obligations next to "check `caller == pool`". | No |
| PN-7 | Low | spec §6 step 4 l.195-203 | Return semantics for `privacy_apply_controlled_transition` are unspecified. If PR #2's interface returns a value, a controller that returns `false`, or empty data, without reverting would be read as approval. The controller address is unconstrained: it could be the pool itself, the token, the verifier or 0. `get_class_hash_at` of an undeployed address returns 0, which matches a committed class of 0. The call then fails, which is safe, but the spec should say so. | A controller written in the "return false on reject" style approves everything. | Require the call to succeed and return one exact magic felt (for example `'TEMPLAR_POLICY_V1'`); anything else reverts. Reject `controller ∈ {0, pool, verifier, token}` and `controller_class = 0` in the pool. Fix the selector name and the authorization felt order in the spec. | No |
| PN-8 | Low (privacy statement accuracy) | spec §8 l.240-246 | (a) "A split reveals the note amount" is wrong. `amount − x` stays inside commitment₁. The amount is revealed only when `x = amount`, because commitment₁ is then zero, and it also leaks through a withdrawal-only fixed outcome. (b) Leaks missing from the list: the P1 statement tag, which marks a policy settlement; the root, which bounds the note's age as in R0; and identical output commitments when a creator reuses an outcome `(receiver, rho, amount)` across notes (for example vesting tranches), which links those settlements publicly. (c) If PN-1(a) is adopted, `policy_id` becomes public. It is brute-forceable when every outcome is low-entropy (a withdrawal-only `o₀` and no rho anywhere), hence the salt. | Two tranche notes with the same outcome preimage settle to the same commitment, and an observer links them. | Correct (a). Add the items in (b). Require a fresh `rho` per outcome output per note. Add a salt if the policy is exposed. | No |
| PN-9 | Low (underspecified plumbing) | spec §5 table l.148-163, §6 l.189-192 | Items to pin down. (1) The level word for PNK, PRECV, POLICY and OUTCOME. Say 0, with fixed payload lengths of 9, 18, 69 and 94. (2) Bridge checks: padding limbs 154-155 are zero; `controller` and withdrawal recipient are below 2^251; felts are canonical through `felt_from_limbs`; `delivery ≠ 0` iff `commitment ≠ 0`; the withdrawal has both recipient and amount or neither; `nullifier ≠ 0`. (3) A distinct binding domain (for example `'TMP1_BIND_V1'`), a distinct account message tag (`TMPZP1_POLICY_V1`), a distinct statement class, and a separate pool storage slot for the P1 adapter, so the R0 `verifier` is never reused. (4) P1 uses the **same** `nullifiers` map as R0. Receiver separation already prevents cross-relation double spends, but one set is simpler to reason about. (5) An inactive slot's ciphertext must be empty, as `compute_binding` requires. (6) The order of controller call, note append and withdrawal payment. Document it, because a controller that expects to hold funds inside the callback cannot. (7) Pin `key(nullifier)` as `hash::key` (Poseidon over the nine words). | A P1 pool accidentally wired to the R0 adapter slot, or a binding without `index`/`type`/`x`/`data`, lets a relayer swap them. | Spell out these items in §5/§6. | No |
| PN-10 | Info | spec §4.1 l.98-99 | "An unused slot … can never be selected (no preimage hashes to zero)" is a 279-bit preimage assumption, which is fine. Note that no one enforces the well-formedness of *unselected* outcomes, `o₀` included. "`o₀` must be fixed" is enforced only when `o₀` is actually settled. | A creator commits `o₀` as a split; the refund can then never settle. This is self-harm only, and a counterparty cannot be harmed by it. | Wallet-side check at creation (PN-5). | No |
| PN-11 | Info | spec §7 l.225-228 | Pinning the class pins code, not behaviour. A controller can `library_call` a class hash held in storage, or read admin-mutable state. | An "immutable" controller whose owner changes the delegated class. | Tell applications that class pinning is necessary but not sufficient; audit controllers for indirection. | No |

## What I checked and found sound

**Hash framing and domain separation (§2, §3, §4).**
- The native sponge (`payment.rs:200-222`), the circuit sponge (`membership.rs:49-77`,
  `sponge_lanes` 148-175) and Cairo (`hash.cairo`, `sponge`) agree. All three overwrite rate
  positions 0..14. A short last block gets 10* padding in the rate; a full last block adds 1 to
  capacity word 15. For a fixed kind the padding is injective in length.
- Framed lengths: PNK 13, PRECV 22, POLICY 73 (1+1+9+9+9+4+36 = 69 payload words), OUTCOME 98
  (1+4+36+36+9+8 = 94). None is a multiple of 15, and each kind has one fixed length.
- The kind word sits at rate position 2 of the first block, where capacity is zero. So
  `H(k,·) = H(k′,·)` with `k ≠ k′` needs a collision of the width-24 permutation-based sponge
  (capacity 9 words, about 279 bits, 9-word output, about 2^139 collision work).
- Equal-length pairs are still separated by the kind word: PRECV/OWNER/INNER/NODE (18-word
  payloads) and PNK/AUTH/NK (9).
- Compress nodes put `[TAG,1,NODE1,level,0,0]` in positions 18..23. A first sponge block has
  zero there and `TAG ≠ 0`. A later block would need six capacity words of a permutation output
  to match, about 2^-186 per state. POLICY (5 blocks) and OUTCOME (7) add intermediate states but
  do not change that bound.

**No cross-spending (§3).**
- R0 derives the receiver as `H(OWNER, H(AUTH,sk)‖H(NK,sk))` (`payment.rs:233-237, 663-671`).
  P1 derives `H(PRECV, pnk‖policy)`.
- A leaf spendable by both relations needs `inner`, and then the receiver, to agree. By
  collision resistance of NOTE and INNER, that means an OWNER/PRECV output collision.
- Every leaf the pool creates has NOTE structure over the pool's own context: `deposit`
  (`pool.cairo:119-132`), R0 outputs (proven), and open-note destinations (`pool.cairo:195`).
  No path inserts a raw commitment.

**Nullifier uniqueness (§3, §5 item 3).**
- For a fixed leaf `(cm, pos)`, collision resistance of NOTE, INNER and PRECV fixes
  `inner → (recv_p, rho) → (pnk, policy)`.
- The position is 32 boolean bits packed into two 16-bit halves (`payment.rs:720-733`), so it
  has exactly one encoding.
- The nullifier `H(NF, pnk‖cm‖pos)` depends on none of the outcome index, the other-digest
  witnesses, `x`, `data` or the holder. Every capability holder derives the same value, and no
  alternative witness produces a second one.
- R0 and P1 share the NF kind. That is fine: equal nullifiers would need equal `cm` and `pos`,
  which is the same leaf, and a leaf can be spent by only one relation.
- Duplicate leaves (identical `cm` at two positions) get two nullifiers. This is intended: they
  are two funded notes.

**Outcome binding, given PN-2 and PN-3.**
- Changing the selected outcome or any other slot means changing `policy`, which is a
  POLICY/PRECV collision.
- Fixed outcomes commit every field. The executor's only choices are `x`, which is split-only and
  range-constrained, and `data`, which the proof binds.
- One-input conservation carries: the limb difference lies in (−3·2^16, 2^16), and with an
  incoming carry in {−2..1} the outgoing carry stays in {−2..1}. R0's gadget is sound unchanged
  for `[amount] = [o₀,o₁,w]` and `[amount] = [x,r]`.
- `1 ≤ x ≤ amount` is exactly "`x` nonzero and `r` range-checked".
- `x = amount` gives `r = 0`, one appended note, and a zero commitment₁ and delivery₁. That is
  consistent with the bridge rule "delivery nonzero iff commitment nonzero".
- `o₀` must be fixed: this is enforceable as `b₀·s = 0` (PN-3).

**Statement and pool binding (§5, §6).**
- The field list covers everything the pool and controller consume. The limb count is
  2+27+9+9+18+18+17+27+8+2+8+9 = 154, padded to 156.
- Chain, pool and token appear in both the input commitment and the statement, and the output
  commitments use the same public context. That rules out cross-chain, cross-pool and
  cross-token replay.
- A separate statement class and message tag in the adapter (the pattern of `adapter.cairo`
  l.65-69) plus a pinned circuit hash (`bridge/lib.cairo:83-86`) mean an R0 proof or fact cannot
  be read as P1, and a P1 one cannot be read as R0.
- The nullifier is marked spent before the controller call. The pool lock (`pool.cairo:349-352`)
  blocks re-entry, and any revert unwinds everything.
- A single message per transaction (`facts[7] == 1`) means one proof per settlement.

**Controller window and refund window.**
- Every value that selects the window (`deadline`) or gates timing (`not_before`) is proven, not
  supplied by the relayer.
- Before the deadline every outcome, the refund included, needs the controller.
- After the deadline only index 0 is allowed, and it is fixed, so no holder-chosen `x` exists
  there.
- A controller upgrade blocks gated outcomes but not the refund.

**Hiding (§8).**
- Creation leaves an ordinary-format leaf. A deposit publishes `inner` and the amount, exactly as
  an ordinary deposit does. The ciphertext caveat is PN-4.
- The statement never publishes `policy`, the outcome digests, `pnk`, `recv_p` or `rho`.
- Fixed-outcome commitments carry a random 9-word `rho`, which makes the receiver and amount
  resistant to brute force.
- Settlement links to creation only through the nullifier, which needs `pnk`.
- Holder knowledge is as §8 states. The creator knows the beneficiary's output `cm` but not `nk`,
  so it can neither spend that note nor see it spent. This keeps ADR-0009 §3's owner-keyed
  property for the outputs.
- The P1 proof's zero-knowledge still depends on the open compact-proof hiding argument, as §8
  says.

**Bearer capability vs ADR-0009 §3.**
- ADR-0009 rejected bearer keys because creator and holder could race to *redirect* value. Here
  every holder can cause only committed outcomes, and the race decides who triggers the
  settlement, not where the value goes.
- The argument is correct under three conditions:
  - the controller can identify the note (PN-1, currently false);
  - the controller pins `x` and permits at most one outcome at a time (PN-6);
  - the beneficiary accepts deadline-boundary risk or holds `cap` itself (PN-5).
- With PN-1 fixed, this reversal of ADR-0009 §3 is justified.

## Re-review of revision 2

2026-09-24. Same reviewer. Inputs: `docs/policy-note-spec.md` revision 2,
`docs/adr/0025-policy-notes.md` (revised), and the protocol review
`policy-note-design-protocol-review.md`, which I read for the first time after writing the
first-round findings above. Read-only; nothing was run.

### Verdict (revision 2)

**CONDITIONAL GO.** Revision 2 fixes the relation-level findings properly.
- The range-check and single-variable rule, the selection formula, the constant version and kind,
  and the type and refund rules are all correct as written.
- The `orest` layout is sound, and it makes a seed-only refund possible.
- I walked the recovery path end to end and it works.

The move to `policy_id` does not fully close PN-1, and the reference escrow has a new flaw.
Two items block implementation:

- **N-1** (Critical): `policy_id` does not commit to the token. The buyer can make a
  **junk-token duplicate** of the approved policy, settle it to use up the arbiter's approval,
  and refund the real note after the deadline.
- **N-2** (High): as written, the escrow's `approved[(policy_id, handle)] == outcome` check lets
  outcome `0` (cancel) pass for any policy the arbiter never approved, because Cairo storage
  defaults to 0. The buyer can then refund unilaterally before release.

Both are one-line spec fixes. N-3 must be fixed before wallet work, but it does not block the
relation or the pool.

### Status of first-round findings

| ID | Status | Reason |
|---|---|---|
| PN-1 | **Partially resolved** | `policy_id` is public, proven (§5 step 5), bound and passed to the controller. The escrow keys on `(policy_id, arbiter = handle)`. A decoy note with a *different* policy now has a different `policy_id`, so the first-round attack is closed. A duplicate with the *same* policy but a *different token* is still open (N-1). Same-token duplicates are harmless: conservation fixes a fixed outcome's destinations and amounts, and the controller pins a split's `x`, so a duplicate pays the approved parties exactly as agreed, from the duplicator's own funds. |
| PN-2 | Resolved | §5 step 1 range-checks every amount limb, `x` and `r`, and requires the same variables to feed hashes, commitments, public fields and conservation. Step 7 requires boolean `active` and zero inactive slots. Step 8 requires split preimage amounts and withdrawal to be zero, the borrow to be zero, and `x ≠ 0`. The inflation and over-draw attacks are closed. Small implementation note in N-6. |
| PN-3 | Resolved | Four boolean selector bits with `Σb = 1` and `index = Σk·b_k`. `version` and `kind` are circuit constants. `type = 1 + s` with `s` boolean. `b₀ ⇒ type = 1 ∧ not_before = 0`. The `orest` formula is checked below. |
| PN-4 | Resolved | The 256-byte `PB01` budget adds up (4+32+16+32+32+32+8+36+8+4+52 = 256). A standard refund plus a deterministic sealed box makes `o₀` recomputable. With `b₀ = 1`, only `orest` is needed (checked below). New issues: N-3, N-4. |
| PN-5 | Partially resolved | The deadline boundary is documented (§7.2), and a checklist exists (§9.3). The checklist leaves out three things: conservation of the relying party's own outcome, `not_before ≤ deadline − margin`, and liveness of `o₀`. Its item "confirm the controller has registered this `policy_id`" cannot be done for the escrow, which registers nothing before approval (N-7). |
| PN-6 | Resolved | §5 and §7.1 now say every capability holder chooses `x` and `data`, and that controllers must pin the index and `x` and allow at most one outcome per `policy_id`. |
| PN-7 | Resolved | Templar-specific selector, `unwrap_syscall`, the exact return `['TEMPLAR_POLICY_OK']`, `controller ∉ {0, pool}`, and a nonzero pinned class. With the magic return, a token or verifier address as controller is harmless. |
| PN-8 | Resolved | The split's amount leak is corrected. The P1 tag and root age are listed. Fresh `rho` per output is required (§4.2). Residual: the brute-force entropy of `policy_id` for non-standard menus (N-5). |
| PN-9 | Partially resolved | Done: level 0 for all kinds, a distinct binding tag (`TMP1_BIND_V1`), a distinct account tag, a separate `policy_verifier` slot, the shared nullifier map, and empty ciphertexts for inactive slots. Not yet written: the P1 bridge's liveness checks (`index ≤ 3`, `type ∈ {1,2}`, `x = 0 ⇔ type = 1`, delivery ⇔ commitment, withdrawal both-or-neither, address ranges, zero padding limb 163) and the per-field felt encoding inside the binding. Non-blocking, but write them before implementing the bridge. |
| PN-10 | Partially resolved | The relation now enforces `o₀` fixed with `not_before = 0` when it settles. It still does not enforce that `o₀` is *live*, for example that it has a private output rather than a withdrawal to a blacklistable or pool address (P-12). See N-5. |
| PN-11 | Resolved | §7.2 "Controller pinning". The reference controller is immutable and has no admin. |

### Checks of the specific revision-2 mechanisms

**Selection formula (§5 step 3).**
- **Refund, `b₀ = 1`.** `o₀ = ô` (recomputed from the selected preimage). `orest = w_rest` (a
  witness). The `o_k` are free witnesses whose OREST hash is computed and discarded. POLICY
  collision resistance fixes `(o₀, orest)` to the committed values, so `ô` must be the committed
  refund. That is exactly what seed recovery provides: `o₀` from the seed and the backup, `orest`
  from the backup.
- **Other outcomes, `b₀ = 0`.** `o₀ = w₀` and `orest = H(OREST, o₁‖o₂‖o₃)`, with `o_k = ô` for
  the one `k` where `b_k = 1`. POLICY and OREST collision resistance fix every slot, so `ô` must
  equal the committed `o_k` for `k = index`.
- Index and slot cannot be separated, because both are functions of the same boolean bits.
- An unused (zero) slot still needs a preimage of zero.
- Every selector product has degree 2.
- The witness description in §5 ("`o₀` or `orest`, and the two unselected `o₁…o₃`") is slightly
  loose: with `b₀ = 1` no `o_k` are needed. This is a wording issue only.

**Frame lengths with the new layout.**

| Kind | Payload words | Frame words |
|---|---|---|
| POLICY | 1+1+9+9+9+4+9+9 = 51 | 55 |
| OREST | 27 | 31 |
| POLICY_ID | 9 | 13 (40 with the N-1 fix) |

None of these is a multiple of 15. The kinds (14, 15) are distinct, and the first-round
domain-separation argument carries over unchanged.

**Split borrow (step 8).** Sound, given two conditions:
- The borrow bits are boolean.
- `r`'s limbs are 16-bit (step 1).

Then `amount_k − x_k − β_k + 2^16·β_{k+1} = r_k` with `β₈ = 0` is integer subtraction without
underflow. The zero test on `r` must be sound in both directions (N-6).

**Seed recovery (§9.1–9.2), walked end to end.**
1. From the seed and the backup (`n`, token, amount, controller, class, handle, deadline,
   `orest`, refund receiver index), the wallet derives `cap → pnk`, `rho`, `rho_refund` and
   `esk_refund`.
2. It rebuilds the refund plaintext and seals it with `esk_refund`. `crypto_box` is
   deterministic given the key and nonce, and the nonce is `BLAKE2b(epk‖pk)`, so the bytes come
   out identical. The digest gives `delivery`.
3. From that it computes `o₀`, then `policy`, `recv_p`, `inner` and `cm`, and checks `cm`
   against the leaf.
4. It proves `b₀ = 1` using `w_rest = orest`.

This works, provided the refund plaintext bytes are pinned (N-4) and `n` is never reused under
the same receiving key (N-3). The deterministic box is an ordinary 304-byte sealed box: 32 bytes
of `epk`, a 16-byte MAC and 256 bytes of ciphertext. Since `esk_refund` is pseudorandom, it
cannot be told apart from a normal box.

**Escrow keyed by `(policy_id, arbiter = handle)`.**
- `handle` is proven to be inside `policy`, so each `policy_id` has exactly one arbiter.
- Only that address can write the approval. That removes the registration race (P-8).
- A decoy on the same arbiter with a different policy is rejected.
- Remaining gaps: the token (N-1) and the zero default (N-2).

### New findings

| ID | Severity | Location | Finding | Concrete attack / failure | Recommended fix | Blocking |
|---|---|---|---|---|---|---|
| N-1 | **Critical** | spec §4.1 l.96-100 (`policy_id = H(POLICY_ID, policy)`), §7.1 l.266-268, §10 l.391-396 | Neither `policy` nor `policy_id` commits to the token, or to chain and pool. The token is only in `cm`. Anyone who knows the approved outcome's preimage and the other digests can fund a second note with the **same `policy`** in a worthless token. The depositor always knows them, and so does the executor. `deposit` accepts any nonzero token (`pool.cairo:122`), and the note needs only the `policy` value and the prover's own `cap′`. That note has the same `policy_id` and settles the same outcome index. §7.1 tells controllers to "check `authorization[0..4]` (tag, chain, pool, token)", but the escrow keeps no expected token to compare against. | The escrow buyer B creates the real note N (1000 USDC; outcome 1 pays seller S) and gives S the opening. S verifies it and ships. Arbiter A calls `approve(P, 1)`. B deploys a junk ERC20 and deposits 1000 JUNK into a note N′ with `recv_p′ = H(PRECV, pnk′ ‖ P)`, then settles N′ at index 1. The authorization carries `policy_id(P)`, the approval matches, and the case is consumed. S receives a 1000-JUNK note. Its committed ciphertext even decrypts to a USDC plaintext that fails S's `cm` check. N can no longer settle outcome 1. After the deadline, B refunds N. S has shipped and has nothing. | Bind the settlement context into the identifier inside the relation: `policy_id = H(POLICY_ID, chain₉ ‖ pool₉ ‖ token₉ ‖ policy)`, computed from the same public context variables as `cm`. That is one more 36-word hash; the frame is 40 words. Every controller then gets token-, chain- and pool-specific approval for free. (Alternatively, commit the token inside `policy`'s header. Putting it in `policy_id` also covers chain and pool.) Add the rejection test "same policy, different token, cannot consume the approval". Keep §7.1's context check as defence in depth. | **Yes** |
| N-2 | High (reference controller) | spec §10 l.391-396 | `approve` records "the only outcome (`1` release, `0` cancel)", and apply checks `approved[(policy_id, handle)] == outcome` and not consumed. Cairo storage maps default to 0. So an unapproved `policy_id` reads as "cancel approved", and outcome 0 passes. | B funds N, S ships, and before A approves anything, B settles N at index 0 (the standard refund, `type = 1`, `not_before = 0`). `approved[(P, A)]` reads 0 and equals outcome 0, `consumed` is false, and the escrow returns OK. B gets the refund inside the controller window and keeps the goods. | Store an explicit approval, for example `approved: Map<(policy_id, arbiter), u8>` holding `outcome + 1` with 0 meaning none, or a separate `is_approved` flag. Apply requires the approval to be present. Add the rejection test "outcome 0 without any approval". | **Yes** (reference-controller spec; this is the acceptance scenario) |
| N-3 | Medium (hiding, key separation) | spec §9.1 l.331-345 | `n` is counted "per chain and pool", but the HKDF info is only `label ‖ n`. Note `n` on two deployments (Sepolia and mainnet, or two pools) therefore gets the **same** `cap`, `rho`, `rho_refund` and `esk_refund`. (a) The same `cap` breaks per-note capability separation. An executor given `cap` for Sepolia note 0 can spend mainnet note 0 once it learns that note's opening minus `cap`, which a mainnet watcher holds by design. (b) "Each `esk_refund` is used for exactly one message" is asserted but not enforced. If the wallet reuses `n` in one deployment (a retried or failed creation with a different amount or policy) under the same refund receiving key, both refund boxes share key and nonce, which reuses the XSalsa20-Poly1305 keystream once both are published or handed to an executor. Across deployments the incoming key differs (push-payment-spec derives incoming keys with chain/pool context), so (b) there is limited to key separation. | (a) A cross-environment executor or watcher gains spend authority it was never given. (b) XORing two refund ciphertexts reveals `rho_refund`, amount and policy differences, which lets someone recognize the refund output commitment. | Put chain and pool (and the wallet account index) into the HKDF info, or derive `s_pol` per chain and pool. Make `n` strictly monotonic and never reused, even when creation fails; recovery then scans for gaps. | Before wallet work; not for the relation or pool |
| N-4 | Low | spec §4.4 l.144-147, §9.1-9.2 | The standard refund's plaintext is described only as "deterministic delivery". Its exact 256 bytes are not pinned: version, `controller` and `policy` fields, padding, and which receiver encoding. Seed recovery needs byte-exact regeneration across wallet versions and implementations. | A later wallet version writes a different version byte or padding. The regenerated box has a different digest, so `o₀`, and then `policy` and `cm`, no longer match, and seed-only refund fails. | Pin the refund plaintext layout byte for byte in §9 (for example, version 2 ordinary with zero `controller` and `policy`) and add a test vector. | No |
| N-5 | Low | spec §4.4, §5 step 6, §4.1 l.113-114 | The relation enforces `o₀` fixed with `not_before = 0`, but not that it has a private output. A menu whose refund is withdrawal-only (i) can freeze past the deadline if that recipient becomes unpayable or is the pool (P-12). (ii) It removes the secret `rho` that §4.1's claim "`policy_id` reveals nothing" relies on. If every slot is withdrawal-only or zero, `policy_id` together with the public header lets someone brute-force the unselected recipients and amounts. | A non-standard wallet creates `o₀` = withdraw to an address that is later blacklisted, and the note is frozen for good. Or a low-entropy menu's unused payouts are recovered from `policy_id`. | Enforce in P1: `b₀ = 1 ⇒ active₀ = 1 ∧ w_amount = 0`. This costs a few degree-2 constraints and gives every policy at least `rho_refund`'s entropy. Otherwise add a 9-word salt to the header. | No |
| N-6 | Low (implementation guidance) | spec §5 step 8 | The spec does not say that the borrow bits are boolean, or that the `r = 0` indicator `z` must be sound in both directions (`r_sum·inv = 1 − z`, `r_sum·z = 0`). If only one direction is enforced, a prover can set `z = 1` with `r ≠ 0` and zero commitment₁. That burns the remainder owed to `out₁`, typically the depositor. | Any capability holder with a controller-approved split burns `amount − x`. | Spell it out, and add the malicious-witness test "`r ≠ 0` with commitment₁ zeroed" to §10's split tests. | No |
| N-7 | Low (application flow) | spec §9.3 checklist l.381-384, §10 | For the escrow, "confirm the controller has registered this `policy_id`" cannot be done before shipping: nothing is registered until the arbiter approves, and the arbiter never sees the opening. The safety of the flow depends on the arbiter approving only the `policy_id` the seller verified. The spec does not say how the arbiter learns that. | B shows S the opening of P, then sends the arbiter the `policy_id` of P′, whose outcome 1 pays B. A approves P′ release, and S is never paid. | State the escrow flow: S verifies the opening and gives `policy_id(P)` to A. A approves only a `policy_id` S has confirmed. Add to the checklist: the relying party's own outcome conserves, `not_before ≤ deadline − margin`, and `o₀` is live. | No |
| N-8 | Info | spec §9.3 l.377-380 | The `PS01` split plaintext gives both split receivers the **note amount**. The `x` side does not need it. | The seller learns the buyer's full escrowed amount. | Put the note amount only in the remainder side's plaintext, or accept it and note it in §8. | No |

Note: while this section was being written, `docs/policy-note-spec.md` moved to revision 3. It
cites N-1, N-2 and N-3, and appears to change `policy_id` to include the context and the amount,
store the approval as `outcome + 1`, and add chain/pool context to the HKDF inputs. This section
reviews **revision 2 only**. Revision 3 has not been reviewed.

## Final pass (revision 3)

2026-09-24. Same reviewer. Input: `docs/policy-note-spec.md` revision 3, stable. Read-only;
nothing was run.

### Verdict (revision 3)

**GO for implementation** of the P1 relation, the P1 bridge and account, the pool entry point and
the reference escrow controller. No blocking items remain.

The four items listed below (F-1 to F-4) are small and should be tracked. F-1 must be settled
before wallet or recovery code is written.

Real value remains gated, as §8 says, on the compact proofs' hiding argument and on the
implementation review. Under `AGENTS.md`, the implementation still needs its own Math Reviewer
pass: soundness tests for the malicious-witness cases in §10, and the selector/range gadgets.

### Checks of the revision-3 changes

**`policy_id = H(POLICY_ID, chain₉ ‖ pool₉ ‖ token₉ ‖ amount₈ ‖ policy)` (§4.1, §5 step 5). This
closes N-1.**
- It is computed from the same public context variables and private amount limbs as `cm`.
- A copy of the policy funded in another token, pool or amount gets a different id, so the
  junk-token and other-amount copies are rejected by any controller keyed on `policy_id`.
- A same-token, same-amount copy pays the approved destinations exactly as agreed, from the
  copier's own funds. It is harmless, as argued before.
- Payload is 44 words (frame 48); the new POLICY payload is 60 words (frame 64). Neither is a
  multiple of 15, and kind 15 is distinct, so domain separation is unchanged.

**`salt₉` in the header.** With 279 bits of seed-derived secret inside `policy`, neither
`policy_id` nor `policy` can be brute-forced, even for a withdrawal-only menu. Including the
private `amount` in `policy_id` therefore reveals nothing. This resolves the entropy half of N-5.

**Refund rule (§4.4, §5 step 6).** `b₀ ⇒ type = 1 ∧ not_before = 0 ∧ active₀ = 1 ∧ w = 0`.
- This is four gated products, all degree 2. The pool also asserts it (§6 step 5).
- A refund always creates a private note, so it cannot get stuck on the pool-address withdrawal
  of P-12. This resolves N-5. (See F-3 for one remaining way a refund can be unsettleable.)

**Split zero test (§5 step 8).** Sound in both directions, with `σ·t = z` and `σ·(1−z) = 0`, and
`σ < 2^19 < p`:
- `σ ≠ 0` forces `z = 1`, since `t = σ⁻¹` exists.
- `σ = 0` forces `z = 0`.

`x` requires `z = 1`. The remainder's flag `z_r` gates both commitment₁ and delivery₁ word by
word. Borrow bits are boolean and the final borrow is zero. This resolves N-6. The naming needs
fixing (F-2).

**Selection and `orest`.** Unchanged from revision 2 and sound. `salt` joins the header as a
witness hashed into `policy`, which changes nothing in the selection argument.

**Binding (§6 step 1).**
- It covers every public field. Digests go in as nine words; every other field as one decoded
  felt.
- The length is fixed, so the Poseidon span is injective.
- The tag is `TMP1_BIND_V1`, distinct from R0.
- The bridge pins the circuit and tag, checks the output count and the zero padding, and decodes
  felts canonically and 16-bit limbs.
- This resolves PN-9's binding half. The P1-specific liveness checks are still not listed for the
  bridge (F-4). The circuit already enforces all of them, and the pool asserts `index 0 ⇒ type 1`,
  so this is defence in depth only.

**Seed derivation (§9.1).** `ctx = chain ‖ pool ‖ ν`, with a fresh random 16-byte `ν`.
- Different deployments and retries now get independent `cap`, `rho`, `salt`, `rho_refund` and
  `esk_refund`.
- A `ν` collision needs about 2^64 notes, so "each `esk_refund` is used for exactly one message"
  now holds.
- This resolves N-3.

**Backup layout (§9.2).**
- The fields add up: 4+32+16+32+32+32+8+36+16+4+44 = 256.
- From the seed and `ν`, the wallet derives `cap`, `rho`, `salt`, `rho_refund` and `esk_refund`.
- The deterministic refund box gives `delivery`, and with it `o₀`, then `policy` (with `salt` and
  the stored `orest`), then `cm`, which the wallet checks against the leaf.
- It proves `b₀ = 1` with `w_rest = orest`.
- The path is complete, apart from F-1.

**Escrow (§10).**
- Approvals are stored as `outcome + 1`, so an unset entry never matches. This resolves N-2.
- Approvals are write-once per `(policy_id, arbiter = handle)`.
- The arbiter approves only a `policy_id` that the protected party verified. This resolves N-7.

**`PS01`.** The `x` side carries a zero amount. This resolves N-8.

### Status of all math findings

| ID | Status |
|---|---|
| PN-1 | Resolved (with N-1). |
| PN-2 | Resolved. |
| PN-3 | Resolved. |
| PN-4 | Resolved. Byte-level detail is in F-1. |
| PN-5 | Resolved. The checklist now covers the refund's executability (P-12); the deadline boundary is documented. |
| PN-6 | Resolved. |
| PN-7 | Resolved. |
| PN-8 | Resolved. |
| PN-9 | Mostly resolved. The bridge liveness list remains (F-4). |
| PN-10 | Resolved (with N-5). |
| PN-11 | Resolved. |
| N-1 | Resolved. |
| N-2 | Resolved. |
| N-3 | Resolved. |
| N-4 | Partially resolved (F-1). |
| N-5 | Resolved. |
| N-6 | Resolved. Naming nit in F-2. |
| N-7 | Resolved. |
| N-8 | Resolved. |

### Remaining items (non-blocking)

| ID | Severity | Location | Finding | Failure | Recommended fix | Blocking |
|---|---|---|---|---|---|---|
| F-1 | Low (recovery) | §9.2 l.395-398; `push-payment-spec.md` delivery contract | The pinned refund plaintext reuses "the ordinary note plaintext": a version plus seven **32-byte** fields. On the M31 path, `receiver` and `rho_refund` are nine M31 words (279 bits, 36 bytes), which do not fit a 32-byte field. The version value is not given, and the M31 path has no real ordinary plaintext yet (`m31-sepolia/wallet.py:37` uses synthetic payloads). Until the bytes are fixed, "byte-for-byte" regeneration is not actually specified. | Two wallet implementations, or two versions of one wallet, pick different packings. The refund `delivery` differs, `o₀`, `policy` and `cm` no longer match, and seed-only refund fails. | Before wallet work, define the M31 ordinary plaintext v-number and layout with 36-byte digest fields, for example version, chain, pool, token (32 each), receiver (36), rho (36), amount (16), zero padding. Drop or zero the legacy controller/policy fields. Pin the HKDF byte encoding of `chain ‖ pool ‖ ν`. Add a test vector for the refund box. | Before wallet work only |
| F-2 | Low (spec wording) | §5 step 8 l.218-226 | "`active₀ = active₁ = 1`" (preimage) and "`r`'s bit `z_r` is `active₁`" give the same name to two different things. The preimage's `active₁` is the hashed constant 1; `z_r` is the published activity of slot 1. An implementer who wires the preimage variable to `z_r` hashes 0 when `x = amount`, and the recomputed outcome digest no longer matches. | `x = amount` becomes unprovable, a liveness bug. §10's `x = amount` test would catch it. | Rename `z_r` to, say, `live₁`, and state that the preimage's `active₁` stays 1 in the hash. | No |
| F-3 | Low | §4.2 l.129-133, §5 step 7 | A fixed active output does not have to carry a nonzero `delivery`. With `delivery = 0` the bridge (commitment ⇔ delivery) or the pool (`ZERO_DELIVERY`, `pool.cairo:324/355`) rejects the settlement, and no ciphertext hashes to 0. An `o₀` built this way passes §5 step 6 but can never settle, so the note freezes after the deadline. | This only happens through creator error or a non-standard wallet; the standard refund has a real delivery. | Add "active ⇒ `delivery ≠ 0`" to §4.2 and constrain it in step 7 (one `nonzero_vector_if`), or add it to the counterparty checklist. | No |
| F-4 | Info | §6 step 1, §10 | (a) The P1 bridge's liveness checks are not listed: `index ≤ 3`, `type ∈ {1,2}`, `x = 0 ⇔ type = 1`, delivery ⇔ commitment, withdrawal recipient ⇔ amount, and the address range for `controller` and the recipient. The circuit enforces them already, so this is defence in depth. (b) The escrow's "checks the context (including the token)" has nothing to compare the token against; `policy_id` already binds it. | None, as long as the circuit is correct. | List (a) in §6. Reword (b) as "chain, pool and tag; token is bound by `policy_id`". | No |
