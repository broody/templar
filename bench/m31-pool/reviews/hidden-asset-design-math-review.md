# Math review: hidden-asset spends and ERC721/ERC1155 notes (R0 V4), design stage

2026-09-24. Independent Math Reviewer. I did not write this design and received no implementer
reasoning. Nothing is implemented; this reviews the design only. Scope is soundness and
zero-knowledge; pool token-handling (Q3, Q7) is covered only where it touches a relation
invariant.

## Scope

- Primary: `docs/hidden-asset-spec.md`, §2–4 and §7–8 in full; §5–6 as context.
- Context: `bench/m31-private-wrapper/client-port/src/payment.rs` (`h`, `commitment`,
  `nullifier`, `climb`, `statement`, `statement_limbs`, `build` and its gadgets `nonzero*`,
  `amount`, `amount_unchecked`, `conservation`), `src/merkle.rs` (`guess_bits`), `src/ro.rs`
  (`guess_m31`), `cairo-r0/bridge/src/lib.cairo`, `cairo-r0/account/src/lib.cairo`,
  `bench/m31-pool/cairo/src/{pool,spend,open_note,hash,adapter}.cairo`,
  `docs/policy-note-spec.md` §2, `README.md` (proving architecture, hiding status), and the
  prior review `bench/m31-pool/reviews/policy-note-design-math-review.md` for format.
- Ran: one arithmetic check (the share of felts at or above 2^251, used in HA-M3). No code was
  built or changed.

## Verdict

**CONDITIONAL GO.** I found no soundness or zero-knowledge break in the design.

- The private asset is one witness shared by all four commitments, and input 0 is always a
  proven tree leaf. So a spend conserves exactly one asset, and that asset belongs to an
  existing note.
- The dummy rule (amount forced to zero when `e₁ = 0`) makes skipping membership value-neutral.
  A dummy nullifier cannot equal another note's nullifier without that note's `nk`. Even the
  owner can collide only with a zero-value note.
- The exit rule forces `x = 1` on any withdrawal or intent, whether or not `x` is boolean. So
  `token_out` always equals the spent notes' asset, and is never 0.
- The V4 binding domain alone rules out V3/V4 confusion.

One spec edit blocks implementation: **HA-M1** (Medium). §4.3 has to state the constraint
system precisely enough that the dummy-zero rule cannot be attached to the wrong variables. If
it is, the result is unbounded inflation. HA-M2 to HA-M8 are Low or Info and can be handled
during implementation.

## Findings

### HA-M1 (Medium, blocking as spec text): the constraint system is not pinned to variables

**Problem.** §4.3 gives the new rules as equations, but it does not say which circuit variables
they constrain or which gadgets implement them. Setting `e₁ = 0` switches off membership. The
only thing then standing between a prover and an arbitrary `amount₁` is rule 3's zero
constraint. That constraint is sound only if it acts on the **same** range-checked limb
variables that are hashed into `cm₁` and fed to `conservation`. PN-2 was the same failure class.

Several points are ambiguous today:

- (a) "amounts range-checked, as V3" (§4.3.1). V3's input gadget `amount()` also asserts
  nonzero (`payment.rs:538-544`). Input 1 and both outputs must use `amount_unchecked`
  (`payment.rs:547-562`), and only input 0 keeps `amount()`.
- (b) "`e₁ ∈ {0, 1}`" and "`x ∈ {0, 1}`" name no gadget. They should be `guess_bits(…, 1)`,
  which enforces `b·(b−1) = 0` (`merkle.rs:13-23`).
- (c) The published root must be `root₀` (the climb of input 0, whose `e₀ = 1` is a constant),
  not `root₁`. The V3 unconditional equality `cur[0] = cur[1]` (`payment.rs:727-729`) becomes
  `e₁·(cur[1]ₗ − cur[0]ₗ) = 0` for all nine words.
- (d) One `token₉` witness enters all four NOTE hashes, and one `e₁` variable is used in both
  the amount rule and the membership rule.
- (e) Output commitments are published unconditionally. The V3 `active` machinery goes away:
  `word·a` (`payment.rs:749-751`), the delivery-zeroing (`752-756`) and `nonzero_*_if`
  (`657-666`). The output receiver and rho use `nonzero_vector`.

**Failure scenario.** An implementation range-checks `amount₁` into one set of limb variables
and applies `(1−e₁)·limb = 0` to a second, separately guessed copy. `conservation` or the NOTE
hash reads the first copy. The prover sets `e₁ = 0` and `amount₁ = 2^127` with no membership,
and mints 2^127 units of any asset they hold a note of.

A second scenario: the amount rule and the membership rule use two independently guessed `e₁`
bits. The prover uses `e₁ = 0` for membership and `e₁ = 1` for the amount, and gets the same
mint.

**Required spec change.**
- Rewrite §4.3.1–3 and §4.3.8 normatively, with points (a) to (e) above.
- For the dummy rule, allow either the limb-wise form or V3's sum form
  `sum₁·(1−e₁) = 0`, as in `payment.rs:664-666`. The sum is below 2^19, so it is zero if and only
  if the amount is.
- Add malicious-witness tests:
  - `e₁ = 0` with `amount₁ ≠ 0`;
  - `e₁ = 1` with a non-member input 1;
  - `e₁ = 2`;
  - `x = 0` with `w_amount ≠ 0`;
  - `x = 0` with `intent ≠ 0`;
  - `x = 2` with no exit;
  - input 0 with amount 0;
  - input 1 with a different `token₉` from input 0.

For the record: with the spec as written and implemented on shared variables, non-boolean `e₁`
or `x` is not exploitable.
- `e₁ ∉ {0,1}` makes both rule-3 products bind, so it is stricter than either branch.
- `x ∉ {0,1}` forces `w_amount = 0` and `intent = 0`. `token_out = x·token ≠ 0` is then rejected
  by the §5.2 exit rule, or by the bridge's canonical-limb check.

Booleanity is still required, so the reasoning does not have to lean on the pool.

### HA-M2 (Low): asset well-formedness moves from a per-spend check to a global leaf invariant; state it

**Problem.** V3 checks the token publicly on every spend:
- nonzero (`bridge/src/lib.cairo:120`, `pool.cairo:379`);
- 28-bit limbs and a canonical felt (`bridge/src/lib.cairo:45-56`);
- below 2^251 (`bridge/src/lib.cairo:123`).

In V4 the circuit never range-checks the private `token₉` limbs, and for an in-pool transfer
nobody sees them. Correctness now rests on an induction the spec only sketches (§4.3, after item
9):

- **Leaf invariant I.** Every leaf the pool appends is `H(NOTE, felt_limbs(chain) ‖
  felt_limbs(pool) ‖ felt_limbs(a) ‖ amount₈ ‖ inner)` with `a ≠ 0`, canonical limbs, and `a`
  either registered or an ERC20 address.
- The base cases are the pool-computed paths: `deposit` (`pool.cairo:153-155`),
  `deposit_erc*`, open-note destinations (`open_note.cairo:247`, `pool.cairo:226`), P1 outputs
  (`pool.cairo:285`) and R0 V3 outputs (public token).
- The inductive case is V4 outputs. Input 0 is a member, so `token₉` is the limb vector of an
  existing leaf, by NOTE collision resistance, and the outputs reuse it.

**Failure scenario.** None in the current pool: even if I were broken, no value can be
extracted.
- A leaf with `a = 0` can be moved in-pool, but it can never exit. The pool's exit rule rejects
  `token_out = 0` together with a withdrawal or intent.
- A leaf with a non-canonical limb (≥ 2^28) is a distinct "asset" in the circuit. At exit it is
  rejected by `felt_from_limbs`.

The risk is a future append path, for example a new relation that appends leaves with a zero or
unvalidated context. That path would silently widen what V4 treats as an asset.

**Required spec change.** State invariant I normatively in §3 or §5, with the list of append
paths. Require every future leaf-creating path to preserve it. Adopt Q2's in-circuit
`token ≠ 0` (see the answer to Q2).

### HA-M3 (Low): asset identifiers are felt252 but are typed and bounded as addresses

**Problem.**
- `a = Poseidon(…)` is uniform over `[0, p)`, where p = 2^251 + 17·2^192 + 1.
- The V3 bridge requires `token < 2^251` (`bridge/src/lib.cairo:26,123`).
- `Spend.token`, `OpenDestination.token` and the `Withdrawn` event use `ContractAddress`
  (`spend.cairo:31`, `open_note.cairo:192`, `pool.cairo:110`), which cannot hold values of
  2^251 or more.

About 2^-54.9 of identifiers are at or above 2^251. An honest collection will essentially never
hit one, but anyone can grind `id` for one with about 2^55 Poseidon calls.

**Failure scenario.** Grinding gives an identifier at or above 2^251. Its deposit succeeds,
because the pool computes the limbs itself. Any V4 exit then fails at the bridge bound or at
deserialization, so the asset is stranded. The effect is self-harm only, since the grinder must
own the asset. If a future pool typed the identifier as felt but routed it through an address
cast somewhere, the failure mode would depend on that code.

**Required spec change.**
- Type `token_out` as `felt252` throughout the V4 spend, the binding and `pay_out`.
- Either have `deposit_erc*` reject `a ≥ 2^251` (simplest, and it keeps the bridge bound), or
  drop the bound for `token_out` in the V4 bridge and keep `felt_from_limbs`' canonical check.

### HA-M4 (Low): the V4 bridge rules are unspecified; put the exit rule there

**Problem.** §4.4 says only that the bridge is a new class. The V3 bridge checks do not all
carry over to V4:
- "zero context" includes `token ≠ 0` (`bridge/src/lib.cairo:120`), and "delivery ⇔ active"
  (`:130-132`) and "no output" (`:137`) assume inactive slots.
- These must keep holding: withdrawal recipient ⇔ amount (`:135`), identity ⇒ intent (`:140`),
  distinct nonzero nullifiers (`:103`, `:125`), and the padding limb (`:117`).

§5.2 puts the exit rule `token_out ≠ 0 ⇔ (w_amount ≠ 0 ∨ intent ≠ 0)` in the reference pool
only. That rule is what forces `x = 0` in a pure transfer, and so it is what makes transfers look
alike (§7).

**Failure scenario.** Suppose a second pool, or a later pool version, consumes V4 facts but
omits the rule. Its users can publish `token_out` on in-pool transfers, deliberately or through
a wallet bug. That shrinks everyone's anonymity set. Separately, a bridge that keeps V3's
`token ≠ 0` rejects every pure transfer (a completeness failure).

**Required spec change.** Specify the V4 bridge checks:
- `token_out ≠ 0 ⇔ (w_amount ≠ 0 ∨ intent ≠ 0)`;
- both commitments nonzero, and both deliveries nonzero;
- recipient ⇔ amount, and identity ⇒ intent;
- nullifiers distinct and nonzero;
- the padding is zero.

Give the V4 statement tags for **both** tree formats, as for V3's `R0V3`/`R0C3`
(`payment.rs:55-58`). Name the V4 account message tag (for example `'TMPZR0_PAYMENT_V4'`,
`account/src/lib.cairo:273`). The pool may repeat the checks as defence in depth.

### HA-M5 (Low): recipients must verify the asset by recomputing `cm`

**Problem.** A V3 recipient could cross-check the plaintext's token against the spend's public
token. In V4 the spend publishes `token_out = 0`, so the plaintext's asset field is
authenticated only by recomputing `cm = H(NOTE, chain ‖ pool ‖ a ‖ amount ‖ inner)` and matching
the leaf. Identifier resolution also needs care. "Absent from the registry ⇒ ERC20" (§3) is a
pool routing rule, not something a wallet can check against the plaintext. By invariant I, a
real leaf's `a` is always registered or a deployed ERC20, but only a wallet that recomputed `cm`
knows the leaf is real.

**Failure scenario.** A sender builds a leaf of a worthless ERC20 `W`, with a ciphertext
claiming asset `T`. A wallet that trusts the plaintext and skips the recomputation shows the
recipient a `T` note that cannot be spent as `T`.

**Required spec change.** Make this normative in §6: accept a received note only after
recomputing `cm` from the decrypted fields and matching it at the published index. For a
registered `a`, also recompute `Poseidon('TEMPLAR_ASSET_V1', standard, contract, id)` from the
`AssetRegistered` event.

### HA-M6 (Low): dummy-input derivation must never repeat

**Problem.** §6 says the dummy's `sk`, `rho` and position are "fresh random". A wallet that
instead derives them deterministically, for seed-only recovery or reproducible proving, will
publish the same dummy nullifier from two different spends.

**Failure scenario.** A spend is re-proved against a newer root after a failed or reverted
submission, and a second spend reuses the same dummy. The second one reverts with
`NULLIFIER_USED`. The reverted transaction is public, and the shared dummy nullifier links the
two spends. It also shows that nullifier was a dummy, because a real note cannot be spent twice.

**Required spec change.** Require fresh CSPRNG randomness per proof. If derivation is wanted,
key it on a value unique per spend, such as `nf₀` plus a proof counter, and never reuse it across
different real inputs.

### HA-M7 (Info): the hiding scope and the privacy caveats §7 should add

- (a) The hidden asset, the input count and the output count are hidden from the wrapping server
  and from chain observers only as far as the compact client proof is zero-knowledge. The README
  lists that argument as still under qualification (`README.md:114`, `:191`). V4 adds three new
  private facts inside that argument (`token₉`, `e₁`, `x`); it adds no new public ones. §7
  should say so, as `policy-note-spec.md` §8 does for P1.
- (b) Anyone who holds a note's `nk`, such as a watch-only service, can recompute that note's
  nullifier. So they can tell which of a spend's nullifiers is real, and whether the spend had
  one input or two. This is inherent in the design; state it.
- (c) The observer knows the asset of every leaf except V4 outputs: deposits, V3 outputs, P1
  outputs and open-note destinations are all public. "The anonymity set is every note in the
  pool" is correct for the *input* of an in-pool transfer. For the asset question, the effective
  set is the assets with live notes, and per-asset deposit/withdrawal history narrows it further
  for rare assets and for ERC721s.
- (d) Dummy ciphertexts must be real `crypto_box_seal` outputs, as §6 says, not 304 random bytes.
  The ephemeral X25519 key is not uniform (its top bit is clear), so random bytes would stand
  out.
- (e) A collect-only invoke (`intent ≠ 0`, `w_amount = 0`) is forced to reveal its asset. No
  budget leaves, so soundness does not require the reveal. It is a privacy cost the spec could
  choose to avoid later. It is not a finding against the current design.

### HA-M8 (Info): coexisting with or retiring V3 (see Q8)

**Problem.** Soundness across versions needs one shared nullifier set and one shared root
history. §5.2 implies both but does not state them.

**Failure scenario.** If V4 entry points were given their own nullifier map, one note could be
spent once under V3 and once under V4. The nullifier formula is identical, but the pool would
be checking two different sets.

**Required spec change.** State that V4 uses the pool's existing `nullifiers` map and
`root_history`, including for dummy nullifiers.

## Answers to the review questions

**Q1 (asset-identifier separation): adequate for soundness; keep ERC20 as the raw address.**
- A confusion needs a deployed contract address equal to a registered
  `Poseidon('TEMPLAR_ASSET_V1', std, contract, id)`.
- Hitting a fixed target costs about 2^251 work in either direction: Poseidon preimage, or
  Pedersen-based address grinding.
- Multi-target grinding over N deployed addresses and 2^k ids succeeds with probability about
  N·2^k/2^251.
- The 721 and 1155 tags separate the two standards for one contract. A hybrid contract that
  exposes both views can only affect its own identifiers, so the per-asset invariant (§3)
  still confines the damage.

Tagging ERC20 would add a registry write and break pre-V4 notes, for no soundness gain.
Defence in depth: `deposit` (ERC20) should reject an identifier present in the registry. The
registry should be write-once and written in the same transaction as the first note of `a`.
`pay_out` should route only by the registry. See HA-M3 for the 2^251 bound.

**Q2 (constrain `token ≠ 0` in the relation): not needed for soundness; add it anyway.**
- Soundness does not need it (HA-M2): a zero-asset leaf cannot exit, because both the pool's and
  the bridge's exit rules reject it (HA-M4), and none exists under invariant I.
- The cost is one `nonzero_vector` (`payment.rs:523-535`): nine boolean selectors and one
  inverse. That is negligible next to 68 membership hashes.
- It removes the relation's dependence on every present and future append path.

Do not attempt an in-circuit canonical-limb check. It would cost about 252 bits, and invariant I
plus the bridge check at exit covers it.

**Q4 (dummy input soundness): no inflation, no double spend, no griefing, subject to HA-M1.**
- *Inflation.* With `e₁ = 0`, `amount₁ = 0` is forced on the conserved limbs, so conservation is
  exactly `amount₀ = out₀ + out₁ + w` with input 0 a proven member.
- *Double spend.* A disabled slot cannot consume a real note. Its `cm₁` commits `amount = 0`, so
  it equals a funded note's commitment only through a NOTE collision. An enabled slot needs
  membership under the same root. `nf₀ ≠ nf₁` (bridge and pool) stops one leaf being spent in
  both slots.
- *Griefing.* `nf₁ = H(NF, nk₁ ‖ cm₁ ‖ pos₁)` equals a victim's `nf` only if `nk₁ = nk_v`, which
  needs `sk_v` (a preimage of NK), and also `cm₁ = cm_v` and `pos₁ = pos_v`. Only the owner can
  do it, and only for a zero-value note. That burns nothing. Copying a pending transaction's
  nullifier needs a proof that outputs it, which again needs the preimage. The wrapping server,
  which sees statements early, can refuse service but cannot front-run a nullifier.
- *Self-collision.* See HA-M6.
- *Cross-relation.* P1 nullifiers use `pnk = H(PNK, cap)` and policy receivers, so a dummy
  collision would need an NK/PNK or OWNER/PRECV collision.
- *Zero-value real notes (dummy outputs).* Nobody holds their `sk`, so nobody can spend them,
  and spending them would be value-neutral anyway.

**Q5 (exit with a foreign asset or with `token_out = 0`): not possible.**
- If `w_amount ≠ 0`, some limb is nonzero; it is range-checked below 2^16, so it is a nonzero
  field element. Then `(1−x)·w_k = 0` gives `x = 1`, even without booleanity. The same holds for
  `intent ≠ 0`, whose limbs are below 2^28 by the bridge.
- So `token_out = token`, the single asset witness that input 0's commitment binds to a leaf.
- By invariant I that asset is nonzero, and the pool's exit rule rejects `token_out = 0` in any
  case.
- `hash_intent` binds `token_out` (§5.2), so an intent cannot name a different budget asset.

**Q6 (indistinguishability): holds at the statement, calldata and gas level, subject to the
client-proof hiding caveat (HA-M7a).**
- *Dummy nullifiers* are `H(NF, ·)` over fresh random keys. A real nullifier looks the same to
  anyone without the note's `nk` (HA-M7b).
- *Dummy commitments* hide under a random 9-word `rho` and receiver, the same as real ones.
- *Dummy ciphertexts* are key-private sealed boxes of the same 304-byte length (HA-M7d).
- *Statement.* The layout and circuit are identical for every shape. In a pure transfer
  `token_out`, `recipient`, `w_amount`, `intent` and `identity` are all zero, provided the exit
  rule is enforced (HA-M4).
- *Gas.* Two nullifier writes, one `insert_two`, two delivery-digest writes and two fixed-size
  events happen for every V4 spend. Tree-update cost depends on the leaf index, not on the shape.
- *Proof size.* STARK decommitment size varies only with Fiat–Shamir query positions, which are
  distributed identically for every shape.
- *Remaining leaks.* Exits by definition, the root (it bounds input 0's age, as in V3), and
  transaction metadata.

**Q8 (migration): safe.**
- *Spending pre-V4 notes.* Commitments, nullifiers and the tree format are unchanged, so V4
  spends pre-V4 notes. This requires the shared nullifier set and root history (HA-M8).
- *Nothing ties a note to its creating relation* except public context. Leaves created by
  deposits, V3, P1 or open-note executions have publicly known assets; V4 outputs do not.
- *Coexisting with V3.* Keeping V3 live is still sound. The V3 and V4 bindings have different
  domains (`'TMR0_BIND_V3'` versus `'TMR0_BIND_V4'`). So even a misconfigured adapter that
  accepted both account tags could not make a V3 fact match a V4 `compute_binding`, or the
  reverse. One adapter per relation (`adapter.cairo:8-11`) is the intended configuration.
- *Why retire V3.* A V3 spend of a V4-created note republishes that note's asset, and V3
  transfers keep partitioning the tree by asset, which weakens V4's privacy. Retiring V3 is
  therefore recommended. V3 facts still in flight at the switch simply revert, and their
  nullifiers remain unspent, so users re-prove under V4.
- *Wallets* must stop relying on the public token (HA-M5).

**Q3 (outside the focus, relation angle only).** P1 requires `1 ≤ x ≤ amount`. For an ERC721
policy note (amount 1), a split is therefore the full note to `out₀` with a zero remainder, which
is a fixed outcome. Rejecting splits in the pool is harmless and gives clearer errors, but
soundness does not need it.

## What I checked and found sound

- **One asset per spend.** One private `token₉` enters the context of all four NOTE hashes
  (§4.3 preamble). Cross-asset spending would need a NOTE collision.
- **Conservation.** The V3 gadget (`payment.rs:571-614`) is unchanged, with two inputs and three
  outputs. A zero dummy or zero outputs do not change the carry bounds {−2..1}.
- **Membership.** Input 0 always climbs to the published root, which the pool checks against
  `root_history`. An enabled input 1 must reach the same root.
- **Nullifier uniqueness per leaf.** This is unchanged from V3: the position is 32 boolean bits,
  packed lo/hi. Dummies use the same derivation and the same set.
- **Identity.** `sk₀` is the real input's key. The bridge's identity ⇒ intent ⇒ `x = 1` chain
  keeps a handle from ever appearing on a pure transfer.
- **Binding.** The field order is unchanged, with `token_out` in the token slot and a new domain
  tag. `token_out = 0` on pure transfers loses no binding, because the asset is bound inside the
  commitments.
- **ERC721 amount.** The relation treats `a` as opaque. Per-asset conservation and the deposit
  rule (amount 1) keep the total of an honest ERC721 asset at 1, so zero-value dummy outputs of
  that asset are harmless.

## Re-review of revision 2

2026-09-24. Same role and constraints: I reviewed the text only and changed nothing except this
file.

**Scope.** I read `docs/hidden-asset-spec.md` revision 2 in full. I checked §4.1–4.5 against
`payment.rs` (`build` :632-782 and its gadgets), `merkle.rs:13-23` and the V3 bridge
(`bridge/src/lib.cairo`). I read §3.1–3.3, §5.1–5.6 and §6–7 for relation invariants, and the
protocol review (`hidden-asset-design-protocol-review.md`) for the origin of the hook and `held`
changes. I ran nothing.

### Verdict

**GO.** Revision 2 resolves every prior HA-M finding. None of its changes introduces a soundness
or zero-knowledge issue.

The relation is now specified to the variable level:
- one `token`, one `e₁` and one `amt₁` shared by every rule;
- `root = cur₀`;
- `guess_bits` for both bits;
- the right amount gadget for each slot.

Its argument closes without relying on the pool, apart from invariant I:
- An exit forces `x = 1`, so `token_out = token ≠ 0`.
- The bridge's exit rule forces `x·token = 0` on a pure transfer. `nonzero_vector(token)`
  (§4.3.1) then forces `x = 0`.
- The dummy rule `sum₁·(1−e₁) = 0` acts on the conserved limbs.

The three new items below (HA-M9 to HA-M11) are Low or Info and can be handled during
implementation.

### Status of prior findings

| ID | Status | Notes |
| --- | --- | --- |
| HA-M1 | **Resolved** | §4.2 pins every witness and says it is created once. §4.3.2–3 use `amount` for input 0 and `amount_unchecked` for input 1, with the dummy rule on the same `sum₁`. The membership rule is `e₁·(cur₁,ℓ − cur₀,ℓ) = 0` and the published root is `cur₀`. §4.3.5 removes the `active` machinery. §4.4 lists the malicious-witness tests; HA-M10 adds a few. |
| HA-M2 | **Resolved** | §3.3 states invariant I with its four append paths and requires future paths to preserve it. §4.3.1 constrains `token ≠ 0`, and says canonicity is left to invariant I plus the exit check. |
| HA-M3 | **Resolved** | §3.1 rejects registration at or above 2^251. V4 fields are `asset: felt252`, and the bridge checks `token_out < 2^251`. This also keeps the unchanged P1 bridge's bound valid. |
| HA-M4 | **Resolved** | §4.5 lists the V4 bridge checks: the exit rule is in the bridge, `token ≠ 0` is dropped, both commitments and deliveries are nonzero, recipient ⇔ amount, identity ⇒ intent, and the padding is zero. Tags `R0V4`/`R0C4`, `'TMR0_BIND_V4'` and `'TMPZR0_PAYMENT_V4'` are named. One nit is in HA-M10. |
| HA-M5 | **Resolved** | §6 receiving rule: recompute `cm` and the registered identifier, reading events from the pool's address. |
| HA-M6 | **Resolved** | §6: dummy-input values come from a CSPRNG for every proof, independent of seed counters, including on re-proof. |
| HA-M7 | **Resolved** | §7 now covers the hiding scope (a), full viewers (b) and the weighted anonymity set (c). §6 requires real sealed boxes for dummies (d). §1 puts collect-only reveal out of scope (e). |
| HA-M8 | **Resolved** | §5.2 uses a single `nullifiers` map and `root_history`, and dummies are marked. §5.6 makes V2 a fresh pool, so V3 never coexists with it and the cross-version question disappears. |

### Changes outside §4 checked against the relation

- **Invariant I and the append paths (§3.3).** I checked each path.
  - The hook deposits and ERC20 `deposit` compute `cm` in the pool from `felt_limbs(a)` with
    `0 < a < 2^251`.
  - Destination funding computes `cm` from `dest.token`, a `ContractAddress` that is recorded as
    ERC20 and is not in the registry.
  - P1 outputs reuse the public token of a proven input leaf, so they inherit I.
  - V4 outputs reuse the witness `token` of member input 0.

  The induction holds. The bound `a < 2^251` also means the V4 bridge's `token_out < 2^251`
  check never rejects a legitimate exit.
- **Push deposits through receiver hooks (§5.1).** The asset is derived from
  `C = get_caller_address()`, so no caller can spoof it. Any contract can call
  `on_erc1155_received` or `on_erc721_received` directly. That only creates notes of
  `H(std, caller, id)`, which is the caller's own identifier. The §3.3 model already accepts this
  ("a malicious contract can affect only notes of its own identifiers"). The same holds for an
  upgradeable collection that is later made malicious. The hook takes the lock, so it cannot run
  inside a spend or inside a payout's recipient hook. Hooks append ordinary NOTE leaves, so the
  relation is unaffected. HA-M9 covers encoding details.
- **`held[a]` accounting.** The accounting is consistent with the relation. A V4 spend proves
  `amt₀ + amt₁ = out₀ + out₁ + w` for one asset. Dummies contribute 0 on both sides, and
  `pay_out` subtracts exactly `w`. So "Σ unspent notes of `a` = `held[a]`" is preserved by V4
  spends, P1 settlements (same conservation), deposits and destination funding. The ERC721 hook's
  `held[a] == 0` precondition, together with the ERC721 deposit amount of 1, keeps each ERC721
  asset's total at 1. Zero-value ERC721 dummy notes do not change `held`.
- **Fresh pool, no V3 (§5.6).** This removes the only cross-version soundness question (HA-M8).
  P1, unchanged, uses the same nullifier map in the V2 pool (§5.2).
- **Zero-knowledge.** No change publishes a new field on in-pool transfers. `token ≠ 0` and the
  bridge rules are either private or constant across honest transfers. The hook deposits are
  public, as deposits already were.

### New findings

**HA-M9 (Low): the hooks' encoding rules for amount, `inner` and `held`.**
- *Problem.* `on_erc1155_received` receives `value: u256`, but a note amount is u128 (eight
  16-bit limbs). §5.1 does not require `value < 2^128`. Nor does it say that the hook `data`'s
  `inner₉` is parsed with `read_digest` (canonical M31 words, `hash.cairo:126-133`) or that the
  ciphertext goes through `delivery_digest`'s word bounds, as `deposit` does. `held[a]` also has
  no stated type. A per-asset sum of u128 notes can exceed 2^128 for a token whose supply is that
  large.
- *Failure scenario.* An implementation truncates `value` to `value.low`. A transfer of
  2^128 + 5 then yields a note of 5, while `held[a]` grows by the full value, or the other way
  round. Either way, "notes = `held`" breaks for that asset. A non-canonical `inner` word yields
  a leaf the M31 circuit cannot open. Both outcomes are confined to the depositor's own funds,
  but the second silently strands value.
- *Required spec change.*
  - Require `value ≤ 2^128 − 1`, and revert otherwise.
  - Parse `inner` with `read_digest` and the ciphertext with `delivery_digest`.
  - Type `held` as u256, or state that a deposit which would overflow a u128 `held` reverts.

**HA-M10 (Info): completeness tests and two bridge nits.**
- *Problem.* The §4.4 list covers soundness. It lacks some negative cases:
  - `x = 1` with no exit (a voluntary reveal; the bridge must reject it);
  - `e₁ = 1` with input 1 equal to input 0 (duplicate nullifier; the bridge rejects it).

  It also lacks positive cases that catch over-constraining regressions:
  - an `e₁ = 0` dummy with a random non-member path and position proves;
  - a pure transfer with `token_out = 0` passes the V4 bridge;
  - a single-input ERC721 spend (1 → 1 + 0) proves.

  Separately, §4.5 drops V3's `pool < 2^251` check (`bridge/src/lib.cairo:123`). This is harmless,
  because the pool compares `pool` to its own address. Wallets must also sample dummy `sk`/`rho`
  words uniformly in `[0, p)`, since `nonzero_vector` and `guess_m31` expect canonical words.
- *Required spec change.* Add the listed tests. Keep the `pool < 2^251` check for parity. State
  the sampling range in §6.

**HA-M11 (Info): a reverted exit reveals its asset.**
- *Problem.* Calldata of a reverted transaction is public. An exit that reverts at the pool
  exposes `asset` without moving value. Examples: `apply_spend_with_invoke` with a registered NFT
  (rejected per §5.2), an ERC1155 recipient without a receiver (HA-P7), or an expired intent.
  Pure transfers are unaffected, because their statement has `asset = 0`.
- *Required spec change.* In §6, require wallets and relayers to simulate exits before
  submitting. §6 already asks this for ERC1155 recipients; extend it to every exit. Note the
  leak in §7.
