# Account-bound notes (R0 V5): math review of design revision 1

- Reviewer: independent Math Reviewer (did not write the design)
- Date: 2026-09-25
- Under review: `docs/account-bound-note-spec.md` (revision 1), `docs/adr/0026-account-bound-notes.md`
- Scope: §3 receivers and S1–S4; §4 relation R0 V5; §5 bridge, binding, spend message and
  statement account; §6 seed and key derivations and the §6.4 SDK rules; §14 questions. Pool,
  server, relayer and privacy are for the protocol reviewer and appear here only where they affect
  soundness.
- Nothing is implemented. Every statement about V5 below is about the text; statements about V4
  are about the code at `94a4298`.

## 1. Verdict

**CONDITIONAL GO.**

S1–S3 hold at the Poseidon2-M31 design level V4 already relies on. The mode rule and the per-word
select admit no mismatched `m`, `account` or `ak`. The account binding is sound (§14 Q2, Q6).
Two things are wrong. S4 ("a key leak is privacy only") fails as written: an ordinary-mode spend
can reproduce a bound wallet's identity handle (AB-M1). And the conservation gadget as referenced
cannot prove a few percent of exits (AB-M2).

Conditions, all spec changes before P2 starts:

1. **AB-M1 (high):** make the identity handle depend on the mode and the account, or forbid it in
   bound mode. Add the tests listed there.
2. **AB-M2 (medium):** state the widened carry range {−3,…,1} and its soundness argument, keep P1's
   gadget unchanged, and add the completeness and tamper tests.
3. **AB-M3 (medium):** extend §6.4 so that the SDK derives no spend authority from `S_w` other than
   bound receivers. This covers policy capabilities, shadow scopes and every self-directed
   receiver.

The low findings should go into revision 2. A short re-review of the revised identity rule and the
conservation text is enough; the rest need no re-review.

## 2. Findings

### AB-M1 (high): the identity handle ignores the mode and account, so a leaked bound key controls the wallet's shadow accounts

- **Section:** §4.3 (the identity paragraph: "stays `H(IDENTITY, sk₀ ‖ scope)` … in either mode"),
  §3.4 S4, §6.4.
- **What is wrong.** Shadow accounts are authorized by the handle alone. `open-note-spec.md`
  ("Shadow accounts") and the ADR-0023 amendment say only the owner of `sk₀` can produce a handle.
  In V5 the handle is the same function of `(sk₀, scope)` in both modes. Anyone who knows `sk` can
  compute the *ordinary* receiver of that key, `H(OWNER, H(AUTH, sk) ‖ H(NK, sk))`, and deposits are
  permissionless.
- **Failure scenario.** This is the S4 threat, `S_w` leaked at rest:
  1. The attacker derives `sk_w(i)` and the wallet's shadow `scope`, which comes from the wallet
     secret (`open-note-spec.md`, `shadow_scope`).
  2. The attacker deposits one unit of any ERC20 to `inner = H(INNER, R_ord ‖ rho)`, where
     `R_ord` is the ordinary receiver of `sk_w(i)`.
  3. The attacker proves an ordinary V5 spend (`m = 0`, `account = 0`) of that note, with the
     identity flag set, the victim's `scope` and a `COMPUTE` intent to the shadow anonymizer. The
     statement's `identity` equals the victim's handle.

  The bridge accepts it, since identity ⇒ intent holds. The statement account makes no call,
  because `account = 0`. The pool derives the victim's identity commitment. The attacker now acts
  as the victim's shadow account and can move its positions out, with no signature from the
  account. The same works through a bound spend under the attacker's own account `M`, because the
  handle does not involve the account.
- **Required change.** Pick one:
  - **(a) Preferred:** `handle = H(IDENTITY, ak₀ ‖ scope)`, where `ak₀` is input 0's per-word
    selected key (`H(AUTH, sk₀)` in ordinary mode, `H(WAUTH, account ‖ sk₀)` in bound mode). This
    costs no extra permutation. Reproducing a bound handle then needs `H(AUTH, sk′) = ak_w` or
    `H(WAUTH, M ‖ sk′) = ak_w`, a second preimage as in S1/S2. A full-viewing-key holder knows `ak`
    but still cannot publish a handle, because the circuit derives `ak` from `sk`. This also
    changes ordinary-mode handles, so the positive test "ordinary V5 statement equals V4 on every
    shared field" must exclude `identity`. State whether V2-era shadow accounts must stay
    addressable.
  - **(a′):** keep the ordinary handle and, in bound mode, use `H(IDENTITY_W, ak_w ‖ scope)` with a
    new kind. Compute both hashes and select per word by `m`. This costs one more 22-word hash.
  - **(b):** the bridge rejects `identity ≠ 0` when `account ≠ 0`, the SDK never derives shadow
    scopes for a bound wallet, and the spec states that bound wallets have no shadow accounts.
  - **Do not** feed `sk₀` in ordinary mode and `ak_w` in bound mode into the same input slot of one
    `IDENTITY` hash. An attacker can use `sk′ := ak_w` as an ordinary spending key, fund its
    ordinary receiver and reproduce `H(IDENTITY, ak_w ‖ scope)`.
- **Tests.** For one `sk` and `scope`, the ordinary and bound handles differ. A bound spend under
  `M ≠ A` with `A`'s `sk` does not reproduce `A`'s handle. Under option (b), a bound statement
  with a nonzero identity is rejected by the bridge.

### AB-M2 (medium): four subtracted terms need carries down to −3; the V4 gadget makes some exits unprovable

- **Section:** §4.3.4, §4.4, §4.5 ("a larger conservation").
- **What is wrong.** The spec passes `[out₀, out₁, out₂, withdrawn]` to `conservation` without
  restating the carry range. The shared gadget (`payment.rs:569-614`) hard-codes carries in
  {−2,…,1}: the quartic `n(n−1)(n+1)(n+2)` and `clamp(-2, 1)`. That range was derived for three
  subtracted terms. With four terms a limb difference lies in (−4·2¹⁶, 2·2¹⁶), and honest carries
  reach −3.
- **Evidence (executed; `carry.py` mirrors the gadget's carry logic).**
  - The witness `in₀ = 0x30000`, `in₁ = 0`, `out₀ = out₁ = out₂ = 0xFFFF`, `w = 3` (the sums are
    equal) needs carry −3 at limb 0.
  - I split random inputs four ways, as an exit with payment, change, fee and withdrawal. The share
    of splits that need carry −3 is 0.85% for amounts below 2³², 2.5% below 2⁶⁴ and 5.5% below
    2¹²⁷.
  - Transfers (`w = 0`) never go below −2. Only exits that carry a fee and change are affected.
- **Impact.** Soundness is not affected, because a narrower carry set is stricter. Completeness is:
  a random fraction of exits fails only after a full proof attempt.
- **Required change.**
  - State the carry set {−3, −2, −1, 0, 1}, constrained by `n(n−1)(n+1)(n+2)(n+3) = 0` or an
    equivalent range check.
  - Give the argument: `|d_k| ≤ 4(2¹⁶−1)` and `|c| ≤ 3`, so every term of each limb equation is
    below 2¹⁹ ≪ p. Each equation therefore holds over the integers and telescopes with
    `c₀ = c₈ = 0`.
  - Implement V5's gadget separately or parameterized by term count. `payment.rs` (V3),
    `payment4.rs` (V4) and `policy.rs` (P1) share the current gadget, P1 is declared unchanged, and
    editing the gadget in place would change P1's circuit hash.
  - Tests: the witness above as a positive test. Carries −4 and +2 rejected through a tamper hook.
    Update the F09 regression list from {−2..1} to {−3..1}.

### AB-M3 (medium): §6.4 forbids only ordinary receivers; other key-only authorities derived from `S_w` turn a leak into theft

- **Section:** §6.4, §1 (policy notes out of scope), §3.4 S4.
- **What is wrong.** Any spend authority the SDK derives from `S_w` alone makes an `S_w` leak a
  theft of what it controls:
  - **P1 policy capabilities.** `s_pol = HKDF(S, 'TEMPLAR_POLICY_SEED')` and `cap` is derived from
    `s_pol` (`sdk-spec.md` §3.2, `policy-note-spec.md` §9). P1 settles with no account call.
  - **Shadow scopes** (together with AB-M1).
  - **Every receiver the SDK uses for itself** beyond "change": deposit receivers, open-note
    destinations and return notes, and a policy's refund outcome.

  Outputs are unconstrained, so a bound spend can also pay a policy receiver. That value then
  leaves the account binding.
- **Required change.**
  - §6.4 lists every self-directed receiver (change, deposits, open-note destinations and returns)
    as a bound receiver of the same account.
  - The SDK derives no `s_pol`, capability or scope from `S_w`, and refuses to create policy notes
    from a bound wallet. Alternatively, it warns that such value is protected by `S_w` alone and
    requires confirmation.
  - S4 is restated to cover bound notes only.

### AB-M4 (low): seed extraction trusts the array layout; the guardian text contradicts §6.2; s-normalization changes the seed

- **Section:** §6.2, §10 (guardian bullet), §11.
- **(a) Guardian contradiction.** §6.2 refuses any layout other than `[r, s]`, `[1, 0, pk, r, s]`
  and `[1, r, s]`, and never uses guardian cosignatures. A guardian account's derivation signature
  (two signers) is therefore refused, and setup cannot finish. §10 says guardian accounts work if
  the wallet adds the cosignature. Choose one:
  - If guardian accounts are refused for bound setup, say so in §10 and §11.
  - If they are supported, specify how the owner entry is extracted, and record this risk
    (inference, not verified): a wallet may send the owner's derivation signature to the guardian
    service to request the cosignature, which would give that service `S_w`.
- **(b) Verify the signature.** Before using `(r, s)`, the SDK should verify it as a Stark ECDSA
  signature on the derivation hash under the owner public key read from the account at a fixed
  block. Secrecy of `S_w` then rests on the owner key's unforgeability rather than on the wallet's
  array formatting.
- **(c) s-normalization.** ECDSA in general accepts both `(r, s)` and `(r, n − s)`. A wallet release that changes s
  normalization changes `S_w`. Either canonicalize (for example `min(s, n − s)`) before HKDF, or
  state that the unlock check will then force a restore.
- **(d) Restore.** Take `A` from the connected wallet, never from typed input. A wrong `A` derives
  unrelated keys whose received notes freeze.

### AB-M5 (low): the binding-to-account argument is right but gives the wrong reason

- **Section:** §4.3 ("The binding reaches the account through input 0"), §14 Q2 and Q6.
- **What is wrong.** The binding determines `account` by collision resistance alone:
  - The chain is `nf₀ = H(NF, nk₀ ‖ cm₀ ‖ pos₀)`, then `cm₀`, `inner₀`, `receiver₀`, `ak₀`. In
    bound mode `ak₀ = H(WAUTH, account ‖ sk₀)`.
  - Two accepted statements with equal bindings but different `account` or mode imply a Poseidon2
    collision or second preimage somewhere on that chain.
  - Membership and "input 0 is real" play no part. `nf₁` also binds the account in bound mode,
    because a dummy input 1's receiver is computed with the same `account`.
  - So a future dummy input 0 would not, by itself, break the link.
- **Required change.** State the invariant normatively: every accepted statement's binding
  contains a digest that is a collision-resistant function of `(m, account)`. Name what would
  break it: a nullifier or commitment format whose derivation no longer passes through `ak`.

### AB-M6 (low): the one load-bearing wiring rule for S3 has no mutation-kill test

- **Section:** §4.2, §4.3.2, §4.4.
- **Load-bearing rules.** S1–S3 rest on:
  - (i) the `account` words hashed by WAUTH are the same variables as the published `account`
    limbs;
  - (ii) `ak` takes exactly one of the two hash values (the select, with `m` boolean);
  - the statement account calling `account` whenever it is nonzero;
  - the bridge's canonical decoding.
- **Hygiene rules.** Both legs of the mode rule and the sharing of `m` across inputs only keep the
  statement tidy:
  - Without leg 1, an ordinary note could be spent under an unneeded signature.
  - Without leg 2, only self-made `H(WAUTH, 0 ‖ sk)` receivers become key-only.
  - With a separate `m` per input, a spender could mix their own ordinary and bound notes.

  None of these allows theft.
- **Gap.** The listed test "a note bound to `A` spent with `account = A′`" does not kill a mutant
  that guesses the published account separately from the hashed one. The honest hint code fills
  both from one value, so the test must use a raw tamper hook.
- **Required change.**
  - Add tamper hooks for (i) published account ≠ hashed account, and (ii) a mode bit per input.
  - Extend V4's "output under a different asset" test to slot 2: `cm₂`'s NOTE hash must use the
    shared `context`, so leaf invariant I holds for the new append path.

### AB-M7 (low): setup checks only acceptance; any signer the account accepts can authorize spends

- **Section:** §6.4 (setup checks), §10, §11.
- **What is wrong.** Bound notes are only as safe as the account's `is_valid_signature`. Setup
  checks that it accepts a test signature, never that it rejects anything.
- **Required change.**
  - Setup also checks, at the same block, that the account rejects a tampered signature and a valid
    signature over a different hash.
  - The compatibility matrix records, per class, every signer that `is_valid_signature` accepts:
    owner, guardian, a guardian-driven escape after its delay, and any session or secondary signer.
    Whether Ready or Braavos accept session or secondary signers here is an inference I did not
    verify.
  - §10 states that each such signer can authorize bound spends.

### AB-M8 (low): re-deriving the seed on every unlock exposes `S_w` at every unlock

- **Section:** §6.4 (backup and key changes).
- **What is wrong.** Each unlock asks the wallet for the derivation signature, which exposes it and
  so `S_w` to the page. It also trains users to approve the one prompt that §10 names as the
  phishing vector.
- **Required change.** Re-derive at setup, at restore, on an explicit check, or after a failed
  authorization. If the signature is meant to be the unlock factor, say so and state the exposure.

### AB-M9 (low): intent-bearing spends are as opaque on the wallet screen as in-pool transfers

- **Section:** §5.3, §10 ("Compromised frontend at spend time").
- **What is wrong.** For `INVOKE` and `COMPUTE` the wallet shows `intent` as a bare felt, with
  destinations and calldata hidden inside it. Only a plain withdrawal (`intent = 0`) can be checked
  on screen: `token_out`, recipient and amount. In addition, an NFT's `token_out` is an asset hash
  typed `ContractAddress`, and wallets will display it as an address.
- **Required change.** Reword §5.3 and §10 accordingly.

### AB-M10 (info): S1 and S2 are second-preimage problems; WAUTH adds no new sponge shape

- **Section:** §3.4, §14 Q1.
- **S1.** An ordinary spend of a note with receiver `R = H(OWNER, ak_w ‖ nk)` needs one `sk′` with
  `H(OWNER, H(AUTH, sk′) ‖ H(NK, sk′)) = R`. That is a second preimage of the receiver (or of
  OWNER), not a collision. Matching `ak` alone is not enough, because `nk` must come from the same
  `sk′`.
- **S2.** It needs `(A′, sk′) ≠ (A, sk)` with `H(OWNER, H(WAUTH, A′ ‖ sk′) ‖ H(NK, sk′)) = R`.
  Even with `sk` leaked, fixing `sk′ = sk` leaves 251 free bits of `A′` against a 279-bit target,
  so no solution is expected. The attacker has to vary `sk′` as well.
- **Bounds.**
  - Generic bounds are 2²⁷⁹ from the output and 2¹³⁹·⁵ from the capacity. The effective level is
    Poseidon2's 128-bit design claim (F42: rounds (8,22) against a minimum of (6,20)).
  - Birthday bounds matter only to a party that picks both receivers, which here is the note's own
    creator, who gains nothing.
- **Structure.** WAUTH's framed input is 22 words, exactly like OWNER's and INNER's: a 15-word
  block, then 7 words padded with `1 ‖ 0⁷`, two permutations. It is not a new length or mode.
  Kinds are separated by word 2 of the first block (AUTH is a 13-word, one-permutation input). The
  padding is injective: 10* on a short final block, a capacity flag on a full one.
- **Caveat.** F42's literature caveat (checked from memory only) applies unchanged.
- **Change.** Reword S1 and S2 as above.

### AB-M11 (info): statement-account details

- **Section:** §5.4, §10 (padding).
- **(a)** V5's `__validate__` must take V5's calldata `(proof_data, salt, signature)`. R4's takes
  `proof_data` only.
- **(b)** The statement account must not expose an `is_valid_signature` that returns `VALID`, or
  the account must reject `account` equal to its own address. The same applies to §10's proposed
  "Templar null-signer account" if it is a real contract: notes bound to either address would be
  key-only, and the SDK must never bind to them.
- **(c) Optional:** require `salt ≠ 0` in bound mode, so that a client bug cannot expose
  `Poseidon(binding, 0)` to scanners.

## 3. Answers to §14

1. **S1–S3 under Poseidon2-M31 (8,22) with the 22-word WAUTH input.** They hold, at the same
   128-bit design level as every V4 note hash (AB-M10). The WAUTH input has the block structure of
   OWNER and INNER. S3 also needs the WAUTH account words to be the published limbs (AB-M6 (i)),
   plus the bridge's decoding. `felt_from_limbs` rejects limbs ≥ 2²⁸ and values ≥ p, and V5 adds
   `< 2²⁵¹`, so the limb encoding of an address is injective. S4 does **not** hold as written
   (AB-M1, AB-M3).
2. **Is the link through input 0 sufficient, with the SNIP-12 envelope?** Yes. The reason is the
   nullifier chain's collision resistance, not input 0 being real (AB-M5). Within one execution,
   the statement account uses `statement.account` both in the signed hash and as the call target,
   so the signer and the proven account cannot differ. A signature cannot be replayed across two
   accounts that share a key: the envelope's account slot and the nullifiers both differ.
3. **Any witness with a mismatched `m`, `account` or `ak`?** No.
   - `m` is boolean.
   - Leg 1 gives `m = 0 ⇒ account = 0`.
   - Leg 2 gives `m = 1 ⇒ account ≠ 0` as M31 words: nine boolean selector bits sum to 1 (9 < p)
     and `picked · inv = m`. Once the bridge accepts canonical limbs, that means `account ≠ 0` as a
     felt.
   - The select gives `ak ∈ {H(AUTH, sk), H(WAUTH, account ‖ sk)}` per word.
   - Any other `ak` needs a second preimage.
   - The statement account decides from `account` alone, which matches `m` through the legs. Which
     rules are load-bearing: AB-M6.
4. **Seed derivation.**
   - `(r, s)` extraction: AB-M4.
   - 224 bits is enough. With RFC 6979, `(r, s)` carries about 251 bits that cannot be predicted
     without the owner key: predicting them would be a forgery. HKDF-SHA256 extracts in the random
     oracle model. The multi-target margin exceeds 2¹⁹⁰ for 2³⁴ users.
   - The word-count marker is sound given `sdk-spec.md` §3.1 (ordinary import takes 24 words and 32
     bytes only) and a bound import that takes 21 only. It is the only barrier against importing
     `S_w` as an ordinary seed, which would create key-only receivers, so test both directions.
   - The derivation and spend messages are separated by domain version (`KEY1` vs `V5`) and primary
     type. The spike's derivation message used purpose `TEMPLAR_SECRET_V1` and version `1`, so no
     spike signature is a production seed.
5. **Three outputs: dummy input, sticky companion, conservation.**
   - The dummy-input rule is unchanged: `e₁` forces input 1's amount to zero.
   - In bound mode the dummy's receiver uses the shared `m` and `account`, so its nullifier depends
     on the account. That is why §6.4's companion rule is needed. It also means that someone
     holding a leaked store cannot publish a bound companion's nullifier without the account's
     signature.
   - The extra output does not affect companions.
   - Conservation: AB-M2. Slot 2 must use the shared asset context (AB-M6).
   - A protocol note, not a math finding: an ERC721 spend (amount 1) can only put fee 0 in slot 2,
     so F22 stays open for NFTs.
6. **Can the pool accept a statement whose signed account differs from the proven one?** No path
   found.
   - The pool sees only `binding`.
   - The adapter accepts only the statement account's message. It pins the sender address, class
     and tag, and `MESSAGE_COUNT = 1` also rejects a callee that emits its own message.
   - That account builds the hash and makes the call from `statement.account`.
   - Any statement with the same binding has the same account, up to a Poseidon2 collision
     (AB-M5).
   - A same-binding statement with `account = 0` would be an ordinary spend of a bound note, which
     S1 excludes.
   - A felt252 Poseidon collision on the binding would at most apply the victim's own spend as
     signed.

## 4. What I checked, how, and what I could not check

**Read.**
- The spec and the ADR.
- `hidden-asset-spec.md` (R0 V4).
- `sdk-spec.md` §3 and §4.2 (full viewing keys contain `ak`).
- `open-note-spec.md` (shadow accounts, scope derivation) and `policy-note-spec.md` §3 and §9
  (capability derivation).
- The ADR-0023 amendment.
- Battle test §1, F09, F15, F42 and the open questions.
- `payment.rs` (framing, sponge, gadgets, conservation), `payment4.rs` (V4 build and
  `bridge_checks`), `membership.rs` (sponge, lanes, equal-length assertion), `merkle.rs`
  (`guess_bits` booleanity) and the policy kinds.
- `cairo-r4` bridge (`felt_from_limbs`, binding) and account.
- `adapter.cairo` (message hash over sender, class, tag, chain, pool, binding; count = 1).
- The spike's SNIP-12 module, SigProbe, the fork tests and the typed data.

**Commands.**
- Hash kinds under the `TMR0` frame: `grep -rhoE "pub const (AUTH|…|POLICY_ID): u32 = [0-9]+"
  bench/m31-private-wrapper/client-port/src`. Result: kinds 1–15 only.
- `grep` over `bench`, `sdk` and `server` for frame words: other M31 hash families use different
  first words (`0x544d5031`, `0x4d335053`, `0x544d5041`). The Cairo `hash.cairo` uses 4, 5, 6 and
  8, and SDK core calls only the relation's own hash functions (`keys.rs`, `note.rs`, `tree.rs`).
  Kind 16 is unused everywhere, and `WAUTH` appears only in the two design documents.
- `python3 carry.py` in the session scratchpad: the explicit witness and Monte Carlo for AB-M2,
  the V5 statement size (156 limbs, 39 QM31 outputs, confirmed) and the transfer-only worst carry
  (−2).
- Counted WAUTH's block layout (22 = 15 + 7).
- Read `target/wallet-sig-spike/probe/snforge-fork-tests.log`: 13 SigProbe tests passed. The
  guardian test is not in that log.

**Not checked.**
- No builds, proofs or snforge runs. The spike was not re-run, and no RPC calls were made.
- Whether Ready or Braavos `is_valid_signature` accepts session or secondary signers (AB-M7), and
  whether guardian cosigning receives the owner's signature (AB-M4): both inferred.
- The current literature on Poseidon2 (8,22) (F42 open item): no network access, not re-checked.
- Whether PROOF2 hides the account from the gateway operator (ADR-0024 gate): out of scope.
- The §13 node-simulation discrepancy: not investigated. The design relies on the virtual OS
  accepting valid signatures and rejecting tampered ones, not on node simulation. Any pre-check
  should use a direct call until the discrepancy is explained.

## Re-review of revision 2

- Date: 2026-09-25. Revision 2 of `docs/account-bound-note-spec.md`, math scope only. I read §3–§6
  in full, and §8.6, §12, §13 and §17 for the points that touch soundness.

### Verdict

**GO.** Every earlier finding is resolved. The three new mechanisms are sound: the widened
conservation gadget, the identity handle over the selected key, and deterministic companions. One
new low item (AB-M12) can be closed during implementation (P2/P4) and needs no re-review.

### Items re-reviewed in full

- **§4.3.4 `conservation5`: correct.**
  - `c(c−1)(c+1)(c+2)(c+3) = 0` has exactly the roots {−3, …, 1}.
  - With every limb below 2¹⁶, each limb equation has absolute value below 2¹⁹ ≪ p, so it holds
    over the integers. The equations telescope, with `c₋₁ = c₇ = 0`, to
    `Σ 2¹⁶ᵏ (Σ inᵏ − Σ outᵏ) = 0`.
  - Completeness matches my round-1 simulation: carry −3 is reachable only with four nonzero
    subtracted terms.
  - Keeping the V3, V4 and P1 gadget unchanged is right. The honest-carry hint must clamp to
    {−3, …, 1}; the positive test with carry −3 covers that.
- **§4.3.5 identity over `ak₀`: correct.**
  - To reproduce a bound handle `H(IDENTITY, ak_w ‖ scope)`, an ordinary spend needs
    `H(AUTH, sk′) = ak_w`, and a bound spend under `M ≠ A` needs `H(WAUTH, M ‖ sk′) = ak_w`. Both
    are second preimages, and the attack in AB-M1 is closed.
  - A full-viewing-key holder knows `ak` but cannot publish a handle.
  - The 18-word payload keeps the existing hash shape.
  - The "never feed `sk₀` and `ak_w` into one slot" warning is included.
- **§6.4 deterministic companions: sound, and no privacy loss compared with the sticky rule.**
  - HA-M6 asked that a derived dummy be keyed per real input and never reused across different
    real inputs. `(cm, leaf index)` is unique per note, so this holds up to an HKDF collision.
    Reuse within one note was already accepted by SDK-M10/M17.
  - The values are PRF outputs under `PRK_w`. Only a holder of `S_w` can tell them from CSPRNG
    output, and such a holder already sees everything.
  - A full-viewing-key holder cannot compute them. It could already identify the real nullifier
    through `nk`.
  - `cm` binds the chain, pool and asset, so companions differ across pools. The derivation's
    labels are separate from SPEND, INCOMING and STORE, so a companion key never equals a real
    `sk_w(i)`.
  - The companion is built in bound mode with account `A`. Publishing its nullifier therefore needs
    `A`'s signature, and a holder of a leaked `S_w` cannot burn a companion in advance.
  - The 4,900-byte expansion is within HKDF's 8,160-byte limit. The 32 siblings are
    unconstrained, since `e₁ = 0`, so deriving them is harmless.

### New items in revision 2 (soundness only)

- **§5.3 `valid_until` removed from the signed struct: no soundness effect.** The statement account
  computes `binding` from the statement (§5.2 includes `valid_until`), and the signature covers
  `Poseidon(binding, salt)`. A server that changes `valid_until` changes the binding and
  invalidates the signature. The only loss is that the value cannot be checked on screen, which
  was already true of the binding.
- **§8.6 protocol fees: no circuit or binding effect.**
  - `fee = floor(w·bps/10⁴) < w` for `bps ≤ 100` and `w ≥ 1`, and `held` falls by the gross
    `w_amount`, so solvency is unchanged.
  - A fee change cannot reach an in-flight statement: `T > E + Q + margin`, the pool enforces
    `valid_until ≤ block + E + Q`, and the SDK refuses statements whose lifetime spans a pending
    fee change.
  - Implementation note: compute `amount · bps` (and a deposit's `amount + fee`) in u256. u128
    overflows above about 2¹²¹, so a checked panic would block large withdrawals and deposits.

### New finding

**AB-M12 (low): pin the encodings that devices and SDK versions must reproduce exactly**

- **Section:** §6.4 (companions), §6.1, §4.4.
- **Problem.** Deterministic companions only help if every device and SDK version derives the same
  bytes. The spec does not fix how `cm` is serialized in the companion info (for example nine u32
  big-endian words, 36 bytes, as in the address payload). If two versions disagree, a note gets a
  second companion beside its real nullifier, which singles the real one out.
- **Required change.**
  - Pin the `cm` serialization and add a known-answer vector for the companion derivation.
  - `TemplarKeyDerivation` gained a `warning` field, so the §5.3 cross-KAT and real-wallet signing
    requirement should also cover the derivation struct. P0b signed a predecessor.
  - Add the test "a bound spend under `M ≠ A` with `A`'s `sk` does not reproduce `A`'s handle". §4.4
    tests only the ordinary-mode case.

### Prior findings

| Finding | Status |
| --- | --- |
| AB-M1 | Resolved (§4.3.5; §4.4 tests; the `M ≠ A` test is added under AB-M12) |
| AB-M2 | Resolved (§4.3.4 `conservation5`, argument, tamper and positive tests; V3/V4/P1 unchanged) |
| AB-M3 | Resolved (§6.5: no policy seed or notes, every self-directed receiver bound; S4 restated in §3.4) |
| AB-M4 | Resolved (§6.2: `A` from the wallet, guardian and multisig accounts refused, ECDSA verified, `s ← min(s, n−s)`) |
| AB-M5 | Resolved (§4.3 Invariant B) |
| AB-M6 | Resolved (§4.3.2 wiring; §4.4 tamper hooks, slot-2 asset test, mutation kills) |
| AB-M7 | Resolved (§6.5 accept and two reject checks at one block; §12 and §13 signers per class). The pool-0 setup-check signature cannot authorize a spend, because the bridge requires `pool ≠ 0` |
| AB-M8 | Resolved (§6.2: no derivation prompt on routine unlock; wrapped `S_w`; fingerprint) |
| AB-M9 | Resolved (§5.3) |
| AB-M10 | Resolved (§3.1, §3.4) |
| AB-M11 | Resolved (§5.4: V5 `__validate__`, own address rejected, no `is_valid_signature`, `salt ≠ 0`) |

### What I checked for this re-review

I read revision 2 §1–§6, §8.1–§8.6, §12, §13 and §17, and the original HA-M6 text
(`bench/m31-pool/reviews/hidden-asset-design-math-review.md`). I rechecked the carry roots, the
limb bound and the HKDF output limit by hand; the round-1 carry simulation still applies. No
builds, proofs or RPC calls.

## Re-review of revision 4

- Date: 2026-09-25. Revision 4 of `docs/account-bound-note-spec.md`, changed sections only: §4,
  §5.1–§5.2, §6.1–§6.4, §7.1–§7.2, §8.1, §8.6 and §17's last table. Unchanged sections are not
  re-reviewed.

### Verdict

**GO.** The simplification removes mechanisms without weakening any property that V5 still relies
on. There are two new items. AB-M13 (low) should be written into §7.2 or `relayer-spec.md`; it
concerns the service's free path, not the pool. AB-M14 is info. Neither needs a re-review.

### Changed sections

- **§4 (two outputs).**
  - 127 + 9 + 2 = 138 limbs, padded to 140, gives 35 QM31 outputs. That is correct, and the bridge
    checks both padding limbs.
  - V4's conservation with carries {−2, …, 1} is exact for three subtracted terms, so AB-M2 is moot.
  - Nothing V5 needs was dropped:
    - the mode legs, the select, the published-equals-hashed wiring and the identity over `ak₀`
      remain, each with a test and a mutation kill;
    - the handle test under `M ≠ A` remains;
    - only slot-2 and `conservation5` items were removed, and V4's conservation tests carry over.
  - **Invariant B** still holds: the binding contains `nf₀`, `nf₁`, `cm₀` and `cm₁`, all
    collision-resistant functions of `(m, account)`.
  - **S1–S3** are unchanged.
  - **S4** holds and is simpler: `S_w` no longer depends on any signature, so a phished signature
    yields nothing.
- **§5.2 binding.** It covers every field the pool acts on (chain, pool, `token_out`, root, both
  nullifiers, both commitments and delivery digests, recipient, `w_amount`, `intent`, `identity`,
  `valid_until`). `account` is omitted as before, bound by Invariant B. The padding limbs are
  checked by the bridge and need no binding.
- **§6.1–§6.2 random seed.**
  - A 224-bit CSPRNG seed is ample.
  - The word-count origin marker stays sound: 24 words only for ordinary imports, 21 only for bound
    imports.
  - `A` now appears in every HKDF context, so `nk` and `ivk` are also account-specific (receivers
    already were, through WAUTH).
  - Rotating the account's key no longer changes `S_w`, which removes the freeze-after-rotation
    risk. The `max_proof_age` rotation window remains.
  - Random companions restore HA-M6 as reviewed, so AB-M12's companion items are moot.
  - The setup-check signature over `pool = 0` still cannot authorize a spend, because the bridge
    requires `pool ≠ 0`.
- **§7.2 free full withdrawal.**
  - **What the check shows.** If `H(NOTE, chain ‖ pool ‖ token_out ‖ 0₈ ‖ inner_j) = cm_j` for
    both `j`, then:
    - the circuit's `cm_j` preimage had `token = felt_limbs(token_out)` and both amounts zero, by
      NOTE collision resistance;
    - V4's conservation then gives `amt₀ + amt₁ = w_amount`.

    The client chooses both openings, so this is a collision bound: 128-bit design level, 2¹³⁹·⁵
    generic.
  - **What needs no extra check.**
    - Exit bit: `w_amount ≠ 0` forces `x = 1`, and the bridge's exit rule gives
      `token_out = token ≠ 0` with canonical limbs, so the server's `felt_limbs(token_out)` equals
      the circuit's words.
    - Delivery digests carry no value.
  - **What must still be checked:** AB-M13.
  - **What it reveals, to the server only.**
    - Both output leaves are zero-value dummies, which the server can remove from its view of the
      anonymity set.
    - The spent notes held exactly `w_amount` in total. In product 1, that is this account's notes.
    - `inner_j` of a CSPRNG dummy output reveals nothing further.
    - On-chain observers learn nothing new.
- **§8.1 and §8.6 (no fees).** `held[a]` is back to V2's per-asset accounting, and `MAX_NOTES = 4`
  matches two outputs. No soundness effect. The fee arithmetic note from revision 2 is moot.

### New findings

**AB-M13 (low): the free-withdrawal check must also require `intent = 0`**

- **Section:** §7.2.
- **Problem.** As written, the free path checks only that both outputs are zero-value and that
  `asset = token_out`. An `INVOKE` or `COMPUTE` spend whose budget is the whole input value also
  passes. Its open-note destinations then append new notes, so value re-enters the pool. The
  result is a free invoke, or a free in-pool round trip, in place of the 2-ticket price.
- **Required change.** The free path requires:
  - `intent = 0`; then `identity = 0` by the bridge;
  - `w_amount` at or above the per-asset minimum;
  - `asset` taken from the decoded `token_out`, never from the client;
  - openings with canonical words.

  `recipient ≠ 0` already follows from the bridge. Whether an ERC721 exit, which always has value
  1, qualifies for "a minimum value" is a protocol choice.

**AB-M14 (info): two small items**

- §6.2: revisions 1–3 said a bound note's companion nullifier is computed in bound mode with the
  same account. Revision 4 dropped that sentence when companions reverted to random. The circuit
  forces the dummy's mode and account, so soundness is unaffected. But the SDK's pre-proof
  "companion not spent" check must compute the nullifier that way, or it checks a value that is
  never published. Restore the sentence.
- §4.4: add the bridge negatives `valid_until = 0` and a `valid_until` limb at 2^28. Only the
  positive `2^56 − 1` test is listed. These are F11-class bridge-only rules.

### Prior findings in revision 4

§17's last table is accurate for the math rows:

- AB-M2 and AB-M8 are moot.
- AB-M4 is reduced to "A from the wallet, guardian refused".
- AB-M12 is reduced to the `M ≠ A` handle test and the key KAT.
- AB-M1, M3, M5, M6, M7, M9, M10 and M11 remain resolved in the changed text.

### What I checked

- Read revision 4 §1–§8.1, §8.6 and §17.
- Recounted the statement limbs.
- Checked the free-withdrawal argument against V4's circuit (`payment4.rs`: shared `context`,
  range-checked output limbs, the exit bit and conservation) and V4's bridge exit rule.
- No builds, proofs or RPC calls.
