# Policy notes — implementation math review (P1 relation, bridge, binding, wallet)

2026-09-24. Independent Math Reviewer. I did not write this code. I received the reviewed spec
(`docs/policy-note-spec.md`, revision 3) and commit `bb04f61`, and no implementer reasoning.
Scope: `client-port/src/policy.rs` (with the R0 gadgets it reuses in `payment.rs`,
`membership.rs`, `merkle.rs`), `client-port/tests/policy_p1.rs`, `cairo-p1/bridge/src/lib.cairo`,
`m31-pool/cairo/src/policy.cairo` (`policy_binding`), `m31-pool/policy_note.py` (`binding`) and
`m31-pool/policy_wallet.py`. The pool entry point was read only where it enforces something the
relation leaves open.

## Verdict

**GO. No blocking findings.**

Every constraint in spec §5 steps 1–9 is in the circuit, on the right variables. No public field is
taken from the prover's `Public` argument except the three the spec makes prover-chosen or
externally checked: the context (the pool checks it), `x` and `data`. I found no witness freedom
that lets a prover publish a statement the committed policy does not imply. The only rule that
spec §5 and §6 describe as enforced in the circuit but that the circuit does not enforce is PI-1,
the withdrawal "both or neither" rule. The bridge and the pool enforce it, so it is a liveness and
wording issue, not a soundness hole.

Before real value, or before a second wallet implementation, fix PI-1 to PI-4. They concern the
spec text, the native reference, the robustness of seed-only recovery, and the missing test
vectors. None of them lets a prover break the relation.

## Findings

| ID | Severity | Location | Finding | Failure scenario | Fix | Blocking |
|---|---|---|---|---|---|---|
| PI-1 | Low (liveness, spec mismatch) | `policy.rs` l.481-486 (withdrawal handled only for splits and, l.531-533, the refund); native `statement` l.276-278 (checks only splits); spec §4.2, §5 step 7, §6 step 1 | For a **fixed** outcome, the rule "`w_recipient` and `w_amount` are both zero or both nonzero" (§4.2) is enforced by neither the circuit nor the native reference. §6 lists it among checks the bridge "re-checks as defense in depth over what the circuit already enforces". In fact only the bridge (`lib.cairo` l.150) and the pool (`pool.cairo` l.328, l.335) enforce it. Scratch test `m9` shows both half-zero shapes are circuit-valid and accepted natively. | A creator commits outcome 1 as `(w_recipient = 0, w_amount = 300)`, or as `(w_recipient = seller, w_amount = 0)` with the value routed to an output. P1 proves the outcome, and the bridge then rejects it, so the outcome can never settle. After the deadline, only the refund remains. Careful inspection catches this (a zero recipient or amount is visible), so the impact is liveness plus reliance on the §9.3 checklist. | Either constrain it in P1 (about 30 rows): `z_w = is_nonzero(w_sum)`, `nonzero_vector_if(w_rec, z_w)`, `zero_when(w_rec, 1 − z_w)`. Or change §5 step 7 and §6 to say the bridge and pool enforce it, not the circuit. Either way, make native `statement` reject it for fixed outcomes, so tooling that uses the reference for acceptance catches it. | No |
| PI-2 | Low (application safety, acceptance tooling) | `payment.rs` `felt_limbs` l.157-163 (accepts any value below 2²⁵²); `policy.rs` l.437-439, l.459-460, l.481 (felt limbs hashed without a range check); native `statement` l.242-342 (no canonicity check on felts) | The circuit does not range-check the 28-bit limbs of hashed felts (`controller`, `controller_class`, `handle`, `w_recipient`, `delivery`), and the reference accepts felt *values* in `[p, 2²⁵²)`. That is sound, because the published limbs are the hashed limbs and the bridge rejects non-canonical ones (`felt_from_limbs`, l.51). But such a policy is provable while its settlement is **rejected at the bridge**, and the native reference does not flag it. | A depositor gives a seller an opening in which the seller's withdrawal outcome names `seller + p`, or whose `delivery` is `digest + p`. Seller tooling that compares felts mod p (typical for Starknet libraries) passes the §9.3 checklist, and the arbiter approves the `policy_id`. The settlement is rejected by the bridge ("non-canonical felt"), and the depositor refunds after the deadline. With `controller + p`, every outcome, the refund included, is frozen forever (griefing at the creator's own cost). | In the reference (`statement`, and a shared acceptance helper in `policy_note.py`), reject felts ≥ p and addresses (controller, withdrawal recipient) ≥ 2²⁵¹. Add to the §9.3 checklist: "every felt of the header and of the relevant outcome is canonical (< p; addresses < 2²⁵¹), compared as integers, not mod p". No circuit change is needed. | No |
| PI-3 | Medium (recovery availability) | `policy_wallet.py` `recover` l.184-210, `parse_pb01` l.150-156 | `recover` passes PB01 fields straight to the Rust tool. A PB01 whose `token` (or `controller`, `class`, `handle`) field is ≥ 2²⁵² makes `felt_limbs` panic. `pn.run` then raises `CalledProcessError`, which aborts the **whole scan**. Anyone can seal a PB01 to a wallet's incoming public key and publish it with a minimal deposit. Scratch check 5 reproduces the abort. The `cm` check does stop recovery from being *fooled*: without `s_pol`, an attacker cannot produce a leaf that matches. It does not stop it from being *blocked*. | A griefer who knows the depositor's incoming key (every payer knows it) deposits one unit with a malformed PB01 ciphertext. The depositor's seed-only recovery crashes before it reaches the real backup. The funds remain recoverable with a patched wallet, but the "refund from the seed alone" property (§1, §9.2) fails in this implementation. | Wrap each candidate in `try/except` and skip it on failure. Validate PB01 fields before any tool call: felts < p, token and controller < 2²⁵¹, `amount > 0`, and `refund_index == i` (the key that decrypted it). Add a test that interleaves a malformed PB01 with a real one. | No (fix before wallet release) |
| PI-4 | Low (byte-exact regeneration) | `policy_wallet.py` docstring l.8; spec §9.1 ("Test vectors pin all of this during implementation"); design review F-1 | There are no known-answer vectors for HKDF labels and context, `M31⁹`, clamping, the deterministic refund box, or the M301/PB01/PS01 bytes. The docstring says `policy_e2e.py` checks the functions' outputs, but e2e draws random seeds and only checks self-consistency. | A refactor changes, say, the label or context byte order, or the PB01 field order. Every test stays green, but notes created before the change can no longer regenerate their refund delivery, so `o₀`, `policy` and `cm` mismatch and seed-only refund fails. A second implementation (for example, a TypeScript wallet) has nothing to match against. | Commit one fixed-seed vector file with seed, chain, pool, ν → `s_pol`, cap, rho, salt, rho_refund, esk, epk, the refund plaintext, box bytes, words and delivery, the PB01 plaintext, and `policy_id`/`cm` for a fixed policy. Check it in a unit test. The libsodium cross-check from scratch check 3 can go in as well. | No (fix before a second implementation or real value) |
| PI-5 | Low (wallet correctness) | `policy_wallet.py` `find_notes` l.213-223 | `find_notes` trusts any M301/PS01 plaintext that decrypts. It does not recompute the commitment against the leaf, which §9.3 requires for PS01 ("the wallet recomputes the commitment and checks it against the leaf"). For the remainder side it reports the note amount, not `amount − x`. | A forged M301 to the victim shows a phantom balance, and spending it fails later at proving. A split remainder receiver sees the wrong amount. | Recompute `cm = H(NOTE, ctx ‖ amount ‖ H(INNER, receiver ‖ rho))` and compare it with the leaf. For PS01, take `x` from `PolicySettled` and compute the side's amount before the check. | No |
| PI-6 | Info (key hygiene) | `policy_wallet.py` `recover` / `standard_refund` l.161-167, l.198-200 | "Each `esk_refund` is used for exactly one message" (§9.1) relies on each ν having one leaf. `recover` regenerates a refund for **every** matching leaf. If a party that holds `cap` also learns ν (which is not in the executor opening today), it can fund a second leaf with the same ν and a different amount. The wallet would then seal two different plaintexts under the same (esk, pk, nonce). | Keystream and Poly1305-key reuse across two refund boxes. The impact is negligible: the plaintexts are known to that party, and sealed boxes are anonymous, so a forgery gains nothing. | In `recover`, flag or refuse a second leaf for the same ν. Alternatively, add the amount and token to the esk derivation context. | No |
| PI-7 | Info (spec wording) | spec §5 step 8 vs `policy.rs` l.494-509 | The spec says `r = amount − x` is computed "limb by limb with boolean borrow bits, the final borrow zero". The implementation instead range-checks `r` and relies on the shared conservation gadget: `amount = cam₀ + cam₁ + w`, with `cam₀ = x`, `cam₁ = r` and `w = 0` for a split. This is equivalent. `r ≥ 0` is range-checked, so `x ≤ amount`, and `x + r = amount` holds as integers (argument below; scratch `m3` covers it). | none | Update §5 step 8 to describe what was built. | No |
| PI-8 | Info (tests) | `tests/policy_p1.rs` | The committed tests change witnesses only through `Private`/`Public`, so the builder always recomputes hints that are consistent with those values (inverses, `nz_r`, carries, selector bits, `s`, `active`). No test checks that the *constraints* reject adversarial hints. That is exactly the N-6 class of attack ("`r ≠ 0` with commitment₁ zeroed"), which §10 asked to be tested. There is also no bridge test for a real P1 proof whose statement violates a bridge-only rule (PI-1). | A future refactor that drops, say, the `r_sum·(1 − z) = 0` half of `is_nonzero` passes every committed test. | Add a `#[cfg(test)]` hint-override hook, like the scratch `Tamper` (below), and port tests `m1`–`m11`. Add a validate-bridge case that proves a withdrawal-half-zero outcome and expects `"withdrawal"`. | No |
| PI-9 | Info | `policy_wallet.py` `m31_9` l.30-35 | An all-zero `M31⁹` raises an error instead of drawing a new ν (§9.1). The probability is 2⁻²⁷⁹. | none | Optional: retry with a fresh ν in `new_policy_note`. | No |

## What I checked and found sound

**Spec §5, constraint by constraint** (`policy.rs` `build`, l.425-644):

1. *Encodings and ranges (PN-2).*
   - All digests and the `cap`, `rho`, `salt` and sibling words are `guess_m31` base-field values, so they are canonical by construction.
   - `cap` and `rho` are nonzero (`nonzero_vector`).
   - The note amount goes through `amount` (range-checked and nonzero).
   - Every preimage amount (`pamt`), `w_amount`, `x` and `r` goes through `amount_unchecked` (sixteen boolean bits per limb).
   - `deadline` and `not_before` go through `limbs16`.
   - Felt limbs are not range-checked in the circuit; the bridge checks them (see PI-2 for the consequence).
   - **Single-variable rule.** `amt` feeds `cm`, `policy_id` and conservation. `pamt` feeds the outcome hash. `cam = pamt + s·e` feeds the output commitments and conservation. For a fixed outcome `s = 0`, so `cam = pamt`. For a split, `m_sum·s = 0` with `m_sum < 2¹⁹`, which forces every `pamt` limb to zero, so `cam = e` (x or r), which is range-checked. So `cam` always equals a range-checked limb vector. `w_rec`, `w_amt`, `not_before`, `deadline`, `controller`, `class`, `handle`, `x` and `data` are each one variable, both hashed (where applicable) and published.
2. *Note.* `pnk = H(PNK, cap)`, `recv_p = H(PRECV, pnk ‖ policy)`, `inner = H(INNER, recv_p ‖ rho)`, `cm = H(NOTE, ctx ‖ amt ‖ inner)`, with `policy = H(POLICY, 1 ‖ 1 ‖ …)`. `VERSION` and `KIND` are `constants(...)`, not witnesses (PN-3c).
3. *Selection.*
   - Four boolean bits, `Σb = 1`, and the published index is `Σk·b_k` (so it is in 0..3).
   - `slot_k = w_k + b_k(ô − w_k)` word by word, where `ô` is the digest recomputed from the hashed preimage.
   - `orest = rest_c + b₀(w_rest − rest_c)`, where `rest_c = H(OREST, slot₁ ‖ slot₂ ‖ slot₃)`.
   - POLICY and OREST collision resistance then fixes `ô` to the committed slot. Scratch `m5` covers two bits set and no bit set; the committed test covers an outcome under another index.
   - A type-3 or version/kind ≠ 1 preimage cannot be selected, because the circuit hashes `1 + s` and the constants (scratch `m11`).
4. *Membership and nullifier.* Both tree formats are climbed with boolean position bits, and `nf = H(NF, pnk ‖ cm ‖ lo ‖ hi)` with `lo` and `hi` packed from the same bits. This matches the native `climb` and `nullifier`.
5. *Public header.* `controller`, `class`, `handle`, `deadline`, `not_before` and `kind` are published from the hashed variables. `policy_id = H(POLICY_ID, ctx ‖ amt ‖ policy)` is computed in-circuit (`cms[3]`).
6. *Type and refund.* `kind = 1 + s` with `s` boolean. `b₀·s = 0`, `b₀·nb_sum = 0` (`nb_sum < 2¹⁸`, so zero iff `not_before = 0`), `b₀·(1 − a₀) = 0`, `b₀·w_rec_k = 0` and `b₀·w_sum = 0`. The committed `refund_slot_rules` and scratch `m5`/`m6` cover this.
7. *Fixed.*
   - `x_sum·(1 − s) = 0` forces `x = 0`, and `r_sum·(1 − s) = 0` forces `r = 0`.
   - `active` is boolean.
   - An active output has nonzero receiver, rho and delivery (`nonzero_vector_if`), and a nonzero amount (`nonzero_if(m_sum, a·(1 − s))`).
   - An inactive output has every field, amount included, multiplied by `1 − a` and asserted zero.
   - Published `cm_j` and `d_j` are gated by `a_j`.
   - The withdrawal is published from the preimage variables.
   - Conservation is below. The one gap is PI-1.
8. *Split.*
   - `s·(1 − a_j) = 0` for both outputs, `m_sum_j·s = 0`, and `s·w_rec_k = 0` with `s·w_sum = 0`.
   - `x_sum·inv = s` makes `x ≠ 0`.
   - `is_nonzero` is sound in both directions: `r_sum·t = z` gives `r = 0 ⇒ z = 0`, and `r_sum·(1 − z) = 0` gives `r ≠ 0 ⇒ z = 1`. `r_sum < 2¹⁹`, so it is zero iff `r = 0` (N-6). Scratch `m1` shows that `r ≠ 0` with `nz_r` forced to 0 (burning the remainder) is rejected; `m2` shows the converse is rejected.
   - The preimage `active₁` stays the hashed `a₁ = 1`, and `nz_r` only gates publication: `g₁ = a₁(1 − s) + s·nz_r` is boolean (F-2).
   - `cm₀ = H(NOTE, ctx ‖ x ‖ inner₀)`, `cm₁ = nz_r·H(NOTE, ctx ‖ r ‖ inner₁)`, `d₁ = nz_r·d₁`, and `d₀` is published with `g₀ = a₀ = 1`.
9. `data` is guessed from the argument and published verbatim.

**Conservation with one input and three outflows** (`payment.rs` l.566-604):
- Each limb difference is `d_k = amt_k − cam₀_k − cam₁_k − w_k`, which lies in `[−3·65535, 65535]`. With `c_in ∈ {−2..1}`, `d_k + c_in ∈ [−196607, 65536]`.
- So `c_out = (d_k + c_in)/2¹⁶` lies in `[−2.99…, 1]`, which is `{−2, −1, 0, 1}` for integers. The quartic constraint covers exactly that set (the field has no other roots).
- Every quantity in `d_k + c_in = c_out·2¹⁶` has absolute value below 2¹⁸, far below p/2, so the field equality is an integer equality.
- Summing with weights 2¹⁶ᵏ, with the last carry fixed at 0, gives `amt = cam₀ + cam₁ + w` over the integers.
- R0's two-input bound, `(−3·2¹⁶, 2·2¹⁶)`, is wider, so the gadget is unchanged and still sound here.
- Scratch `m3`: `x > amount` with the wrapped `r = amount − x mod 2¹²⁸` is rejected under the default and 64 random carry vectors. Scratch `m4`: an output inflated by 2¹⁶ is rejected under 28 targeted carry patterns.

**Hash framing and lengths.**
- OUTCOME is 94 words (1 + 4 + 2·36 + 9 + 8), POLICY 60 (2 + 9·3 + 4 + 9·3), POLICY_ID 44, NOTE 44, PRECV/INNER 18, OREST 27, PNK 9 and NF 20.
- All are at level 0, with kinds 10–15, disjoint from R0's 1–9.
- `hash_batch` only groups equal-length requests: {PRECV, INNER, INNER} at 18 and {NOTE ×3, POLICY_ID} at 44. The rest are singletons. `sponge_lanes` asserts equal lengths anyway, so a mismatch would panic rather than hash wrongly.
- The native `outcome_payload`, `policy_digest` and `policy_id` use the same order and lengths. The committed test `circuit_statement_matches_native…` checks the circuit output against `statement_limbs` for all five shapes and both trees, and checks that the topology is shape-independent.

**Bridge** (`lib.cairo`):
- The offsets are tag 0–1, chain 2, pool 11, token 20, root 29, nullifier 38, cm₀ 47, cm₁ 56, d₀ 65, d₁ 74, w_rec 83, w_amt 92–99, controller 100, class 109, handle 118, policy_id 127, deadline 136–139, not_before 140–143, index 144, kind 145, x 146–153, data 154–162, and a zero pad at 163. This matches `statement_limbs` exactly, and `validate_bridge_p1.py` checks an exact decoded-statement match on real proofs.
- `felt_from_limbs` rejects limbs ≥ 2²⁸ and values ≥ p. `from_limbs16` rejects limbs ≥ 2¹⁶.
- All spec §6 step 1 checks are present: index < 4, type ∈ {1, 2}, `type = 1 ⇔ x = 0`, `delivery ≠ 0 ⇔ commitment ≠ 0`, withdrawal both-or-neither, a nonzero nullifier, addresses < 2²⁵¹ (pool, token, recipient, controller), and refund ⇒ type 1.
- **Binding order** is identical in the bridge `binding`, the pool `policy_binding` and the Python `binding`: tag, chain, pool, token, root₉, nf₉, cm₀₉, cm₁₉, d₀, d₁, w_rec, w_amt, controller, class, handle, policy_id₉, deadline, not_before, index, type, x, data. Digests enter as nine words, and every other field as one felt. The pool's `read_digest` rejects words ≥ p.

**Wallet** (§9), verified by scratch checks:
- **HKDF.** It uses an empty salt, implemented as 32 zero bytes, which is identical under HMAC key padding. It matches RFC 5869 test case 3 and `cryptography`'s HKDF. The info is `label ‖ chain₃₂ ‖ pool₃₂ ‖ ν₁₆`. Because the context has a fixed 80-byte length, the label is recoverable, so the labels are domain-separated. `s_pol` has its own label.
- **M31 mapping.** `M31⁹` maps 8-byte BE chunks mod p (bias ≈ 2⁻³³).
- **Clamping** follows RFC 7748.
- **Deterministic sealed box.** It is **byte-identical to libsodium `crypto_box_seal`** when libsodium's RNG is made to return the same ephemeral scalar (checked through `randombytes_set_implementation` on the system libsodium 1.0.18). It opens with `SealedBox`, and its length is 304 bytes.
- **Plaintext layouts.** M301 is 4+32+36+36+16+132 bytes, PS01 is M301 with the side byte at offset 124, and PB01 is 212 bytes + 44 bytes of zero padding. All match §9.2.
- **Seed-only recovery cannot be fooled.** Recovery recomputes `cm` from `s_pol`-derived `cap`, `rho` and `salt`, the wallet's own refund, and the backed-up header and `orest`, and compares it with the leaf. Someone else's PB01 therefore yields a matching leaf only if its author knows `s_pol`-derived secrets (both `cap` and ν). Even then, the recovered refund pays the victim's own receiver. It can be blocked, though (PI-3).

## Scratch tests run

Location: `~/.local/share/templar/review-scratch/policy-impl-math/`. It holds a copy of the crate, with path deps symlinked to the repository and nothing in the repository modified. It also holds `tamper-policy.diff` and `tamper-payment.diff`, which add a test-only `Tamper` hint override and a forced-carry hook, and `bench/m31-pool/review_wallet.py`.

- Committed `tests/policy_p1.rs`: 7/7 pass.
- `tests/review_malicious.rs`: 11/11 pass. Each case asserts rejection, except `m9`, which documents PI-1, and `m10`.
  - `m1`: split with `r ≠ 0` and `nz_r` forced to 0: **rejected**.
  - `m2`: split-all with `nz_r` forced to 1: **rejected**.
  - `m3`: `r ± 1`, and `x > amount` with the wrapped `r` under default and 64 random carry vectors: **rejected**.
  - `m4`: a fixed output inflated by 2¹⁶ under 28 forced carry patterns: **rejected**.
  - `m5`: selector with two bits, no bit, or the settle outcome under `b₀`: **rejected**.
  - `m6`: `s` flipped for fixed (settle, withdraw, refund) and split outcomes: **rejected**.
  - `m7`: `active` flipped either way: **rejected**.
  - `m8`: a fixed active output with zero amount, an inactive output with a delivery, a split with an inactive out₁, a split with a withdrawal recipient, a split with a committed amount, and a split with a zero delivery: **rejected**.
  - `m9`: a fixed withdrawal with a zero recipient and nonzero amount, or the reverse: **circuit-valid and natively accepted (PI-1)**.
  - `m10`: a `prove-refund` witness (other slots zero, only `orest`) gives the same statement. A non-refund index with zeroed slots changes the statement.
  - `m11`: a committed type-3 outcome cannot be selected under its `policy_id`.
- `review_wallet.py`: HKDF (RFC TC3 and `cryptography`), `M31⁹`, clamping, **libsodium byte-compatibility of `seal(esk)`**, the M301/PS01/PB01 layouts, and **PI-3 reproduced**: a malformed PB01 makes `recover` raise `CalledProcessError`.

No proofs were generated (no PROOF2).
