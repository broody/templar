# R0 V5 relation (P2): math implementation review

- Reviewer: independent Math Reviewer (did not write the code)
- Date: 2026-09-25
- Under review: the uncommitted P2 change under `bench/m31-private-wrapper/client-port/`
  (`src/payment5.rs`, `src/prove.rs` `R5`, `src/lib.rs`, `Cargo.toml`, `tests/payment_r5.rs`,
  `tests/payment_r5_malicious.rs`, `examples/prove_payment_r5.rs`, the relation-selectable hiding
  examples, `results/stwo-client-r5/`).
- Against: `docs/account-bound-note-spec.md` revision 4 §4 (relation) and §5.1 (the Rust bridge
  mirror). The baseline is `payment4.rs` and `payment.rs`.

## 1. Verdict

**CONDITIONAL GO.**

The relation is correct and conforms to §4.3:

- I found no witness that the circuit admits and that should be rejected, other than the
  statements §5.1 deliberately leaves to the bridge.
- Every new V5 constraint has a test that fails when the constraint is deleted. I confirmed this
  by mutation.
- The bridge mirror implements every §5.1 rule.

**Condition**, to be met before P3 pins the V5 circuit hash (AB-IM1): commit the F09 tamper cases,
so that the constraints guarding against inflation (the carry range and bit booleanity) are killed
by a test. Today two such mutants survive both suites.

The other findings are low or info and can be closed in P3.

## 2. Conformance to §4 (checked by reading `payment5.rs` against the spec and `payment4.rs`)

- **§4.1 layout.** V4's 127 limbs, then `account` (limbs 127–135), `valid_until` (136–137) and two
  constant-zero limbs (138–139): 35 outputs. Tags `R0V5` and `R0C5`. `statement_limbs`,
  `decode_statement` and the recorded `statement_layout` agree.
- **§4.2 variables.**
  - `account` is guessed once (`build` l.554). The same `Var`s go to the mode rules, to both WAUTH
    payloads and to the published limbs.
  - `m` is one variable for the mode rules and both selects.
  - `valid_until` is two guessed words, published verbatim.
- **§4.3.1 mode.**
  - `m·(m−1) = 0` is present.
  - `accountₗ·(1−m) = 0` holds for all nine limbs.
  - `nonzero_vector_if(account, (m, …))` is present.
  - Both legs force `m ∈ {0, 1}` by themselves, so the booleanity check is redundant, as the code
    comment says. I agree: its deletion is an equivalent mutant.
- **§4.3.2 keys.**
  - `H(AUTH, skᵢ)` is computed in the V4 key batch and `H(WAUTH, account ‖ skᵢ)` in a batch with
    the two output INNER hashes. All four are 22-word frames, which meets `sponge_lanes`'
    equal-length requirement. Both are always computed.
  - Selection is per word, `a + m·(w − a)`, with the shared `m`.
  - OWNER reads the selected key.
  - The dummy input 1 uses the same `m` and `account`: `ak1` goes through the same select.
  - Lane packing is injective because every packed value is a base-field value, the selects
    included.
- **§4.3.3 identity.** `H(IDENTITY, ak₀ ‖ scope)`: the payload's first nine words are the same
  `Var`s OWNER₀ reads. The handle is masked by a boolean `id_active`, and the hash is batched with
  OWNER₀ and OWNER₁ (22 words each).
- **§4.3.4 published limbs.** The order is as specified. `account` and `valid_until` are not
  range-checked in the circuit (left to the bridge, as specified).
- **V4 unchanged.**
  - The asset nonzero rule, input 0 real, the `e₁` rules, the nullifiers, outputs with nonzero
    receiver and `rho`, `conservation([amt₀, amt₁], [out₀, out₁, withdrawn])` with carries
    {−2..1}, and the exit bit and `token_out = x·token` are all line-for-line V4's.
  - `payment.rs`, `payment4.rs`, `policy.rs`, `merkle.rs` and `membership.rs` are unchanged
    (`git diff --quiet`), so V3, V4 and P1 are unaffected.
- **Topology.** It is witness-independent: the tamper hints and `record` change values or
  `debug_info` only. The test builds every shape in both modes with the same topology. All 16
  recorded proofs, including the two made with the tamper feature, carry one circuit hash and
  trace size 2^18.
- **Native reference.** `ak_of` branches on `account ≠ 0`, which equals `m` under the mode rules.
  `statement` matches the circuit for every shape, mode and tree; the test compares all 140 limbs.
- **§5.1 mirror (`decode_statement`, `felt_from_limbs`, `bridge_checks`).** It checks:
  - the tag;
  - the 140-limb length;
  - distinct nullifiers;
  - 16-bit amount limbs;
  - 28-bit `valid_until` limbs;
  - zero padding;
  - `felt_from_limbs` on every felt field (limbs below 2^28, value below p);
  - canonical felts (F15 fixed);
  - V4's rules;
  - `account < 2^251`;
  - `valid_until ≠ 0` and below 2^56.

  This is everything §5.1 lists.

## 3. Mutation check (executed)

I copied `client-port` to `.review-p2`, applied each mutant with a script, and ran both suites
with `--no-fail-fast`. The copy was deleted afterwards. Baseline: 16/16 and 12/12 pass.

| Mutant | Result |
| --- | --- |
| Mode leg `accountₗ·(1−m)` deleted | killed (`m_zero_with_account_isolated`, `m_flipped`) |
| Mode leg `nonzero_vector_if` deleted | killed (`m_one_with_zero_account_isolated`, `m_flipped`) |
| Published account guessed as a copy | killed (`wiring_uses_the_same_variables`) |
| Identity over `sk₀` | killed (4 tests) |
| Input 1 always ordinary (select with 0) | killed (16 tests) |
| `sum₁·(1−e₁)` deleted | killed (2 tests) |
| `(1−x)·withdrawn` deleted | killed (`x_zero_with_exit_and_non_boolean`) |
| Mirror: padding, `valid_until` limbs, `account < 2^251`, `valid_until ≠ 0` deleted | each killed |
| **`(1−x)·intent` deleted** | **survives** (bridge exit rule backstops it) |
| **Identity-flag booleanity deleted** | **survives** (not exploitable, see AB-IM1) |
| **Shared carry range `n(n−1)(n+1)(n+2)` deleted (`payment.rs`)** | **survives** (inflation: F09's free-carry mint) |
| **Shared `guess_bits` booleanity deleted (`merkle.rs`)** | **survives** (inflation: F09's negative limb) |
| **`nonzero_vector(token)` deleted** | **survives** (invariant I backstops it) |
| **Mode rules over a guessed copy of `account`** | **survives** (hygiene, see AB-IM3) |
| **Mirror: amount-limb range deleted** | **survives** (see AB-IM2) |

The implementer's table (README) matches every row I re-ran.

## 4. Findings

### AB-IM1 (medium): the inflation-critical constraints V5 inherits from V4 have no killing test (F09 still open)

- **Where:** `tests/payment_r5_malicious.rs`; spec §4.4 ("V4's conservation tests and mutation list
  carry over unchanged").
- **What is wrong.**
  - Two shared constraints survive both suites: the conservation carry range and the booleanity in
    `guess_bits`, which range-checks every amount limb, position bit and selector bit. Deleting
    either lets a prover mint value, according to F09's executed proofs of concept (free carry of
    p; negative limb).
  - V4's suite never gained F09's tamper cases, so "carries over" carries over nothing.
  - `payment5.rs` re-implements V4's exit and identity-flag wiring, so V4's tests do not cover
    those lines either. `(1−x)·intent` and the identity-flag booleanity survive.
  - Neither of those two is exploitable:
    - with `x = 0` and an intent, the statement publishes `token_out = 0`, which the bridge's exit
      rule rejects;
    - a flag `k ∉ {0, 1}` publishes `k·handle`, and matching a victim's handle would need a hash
      output proportional to it word by word, a 248-bit condition.
  - The V5 circuit hash is about to be pinned, and F09 notes that the pin re-derives from whatever
    code is proved.
- **Required.** Add to `payment_r5_malicious`, using raw hint hooks (`payment::CARRIES` exists; add
  overrides for amount-limb bits, position bits, input-1 limbs and the identity flag):
  - carries outside {−2..1};
  - a non-boolean amount bit;
  - input-1 limbs (p−5, 5, 0, …) on a dummy;
  - an output limb at or above 2^16;
  - a non-boolean position bit with sibling = node;
  - a zero-budget invoke with `x` forced to 0;
  - an identity flag of 2.

  Then re-run the mutation table, so that every mutant above is killed or documented as
  equivalent. The token-nonzero mutant may be documented as backstopped by invariant I.
- **Condition:** before P3 pins the V5 circuit hash.

### AB-IM2 (low): the bridge mirror's decoder rules are not each covered by a raw test

- **Where:** `tests/payment_r5.rs` `bridge_only_rules`; `payment5.rs` `decode_statement`.
- **What is wrong.**
  - Deleting the amount-limb range check survives. No test feeds an amount limb at 2^16.
  - The only felt-limb range test is on `account`, at limb 127.
  - Digest words (root, nullifiers, commitments, identity) are not checked against p. A real proof
    cannot produce such a word, and I infer, without verifying, that Cairo's M31 type cannot carry
    one either.
- **Why it matters.** P3's Cairo bridge will be written against this mirror, so every rule should
  have a raw test whose failure names it.
- **Required.** Add raw decode tests for:
  - an amount limb at 2^16;
  - a limb at 2^28 in each felt field;
  - a value at p in each felt field.

  Either reject digest words ≥ p in the mirror, or state why they are impossible.

### AB-IM3 (low): the wiring check does not cover the mode rules' `account` variables

- **Where:** `payment5.rs` `mode_rules` / `record`; `wiring_uses_the_same_variables`.
- **What is wrong.** A mutant that applies both mode legs to a separately guessed copy of `account`
  survives. The honest hints fill the copy with the same values, and `record` stores only `m` for
  the mode rules.
- **Impact.** It is not exploitable. Theft resistance rests on the WAUTH-equals-published wiring,
  which the test does check. But it breaks the stated `m = 1 ⇔ published account ≠ 0`: a prover
  could publish `account = 0` with `m = 1` and spend self-made `H(WAUTH, 0 ‖ sk)` notes as
  ordinary.
- **Required.** Record the `account` variables inside `mode_rules`, and assert that they equal
  `account.published`.

### AB-IM4 (info): no Rust reference for the §5.2 binding

- There is no Rust `binding` for V5; V4 had none either.
- P3 needs a known-answer vector for `TMR0_BIND_V5` over a V5 statement. In particular it must
  show that `valid_until` enters as one felt, that `account` and the padding are excluded, and
  that the binding is identical across modes.
- Add it to the P3 KATs, as a Rust or Python reference.

### AB-IM5 (info): F27 partly addressed; record hygiene

- **F27.** The hiding examples now run on V5 and are clean:
  - rank: 8 shapes × 2 modes, 0 unblinded;
  - invariants: rank 336/336, 0 seed-invariant combinations.

  The per-point run is pending, and the README still has a `POINTS_RESULT` placeholder. F27's other
  fixes are still open, as they are for V4:
  - make the Jacobian dimension test the hiding regression;
  - check `16k ≥ dim V_pub` in `prove()`;
  - port `h12_model`'s structural checks.
- **Record hygiene.** `proofs/proofs.json` contains a stray `forge-dbg` entry (a second
  `valid-until-zero` forgery). Remove it or label it.

## 5. What I checked, how, and what I could not check

**Read.**
- `payment5.rs` in full, the `R5` impl in `prove.rs`, and both test files in full.
- `prove_payment_r5.rs` (the forgeries) and the `support/mod.rs` diff.
- `results/stwo-client-r5/`: README, `trusted-config.json`, `proofs.json` (16 proofs, one circuit
  hash, tag `R0C5`, trace 2^18) and the hiding summaries.
- For comparison: `payment4.rs`, `payment.rs`, `membership.rs` and `merkle.rs`.

**Ran.** In `bench/m31-private-wrapper/.review-p2`, a copy with its own target directory, since
deleted:
- `cargo +nightly-2026-01-15 test --release --test payment_r5` (16 pass);
- `… --features tamper --test payment_r5_malicious` (12 pass);
- 18 mutants through a script (kept at the session scratchpad as `mutate.py` and `mutants.json`).

Nothing under `client-port` was modified or built; its `git status` is unchanged.

**Not checked.**
- Real proving; I relied on the recorded proofs.
- The per-point hiding run, which is still in progress.
- The WASM proof time; the trace size is unchanged.
- Cairo's M31 bound on digest words (inferred).
- The shape of P3's Cairo bridge.

## Re-check

- Date: 2026-09-25. Only the changed parts were checked: `merkle.rs`, `payment.rs`, the changed
  parts of `payment5.rs`, both test files, and the README and `proofs.json`.

### Verdict

**GO.** The AB-IM1 condition is met. AB-IM2 and AB-IM3 are resolved. AB-IM5 is resolved for this
relation: the per-point hiding run is recorded and `forge-dbg` is removed. F27's remaining
structural fixes stay open for V4 and V5 alike, as noted. AB-IM4, the binding known-answer vector,
remains a P3 item.

### What changed and what I checked

- **Gadget refactor emits the same gates.**
  - `guess_bits` now calls `guess_bits_raw`, which runs the same per-bit sequence: `guess_m31`,
    `b·(b−1)`, `eq`.
  - `amount_unchecked` now calls `amount_from_bits(amount_bits(a))`, which yields the same 16 bits
    per limb, least significant first, and then the same limb and sum evaluation.
  - In a copy I recomputed the circuit hashes from the new code as `prove()` does (topology,
    blinding loop to 2,390, preprocessed root). R4 gives `[4130052835, 1598900057, …]`, equal to
    `results/r4-bridge/bridge-build-record.json`. R5 gives `[1903585510, 1708577544, …]`, equal to
    `results/stwo-client-r5/trusted-config.json`. P1 uses the same two gadgets.
- **`payment5.rs`.**
  - Each honest hint and its tamper override go through the same call: position bits and the
    identity flag through `guess_bits_raw`; the input-1, output and withdrawal amounts through
    `amount_from_bits`. So each test exercises the gate the honest path uses. Input 0 keeps
    `amount()`, which shares the gadget.
  - `mode_rules` records its `account` variables, and the wiring test asserts that they equal the
    published limbs.
  - `decode_statement` rejects any limb ≥ p.
- **The F09 tests are well formed.** Each plants a witness that reaches the real root, so only
  the targeted constraint can reject it.
  - The carry test overrides the carries with field values that close the last limb equation mod
    p (out = in + p).
  - The negative-limb, dummy-value (p−5, 5) and 2^16-limb tests use integer carries that balance
    exactly.
  - The position-bit test puts the note as its own level-0 sibling, so bit 2 leaves the path
    unchanged and yields a second nullifier.
  - There are also a zero-budget invoke with `x = 0` and an identity flag of 2.
- **Suites** (in `.review-p2`, own target directory, since deleted): `payment_r5` 17/17 and
  `payment_r5_malicious` 19/19.
- **Mutation re-run.** My 18 mutants, with patterns updated for the refactor, are **all killed**.
  The 7 earlier survivors are now killed by:

  | Earlier survivor | Now killed by |
  | --- | --- |
  | `(1−x)·intent` | `exit_bit_is_forced_by_an_intent_alone` |
  | identity-flag booleanity | `identity_flag_is_boolean` |
  | carry range | `carry_range_stops_a_mod_p_mint` |
  | `guess_bits` booleanity | the three amount-bit tests, the position-bit test and the identity-flag test |
  | token nonzero | `zero_asset_fails_on_a_consistent_tree` |
  | mode rules over a copy | `wiring_uses_the_same_variables` |
  | mirror amount-limb range | `bridge_only_rules` |
- **Records.**
  - `proofs.json` has 15 proofs with one circuit hash and no `forge-dbg`.
  - `hiding/points.json`: transfer and single in both modes are at full rank (468/468 and
    6,768/6,768), the same as the V3 baseline.

Nothing under `client-port` was modified or built; its `git status` is unchanged. The mutation
results are kept in the session scratchpad as `mutants-recheck.json`.
