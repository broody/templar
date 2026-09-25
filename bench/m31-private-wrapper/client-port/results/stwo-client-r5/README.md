# R0 V5 client relation (P2)

2026-09-25. The R0 V5 payment relation of
[`docs/account-bound-note-spec.md`](../../../../../docs/account-bound-note-spec.md) §4
(revision 4): R0 V4 plus account-bound notes (hash kind `WAUTH = 16`, one mode bit per spend)
and a published `valid_until`. Code: [`src/payment5.rs`](../../src/payment5.rs); tests:
[`tests/payment_r5.rs`](../../tests/payment_r5.rs) and
[`tests/payment_r5_malicious.rs`](../../tests/payment_r5_malicious.rs) (feature `tamper`); prover:
[`examples/prove_payment_r5.rs`](../../examples/prove_payment_r5.rs). Nothing here is deployed;
the bridge and statement account are P3.

## Result

| | R0 V4 | **R0 V5** |
| --- | ---: | ---: |
| Statement | 127 limbs, 32 outputs | **138 limbs + 2 zero, 35 outputs** |
| Trace (every shape, both modes) | 2^18 | **2^18** (spec §4.5 target met) |
| `qm31_ops` rows, `Tree::Compress` | 182,993 | 183,211 (+218, +0.12%) |
| Equality gates | 1,191 | 1,212 |
| Sponge permutation groups | 7 + tree + nf | same (see below) |
| Proof, native, 36 threads | — | 0.57–0.75 s |
| Proof size | 29.5k–30.3k felts | 29.5k–30.6k felts |
| Blinding rows / revealed FRI values | 2,390 / — | 2,390 / 1,707–1,782 |

- **One circuit for both modes.** Ordinary and bound spends of every shape have the same topology
  (`circuit_statement_matches_native_and_topology_is_fixed`) and the same circuit hash: all 15
  real proofs in [`proofs/proofs.json`](proofs/proofs.json) (bound and ordinary, repeat runs, seven
  forgeries) carry the hash in [`trusted-config.json`](trusted-config.json). Proof size varies per
  proof with the query positions, by the same amount in both modes.
- **No extra permutations.** The two WAUTH hashes share a lane-packed batch with the output INNER
  hashes (all 22-word frames), and the identity hash, now over the selected key `ak₀`, joins the
  OWNER batch. V4 hashed the identity in a batch of its own, so the number of batches is V4's.
- The WASM proof time is not re-measured: the trace stays at 2^18 (spec §4.5). The SDK measures
  it again in P4.

## Tests

`cargo +nightly-2026-01-15 test --release --test payment_r5` (17 tests) and
`cargo +nightly-2026-01-15 test --release --features tamper --test payment_r5_malicious` (19
tests). The V3, V4 and P1 suites pass (7, 12 + 7, 7 + 11).

Spec §4.4 coverage:

- **Malicious witnesses:** `m = 2`; `m = 1` with `account = 0` and `m = 0` with `account ≠ 0`,
  each also **isolated** (a witness planted so that the tree agrees and only that mode rule can
  reject it); a bound note spent with `m = 0`, an ordinary note with `m = 1`, a note bound to `A`
  under `A′` (each fails or proves under an unknown root); inputs bound differently (ordinary, or
  to another account) spent together; non-canonical `account` limbs (a limb at 2^28, a value at
  2^251 and at p) and `valid_until` limbs, `valid_until = 0`, nonzero padding (rejected by the
  bridge mirror `decode_statement`); an ordinary or other-account spend with `A`'s `sk` and scope
  does not reproduce `A`'s identity handle.
- **Wiring (AB-M6):** `wiring_uses_the_same_variables` checks, on the circuit variables, that the
  published account limbs are the words both WAUTH hashes read, that one `m` serves the mode rules
  and both selects, and that the identity hash reads the same `ak₀` variables as OWNER₀.
- **Positive:** every V4 shape in both modes; a bound dummy input (its nullifier is the bound-mode
  one, AB-M14); ordinary and bound receivers paying each other and the created note spent; an
  ordinary V5 statement equal to V4's on every field except `identity`; `valid_until` of 1 and
  2^56 − 1; an account just below 2^251; the decoder reads back every native statement exactly.
- **V4 carried over, both modes:** conservation ±1, zero output receiver and rho, dummy with
  value, disabled real input, enabled input off the tree, wrong siblings, other asset, zero real
  input, zero asset, inputs under two assets, the same leaf twice, the `e₁` and `x` hint
  tampering, voluntary reveal.
- **F09, the inflation-critical gadgets V5 shares with V4** (AB-IM1). Each case is isolated: the
  witness reaches the planted tree and balances every limb equation, so only the named gate can
  reject it.
  - The carry range: `out = in + p` with carries solving every limb equation over M31
    (`payment::CARRIES`).
  - Bit booleanity, which range-checks every amount limb and position bit:
    - an output limb of −1 minting one unit;
    - dummy limbs (p − 5, 5) carrying 5·2^16 − 5 while their sum is 0;
    - an output limb at 2^16;
    - a position bit of 2 beside an equal sibling, which gives the same note a second nullifier.
  - `(1 − x)·intent` on a zero-budget invoke.
  - An identity flag of 2.

  The raw hints go through the same call as the honest ones. `merkle::guess_bits` and
  `payment::amount_unchecked` gained raw entry points (`guess_bits_raw`, `amount_from_bits`)
  that emit the same gates: the R4 circuit hash still equals the deployed bridge's record, and
  R5's is unchanged.
- **Bridge-mirror decoder** (AB-IM2): every amount limb at 2^16, a limb at 2^28 and the value p in
  every felt field, and a word at p in each digest and the expiry (`M31 range`).

**Mutation check (F09).** 27 mutants (the implementer's, the Math Reviewer's 18, and the decoder
rules) were each applied to `payment5.rs`, `payment.rs` or `merkle.rs`, and both suites were run:

| Mutant | Killed by |
| --- | --- |
| Mode rule `accountₗ · (1 − m) = 0` deleted | `m_zero_with_account_isolated`, `m_flipped` |
| Mode rule `nonzero_vector_if(account, m)` deleted | `m_one_with_zero_account_isolated`, `m_flipped` |
| Select always `H(WAUTH, …)` / always `H(AUTH, …)` / input 1 always ordinary | several tests each |
| Published account, WAUTH₁'s account or the mode rules' account guessed as a copy; a separate `m` for input 1 | `wiring_uses_the_same_variables` |
| Identity hash over `sk₀` instead of `ak₀` | `identity_handles_follow_the_selected_key` and 2 more |
| `valid_until` not published | several tests |
| `(1 − x)·intent` / `(1 − x)·withdrawn` deleted | `exit_bit_is_forced_by_an_intent_alone` / `x_zero_with_exit_and_non_boolean` |
| Identity-flag booleanity deleted | `identity_flag_is_boolean` |
| `sum₁·(1 − e₁)` deleted | `attacker_mutations_fail_the_circuit` and 1 more |
| Asset nonzero deleted | `zero_asset_fails_on_a_consistent_tree` |
| **Shared carry range deleted** (`payment.rs`) | `carry_range_stops_a_mod_p_mint` |
| **Shared bit booleanity deleted** (`merkle.rs`) | the three `amount_bit_booleanity_*` tests (and the position case) |
| Mirror: padding, `valid_until` limbs, amount limbs, account range, `valid_until ≠ 0`, M31 range, felt limb range | `bridge_only_rules` (and the tamper decoder tests) |
| `m·(m − 1) = 0` deleted | **survives: equivalent.** The two mode rules force `m = 1` when `account ≠ 0` and `m = 0` when `account = 0`; the booleanity check is kept because the spec states it. |
| Mirror: canonical check in `felt_from_limbs` deleted | **survives: equivalent.** `bridge_checks` rejects the same non-canonical felt with the same reason. |

## Hiding (F27)

The hiding audits take `--relation r0|r5|r5-bound` and `--shape S` (default `r0`, which reproduces
the committed V3 baselines exactly). On V5:

- **Rank** ([`hiding/rank.json`](hiding/rank.json)): all 8 shapes in both modes, every component
  and tree at full rank, **0 unblinded combinations**.
- **Seed invariants** ([`hiding/invariants.json`](hiding/invariants.json)): transfer and single in
  both modes, 336 functionals at rank 336, **0 seed-invariant combinations**.
- **Per point** ([`hiding/points.json`](hiding/points.json)): transfer and single in both modes,
  full rank at 35 and 560 LDE points per column (468/468 and 6,768/6,768 functionals), as V3.

F27's remaining fixes are open for V4 and V5 alike and are not part of P2:
- make the Jacobian dimension test the hiding regression;
- check `16k ≥ dim V_pub` in `prove()`;
- port `h12_model`'s structural checks.

## Forged statements for P3

`prove_payment_r5 --forge K` proves a statement the circuit admits and the bridge must reject, for
the bridge's real-proof negatives (F11). Each was proved and verified natively, and the Rust
bridge mirror rejects it for the named reason:

| Forgery | Reason |
| --- | --- |
| `account-range` (account = 2^251) | `account range` |
| `account-limb-range` (tamper) | `limb range` |
| `valid-until-zero` | `valid_until` |
| `valid-until-limb-range` (tamper) | `limb range` |
| V4's: `voluntary-reveal`, `zero-delivery`, `asset-range`, … | as V4 |

`statement-limbs.json` beside each proof holds the exact published limbs, since a limb-range
forgery has no hex form.

## Review

Math implementation review: [`docs/reviews/account-bound-p2-math-review.md`](../../../../../docs/reviews/account-bound-p2-math-review.md),
CONDITIONAL GO.

| Finding | Resolution |
| --- | --- |
| AB-IM1 (condition) | The F09 tamper cases above, and the re-run mutation table: every mutant is killed except two, both documented as equivalent. |
| AB-IM2 | Raw decoder cases for every rule; the mirror rejects words at or above p (`M31 range`), which the Cairo bridge gets from QM31 decoding. |
| AB-IM3 | `mode_rules` records its `account` variables; the wiring test checks them against the published limbs. |
| AB-IM4 | Deferred to P3: a `TMR0_BIND_V5` known-answer vector (Rust or Python reference) beside the Cairo binding. |
| AB-IM5 | Per-point hiding recorded; the stray `forge-dbg` entry removed; F27's other fixes stay open (above). |
