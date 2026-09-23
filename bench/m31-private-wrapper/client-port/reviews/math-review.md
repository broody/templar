# Independent math review: arithmetic-only profile, lane packing, R0, Tree::Compress

2026-09-23. Reviewer: independent (Claude), no code changes made.

**Verdict: CONDITIONAL GO for continued research use** of the arithmetic-only profile, lane-packed
hashing and the R0 relation with `Tree::Sponge`. I found no soundness break in the fork changes
or in R0 as used in the pinned bridge. Two conditions apply:

1. The absent-component zero-sum check can be omitted today without any test noticing, and
   omitting it lets a prover forge any public output (demonstrated below). It must become part
   of one library verification entry point and get a real negative test.
2. The hiding claim is not supported by the 45-row padding budget. The budget does not
   account for the FRI first-layer coset openings (fold step 4). Privacy must remain "not
   established".

**`Tree::Compress`: NO-GO for adoption as specified.** It is fine as a measured variant, but
its separation from sponge-mode hashes is only about 2^62 (finding M1). Its compression-mode
cryptanalysis is also still owed.

Scope reviewed:
- The fork diff `5a7c5ed..852bc4d87`, covering `crates/` and `stwo_cairo_verifier/`.
- In client-port: `src/{payment,membership,sym,ro,merkle}.rs`, `tests/payment_r0.rs`,
  `examples/{support/mod.rs,prove_payment_r0.rs,gen_cairo_consts.rs}` and
  `cairo-r0/bridge/src/lib.cairo`.
- The four results READMEs and ADR-0024.

Tests run:
- Fork `circuit-prover`, `circuit-verifier`, `circuit-common`: 29 + 10 passed.
- client-port `payment_r0` (5 passed) and `spike_membership` (2 passed).

I also ran one new experiment (Appendix A).

---

## Findings (by severity)

### Critical

None found.

### High

**H1. The hiding budget does not cover the FRI first-layer openings, so row padding alone
cannot give a hiding argument (hiding, not soundness).**

- Where:
  - `target/proving-arith/crates/cairo_verifier/src/verify.rs:71-74` defines
    `NON_QUERY_INFO_LEAK = 10` as "2 OODS queries × 4 + 2".
  - `examples/prove_payment_r0.rs:21` sets `BLINDING = 35 + 10`.
  - `crates/circuit_common/src/finalize.rs:91-114,179-194` generates the blinding rows.
  - `crates/stwo/src/core/fri.rs:470-481,621-640` does the first-layer coset decommitment,
    `2^fold_step` values per query.
  - `crates/circuit_prover/src/prover.rs:174` fixes `channel_salt = 0`.
- **How much randomness there is.** Per blinding iteration, the Arithmetic profile adds four
  fresh QM31 values:
  - qm31_ops gets `x+0=x`, `0+y=y` and `z+0=z`;
  - eq gets `x'` through `x'+0=x'` and `eq(x',x')`.

  That is 16 M31 per iteration, or about 720 M31 of randomness per proof at 45 iterations.
- **What the base trace reveals.** For each of its 16 distinct M31 columns, the base trace
  reveals:
  - 35 query values;
  - 4 M31 of OODS (the eq `in0`/`in1` columns are identical, so they count once).

  That is about 624 M31, which fits: `in1` has 45 random rows against 39 reveals.
- **What the budget misses.** With `fold_step = 4` (fixed by `build_bridge_arith.py`), each
  query also opens **15 further DEEP-quotient values** through the first FRI layer's
  `fri_witness` (`fri.rs:621-633`). That is about 525 QM31, or 2,100 M31, of extra functionals
  per proof. Each one is a public-coefficient combination of every committed column at a point
  that was not queried.
- **Other gaps.** The count also leaves out:
  - interaction and composition openings, which carry no randomness of their own;
  - unsalted Merkle leaves across all trees.
- **Failure scenario.** The transcript carries far more field elements (over 2,700 M31) than
  the blinding entropy (about 720 M31). So its distribution cannot be independent of the
  witness. Some public combinations of opened values are functions of the witness trace alone.
  No practical extraction is shown here. But a simulation-based argument
  (`privacy-contract.md` §4) cannot be built on the row count.
- **Fix, choose one:**
  - (a) Budget the blinding for everything revealed, e.g.
    `n_padding ≥ n_queries·2^fold_step + non-query leak` per column, plus slack. This is
    about 570 iterations, or ~2.3k extra rows, cheap next to 175k–295k.
  - (b) Use a first-layer fold step of 1.
  - (c) Add a masking polynomial to the DEEP/FRI batch, with salted Merkle leaves.

  Then write the simulation argument over the full transcript: base, interaction and
  composition trees, OODS, FRI layers, PoW and the claimed sums. This is shared with
  upstream's design, not introduced by the profile.

### Medium

**M1. `Tree::Compress` inputs are separated from later sponge-mode permutation calls by only
~62 bits.**

- Where:
  - `src/payment.rs:192-203` (native `node`) and `src/payment.rs:505-515` (circuit);
  - `src/membership.rs:194-210` (`compress_lanes`);
  - claim in `results/stwo-client-r0-compress/README.md:56`.
- **Layout comparison.**
  - The compress input is `[TAG,1,NODE1,level, l0..l8 (4-12), r0..r8 (13-21), 0, 0]`.
  - A sponge absorb after the first block has attacker-chosen rate words in positions 0..14.
    Its capacity words 15..23 are the previous permutation's output.
- **Concrete case (INNER hash).** Take the 22-word `INNER` hash of an output note,
  `H(INNER, receiver‖rho)` (`payment.rs:471-472`):
  - Block 2 places `rho[2..9]` at 0..6, then `1` at 7 and zeros at 8..14.
  - Choose `rho[2..6] = (TAG,1,8,level)`. Then search over the free block-1 words (receiver
    and `rho[0..2]`) until the first permutation's output words 22 and 23 are both 0. That
    takes about 2^62 work.
  - The two permutation inputs are then identical. So
    `INNER(receiver,rho) = node(level, (rho6,rho7,rho8,1,0,0,0,0,0), (0,0,c15..c21))`.
  - `OWNER` is not usable this way, because its second block is `nk`, a hash output.
- **Impact.** This is not an R0 membership attack: the depth is fixed and every level
  carries its own tag. It does falsify the stated domain separation. It would matter for any
  later format that compares digests across roles, such as variable depth, append proofs, or
  a leaf/node ambiguity.
- **Fix.** Put all six fixed words in sponge-capacity positions, e.g. `l,r` at 0..17 and
  `[TAG,1,NODE1,level,0,0]` at 18..23. A later-block collision then needs six capacity words
  (186 bits) to match. First-block sponge inputs have zero capacity, and `TAG ≠ 0`, so the
  two modes stay distinct. Alternatively use mode-specific round constants or IV.

**M2. The absent-component zero-sum check is necessary but is enforced only by caller
convention in Rust, and no negative test exercises it.**

- Where:
  - `crates/circuit_verifier/src/circuit_claim.rs:75-81` (the predicate);
  - `examples/support/mod.rs:83` (the only production-path caller);
  - `crates/circuit_prover/src/prover_test.rs:267,568-580`;
  - `examples/support/mod.rs:110-116` (the "claimed-sum-shift" negative);
  - `results/stwo-client-arith/README.md:88`.
- **Demonstration (Appendix A).** Without the check, a prover can publish any output value:
  - Set `claim.output_values[0]` to a forged value before mixing it into the channel.
  - After drawing the lookup elements, set `claimed_sums.triple_xor -= lookup_sum`.
  - The eq/qm31_ops constraints and FRI still pass, because the absent component has no
    constraints.
  - The client-port verifier flow accepts the forgery with the check removed, and rejects it
    with the check in place.
- **The existing negatives miss it.** The existing negative moves one unit from `eq` to
  `triple_xor`. That breaks eq's own cumulative-sum constraint, so it fails STARK verification
  (`OodsNotMatching`) whether or not the check is present (Appendix A, last line). The fork's
  `test_arithmetic_profile_rejects_absent_claimed_sum` only calls the predicate. The Cairo
  bridge negative does exercise the Cairo assertion, because it runs first (`lib.cairo:185-188`).
  But a verifier without it would still reject that tamper through OODS.
- **Fix.**
  - Move the check into a single `verify_circuit_proof` library function in
    `circuit_verifier`. It should run next to `lookup_sum`, and all Rust callers should use it.
  - Replace the shift negative with the Appendix A forgery: it must pass with the check
    removed and fail with it.
  - Add the same forgery as a Cairo negative.

### Low

**L1. The R0 soundness tests cannot detect under-constrained gates.**
- Where: `tests/payment_r0.rs:46-72`.
- Each "broken witness" is re-derived consistently by the honest `build`, and `check` accepts
  "valid but a different statement". So the tests exercise witness generation and statement
  binding, not constraint completeness.
- My manual audit (§C) found no under-constraint. Regressions would not be caught, though.
- **Fix.** Add adversarial-assignment tests. For each of these, modify the value vector,
  propagate forward, and assert `!is_circuit_valid()` unless the statement changes:
  - a carry set to 2;
  - a position or amount bit set to 2;
  - a two-hot `nonzero_vector` selector;
  - an `unpack` with swapped lanes;
  - a non-base lane.

**L2. Checks in the reference statement that R0 omits.** Here `statement.cairo` is
`bench/controlled-push-e2e/cairo/src/statement.cairo`. See §C for the full list. Two of them
should be restored at the bridge or pool rather than left out:
- `delivery != 0` (`statement.cairo:57`);
- context nonzero and address range (`statement.cairo:25`).

The bridge only checks canonical felts (`cairo-r0/bridge/src/lib.cairo:35-46`).

**L3. `pack` is base-field only by convention.**
- Where: `src/membership.rs:116-120`, which relies on `ro.rs:265-268` and
  `context.rs:216-223`.
- Every current caller passes base-field values (§B). A future QM31-valued word would spill
  its extension coordinates into the neighbouring lanes, silently.
- **Fix.** Take `M31Wrapper<Var>` in `pack` and the lane APIs, or add a debug assertion on
  the value.

**L4. Wording in the results.**
- `stwo-client-r0-compress/README.md:52` says "22 of 24 words controlled". It is 18 free
  words. The level is fixed by position, and six words are fixed.
- `stwo-client-r0-lanes/README.md:57` says "five broken witnesses fail". Some of them change
  the statement instead.
- `stwo-client-arith/README.md:88` implies the shift tamper tests the absent check. It does
  not (M2).

### Note

- **N1. Trust chain for the circuit hash.** The bridge pins a hash taken from a manifest that
  the proving run itself wrote (`build_bridge_arith.py:1-8`, `prove_payment_r0.rs:75-86`).
  Add a CI step that recomputes the hash from `payment::build::<NoValue>` at a pinned commit.
  It should match `pinned.cairo`.
- **N2. The R0 note has no controller/policy fields** (`payment.rs:186-189` vs
  `statement.cairo:15`). When controlled notes arrive, they need a different kind or explicit
  fields. Otherwise ordinary and controlled note formats become ambiguous.
- **N3. The Rust native flow does not check relation uses (< P).** The Cairo verifier does
  (`lib.cairo:236-246`). This is harmless for R0: the multiplicities are preprocessed and a
  2^19-row trace is far below P. A library verifier should still include it for parity.

---

## A. Arithmetic-only profile

**Is removing the absent components sound for the LogUp/Gate relation?** Yes, given the
zero-sum check.
- An absent component contributes no columns and no constraints (`circuit_claim.rs:42-44`,
  `circuit_components.rs:163`, `circuit_air.cairo:150-270`).
- With its claimed sum forced to 0, it adds nothing to `lookup_sum`. The statement is then
  exactly "a circuit whose Blake/XOR/M31-to-u32 gate lists are empty".
- The remaining balance involves eq, qm31_ops, the `u` term and the public outputs, with
  multiplicities taken from the committed preprocessed `qm31_ops_mults`. That is upstream's
  argument unchanged.
- The prover refuses Arithmetic for a circuit that has such gates (`finalize.rs:299-315`).
  The verifier does not rely on that refusal, since the topology is fixed by the committed
  preprocessed root.

**Is log size 0 an unambiguous, committed sentinel?**
- A present component has a padded size of at least `N_LANES`, so its log size is at least 4
  (`finalize.rs:326-328`). Fixed tables are constants of at least 4. So 0 means absent and
  nothing else.
- Rust:
  - `circuit_component_log_sizes` returns 0 for non-arithmetic components exactly when the
    trusted layout is arithmetic (`statement.rs:182-213`).
  - `layout_profile` accepts only exactly the 10 eq+qm31_ops columns, or any layout containing
    `seq_16` (`preprocessed.rs:130-144`).
  - Mixed layouts panic, which fails closed.
- Cairo: the sizes are generated constants (`gen_cairo_consts.rs:79-86`), with fixed tables at
  0 when `seq_16` is absent.
- Both circuit-hash implementations pack all 11 log sizes (Rust
  `circuit_verifier/src/circuit_hash.rs:24-40`, Cairo `circuit_hash.cairo:19-37`). So the
  sentinel is committed, and the bridge's pinned hash (`bridge/src/lib.cairo:59-62`) binds it.

**Is the zero-sum check necessary and sufficient, and placed so it is always enforced?**
- Necessary: yes (M2, Appendix A).
- Sufficient: yes, by the argument above.
- Placement:
  - Cairo checks it unconditionally, after the lookup elements are drawn and before
    `lookup_sum` (`lib.cairo:185-192`). Order does not matter, since every assertion must hold.
  - The absent sums are still mixed into the channel with the others (`lib.cairo:196`, Rust
    `mix_felts(&claimed_sums.into_array())`), so the transcript format is unchanged.
  - Rust enforces it only where the caller remembers (M2).

**Can a proof be accepted under the wrong profile, or with columns misaligned?** I found no
path.
- The profile comes from the verifier's trusted configuration, never from the proof:
  - Rust takes it from the trusted `PreprocessedCircuit` layout (`support/mod.rs:57-64`);
  - Cairo takes it from generated constants plus the pinned hash.
- Column lists are built by the same filter on both sides:
  - `column_log_sizes_per_tree` skips log 0 (Rust `circuit_claim.rs:37-49`, Cairo
    `claims.cairo:107-128`).
  - The prover commits eq then qm31_ops, in `ComponentList` order (`trace.rs` arithmetic path).
- Cairo `validate_mask_usage` (`circuit_air.cairo:272`) rejects leftover or missing mask values.
- In the arithmetic build, the absent components' preprocessed indices are `INVALID_COLUMN_IDX`
  (`gen_cairo_consts.rs:116-122`). They are never read, and reading one would fail.
- Relation-use accounting skips only log-0 components (`claims.cairo:151-158`), which is
  consistent.
- The in-circuit Rust verifier still asserts the full profile (`statement.rs:67`).

## B. Lane packing

**Is lane-wise compilation exact?** Yes. QM31 addition and subtraction are coordinate-wise.
A product with `(c,0,0,0)` is multiplication by the embedded M31 scalar `c`, which scales all
four coordinates. `pointwise_mul` is coordinate-wise by definition. So the map
`M31^4 → QM31`, `(l0..l3) ↦ l0 + l1·i + l2·u + l3·iu`, turns the recorded M31 circuit into
four independent copies. Operation by operation (`sym.rs:244-300`):
- add/sub with a constant broadcasts `(c,c,c,c)` (262-265, 280-283);
- constant × variable uses the base scalar, asserted base at 257-261 and 286-287;
- variable × variable uses `pointwise_mul` (288);
- constant-only outputs broadcast (296).

Constant folding cannot introduce cross-lane terms:
- Sym folds only constant∘constant and the ±0/×1 identities (`sym.rs:66-99`).
- The upstream `add` shortcut returns the other operand when one operand is the canonical
  zero (`circuits/src/ops.rs:106-118`).
- Literals in `eval!` are base constants (`ops.rs:50-52`), and none is applied to a packed
  value.

`permute` uses only `+`, `*` and `From<M31>` (`membership.rs:19-40`,
`m31-private-blake/client/src/hash.rs:10-33`).

**Is `pack` injective, and `unpack` unique?** Yes, given base-field inputs.
- `pack` is `from_partial_evals` (`membership.rs:118-120`). With base-field inputs, the four
  inputs are exactly the four coordinates.
- `unpack` guesses four `guess_m31` values, each pinned by `x .* (1,0,0,0) = x` at
  finalization (`context.rs:220-223`), and asserts that they repack to `v`
  (`membership.rs:139-144`). A QM31 value has exactly one base-field coordinate 4-tuple, so the
  split is unique.

**Can a lane be exploited, including junk lanes or non-M31 words?**
- Every operation after packing is coordinate-wise, so no lane's value can affect another's.
- Junk lanes hash the constant all-zero message (`membership.rs:154,197`). Their unpacked words
  are constrained, and only marked maybe-unused (181-187, 203-208).
- The one way to get cross-lane leakage is a non-base input word.

**Are all packed message words base-field constrained?** Yes. The packed words are:
- frame constants (`payment.rs:424,509`);
- `guess_m31` words: context, sk, rho, receivers, siblings (`payment.rs:338-340,491`);
- amount limbs `Σ b_k 2^k` with boolean base bits (`payment.rs:371-379`);
- position limbs (522-529);
- `unpack` outputs (digests);
- selector blends `x + bit·(y−x)` of base values (497-499);
- `zero` / `one4`.

Nothing QM31-valued is packed. L3 recommends making this a type invariant.

## C. R0 relation versus `privacy-contract.md` §3 (lines 105-112)

| Obligation | Status | Evidence |
| --- | --- | --- |
| Ownership | OK | `ak = H(AUTH,sk)`, `nk = H(NK,sk)`, `receiver = H(OWNER, ak‖nk)` (`payment.rs:465-473`). `sk ≠ 0` via a one-hot selector plus inverse (352-364). A payer who knows `(receiver, rho, amount)` cannot produce `nk` or spend. |
| Input commitment | OK (R0 scope) | `cm = H(NOTE, ctx27 ‖ amt8 ‖ H(INNER, receiver‖rho))`. The same `context` vars feed all four notes (436, 479-485) and the statement (548). Controller/policy fields are absent, not zero (N2). |
| Membership | OK | Bits: 32 `guess_bits`, each boolean via `b(b−1)=0` (`merkle.rs:378-388`, `payment.rs:450`). Ordering: `left = x + b(y−x)`, `right = y − b(y−x)` gives `(cur,sib)` at `b=0` and `(sib,cur)` at `b=1`, matching `climb` (495-500 vs 206-213). Levels: each carries its level tag. Both paths must reach one root: word-wise `eq` (519-521), with root = `cur[0]` in the statement. |
| Nullifiers | OK | `nf = H(NF, nk ‖ cm ‖ pos_lo ‖ pos_hi)`. The same path bits are packed as two base values below 2^16 (522-535), which is injective and matches native `nullifier` (215-217). Duplicates are rejected publicly: `nf0 ≠ nf1` in the bridge (`bridge/src/lib.cairo:77`) inside the verified OS run, plus the pool's spent-set. |
| Outputs | OK | Commitments are recomputed from private `(receiver, rho, amount)`, with receiver and rho nonzero (455-463, 483-484). Delivery digests are public limbs placed in order after each commitment (537-541). They are bound only as statement elements, which matches the §3 "binding, not encryption correctness" scope. |
| Amounts | OK | 8 limbs × 16 boolean bits. Nonzero via the limb sum (< 2^19, so no wrap) and an inverse (367-385). Conservation (388-416): `d_k + c_k = c_{k+1}·2^16`, `c ∈ {−1,0,1}` by `n(n−1)(n+1)=0` on a base-pinned guess, final carry 0. All magnitudes are at most 131,071, far below p/2, so the M31 equalities are integer equalities and `a0+a1 = b0+b1` holds over the integers (129-bit). For completeness, `|d_k + c_k| ≤ 131,071 < 2·2^16`, so carries in {−1,0,1} always exist. |
| Hash wiring | OK | Frames `[TAG,1,kind,level]`, 10*-padding on a short last block, `+1` on capacity word 15 for a full last block, and capacity chaining through packed state (`membership.rs:148-189`). This matches `native_sponge` (`payment.rs:147-169`). Equal lengths per batch are asserted (151). |
| Public binding | OK | 92 base limbs are packed four per output (548-550). The order is identical to `statement_limbs` (125-136) and to the bridge's slices (`bridge/src/lib.cairo:73-86`). Coordinates are canonical M31. The bridge enforces felt limbs below 2^28 and a canonical felt252. |

**Checks the reference makes that R0 omits** (`statement.cairo`):

| Omitted check | Assessment for R0 |
| --- | --- |
| `version` (21) | Replaced by the statement tag plus the pinned circuit hash. Fine. |
| `chain, pool, token ≠ 0`; `addr(pool)`, `addr(token) < 2^251` (25) | Not checked in-circuit or in the bridge. Fine only if the pool supplies its own address and token. Better to assert in the bridge (L2). |
| `nf ≠ 0` (40); `ak ≠ 0 ∧ nk ≠ 0` (42); input `receiver ≠ 0` (13) | Hash outputs; zero with negligible probability. Fine. |
| Output `cm ≠ 0` (57) | Negligible. Fine. |
| Output `delivery ≠ 0` (57) | Not checked anywhere. In the reference, 0 is the padding value for an empty slot. Add it to the bridge or pool (L2). |
| In-statement duplicate-nullifier check (49) | Moved to the public bridge. That is acceptable, since the bridge runs inside the verified computation (§5). |
| Controller, policy, deadline, nonce, transition, withdrawals, variable counts (23-31, 63-72) | Out of R0 scope (§2). Fine. |
| Leaf hashing without a level tag (46) | R0 adds level tags, which is stricter. Fine. |

I found no under-constraint in R0 (see L1 on test strength).

## D. `Tree::Compress`

**Construction.** `node = P([TAG,1,NODE1,level, l9, r9, 0,0])[0..9]`, with no feed-forward.
Of the 24 words, 18 are free (l, r), 1 is fixed by position (`level`) and 5 are constants.
- Generic bounds, for an ideal permutation with forward and inverse queries:
  - collision: about 2^139 (279-bit output);
  - second preimage: about min(2^279, 2^186), since six fixed input words cost 186 bits on
    inversion.
- Both are adequate against the proof system's ~96-bit target.

**Domain separation.**
- Against sponge **first** blocks: holds. Their capacity is 0 and word 2 is a kind in 1..7,
  while NODE1 = 8.
- Against later sponge blocks: about 62 bits only (M1).
- Across levels: the level word separates them.

**Round numbers.** The instance is RF = 8 (4+4), RP = 22, α = 5, t = 24 over 2^31−1
(`m31-private-blake/client/src/constants.rs:2,28,54`). That matches the standard 128-bit
Poseidon2 instance for this field and width, the one Plonky3 uses. Plonky3 also uses its
Poseidon2 in `TruncatedPermutation` Merkle compression, but that is precedent, not proof.
Compression mode gives the attacker more of the state than one sponge absorb does: 18 free
words and a 9-word output, against 15 rate words behind a zero capacity. Published
cryptanalysis of small-field Poseidon2 in compression or truncation modes is thinner than for
sponge mode, and it has been active in 2024-2025. I could not consult it offline.

**Recommendation.** Keep `Tree::Sponge` as the reference. Adopt Compress only after all of
the following:
- (1) the M1 layout fix;
- (2) a written check of the algebraic-attack bounds (Gröbner/CICO) for this compression
  setting at t = 24, RP = 22, possibly with a margin of +2 RP;
- (3) a literature check on the recent compression-mode attacks;
- (4) a known-answer test of the constants against the Poseidon2 reference generator (round
  constants and the internal diagonal `[-2, 2^0..2^22]`), which I did not verify.

## E. Hiding (assessment, not a proof)

With only eq and qm31_ops, no multiplicity depends on the witness: all of them are preprocessed
from the fixed topology. The topology does not depend on the witness either, which is tested:
`payment_r0.rs:26-31`, and `prove_payment_r0.rs:51-53` builds with a zero seed and asserts
equality. The blinding seed comes from OsRng for each proof (`prove_payment_r0.rs:45-48`).

What remains to argue:
- **(i) A full-transcript count or simulation (H1).** Base-trace query and OODS reveals fit
  the 45 rows: about 156 reveals against 180 random M31 per coordinate. The FRI first-layer
  coset values (15 per query at fold step 4), the composition openings, and the interaction
  columns (nonlinear in the same randomness, no new entropy) do not fit. The `in1` and eq
  columns have 6 M31 of slack each even before FRI.
- **(ii) Merkle leaves are unsalted and `channel_salt = 0`** (`prover.rs:174`). The
  unqueried leaves hide the witness only while their preimages keep min-entropy after
  everything else is revealed. That fails once the budget in (i) is exhausted.
- **(iii) Repeated proofs** of the same notes, and a server that chooses when to request
  proofs (`privacy-contract.md` §4).

Does lane packing or R0 add new witness-dependent structure?
- No new components, and no witness-dependent topology or multiplicity.
- `unpack` guesses, one-hot selectors, inverse witnesses and carries are ordinary values in
  existing qm31_ops and eq rows. They are covered by the same argument, and need nothing extra
  once (i) holds.
- Junk lanes hold public constants, which does not matter to the simulator.
- The statement adds 23 public outputs, which are public by design.
- Log size changes (log 18/19) do not change the per-column budget.

---

## Limits of this review

- I did not review:
  - upstream eq/qm31_ops AIR constraints, the LogUp framework or the stwo verifier core;
  - the bounded-memory commit `8acdbe55d`;
  - the Cairo `verify` core, account, pool, binding and delivery hashing (see
    `reviews/binding-review.md`, which I did not rely on);
  - PROOF2 and the OS.
- Poseidon2 constant provenance and the round-number derivation were not checked against the
  reference generator. The Poseidon2 security claims are not re-derived.
- The hiding assessment is a counting argument, not a proof. H1 shows the stated budget is
  insufficient; it does not show a practical leak.
- The soundness conclusions for R0 come from a manual constraint audit, plus tests showing
  the circuit output equals the native reference. I did not machine-check them.
- I ran the client-port tests `payment_r0` and `spike_membership` only, not the slower suites.

---

## Appendix A: reproduction of M2 (forgery without the absent check)

The throwaway crate is at
`/tmp/claude-1000/-home-broody-development-templar/5fc13b65-b1f1-4714-b584-08d0d0577803/scratchpad/review-math/absent-forge/`.
It has path dependencies on `target/proving-arith/crates` and uses the client-port
`Cargo.lock`. Build with `RUSTUP_TOOLCHAIN=nightly-2026-01-15 cargo build --release`.

- **Circuit:** `y = x·x` with `x = 5`, one output, 45 blinding rows, `Profile::Arithmetic`.
- **FRI config:** `FriConfig::new(10, 0, 2, 35, 4)`.
- **Forging prover:** `prove_circuit_with_precompute_bounded` (`prover.rs:149-251`) copied
  with two edits:

```rust
let (mut claim, log_sizes, igen) = write_trace(values, pp.preprocessed_trace.clone(), pp.n_outputs, &mut tb, &tg, &twiddles);
claim.output_values[0] = forged;                       // public output no longer matches the trace
// ... mix circuit hash and claim, commit trace, grind, draw elements ...
let mut ic = write_interaction_trace(&log_sizes, igen, &mut tb, &elements, &twiddles);
let imbalance = lookup_sum(&claim, &ic, &elements);    // nonzero
ic.claimed_sums.triple_xor -= imbalance;               // free term on the absent component
// ... mix ic, commit interaction trace, prove_ex as upstream ...
```

- **Verifier:** `examples/support/mod.rs::native_verify`, with the trusted root, trusted
  statement `[forged]` and the check toggled.

Output:

```
honest output = (25 + 0i) + (0 + 0i)u (5^2)
forged output = (1234568 + 0i) + (0 + 0i)u
verify WITHOUT absent check: Ok(())
verify WITH absent check:    Err("absent component claimed sum")
honest proof, no check:      Ok(())
shift negative, no check:    Err("stark: OodsNotMatching")
```

The last line shows that the existing "claimed-sum-shift" negative is rejected by STARK
verification alone, so it does not exercise the check.
