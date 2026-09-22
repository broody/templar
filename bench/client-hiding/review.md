# Math Review: client-side hiding construction (gate M1)

Status: **conditional-go for M2 implementation work as lemma-development and measurement
infrastructure only; the construction's hiding lemmas (L2/L3) are NOT approved as
proven, and no privacy qualification can follow from the M3 empirical battery alone.**
The observation inventory is substantially correct but contains three material
corrections (one mathematical: the FRI-side functionals are not linear; two
accounting/citation). Soundness preservation (L4/L5) is assessed as achievable with
two required amendments. The equalization lemma (L2) is the load-bearing gap; a
precise reformulation and the required lemma shape are stated below. This review is
consistent with `bench/client-privacy-feasibility/review.md` (qualification bar,
line 72) and `bench/direct-air/privacy-review.md` (escalation and no-arbitrary-padding
boundaries); no divergence from them is taken.

## 0. Review basis

- Role per `target/direct-air/stwo/AGENTS.md` (Math Reviewer: reviews and escalates
  only; this document is the sole artifact written). The
  `soundness-review-checklist` (`.codex/skills/`, byte-identical policy), the
  paper distillations `INDEX.llm.md`, `Circle_STARKs.llm.md`,
  `Stwo_Whitepaper.llm.md`, and the paper-implementation divergence log were read
  before judging.
- Pinned trees verified read-only against the claims below:
  stwo `489a0f3` (`crates/stwo`, `crates/constraint-framework`), stwo-cairo
  `9b6be27`, stwo-circuits `5ef951a`.
- Reviewed deliverables: `bench/client-hiding/spec.md` (primary),
  `bench/client-hiding/measurement-plan.md`,
  `bench/poseidon-membership/component-inventory.md`, both prior privacy reviews.
- **Verified directly in pinned code:** every inventory item below (§1), the
  channel ordering, the LogUp constraint structure and the absence of multiplicity
  cap checks, the FRI layer/complement/last-layer structure, the lifted-opening
  geometry, the storage-mode protocol-neutrality, the client config.
- **Assessed analytically (no code or paper proof exists yet):** L1's corrected
  form, single-column recoverability's exception probability, the entire L2
  equalization question, the secant-variety refinement, the statistical-hiding
  lemma, and the d ≈ 27 free-parameter estimate.

## 1. Observation inventory (spec §1) — verification and corrections

Config claims verified: `pow_bits=27`, `FriConfig::new(0, 3, 23, 4)`,
`lifting_log_size = Some(23)` at
`bench/poseidon-membership/client/src/main.rs:43-47` (spec cites 42-48 — the
`PcsConfig` block is 43-47; immaterial). Security metric `27 + 3·23 = 96` matches
`core/pcs/mod.rs:44-46` and `core/fri.rs:77-79`.

Column counts: original ≈ 820 and interaction ≈ 404 M31 columns match the sum of
the component inventory (342+126+169+141+20 variable + 22 fixed original; 56+24+36+
200+32+4 variable + 52 fixed interaction); + 8 split-composition columns ⇒ K ≈ 1228.
Composition tree: 2 halves × 4 coordinate polys
(`prover/mod.rs:74-79`, `into_coordinate_polys`).

**O1 — OOD samples of every committed column incl. mask-offset extras and the
periodicity sample: CONFIRMED, with citation and scope corrections.**

- OODS point drawn after composition commitment: `prover/mod.rs:83` (order:
  commit :74-79 → draw :83 ✓).
- Per-column sample points = one point per mask offset:
  `constraint-framework/src/component.rs:253-265` (points `point + trace_step·offset`);
  aggregated with the `include_all_preprocessed_columns` flag at
  `prover/mod.rs:112-116`; composition columns get exactly the OODS point
  (`prover/mod.rs:119`, `vec![oods_point]; 2·4` columns).
- Every committed column of every tree is evaluated at its sample points and the
  values are mixed into the channel: `prover/pcs/mod.rs:251-273` (evaluation),
  `:294` (`mix_felts`). Barycentric evaluation at off-domain points:
  `prover/pcs/mod.rs:196-222, 256-258` (public weights).
- Periodicity sample for exactly-2-sample columns:
  `core/pcs/quotients.rs:313-326` (the spec's citation
  `prover/pcs/quotients.rs:312-330` has the wrong directory — the file is
  `core/pcs/quotients.rs`, lines 313-326; content correct).
- Corrections: (i) preprocessed columns receive OOD samples only when
  `include_all_preprocessed_columns` is set or a component references them
  (`core/air/components.rs:39-49`); unreferenced preprocessed columns are opened at
  queries only. Public data either way — O7 refinement. (ii) An M31 column's OOD
  sample is carried as a QM31 (`PointSample.value: SecureField`,
  `core/pcs/quotients.rs:30`) but carries ≤ 1 informative M31 for base columns;
  counting 4 M31 per OOD sample (as `D_obs` does) is a conservative upper bound.

**O2 — 23 query openings per column across all trees, incl. multiplicity and
LogUp cumulative-sum columns: CONFIRMED, minor refinements.**

- The FRI decommitment produces the shared query positions
  (`prover/pcs/mod.rs:332-336`), and every tree is decommitted at them, one value
  per column per position: `prover/pcs/mod.rs:357-367`; preprocessed positions
  derived at `:338-342`. Interaction columns (multiplicities and cumulative sums,
  QM31 = 4 M31 each, generated in `constraint-framework/src/prover/logup.rs:108-148`)
  are ordinary committed columns of the interaction tree and are opened like any
  other column ✓. Consumption on the verifier side:
  `core/pcs/quotients.rs:120-160` ✓.
- Refinements: `Queries::new` deduplicates (`core/queries.rs:41-49`), so openings
  are ≤ 23 distinct positions (duplicate probability ≈ 253/2²³ — negligible;
  first-order count correct).

**O3 — single channel-random-combined QM31 FRI column over the lifting domain:
CONFIRMED with two material corrections.**

- `compute_fri_quotients` (`prover/pcs/quotient_ops.rs:87-138`) takes ALL columns of
  ALL trees, assigns global random powers from the channel-drawn `random_coeff`
  (drawn after the OOD values are mixed: `prover/pcs/mod.rs:294,297`; power
  assignment `core/pcs/quotients.rs:297-301,324,328`), and
  `combine_accumulated_numerators` (`quotient_ops.rs:239-283`) produces ONE QM31
  column on the domain of size 2^lifting_log_size (docstring `:37-47`); it is
  committed as the FRI first layer (`prover/fri.rs:119-129`). With
  `lifting_log_size = 23`, the FRI first layer is log 23 and its degree bound is
  2^20 = lifting − blowup (`prover/mod.rs:108-109`) ✓.
- Correction 1 (information): the 23 first-layer "query values" are **not
  transmitted and carry no independent information** — the verifier *derives* them
  from the OOD samples and the trace query openings via `fri_answers`
  (`core/pcs/quotients.rs:120-160`; verifier flow `core/verifier.rs:72-128`). The
  FRI tree transmits only complement (witness) values. O3's "23 query values + fold
  complements" should read "0 independent functionals at query positions (derived
  from O1+O2) + fold complements".
- Correction 2 (structure): the combined-column functionals are **not linear** in
  the committed column values; see L1 below.

**O4 — FRI fold complements: CONFIRMED, structure verified exactly.**

- Layer chain for the pinned config: first layer log 23
  (`prover/fri.rs:119-129`), inner layers at logs 19, 15, 11, 7
  (`prover/fri.rs:134-184`: circle→line fold + fold_step−1 extra line folds
  :147-153; while-loop :165-173; final 4-fold :176-181), last layer domain log 3
  with degree log 0 (`core/fri.rs:73-75`; verifier layer chain
  `core/fri.rs:128-178`). So 5 layers with complements ✓ exactly as the spec says.
- Complements: per folding coset of size 2^fold_step = 16, the witness values are
  the coset positions that are *not* query positions — 15 per query per layer
  (`prover/fri.rs:413-443`, esp. :423-439 `next_if_eq` logic; verifier mirror
  `core/fri.rs:598-633`; `FriLayerProof.fri_witness` doc `core/fri.rs:392-396`).
  5 × 23 × 15 = 1725 is the correct upper bound (shared cosets and query dedup
  reduce it) ✓.
- The complements are joint functionals over all trees: each first-layer value is
  the combined quotient at a distinct lifting-domain point (accumulates every
  column's numerator terms), and inner-layer values are public-α linear images of
  first-layer values (`core/fri.rs:697-741` folds). ✓ "no column can be hidden in
  isolation" holds.
- Structure correction (same as O3): these are bilinear functionals, not linear —
  see L1.

**O5 — last layer sent in full + last-layer query evals: CONFIRMED.**

- `commit_last_layer` sends all coefficients and mixes them
  (`prover/fri.rs:196-214`, mix at :211; degree assert :206-208); verifier checks
  length ≤ 2^0 = 1 (`core/fri.rs:183-185`) and evaluates the folded query values
  against the poly (`core/fri.rs:271-291`). 1 QM31 coefficient + ≤ 23 folded evals ✓.
  The last-layer coefficient is a global functional of the combined column ⇒ joint
  over all columns ✓.

**O6 — claimed sums/roots/log sizes/PoW public: CONFIRMED.**

- `claim.mix_into` (`stwo-cairo prover.rs:228`), interaction elements drawn after,
  `interaction_claim.mix_into` (`:255`); the generator balances the lookup argument
  (`:248-253`, `lookup_sum(...) == 0` debug assert). "One QM31 per component, 12
  total" is consistent with the inventory (6 relation components + 6 fixed tables);
  exact enumeration is an M2 task as the spec says.

**O7 — preprocessed openings public, excluded from hiding: CONFIRMED** (query
openings always, `prover/pcs/mod.rs:338-367`; OOD only per the flag above,
`core/air/components.rs:39-49`).

**`D_obs ≈ K·(23 + 4·#OOD) + 4·1725 ≈ 1228·35 + 6900 ≈ 50,000` — arithmetic
confirmed, framing notes.** 1228·35 + 6900 = 49,880 ✓. The formula treats every
column as a 3-point OOD column (23 + 12 = 35); most columns are 1-point (23 + 4 =
27), so the realistic value is ≈ 1228·28 + 6900 ≈ 41,300 — same order; exact
per-component count is correctly deferred to M2. Additional biases: M31-column OOD
samples count 4 but carry ≤ 1 informative M31 (overcount, conservative direction
for hiding, pessimistic for cost); O3's 23 values are not independent (see O3).
None of these change the order of magnitude or the under-padding conclusion.

**Structural facts (spec §1, page-bottom list):**

- Fact "all observations are fixed linear functionals": **INCORRECT as stated** —
  corrected under L1 (O4/O5 bilinear, O6 rational, O3 derived). The linear part
  covers O1/O2 only.
- Fact "Opened points never lie on the commitment domain (`core/pcs/mod.rs:8`)":
  **INCORRECT as literally stated.** The cited doc note is a loose comment. What
  actually holds, derived from the lifted-tree construction:
  1. Trace-row cosets are never opened. The trace lives on `CanonicCoset(n)` =
     `Coset::odds(n)` (`core/poly/circle/canonic.rs:28-33`) and each column is
     committed on `odds(n+3)` (`CommitmentTreeProver::new` →
     `evaluate_polynomials` at trace log + blowup, `prover/pcs/mod.rs:449-481`);
     `odds(n)` ∩ `odds(n+3)` = ∅ (odd-index vs. index ≡ 8 mod 16 points), and
     query openings evaluate each column at points of its own committed coset
     (lift `f̃(p) = f(π^{k}(p))`, documented with a worked example at
     `prover/backend/cpu/merkle_lifted.rs:14-45`). So raw trace rows are indeed
     never opened, and **every opened value is a global linear functional of the
     column's committed row values** — the spec's bottom line ("the leak is
     entirely through these functionals") is correct.
  2. Full-height columns (committed log = lifting log 23: the split-composition
     columns, and `range_check_20`'s columns at LDE log 23) **are** opened at
     points of their own commitment domain — the doc note and the spec's fact are
     false for them. OOD points (ζ and offset/periodicity variants) are off every
     commitment domain ✓.
  3. This documentation divergence should be recorded in the divergence log per
     policy (the note in `core/pcs/mod.rs:8` does not describe the actual opening
     geometry).
- Fact "single-row sparse column recoverable": CONFIRMED analytically — see §2.
- Fact "upstream `add_zk_blinding` pads five gate components with n_queries rows;
  ≲ 10³ free M31 — structurally under-padded": CONFIRMED in kind
  (`stwo-circuits crates/circuit_common/src/finalize.rs:154`; consistent with
  `bench/client-privacy-feasibility/review.md:26-39`). Two notes: upstream pads
  circuit gates with `n_padding = outer query count = 35` (circuit config), while
  this family's `n_queries = 23` ⇒ 23·27 ≈ 621 ≲ 10³ — the conclusion is unchanged
  and slightly stronger; the "~35" figure is upstream-specific and should not be
  carried into this family's derivations.

## 2. Load-bearing claims

### L1 (observation linearity) — INCORRECT as stated; corrected form below

Verified in code:

- The DEEP quotient term for column i at queried point p is
  `c_i·f_i(p) − (a_i·p.y + b_i)` with per-point public denominator
  (`core/pcs/quotients.rs:177-192`; denominators `:253-276`). The line coefficients
  (a, b, c) are computed from the column's **OOD sample value**: a = v̄ − v,
  c = ȳ − y (public), b = v·c − a·y — all **linear in v**
  (`core/constraints.rs:119-134`). Hence each FRI-side functional is a
  **product of two linear functionals of the same column** (its OOD sample at the
  projected OOD point and its value at the functional's own point) plus affine
  terms: **bilinear in the committed column values**, with all coefficients public.
  Folds compose linearly with public α (`core/fri.rs:697-741`), so inner-layer
  complements and the last-layer coefficient remain bilinear. For columns of the
  composition tree, the base-trace dependence is quartic (products of quadratic
  composition-column values) — still bilinear in *committed columns*.
- O6 (claimed sums) is a **rational** functional of the committed columns:
  Σ mult_i/(z + Σ α^j x_j) (`constraint-framework/src/logup.rs:13-14`) — not
  linear, formula public.
- O1 and O2 **are** fixed affine functionals with transcript-public coefficients ✓
  (barycentric/LDE structure verified above).

Corrected L1 (for the spec to adopt): every verifier observation is a fixed
*polynomial of bounded degree* in the committed column values with
transcript-public coefficients: O1/O2 affine; O3 derived from O1+O2 (zero
independent information); O4/O5 bilinear in committed columns (equivalently:
linear in the column values **conditioned on the OOD samples O1**); O6 rational.
This does not change the observation *count*, but it changes the shape of every
downstream lemma: pad contributions to O4/O5 are bilinear in pad unknowns, and the
equalization argument must be staged (see L2). Confidence in this correction: 95%
(verified directly in `constraints.rs:119-134` and `quotients.rs:162-195`).

### Single-column recoverability — CONFIRMED (analytical)

For a column whose private content is a single row x at position j, every opened
value equals x times a public coefficient (the lift of the row-j Lagrange basis
evaluated at the opened point). A nonzero L'_N-space function has ≤ N zeros
(`Circle_STARKs.llm.md` `prop:LN:properties`); the basis consumes N−1 of them on
the domain, leaving ≤ 1 exceptional off-domain zero per (row, transcript), so
coefficient-zero events have negligible probability over the channel randomness.
With ≥ 2 functionals at distinct points, (j, x) is identified up to negligible
collisions. This is consistent with the direct-air empirical recovery and is a
property of the *unpadded/under-padded* regime only.

### Under-padding accounting — arithmetic confirmed; d unverified; §3 estimates have ±1 log-size errors

- Naive regime: `B = n_queries = 23` ⇒ ≈ 621 free M31 ≪ D_obs ⇒ structurally
  under-padded ✓ (spec's "~35×(9-30)" uses the upstream circuit query count; for
  this family 23·27 ≈ 621 — same conclusion).
- Full-coverage regime: 50,000/27 ≈ 1,852 ≈ "2,000" ✓; B·d = 54,000 ≥ 50,000 ✓ but
  the margin is ≈ 8% over an order-of-magnitude D_obs and an **unverified** d.
- **d ≈ 27 is not supported by the checked code.** In the pinned AIR representation
  a felt252 is 28 M31 limbs of 9 bits (`stwo-cairo/stwo_cairo_prover/crates/
  cairo-air/src/components/memory_id_to_big.rs:23,67` — "each value containing 9
  bits"; matches the inventory's 29-column big table). The spec's "9 (input state,
  M31) + 18 (requested values)" matches neither one felt (28 limbs) nor three
  (84), and limb values are range-boxed, not free M31s. The invariant that matters
  for L2 is the *total* pad unknown count against D_obs, not the per-instance
  split; the spec should pin the product and derive d per component in M2 and
  measure it in M3.
- §3 row estimates are internally inconsistent at B = 2,000: 128 + 2000 = 2128 →
  log 12, not log 11 (aggregator); full-chain 8·(128+B) ≈ 17k → log 15, not 14
  (the quoted numbers fit B ≈ 1,900). Cost-estimate-only errors; B and the padded
  log sizes must be pinned exactly in M2 (the spec already defers this).

### L2 (pad equalization) — NOT PROVEN; precise gap identified; required lemma stated

The spec's L2 ("pads can equalize any two valid traces' full observation vectors")
is the crux. My assessment:

1. **The rank-1 framing is insufficient as stated.** The measurement-plan's
   "L_{i_b}(·) ⊗ row_b" span argument treats the row factor as freely choosable
   per column. Pad rows are confined to the valid-row manifold M (≈ d free
   parameters, with the remaining 342+ columns determined), so the pad-reachable
   observation set is the image of M^B under the observation map — a curved
   B·d-parameter family — not the linear span of rank-1 terms. "Span" arguments
   prove that linear *combinations* of pad configurations reach a target; a single
   pad configuration must reach it.
2. **Nonlinear couplings** (after the L1 correction): FRI functionals bilinear
   (conditioned-linear on O1), claimed sums rational, multiplicity increments
   controllable only through positions (+1). The equalization system is nonlinear
   in ~B·d ≈ 54k unknowns against ≈ 50k equations — dimension count favors
   feasibility; structure is unproven.
3. **Marginal vs joint:** "every observation is marginally randomized by ≥ 1
   unknown pad entry" does not imply the joint vector is simulatable. The joint
   requirement is that the *difference* Φ(T) − Φ(T′) (a ≤ 5-dim secant family per
   §3's refinement) lies in the pad-difference set Ψ(U) − Ψ(U) (exact) or that the
   translated pad-observation distributions be statistically close (≤ 2^{-λ}).
   Neither is established. No counterexample is known either: appended pads reach
   every LDE functional (verified global-functional structure, §1), so there is no
   structural dead zone — the gap is the lemma, not an identified break.
4. **Ill-typed literal statement:** "the complete observation vector identical"
   compares vectors under different transcript randomness (different ζ/queries/α).
   The correct targets are (i) per-fixed-randomness equalization as a simulator
   step, or (ii) distributional equality of complete transcripts. The spec must
   restate L2 in one of these forms.

**Lemma that must be proven (either fork):**

- **L2-exact:** for all valid T, T′ and all transcript randomness, ∃ pads u, u′
  with identical complete observation vectors. A provable sufficient route:
  exhibit, per component, pad-row families with genuinely *free* (unconstrained or
  box-full-range) M31 parameters in enough columns to make the two-stage
  pad-difference map linearly surjective onto R^{D_obs} (rank condition +
  unbounded ranges ⇒ any target reachable exactly). This requires deriving which
  pad fields are free in each component's AIR — currently undemonstrated.
- **L2-stat:** pads u ~ explicit distribution; SD(obs|T, obs|T′) ≤ 2^{-λ} for all
  valid pairs. Requires a smoothing/leftover-hash-style lemma for the
  conditioned-linear observation map against the ≤ 5-dim (single-path) / 9-dim
  (two-path) difference family, *jointly* over all functionals. No anchor for this
  exists in the distillations; Haböck–Al Kindi ePrint 2024/1037 uses *unconstrained*
  random mask polynomials (with degree slack) and a separate FRI masking step, and
  therefore does **not** cover valid-row-constrained masks — a documented
  divergence if this route is taken.

Two-stage structure that makes L2 tractable (recommended for the M1 successor):
Stage 1 — equalize O1 (OOD samples) and O6 (claimed sums); Stage 2 — with OOD
samples pinned equal, O2/O4/O5 become *linear* in the remaining column values with
public coefficients, reducing Stage 2 to a (large) linear surjectivity problem. The
pad unknown budget must cover both stages jointly (total functionals ≈ D_obs once,
not summed twice). This is the shape in which the lemma is plausible at full-
coverage B; it is not written anywhere yet.

### Secant-variety refinement — arithmetic correct; B-reduction conditional on a lemma that does not yet exist

The valid-trace family for the tiny single-path relation is ≤ 2-dimensional (leaf +
position), so its secant has dim ≤ 2·2 + 1 = 5 ✓ (standard; the two-path depth-32
relation gives 4 parameters ⇒ ≤ 9 — must be re-derived at M5). Under a *statistical*
hiding notion, the required B is governed by the smoothing lemma's entropy
condition, not by D_obs, so a far smaller B is conceivable — but only *through* the
lemma. Whether a distinguishability-bounded notion is acceptable under the repo's
bar: `bench/client-privacy-feasibility/review.md:72` requires "a versioned upstream
or independently reviewed hiding construction with an applicability statement
covering the actual circuit family, all exported information and randomness
policy". That bar demands a *reviewed argument* with an explicit bound and scope —
it does not forbid statistical notions. A measured M3 rank result is not such an
argument. So: acceptable in principle, gated on a written, proven, reviewed lemma
with the applicability statement; the M3 harness supplies necessary precondition
evidence (achievable-pad span vs. private-dependence dimension) only.

### L4 (lookup accounting) — achievable; two required corrections

- **Per-row multiplicity caps: there is NO verifier-enforced cap.** Multiplicities
  are unconstrained M31 trace masks entering the LogUp relation
  (`stwo-cairo/.../components/range_check_20.rs:55-112` — raw masks into
  `add_to_relation`; `constraint-framework/src/logup.rs:13-14` — the constraint is
  Σ mult_i/(z + combo) = claimed sum via cumulative sums; the claimed sum enters as
  `cumsum_shift = claimed_sum / n_rows`,
  `constraint-framework/src/prover/logup.rs:108-148`). The bound mult < char is a
  *theoretical assumption* of the LogUp soundness argument
  (`Stwo_Whitepaper.llm.md` `thm:IOPP:soundness`, `rem:IOPP:soundness`),
  automatically satisfied per value (any M31 < q) and for aggregates at this
  workload (counts ≪ q). L4 must argue the cap analytically; it cannot cite a code
  check.
- **Claimed-sum entropy / Q2 wording:** the spec's §5 Q2 says pads contribute "+1
  at random positions with a *public value*". If the pad *lookup values* were
  public constants, each pad's fraction 1/(z + combo(public value)) would be a
  public constant and the claimed sums would shift deterministically — no entropy.
  The intended (and required) design is: multiplicity increment +1 public; pad
  lookup values attacker-unknown, uniform over the table's accepted range
  (consistent with measurement-plan.md §Construction item 3). Resolve the wording
  before M2.
- Claimed-sum equality with pads on both sides ✓ (pads participate as honest
  requests; generator balance assert `stwo-cairo prover.rs:248-253`).
- The subset-sum/position-control lemma for simultaneously equalizing the
  multiplicity functionals and the claimed sums is unproven (measurement-plan
  flags it; see escalation E4).

### L5 (soundness preservation) — achievable; degree-bound wording must be corrected

- Pad rows valid ⇒ no under-constraint; constraint set untouched ✓. DEEP-ALI and
  the composition identity at the OOD point hold for padded traces automatically
  (prover sanity check `prover/mod.rs:128-141`; verifier
  `core/verifier.rs:99-128`).
- **"Pad rows don't change column degrees" is imprecise.** Appending rows grows
  each column's interpolant degree (trace log n → n′). What is actually preserved:
  the lifting domain log 23 is fixed and public (`lifting_log_size = Some(23)`);
  the FRI first-layer degree bound 2^20 = lifting − blowup is trace-size-
  independent (`prover/mod.rs:108-109`); the last-layer config is unchanged
  (`core/fri.rs:183-185`). **Required constraint (absent from the spec):** every
  padded trace log size must stay ≤ lifting_log_size − log_blowup = 20, or the
  quotient accumulation subdomain degenerates. At the full-coverage B the largest
  padded component is ≤ log 16 ⇒ LDE 19 ≤ 23 ✓, but M2 must enforce and document
  this bound (the failure mode is a prover error, not unsoundness — still, it is a
  silent-construction hazard under B/topology changes).
- No parameter/transcript-format/PoW/query-count changes ✓; claim *values* (log
  sizes, sums) change by design and are public — L5's "transcript message" wording
  should say "no new message types or protocol-format changes; honest claim values
  change and are public".
- Unblinded baseline byte-reproducibility ✓ (feature-gating; M2 obligation).

Storage-mode interaction (Q6 context), verified: low-memory and bounded-memory
modes are storage policies with unchanged proof format and quotient outputs
(`prover/pcs/mod.rs:81-102` docstrings; parity tests `:741, :847-862`;
`compute_fri_quotients_bounded` equality tests
`prover/pcs/quotient_ops.rs:308-409`). Pads compose at the protocol level ✓; cost
composition is M4 work as planned.

## 3. Spec §5 open questions — answers and escalations

**Q1 (L2 at full-coverage B; minimal rigorous B; statistical acceptability).**
L2 is plausible at full-coverage B but unproven; the exact fork is likely hard
(nonlinear hitting of unbounded targets through a constrained manifold); the
statistical fork is plausible with a new smoothing lemma. A minimal rigorous B
below full-coverage **cannot be certified today**; with the statistical lemma the
requirement is the lemma's entropy condition, not D_obs. Statistical variant:
acceptable only with a written, proven, reviewed, explicitly bounded lemma plus an
applicability statement; the M3 battery alone never qualifies (escalations E1/E2).

**Q2 (multiplicity hiding).** Position-randomness makes the *values* looked up the
entropy source only if they are attacker-unknown; the "+1" increment is public.
Resolve the spec's "public value" wording accordingly. No verifier cap check
exists; the cap is the whitepaper's theoretical assumption, satisfied analytically
here. The joint (multiplicity functionals + claimed sums) equalization needs the
subset-sum lemma (E4).

**Q3 (composition/FRI columns).** This is load-bearing, not a detail. With the
corrected L1, pad coverage of the composition/FRI trees is handled by the two-stage
structure (Stage 2 conditioned-linear); without that structure the bilinear/quartic
dependence blocks any linear-span argument. The L2 lemma must explicitly include
the composition tree columns, the FRI complement functionals, and the last-layer
coefficient (E3).

**Q4 (memory-model interaction).** Pad synthetic IDs/amounts must be defined inside
the approved public lookup boundary (component-inventory.md:57-63 requires the
verifier-derived boundary to authenticate every lookup incl. multiplicities and
padding behavior). The pad accounting must be added to that boundary definition and
re-reviewed as part of the M2 design; per-component decision.

**Q5 (cross-proof linkage).** Consistent with prior reviews: statement-level public
fields (root, nullifier, address) are public by design; single-use notes preclude
re-proof linkage. The disclosure list must be enumerated in the applicability
statement (qualification requirement), including anything derivable from public
Merkle paths.

**Q6 (bounded-memory mode).** Storage modes are protocol-neutral (verified above);
pads compose. M4 measures the cost composition as planned. No soundness concern
identified.

## 4. Escalations

SOUNDNESS-ESCALATION:
  File: bench/client-hiding/spec.md (§4 L2; §3 full-coverage regime)
  Change: pad-equalization lemma claimed as the hiding basis at B ≈ 2,000 valid-row pads
  Invariant at risk: transcript indistinguishability (FS-ZK hiding) of the client artifact
  Paper reference: Haböck–Al Kindi ePrint 2024/1037 uses unconstrained random mask polynomials (degree slack) — no coverage of valid-row-constrained masks; Circle_STARKs.llm.md `thm:AIR:soundness` / Stwo_Whitepaper.llm.md `thm:IOPP:soundness` establish soundness, not hiding
  Code location: construction-level (no code yet); reachable-set structure verified via prover/pcs/quotient_ops.rs:87-138 and core/pcs/quotients.rs:162-195
  Confidence: 30% that exact L2 is provable as stated at the claimed B without redesign
  Reason: the reachable pad set is a curved manifold-constrained family, not the claimed linear span; exact hitting of unbounded targets and distributional equality are unproven; the two-stage conditioned-linear reformulation or a free-parameter redesign is required before the lemma can be attempted

SOUNDNESS-ESCALATION:
  File: bench/client-hiding/spec.md (§4 L1)
  Change: claim that all observations O1-O7 are fixed linear functionals of committed column values
  Invariant at risk: correctness of the L2/L3 proof shape (and of the D_obs interpretation)
  Paper reference: Circle_STARKs.llm.md `prop:deep:quotients` (single-point quotients over F(i), line-quotient structure); Circle_STARKs.llm.md `rem:DEEP:quotients:batching`
  Code location: core/constraints.rs:119-134 (line coefficients linear in the OOD sample); core/pcs/quotients.rs:162-195,177-188 (queried value × sample-dependent coefficient); core/pcs/quotients.rs:120-160 (O3 derived by verifier); constraint-framework/src/logup.rs:13-14 (O6 rational)
  Confidence: 95% in the correction (verified in code)
  Reason: O4/O5 are bilinear in committed column values (conditioned-linear on O1), O6 is rational, O3 carries no independent information; the spec must adopt the corrected L1 before the L2 lemma work, since pad contributions to the FRI functionals are bilinear in pad unknowns

SECURITY-ESCALATION:
  File: bench/client-hiding/spec.md (§3 refinement; §5 Q1)
  Attack surface: a statistical (distinguishability-bounded) hiding claim without a proven bound could be marketed as qualifying while leakage persists through the ≤ 5-dim (single-path) difference family not covered by pad entropy
  Mitigation: existing — the M3 battery reports recovery as a blocked gate (spec §6); prior reviews forbid spin (bench/direct-air/privacy-review.md; bench/client-privacy-feasibility/review.md:72)
  Recommendation: before any statistical claim, write and review the smoothing lemma (conditioned-linear observation map, joint over all functionals, explicit 2^{-λ} bound, entropy requirement sizing B); derive — do not measure — the required B under it; add the valid-row-mask divergence to the paper-implementation divergence log
  (Reviewer confidence that a reviewed statistical lemma at the 96-bit target can be established within M1-M3 as currently planned: 45%)

SOUNDNESS-ESCALATION:
  File: bench/client-hiding/spec.md (§5 Q2; §2 rule 2)
  Change: multiplicity hiding via "+1 at random positions with a public value" + claimed-sum entropy
  Invariant at risk: L4 (lookup accounting) and the claimed-sum (O6) entropy argument
  Paper reference: Stwo_Whitepaper.llm.md `thm:IOPP:soundness`, `rem:IOPP:soundness` (multiplicities < char as theorem assumption); `e:flat:AIR:consistency`
  Code location: stwo-cairo/.../components/range_check_20.rs:55-112 (no cap check); constraint-framework/src/logup.rs:13-14 and src/prover/logup.rs:108-148 (constraint/wraparound only)
  Confidence: 40% that simultaneous equalization of the multiplicity functionals and the claimed sums is provable at the planned B without a dedicated design change
  Reason: no verifier cap exists (cap must be argued analytically — satisfied here); the "public value" wording contradicts the claimed-sum entropy requirement and must be resolved (pad lookup values attacker-unknown); subset-sum ambiguity lemma unwritten

SOUNDNESS-ESCALATION:
  File: bench/client-hiding/spec.md (§1 D_obs; §3 B/d and row estimates; §4 L5)
  Change: B ≈ 2,000 derived from order-of-magnitude D_obs and estimated d ≈ 27; "pad rows don't change column degrees"
  Invariant at risk: the L2 premise (total pad unknowns ≥ D_obs) and the padded-domain capacity
  Paper reference: Stwo_Whitepaper.llm.md `e:STARK:degree:bound`, `e:max:domain:size` (domain capacity rules)
  Code location: prover/mod.rs:108-109 (degree bound 2^20); core/poly/circle/canonic.rs:28-33 + prover/backend/cpu/merkle_lifted.rs:14-45 (opening geometry); stwo-cairo/.../components/memory_id_to_big.rs:23,67 (felt252 = 28 nine-bit limbs)
  Confidence: 30% that "B ≈ 2,000 suffices" holds as stated (d unverified; D_obs order-of-magnitude; ~8% margin)
  Reason: d must be derived per component in M2 and measured in M3; exact D_obs required; padded trace log sizes must be constrained ≤ lifting_log_size − log_blowup = 20 (unstated); L5's degree wording must be corrected (interpolant degrees grow; protocol-level bounds preserved); §3 row/log estimates are ±1 log off at B = 2,000 (cost only)

Documentation divergence (record per policy; not a soundness defect):
  File: target/direct-air/stwo/crates/stwo/src/core/pcs/mod.rs:8 vs bench/client-hiding/spec.md §1 fact (6)
  Observation: the doc note "Opened points cannot come from the commitment domain" is false for full-height columns (committed log = lifting log 23: split-composition and range_check_20 columns); the true invariant is trace-row-coset disjointness (odds(n) vs odds(n+3)) plus the global-functional property of all openings (prover/backend/cpu/merkle_lifted.rs:14-45). The spec's conclusion (trace rows never opened; leak entirely through functionals) stands; its stated reason does not.

## 5. Verdict

**CONDITIONAL-GO.** M2 may proceed only as far as the enumerated conditions allow;
the construction is not approved as a qualifying hiding construction until they
close. An M3 pass (no recovery findings, ranks as hoped) is necessary supporting
evidence and is **explicitly not** the qualification the repo requires; the
qualification decision requires the lemma-level sign-off below (successor to this
review), per `bench/client-privacy-feasibility/review.md:72`.

Conditions:

1. **Spec amendments before M2 code (blocking):** adopt the corrected L1
   (bilinear/conditioned-linear O4/O5, rational O6, derived O3); restate fact (6)
   as trace-row-coset disjointness + global functionals (full-height columns are
   opened on their commitment domain); correct L5's degree wording and add the
   constraint *padded trace log size ≤ 20 = lifting_log_size − log_blowup*; fix
   §3 row/log accounting; restate L2 in a well-typed form (per-fixed-randomness or
   distributional); resolve Q2's "public value" (pad lookup values
   attacker-unknown; the +1 increment public).
2. **L2 lemma (blocking for any privacy claim):** reformulate as the two-stage
   argument (Stage 1: O1 + O6; Stage 2: O2 + O4 + O5 conditioned-linear) and either
   (a) prove L2-exact via a per-component free-parameter analysis making the
   pad-difference map linearly surjective, or (b) prove L2-stat with an explicit
   distinguishability bound and derive the required B from it. Until then no
   hiding claim may be attached to any artifact.
3. **M2 scope:** pad generators, the B parameter, seed/position policy, and M3
   instrumentation only, behind a feature preserving unblinded byte-reproducibility.
   No privacy-qualified artifact may be produced or advertised.
4. **Exact accounting in M2:** exact per-component D_obs; measured/derived
   per-component pad-manifold dimension; B chosen with a documented margin over
   B·d ≥ D_obs under the log-size constraint; padded log sizes public and fixed.
5. **L4:** analytic multiplicity-cap argument (all multiplicities ≪ q; no verifier
   check exists to cite) plus the subset-sum/claimed-sum equalization lemma, or a
   dedicated blinding-fraction design if that lemma fails.
6. **L3:** write the FS-ZK argument against the corrected L1/L2, with the explicit
   mapping obligations to Haböck–Al Kindi (witness randomization, separate FRI
   masking) and the circle-domain batch FRI, and record the valid-row-mask
   divergence in the divergence log.
7. **M3/M4 as planned:** rank harness, recovery battery (any finding = blocked
   gate), uniformity checks, soundness regression (unchanged verifier, mutation
   suites), cost deltas including bounded-memory composition and a WASM randomness
   probe. Results feed the lemma preconditions; they do not replace them.
8. **Consistency with prior reviews maintained:** no qualification without the
   reviewed construction and applicability statement; B is inventory-derived (no
   arbitrary padding as a fix); the complete constrained payment statement and
   output binding remain separate gated work.

## 6. Corrections summary (spec vs. verified reality)

| # | Spec claim | Finding |
| --- | --- | --- |
| 1 | §1 "All observations are fixed linear functionals" | Wrong for O3-O5 (bilinear; O4/O5 conditioned-linear on O1) and O6 (rational); O3's 23 values are verifier-derived, no independent information (`core/constraints.rs:119-134`; `core/pcs/quotients.rs:162-195,120-160`) |
| 2 | §1 fact "Opened points never lie on the commitment domain (`core/pcs/mod.rs:8`)" | False for full-height columns; true invariant is trace-row-coset disjointness + global functionals (`core/poly/circle/canonic.rs:28-33`; `prover/backend/cpu/merkle_lifted.rs:14-45`); conclusion unaffected |
| 3 | §1 O1 citation `prover/pcs/quotients.rs:312-330` | Path is `core/pcs/quotients.rs:313-326`; content correct |
| 4 | §1 O2 "23 openings" | ≤ 23 after dedup (`core/queries.rs:41-49`); first-order correct |
| 5 | §1 under-padding "35×" figure | Upstream circuit query count; this family: 23 ⇒ ≈ 621 ≪ D_obs; conclusion unchanged |
| 6 | §1 D_obs ≈ 50,000 | Order-of-magnitude confirmed (1228·35 + 6900 = 49,880); realistic ≈ 41-50k; exact count is M2 |
| 7 | §3 d ≈ 27 free M31/pad | Unverified; felt252 = 28 nine-bit limbs in the AIR (`memory_id_to_big.rs:23,67`); limb boxes, not free M31s; pin total-unknowns ≥ D_obs instead |
| 8 | §3 row/log estimates | ±1 log-size off at B = 2,000 (aggregator log 12 not 11; full chain log 15 not 14); cost-only |
| 9 | §4 L5 "pad rows don't change column degrees" | Interpolant degrees grow; protocol-level bounds (lifting log 23, FRI bound 2^20) preserved; add padded-trace-log ≤ 20 constraint |
| 10 | §4 L4 "per-row multiplicity caps" (verifier-checked) | No verifier cap exists; cap is the whitepaper's theoretical assumption, satisfied analytically (`range_check_20.rs:55-112`; `logup.rs:13-14`; `prover/logup.rs:108-148`; Stwo_Whitepaper `rem:IOPP:soundness`) |
| 11 | §4 L2 / measurement-plan rank-1 span framing | Manifold-constrained; insufficient as stated; two-stage reformulation required |
| 12 | §5 Q2 "public value" | Contradicts claimed-sum entropy; pad lookup values must be attacker-unknown |

All other inventory items (O1 structure and counts, O4 layer/complement
arithmetic 5×23×15, O5 last-layer form, O6 mixing, O7 exclusion, config and
security-metric numbers, column counts, joint-ness of O4) verified correct against
the pinned sources as cited in §1.
