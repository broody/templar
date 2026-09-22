# Client-side hiding construction spec (M0 deliverable, amended per M1 review)

Status: **spec as amended after Math Review (gate M1: conditional-go).**
Companion documents: [measurement-plan.md](measurement-plan.md) and the
review verdict in [review.md](review.md) (conditions C1-C8 govern M2+).
No implementation yet. Pinned sources: stwo
`489a0f3ee44a59e03944ad9aa4f3e5a91a3d3f08` (2.2.0, storage-only patches),
stwo-cairo `9b6be2710e4d7124bc93fe80a5af36556d42ed29`, stwo-circuits
`5ef951a12727e3489a2ee991c580a5b925c59c69`. Target AIR: the
poseidon-membership component family
([component inventory](../poseidon-membership/component-inventory.md)),
developed first on a tiny same-family relation (depth-8 single path).

## 1. Exact observation inventory (what the verifier learns)

Configuration (all client experiments): `pow_bits=27`,
`FriConfig::new(0, 3, 23, 4)` = last-layer degree log 0, blowup log 3, 23
queries, fold step 4; `lifting_log_size = Some(23)`
(`bench/poseidon-membership/client/src/main.rs:43-47`). Security metric
`27 + 3·23 = 96` bits (`core/pcs/mod.rs:44-46`, `core/fri.rs:77-79`).

Trees committed in order: preprocessed (public — excluded from hiding),
original (~820 M31 columns), interaction (~404 M31 columns; QM31 columns
count as 4 M31 columns), split composition (2 halves × 4 coordinate polys ≈
8 M31 columns) ⇒ K ≈ 1228 committed M31 columns. Column counts from the
component inventory (variable components at workload size 128 permutations:
aggregator 342, full-round chain 126, 3-partial-rounds-chain 169, cube 141,
width-27 20; fixed tables 22 original + 52 interaction M31 columns).

Verifier-visible values, all in the clear:

| # | Observation | Count | Type | Source |
| --- | --- | --- | --- | --- |
| O1 | OOD samples of every committed column at the OODS point, plus one extra point per additional mask offset (chain components read ±1 rows); QM31 each; 2-point columns get one extra periodicity sample | ~1-3 points × every column | QM31 | `prover/mod.rs:82-122`; `constraint-framework/src/component.rs:253-265`; `core/pcs/quotients.rs:313-326` |
| O2 | Query openings: every committed column at the ≤23 deduplicated shared query positions | ≤23 × every column | M31 (original/composition), QM31 (interaction) | `prover/pcs/mod.rs:357-367`; `core/queries.rs:41-49`; consumed at `core/pcs/quotients.rs:120-160` |
| O3 | FRI combined column: `compute_fri_quotients` accumulates all committed columns' OOD-quotient numerators with a channel-drawn `random_coeff` into a **single** QM31 column over the lifting domain (log 23). Its values at query positions are **verifier-derived from O1+O2 — zero independent information**; only the fold complements are transmitted | 0 independent at query positions + fold complements | QM31 | `prover/pcs/quotient_ops.rs:87-143`; `core/pcs/quotients.rs:120-160,162-195` |
| O4 | FRI fold complements (`fri_witness`): at fold 4 each query needs its 16-point coset; 15 complements per query per layer. Layers: first (log 23) + inner (log 19, 15, 11, 7) = 5 layers with complements; last layer (log 3) checked against the full last-layer poly | 5 × 23 × 15 ≈ 1725 | QM31, **joint** functionals over all committed columns | `prover/fri.rs:298-336,371-376,413-443`; `core/fri.rs:218-301,598-633` |
| O5 | Last layer poly sent in full (degree log 0 → 1 QM31 coefficient) + last-layer query evals | 1 + ≤23 | QM31 | `prover/fri.rs:196-213`; `core/fri.rs:176-187,271-291` |
| O6 | Interaction claimed sums (one QM31 per component, 12 total), roots, log sizes, PoW nonces | public-mixed | QM31 | `stwo-cairo prover.rs:228-255` |
| O7 | Preprocessed columns opened at queries (always) / OOD (per flag) | public data | M31 | `prover/pcs/mod.rs:338-367`; `core/air/components.rs:39-49` |

Total independent M31-valued functionals of the committed columns:
`D_obs ≈ K·(23 + 4·#OOD-points) + 4·1725 ≈ 1228·35 + 6900 ≈ 50,000`
(upper bound; realistic ≈ 1228·28 + 6900 ≈ 41,300 since most columns are
1-point OOD columns; OOD samples of M31 columns carry ≤1 informative M31, an
overcount in the conservative direction; exact per-component count is an M2
task). Crucially, the O4 functionals are **joint** over all trees: no column
can be hidden in isolation.

Key structural facts (verified in source, corrected per M1 review):

- **L1 (corrected):** every verifier observation is a fixed *polynomial of
  bounded degree* in the committed column values with transcript-public
  coefficients: O1/O2 are fixed affine functionals; **O3 is verifier-derived
  from O1+O2 (no independent information)**; **O4/O5 are bilinear in the
  committed columns** — equivalently linear in column values *conditioned on
  the OOD samples O1* (the DEEP line coefficients are linear in the OOD
  sample: `core/constraints.rs:119-134`, applied at
  `core/pcs/quotients.rs:162-195`); **O6 is rational**
  (`constraint-framework/src/logup.rs:13-14`). This conditions every
  downstream lemma.
- **Opening geometry (corrected):** raw trace rows are never opened — trace
  rows live on `CanonicCoset(n)` while columns are committed on `odds(n+3)`,
  disjoint cosets, and every opened value is a global linear functional of
  the column's committed row values (`core/poly/circle/canonic.rs:28-33`;
  `prover/backend/cpu/merkle_lifted.rs:14-45`). Exception: full-height
  columns (committed log = lifting log 23 — split-composition and
  `range_check_20` columns) are opened at points of their own commitment
  domain; the doc note at `core/pcs/mod.rs:8` does not describe this
  geometry (divergence logged per policy). The bottom line stands: **the
  leak is entirely through these functionals.**
- A column whose private content is sparse is recoverable: a single-row
  column opened at ζ satisfies `obs = L_j(ζ)·x`; the basis has ≤1 exceptional
  off-domain zero per (row, transcript), so with ≥2 functionals at distinct
  points, (j, x) is identified up to negligible collisions. A property of the
  unpadded/under-padded regime only.
- Upstream `add_zk_blinding` pads only five circuit gate components with
  `n_padding = n_queries`. For this family (`n_queries = 23`), that regime
  supplies ~23·27 ≈ 621 free M31 unknowns ≪ D_obs — **structurally
  under-padded**, consistent with the source review's rank-based skepticism
  (`bench/client-privacy-feasibility/review.md:26-39`) and the direct-air
  recovery result. (The "~35" figure is the upstream circuit config's query
  count; it must not be carried into this family's derivations.)

## 2. Construction (C1): random valid rows with per-column unknowns

Append `B` random **valid** rows to every variable-size component (random
permutation instances: random input state, fresh synthetic memory-value
IDs/amounts for lookup requests), and inject random lookup entries into the
fixed tables (`+1` multiplicities at uniform-random table positions — no
table rows are added).

Design rules:

1. Every committed original column receives attacker-unknown entries at pad
   rows (independent across columns — no shared pads between correlated
   columns; the direct-air eq-row failure showed shared pads cancel in
   attacker-computable differences). Poseidon is a bijection on its state
   (`x ↦ x⁵` is a bijection on F_{2³¹−1} since 5 ∤ 2³⁰−1; MDS layers
   invertible), so random inputs make every state column exactly uniform.
2. Interaction columns are randomized through the pad lookups: multiplicities
   receive `+1` at uniform-random table positions (the *increment* is
   public; the **pad lookup values are attacker-unknown**, uniform over the
   table's accepted range — they are the entropy source), cumulative sums
   are shifted by unknown fractions. Claimed sums (O6) absorb pad fractions,
   so they stop being deterministic functions of the private trace.
3. Pad rows satisfy every constraint of their component including lookup
   semantics and the public memory/lookup boundary; verifier-side checks
   (DEEP-ALI, FRI) are unchanged. Note: **no verifier-enforced per-row
   multiplicity cap exists** — the `mult < char` bound is a theoretical
   assumption of the LogUp soundness argument, satisfied analytically here
   and argued in L4, not checked in code.
4. `B`, padded log sizes, and the blinding scaffold are **fixed and public**
   (no secret-dependent topology). Fresh OS CSPRNG seed per proof; pads never
   reused across proofs. **Constraint: every padded trace log size must stay
   ≤ lifting_log_size − log_blowup = 23 − 3 = 20**, or the quotient
   accumulation subdomain degenerates; M2 enforces and documents this.
5. Chain components are padded with whole permutations (their rows are
   chained); the aggregator/chain/cube rows grow by `B` permutation
   instances; fixed tables only accumulate multiplicity entries.

## 3. Pad budget: two regimes and the refinement

The governing invariant is the **total attacker-unknown pad parameter count**
across all pad rows (not a per-instance split): the full-coverage regime
requires `total pad unknowns ≥ D_obs`. The per-instance free-parameter
dimension (`d`) must be derived per component in M2 (the earlier "d ≈ 27
free M31" guess is unsupported — a felt252 is 28 nine-bit limbs in this AIR
representation, and limb values are range-boxed, not free M31s).

- **Naive regime (rejected):** `B = n_queries = 23` (upstream precedent)
  gives ~621 free M31 ≪ D_obs — structurally under-padded.
- **Full-coverage regime (working estimate):** total pad unknowns ≥ D_obs ⇒
  `B ≈ D_obs/d ≈ 2,000` pad instances (order-of-magnitude; exact `d` and
  margin are M2/M3 tasks). Rows at B = 2,000: aggregator 128 → 2128 (log
  12), full chain 8·2128 ≈ 17k (log 15), partial chains 27·2128 ≈ 57k spread
  over 3 chains (log 16 each), cube/width-27 → log 12. Estimated cost:
  **+~0.6-1 GiB LDE** on the ~2 GiB membership baseline, proof size roughly
  unchanged, prove time possibly ~2× (chain components grow ~15×). Fits 8
  GiB desktop caps; **exceeds the 2 GiB browser engineering target** —
  flagged as an open cost problem, not hidden.
- **Structure refinement (review-assessed; settle via the L2 lemma + M3
  harness):** the private-dependence family is small — valid traces form a
  ≤2-dimensional variety (note secret + position; ≤4 parameters ⇒ secant ≤9
  for the two-path relation), so observation differences Φ(T) − Φ(T′) lie
  in a low-dimensional secant family. If the accepted hiding notion allows
  a distinguishability-bounded (statistical) argument backed by a proven
  smoothing lemma, the required `B` may be far smaller than the
  full-coverage estimate. The M3 rank harness measures the actual
  achievable-pad span vs the actual private-dependence dimension and
  reports both, so the review can place `B` between the bounds with
  evidence. A measured M3 result alone is never the qualification.

## 4. Lemma statements (as corrected by M1 review)

- **L1 (observation structure — corrected, verified):** every verifier
  observation is a fixed polynomial of bounded degree in committed column
  values with transcript-public coefficients: O1/O2 fixed affine; O3
  verifier-derived from O1+O2 (zero independent information); O4/O5
  bilinear in committed columns — equivalently linear in column values
  *conditioned on the OOD samples O1* (DEEP line coefficients are linear in
  the OOD sample: `core/constraints.rs:119-134`); O6 rational
  (`constraint-framework/src/logup.rs:13-14`). Verified in code (review.md
  §2, confidence 95%).
- **L2 (pad equalization — restated well-typed; NOT yet proven):** the
  load-bearing lemma. Well-typed targets (literal "identical vectors" under
  different transcript randomness is ill-typed): either (i) **L2-exact** —
  for all valid T, T′ and all transcript randomness, ∃ pads u, u′ yielding
  identical complete observation vectors; or (ii) **L2-stat** — pads drawn
  from an explicit distribution satisfy SD(obs|T, obs|T′) ≤ 2^{−λ} for all
  valid pairs. Required proof shape (two-stage argument): *Stage 1* —
  equalize O1 (OOD samples) and O6 (claimed sums); *Stage 2* — with OOD
  samples pinned equal, O2/O4/O5 become linear in the remaining column
  values with public coefficients, reducing Stage 2 to a linear
  surjectivity problem over the remaining functionals. For L2-exact, M2
  must exhibit per-component pad fields with genuinely free (unconstrained
  or box-full-range) M31 parameters making the pad-difference map linearly
  surjective (rank condition + unbounded ranges). For L2-stat, a
  smoothing/leftover-hash-style lemma over the conditioned-linear
  observation map against the ≤5-dim (single-path) / ≤9-dim (two-path)
  difference family is required, with the entropy condition sizing B. No
  anchor for valid-row-constrained masks exists in Haböck–Al Kindi ePrint
  2024/1037 (it uses unconstrained mask polynomials with degree slack) — a
  documented divergence if the statistical fork is taken.
- **L3 (simulator / FS-ZK):** given L2, the FS-compiled proof is
  zero-knowledge against the server observing the full artifact; transcript
  handling follows standard FS-ZK compilation, with the explicit mapping
  obligations to Haböck–Al Kindi (witness randomization, separate FRI
  masking) and the circle-domain batch FRI, and the valid-row-mask
  divergence recorded in the divergence log.
- **L4 (lookup accounting):** blinding entries preserve LogUp soundness —
  the multiplicity bound (`mult < char`) argued **analytically** (all
  multiplicities ≪ q; no verifier cap check exists to cite), claimed-sum
  equality on both sides (pads participate as honest requests), cumulative
  sum consistency — with pads included; plus the subset-sum/claimed-sum
  equalization lemma, or a dedicated blinding-fraction design if that lemma
  fails.
- **L5 (soundness preservation — corrected wording):** pad rows are valid ⇒
  no under-constraint; the constraint set, verifier logic, PoW, query
  count, and protocol parameters are unchanged (no new message types or
  protocol format changes; honest claim *values* — log sizes, sums — change
  by design and are public). Appending rows grows each column's interpolant
  degree; what is preserved is the protocol-level envelope: lifting domain
  log 23 fixed and public, FRI first-layer degree bound 2^20 = lifting −
  blowup independent of trace size, last-layer config unchanged. The
  padded-trace log ≤ 20 constraint (§2 rule 4) keeps the quotient
  accumulation subdomain intact. The unblinded baseline remains
  byte-reproducible.

## 5. Reviewer answers and escalations

All six open questions were answered and five escalations raised in
[review.md](review.md) (§3-§4): E1 L2-exact unproven (confidence 30% as
stated; two-stage reformulation required); E2 statistical fork needs a
proven smoothing lemma (confidence 45%); E3 composition/FRI coverage is
load-bearing and handled by the two-stage structure; E4 multiplicity /
claimed-sum joint equalization needs a dedicated lemma (confidence 40%);
E5 accounting corrections (d unverified, exact D_obs required, padded-log ≤
20 constraint added). The documentation divergence in `core/pcs/mod.rs:8`
is logged per policy. Conditions C1-C8 in review.md §5 govern all
subsequent work.

## 6. Measurement obligations (M3/M4, after conditions close)

Rank harness (achievable-pad span vs private-dependence dimension, per
component), recovery battery (OOD-only, query-only, combined, FRI-layer,
multiplicity inference, cross-proof), statistical uniformity of openings vs
simulator samples, soundness regression (mutation suites, unchanged
verifier), and cost deltas vs the unblinded baseline (RSS, wall time, proof
size) on the pinned configs, including bounded-memory composition and a
WASM randomness probe. Results feed the lemma preconditions; they never
replace them. Any recovery finding is reported as a blocked gate, never
spun as success.
