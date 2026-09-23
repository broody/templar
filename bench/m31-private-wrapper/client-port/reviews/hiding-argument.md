# Hiding argument for arithmetic-profile stwo-circuits client proofs (draft)

2026-09-23. **Draft for review. This is not a proof.** It states what zero knowledge (ZK)
means here and splits the claim into lemmas. For each lemma it records what the tests
establish, what is proven on paper, and what is only a proposed route. It ends with the
precise open claims and three design options that would make them easy.

It applies to the R0 client proof: the `eq` and `qm31_ops` components, blinding per fork
`4de7408a6` (H1 budget, H2 mul row), blowup 2², 35 queries, fold step 4, Blake2s channel.

## 1. Target and model

**Target:** honest-verifier statistical ZK in the random-oracle model (Fiat–Shamir with
Blake2s as the oracle). A simulator that knows only the public statement (circuit, outputs
and configuration) must produce a transcript whose distribution is close to a real one.
Because the proof is non-interactive, a malicious verifier's only lever is the choice of
statement, which is public. The service that wraps the proof and every chain observer are
such verifiers.

**The verifier's view** (with challenges drawn from the transcript):

| Part | Content |
| --- | --- |
| Commitments | Merkle roots of the base (T1), interaction (T2) and composition (T3) trees; FRI layer roots |
| Claims | public outputs; claimed LogUp sums per component |
| OODS | every column of T1–T3 at `z`, and at `z − step` where the mask needs it |
| Queries | every column of T0–T3 at 35 LDE points, with Merkle decommitments |
| FRI | each layer's witness values (the rest of each 16-point coset), sibling hashes, the last layer |
| PoW | two nonces |

T0 (preprocessed) is public. **Field values** is our name for everything above that is not a
hash or a nonce.

**The blinding.** Each of the 2,390 iterations adds five `qm31_ops` rows and one `eq` row:
- `x + 0 = x`, `0 + y = y`, `z + 0 = z`, `x · y`, `e + 0 = e`, and `e == e`;
- `x`, `y`, `z` and `e` are uniform QM31 values from ChaCha20 seeded by the OS RNG (but see
  H3).

The row positions of the blinding are public (circuit topology); their values are secret.

## 2. Reduction

Standard reductions take the simulator most of the way.

1. **Challenges.** The simulator programs the random oracle so that its transcript's
   challenges (lookup elements, `z`, DEEP and FRI coefficients, queries) are uniform.
2. **Commitments.** Each Merkle leaf hashes one LDE point's values across a tree's columns.
   - Every T1–T3 column's LDE values are dense combinations that include blinding rows
     (Lemma B), so unopened leaves are high-entropy oracle inputs.
   - The simulator therefore sets roots, sibling hashes and FRI layer roots to fresh random
     oracle outputs, consistent with the leaves it does open.
   - An adversary distinguishes only by querying an unopened leaf's preimage, which needs
     the leaf's field values. That is negligible given their min-entropy. The lemma still
     needs the entropy bound per unopened leaf (open item O3).
3. **Field values.** What remains is **Claim V:** given the challenges, the joint
   distribution of the field values is statistically close to a distribution `D_pub` that
   depends only on public data. The simulator samples `D_pub`.
   - `D_pub` is "uniform, subject to the public linear relations every honest transcript
     satisfies": FRI folding and the low-degree structure, DEEP quotient consistency, the
     LogUp balance, and the absent components' zero claims.
   - The nonlinear consistency (composition equals constraints over trace values) is also
     public, and the simulator enforces it by computing derived values (§4).

Everything below concerns Claim V.

## 3. Lemmas for the linear part

**Lemma A (openings are exactly uniform).** Fix the challenges. Let `v` be the vector of
the `y` and `z` blinding limbs, and condition on `x`, on `e` and on the witness. Then the
T1 `qm31_ops` openings at the 35 query points and at `z` are an affine map `M·v + c(w)`.
- **Tested:** `M` has full row rank (468/468) at random points of the right kind, and still
  6,768/6,768 at 560 points per column (`hiding_points`). Hence the openings are exactly
  uniform, whatever the witness `w`.
- **Paper route to "for all points except a negligible set":** stwo's barycentric weight
  is `w_P(i) = v_n(P) / (s_i · v_{h_i}(P))`, where `v_h(P) = (P − h).y / (1 + (P − h).x)`
  is the tangent of half the angle between `P` and `h`. So `1/v_{h_i}(P)` is
  `cot((θ_P − θ_i)/2)`. With `u = e^{iθ}` that is `i(u_P + u_i)/(u_P − u_i)`, a Cauchy
  matrix plus a rank-one term, not a pure Cauchy matrix. Nonzero minors are therefore not
  automatic. A proof must either show them for distinct off-domain points, or bound the
  failure probability over random challenge points (Schwartz–Zippel in `z`; a counting
  argument for LDE queries). The cross-column coupling (`dst` shares `y` with `op1` and `z` with `op0`) is block
  triangular under the variable order (`z` via `op0`, then `y` via `op1`, then `dst`'s
  remaining freedom), with `x · y` supplying `dst`'s own freedom. **To be written out**
  (open item O1).
- **The same argument for `eq`** (4 columns, `e` rows). Tested only through Lemma B.

**Lemma B (no unblinded direction).** No nonzero public combination of a component's
columns is constant on all blinding rows, in T1 or T2.
- **Tested:** exactly, by the rank of two-seed trace differences (`hiding_rank`: full
  rank for all four component–tree pairs). Empirically at points, by `hiding_invariants`
  (336/336).
- Lemma B is necessary for Lemma A to hold for every column combination. H2 was exactly
  its failure.

**Lemma C (whole transcript, linear).** With the challenges pinned, no linear combination of
all field values of a proof is both seed-invariant and witness-dependent.
- **Tested:** at 35 queries on a small circuit with private multiplications, 813 invariants,
  all witness-independent (`hiding_transcript`). The pre-fix control shows 72
  witness-dependent invariants.
- This is evidence, not a proof: it shows that `D_pub`'s *linear* constraints are exactly
  the public ones. It does not show that the distribution is uniform on the rest.

## 4. The nonlinear part (open)

Three places make field values nonlinear in the blinding.

1. **Interaction (T2).** Each lookup contributes `±1/(γ − ℓ(addr, value))` per row, and the
   columns are cumulative sums of those fractions. So T2 values at any point are *linear in
   the per-row fractions* `g_i(v_i)`, each a rational function of **one row's** values.
   - **Proposed route: a Fourier bound with Weil sums.**
     - Write the relevant field values as `(A·v, C·g(v))` plus constants.
     - For a nontrivial character `χ`, `|E χ| = Π_rows |E ψ(a_i·v_i + b_i·g_i(v_i))|`, since
       rows are independent.
     - Each factor with `(a_i, b_i) ≠ 0` is at most `(deg·2)/√q` (Weil; `q = p⁴`, and `ℓ` is
       bijective on a row's limbs when the lookup elements generate QM31).
     - If every nontrivial combination has support on more than `2m + λ/log q` rows, where
       `m` is the number of revealed values, the L2 bound gives statistical distance at most
       `2^(−λ)`. The support bound would come from the structure of Lemma A (an MDS-type property, still to prove).
   - **Consequence to check:** this route needs about **twice as many random rows as revealed
     values**, not the H1 budget's one-to-one. qm31_ops has 5 random rows per iteration, so
     it likely meets this; `eq` (1 row per iteration) is the tight case. Open item O2.
2. **Composition (T3).** The constraint evaluation multiplies trace values within a row
   (`dst − op0·op1·flag…`), and the composition polynomial's value at a point `P` is a
   polynomial in the trace values at `P` and `P − step`, which are products of barycentric
   sums *across* rows. Characters no longer factor per row, so the Weil route does not apply
   directly.
   - **Proposed route: derived values.** T3 openings at `P` are a public function of all
     trace values at `P` and `P − step`. If Lemmas A and D hold for the enlarged point set
     (queries, their `step` neighbours and `z`), the simulator samples those trace values
     and computes the T3 openings. The FRI part then remains (next item).
3. **FRI beyond layer 0.** Deeper layers reveal folds of the DEEP quotient `Q`, and each such
   value is a linear functional of `Q` over up to `16^j` layer-0 points. `Q` contains T3,
   which is quadratic in the blinding. We have no argument for these values yet, beyond
   Lemma C's evidence that no *linear* witness-dependent relation exists.

**Lemma D (conjecture).** Claim V holds with statistical distance `≤ 2⁻⁸⁰` for the
production parameters. Evidence: Lemmas A–C and all five tests. The unproven parts are §4.2
and §4.3.

## 5. Findings from this work

| ID | Issue | Status |
| --- | --- | --- |
| H1 | Padding sized for query openings only; FRI cosets need more | fixed (budget 2,390) |
| H2 | Add-only qm31 blinding leaves `dst − op0 − op1` unblinded | fixed in the fork (mul row) |
| **H3** | Blinding limbs are `u32` reduced mod `p`: 0 and 1 are 1.5× as likely. That is ~2⁻³¹ statistical distance per limb, and ~2⁻¹⁶ over the ~38k limbs of one proof | **open**; fix: rejection-sample (`< p`) or reduce a `u64`. Upstream code, all profiles |

| **H4** | Upstream full profile: one `blake_g_gate` LogUp batch is unblinded. Blinding rows never use the gate outputs, so their output yields have multiplicity 0 | **open upstream**; does not apply to the arithmetic profile (no `blake_g_gate`) |

H3 caps any statistical ZK bound near `2⁻¹⁶` per proof until fixed.

**Upstream status** ([`stock-hiding/`](../../stock-hiding/README.md), unmodified `proving@5a7c5ed`,
full profile, production config): H2 is confirmed end to end on an upstream proof (70/70
queries matched in another seed's extension). H4 was found by the same rank audit. H1 and
H3 are in the same code. Upstream's `privacy_circuit_verify` and `leaf_prover` use this
blinding.

## 6. Open items and design options

**Open items for a reviewer or us:**
- **O1.** Write out Lemma A for all points (the Cauchy-plus-rank-one structure of the
  barycentric matrix, block triangular coupling), including `eq` and the `step` neighbours.
- **O2.** The Weil/Fourier argument for T2, with the exact support bound and row budget.
  Check `eq`'s one random row per iteration.
- **O3.** The per-leaf min-entropy bound for unopened Merkle leaves.
- **O4.** The composition and deep-FRI values (§4.2–4.3): the missing piece.
- **O5.** Fix H3.

**Design options that would make O4 easy:**
- **(a) A masking polynomial for FRI.** Commit a random polynomial `R` of the composition
  degree and run FRI on `Q + R`, as ZK-FRI constructions do. FRI values become uniform
  outright, and the argument reduces to the openings (Lemmas A and D at the enlarged
  points).
- **(b) Randomizer columns for the composition.** Split the composition with random
  low-degree masks whose sum cancels, so T3 openings are uniform.
- **(c) Salted Merkle leaves.** Replaces O3's entropy argument with a random salt per leaf.
  It is cheap and upstream-compatible, like the TMPZK002 route's salted commitments.

All three cost prover work and change the proof format. (a) is the most standard.

## 7. Evidence index

| Test | Result | Pre-fix control |
| --- | --- | --- |
| `hiding_leak` | `dst − op0 − op1` not found in another seed's trace (0/35) | 35/35 |
| `hiding_rank` | 0 unblinded combinations | 4 |
| `hiding_points` | 468/468; 6,768/6,768 | 312/468 |
| `hiding_invariants` | 0 of 336 | 48 |
| `hiding_transcript` | 0 witness-dependent (35 queries) | 72 |

Results are under `client-port/results/hiding-*`; the plan is `hiding-test-plan.md`.
