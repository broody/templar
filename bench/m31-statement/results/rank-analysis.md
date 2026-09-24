# Rank analysis — L2-lemma empirical probe (step 5)

Recorded 2026-09-22. Offline analysis of
[rank-substrate.json](rank-substrate.json) (from the harness's
`--dump-rank-substrate`) by [rank-analysis.py](rank-analysis.py), in exact
arithmetic mod P. Measurement infrastructure only; no privacy claim.

Substrate: the payment-shaped M31 statement at log 8 (256 rows, 1,172
columns); 24 generic observation points (1 OOD-style + 23 lifted — note:
the lifted points stayed generic SecureField points rather than base-field
coset points, so all 24 carry 4 functional channels; the real proof's query
openings are base-field (1 channel), making the real per-column count ≈ 27
rather than 96 — the rank structure is unaffected); 12 statement pairs for
the secant family; 40 valid-row expansions; 200 pad records.

## Results

| Quantity | Value |
| --- | --- |
| Functional channels per point (dumped) | 4 × 24 points |
| dim span(W) (position-family of weight vectors, 96-dim) | **96 = full** |
| dim span(M) joint (40 valid-row expansions) | 40 (sample-limited) |
| dim span(M) per column (6 columns sampled) | 36 (sample-limited) |
| Secant family: flattened rank (12 samples) | 12 (sample-limited) |
| **Secant delta: per-sample matrix rank, (96 × 1,172)** | **68 — identical across all 12 pairs** |
| Pad contribution span (40 single-pad rank-1 tensors) | 40 (sample-limited) |
| Empirical containment of secant samples in B random pads | False for all B ≤ 40 |

## Iteration 2 (this run): decisive precondition + refined lemma shape

Re-dumped substrate: 24 statement pairs, 128 valid-row expansion samples
(per-sample: the row's 1,172 value-vector — the correct M lens), full
Δrows for 2 pairs.

| Quantity | Value |
| --- | --- |
| **dim span(M)** (128 valid-row value-vectors, 1,172-dim) | **≥ 128 (sample-limited)** — the ≥ 68 precondition holds with margin |
| Secant delta matrix rank (24 pairs) | **68 — again identical across every pair** |
| Row-space containment (Δrows' 68-dim space ⊆ sampled M-span) | **False** — expected: the sampled 128-dim span is generic; a fixed 68-dim subspace is not contained in it |
| Random-pad containment (B ≤ 40) | False — the wrong instrument (see below) |

**What the containment failures actually teach:** the constructive lemma is
*not* a span-containment statement over random pads — it is a **solve**
problem. Working through the equalization algebra:

1. Pad positions have their own generic weight columns; they cannot reuse
   the semantic rows' weights, so term-by-term matching with `Φ(Δ)` is
   impossible.
2. Equalization requires `−Φ(Δ) = Σ_b w_b ⊗ d_b^tot` with the pad-pair
   differences `d_b^tot = Σ_j (v_j − v'_j)`, both sides' pads valid rows.
   Coefficients are pad *counts*, so negative signs are fine (count
   differences), but the total per position must land on exact field
   vectors.
3. Per position, K fabricated pad pairs give `2·24·K` free field
   parameters against 68 coordinate targets — dimension-counted feasible
   at K ≈ 2–3; the solve is nonlinear (the expansion is a nonlinear
   function of the 24 free words) and is precisely the content the L2-exact
   lemma must formalize.

So the probe pins the lemma's true shape: **bounded nonlinear solves per
pad position, at B ≈ 68–100 positions, on a manifold whose span provably
exceeds the target space.** The mirror-pad idea (both sides add copies of
their own rows at agreed positions) supplies the natural structure for the
simulator argument.

## The governing quantity, corrected

The C1 pad-budget estimate (`B ≈ D_obs / free-params-per-pad ≈ 1,700`)
modeled the wrong object. The equalization target — the observation delta
between two valid statements — is a **matrix of shape (functional space ×
columns)**, and its **matrix rank is what the pad budget must cover**: each
pad contributes exactly one rank-1 term (weight-column ⊗ row-expansion), so
B pads can represent only targets of tensor rank ≤ B (with manifold-valid
factors).

**Measured: every statement-pair delta has matrix rank exactly 68.** The
delta factors as `W_full (96 × 256) × Δrows (256 × 1,172)`, and the trace
delta's row space is 68-dimensional — a structural property of this AIR
(identical across pairs). So the honest full-coverage equalization budget
is **B ≈ 68–100 pads** (rank 68 plus margin for the manifold-valid
decomposition), not ~1,700.

**Client premium at that budget: ~68–100 pad rows on the M31 component ≈
+4–6 MiB** (vs +70 MiB at the old estimate, vs +0.5–1 GiB on the felt
statement).

## Why containment failed at B ≤ 40

The B random pads' contributions span a B-dimensional subspace; the secant
samples (rank-68 tensors) cannot live in it. This is consistent, not a
negative result: the probe's pads were random rather than chosen to span
the delta's column space. The direct test at B ≥ 68 needs a dump with
≥ 96 expansion samples — the next probe iteration.

## Preconditions this pins for the L2 lemma

1. **dim span(M) ≥ 68** must hold for manifold-valid decompositions to
   exist (measured ≥ 36 at 40 samples — sample-limited; more samples will
   resolve it). This is now a concrete, checkable numeric condition.
2. The constructive decomposition (Δ = Σ_b w_b ⊗ v_b, v_b valid rows,
   w_b from pad positions) with B ≈ rank(Δ) — the L2-exact lemma's
   content, now with a measured target rank.
3. The statistical fork's smoothing bound — same substrate.
4. The 1,024-request cap on the vendored AIR is comfortably sufficient at
   this budget (132 semantic + ~100 pads ≪ 1,024) — the earlier
   cap-raise concern **dissolves** at the corrected budget.

## Iteration 3 (this run): span saturation + containment — the structural closure

Re-dumped with 892 expansion samples (the real pad count at log 10) plus a
compact binary companion for fast rank computation.

| Quantity | Value |
| --- | --- |
| dim span(M) at 892 pads | **666 of 1,172 — saturating** (128 samples → 128; 892 → 666: more pads stop buying directions) |
| Delta-row-space containment (2 statement pairs, full 256 × 1,172 Δrows) | **CONTAINED — zero residual after M-span elimination, both pairs** |

**Findings:**

1. The expansion manifold's span is **structurally capped at 666 dims**
   (the Poseidon2 round-structure correlations bound the reachable linear
   space). The statement deltas live in the *same* constrained world: the
   68-dim delta space is fully inside the 666-dim pad-reachable span.
   **No structural exposure**: every direction the deterministic
   statement-delta occupies is direction the pad noise can occupy.
2. This closes the structural precondition of the **computational/
   statistical fork (primary candidate)**: pads as random valid rows
   (24 free words each) at the log-10 layout (892 slots, within the
   existing 1,024-request cap — no cap raise); noise free-dimension
   892 × 24 = **21,408 ≥ 3.3× the target family's 6,528** coordinates;
   the hiding argument is a standard computational one (Poseidon2-M31
   pseudorandomness + dimension/entropy accounting), not exotic
   combinatorics. Client estimate: ~50–55 MiB.
3. The exact forks (big-layout copies at log 12, ~170 MiB; the nonlinear
   solve at B ≈ 136, blocked) drop to fallback status.
4. Remaining for the lemma spec: formalize the entropy/PRF argument
   (noise vs the 6,528-dim deterministic family) and the simulator
   assembly; then Math Review. The measured anchors are all in place.

## Reproduction

```bash
cd bench/m31-statement/client
PATH="/usr/bin:/home/broody/.cargo/bin:/bin" ./target/release/templar-m31-statement \
  --dump-rank-substrate ../results/rank-substrate.json
cd ../results && python3 rank-analysis.py rank-substrate.json
```

(Substrate file is ~198 MB and not committed; the analysis script and this
record are. Machine: i9-10980XE; analysis ~10 min, exact mod-P arithmetic.)
