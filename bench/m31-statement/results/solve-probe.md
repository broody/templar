# Solve probe — empirical per-position feasibility (step 6)

Recorded 2026-09-22. Tests the L2-exact constructive path's per-position
solve ([solve-probe.json](solve-probe.json), `--solve-probe` in the
harness): Gauss–Newton over F_p on
`Σ_{j≤K}(E(a_j) − E(b_j)) = d`, d drawn from the measured 68-dim
statement-delta space, K ∈ {1, 2, 4}, exact dual-number Jacobians
(product-rule s-box, 1,172 columns).

## Results

| Test | Result |
| --- | --- |
| Known-preimage starts (sanity) | **zero residual in 0 steps** — exact, as constructed |
| Random starts → single-difference target (K=1) | 0/8 converged |
| Perturbed starts → perturbed targets (K=2) | 0/8 converged |
| Random delta-space combos (K=4) | 0/8 converged |

## Interpretation — and why the failure is informative

Over a finite field there is no metric: Gauss–Newton has no descent
notion, so it converges only from algebraically special starts. The 0/8s
say the pad-pair differences cannot be *iteratively searched for* — the
construction must be **algebraic, not numeric**. Working the algebra
through changes the formulation:

**The copy-assignment reformulation.** Both the prover's and the
simulator's pads can be *copies of their own semantic rows* (each copy is
a valid row by construction). A pad pair at slot position `p` — prover
copies its row `r(p)`, simulator copies its row `s(p)` — contributes
exactly `w(p) ⊗ Δrow_{r,s}` where `Δrow_{r,s} = E_r − E_s` is the
difference of the two copied rows. The full equalization condition

```
Σ_p w(p) ⊗ Δrow_{r(p),s(p)}  =  Σ_i W(i) ⊗ Δrow_i  =  Φ(Δ)
```

becomes: choose the **assignment** of row-pairs to pad positions such that
the weight-family subset sums reproduce the target. Everything nonlinear
(the expansion `E`) is *frozen inside the copied rows*; the only unknowns
are the assignment — a linear-algebra/feasibility problem over the
**measured weight family** (`dim span(W) = 96` full, 380 slots at log 9,
targets `τ_j = −Σ_i β_{j,i} W(i)` in the 96-dim channel space).

Refined lemma content (replaces "bounded nonlinear solves per position"):

1. The one-hot assignment problem: find `{γ_p}` (each `γ_p` one of the 256
   Δrow-coefficient vectors `β_{:,i}`, or a small sum over a position
   block) with `Σ_p w(p) ⊗ γ_p = T` (the 96 × 68 target). Sufficient
   density: the weight family spans the channel space fully, and subset
   sums of ~380 vectors in 96 dims cover targets with high multiplicity —
   expected feasible, unproven.
2. The per-direction block trick: dedicate position blocks per basis
   direction `e_j`, choosing row pairs `i*(j)` with the right `β` pattern
   to control cross-talk.
3. The simulator argument on top of the copy structure (mirror pads) —
   unchanged from the previous analysis.

**Cost translation (unchanged):** pads are copies, so the premium is still
~68–100 rows ≈ +4–6 MiB; no extra rows needed for the assignment.

## Why this is progress, not a setback

The numeric probe falsified the "iterative solve" route cleanly and
cheaply (one session, no ambiguity), and the falsification *produced* the
copy-assignment reformulation — a strictly simpler lemma: a one-hot
feasibility statement over linear-structured, fully-measured families,
with zero nonlinear content. That is exactly the kind of statement a Math
Review can adjudicate decisively.

## Reproduction

```bash
cd bench/m31-statement/client
PATH="/usr/bin:/home/broody/.cargo/bin:/bin" ./target/release/templar-m31-statement \
  --solve-probe ../results/solve-probe.json
```
