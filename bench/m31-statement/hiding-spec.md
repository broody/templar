# Client hiding spec for the M31 statement (γ fork) — M0 deliverable

Status: **spec for Math Review (gate). No implementation of the hiding
layer.** Companion documents: [inventory.md](inventory.md),
[rank-analysis.md](results/rank-analysis.md),
[solve-probe.md](results/solve-probe.md), and the C1 program's
[spec](../client-hiding/spec.md)/[review](../client-hiding/review.md)
(the corrected observation model originates there).

Pinned identities: stwo `489a0f3` (storage-only patches), stwo-cairo
`9b6be27`, the vendored width-24 Poseidon2 AIR (byte-identical to the
reviewed m31-append source, hashes in
[client/src/statement.rs](client/src/statement.rs)). Target: the
payment-shaped M31 statement (2 notes, depth-32 paths, leaf preimages,
nullifiers — 132 semantic requests).

## 1. What is being hidden, from whom

Architecture (per the exploration): the client produces a compact
self-hiding M31 proof and hands it to an **untrusted wrapping server**;
the server wraps it into PROOF1. The server therefore observes the full
client artifact. The privacy goal: the server learns nothing about the
note secrets, positions, or amounts beyond the intentionally public
statement fields (root, nullifiers, leaves, chain, pool, version,
amounts-as-bound-in-preimages).

The artifact's openings follow the standard inventory
([C1 spec §1](../client-hiding/spec.md)): per committed column, the OOD
sample + ≤23 query openings; FRI complements; claimed sums. All are fixed
linear-ish functionals of the trace rows. For the M31 statement:
~1,180 columns, ~112k joint observable coordinates, and the deterministic
statement-delta family Φ(Δ) spanning **6,528 coordinates** (68 delta-row
dimensions × 96 channel dimensions; the 96 is the full channel span —
measured `dim span(W) = 96`).

## 2. The construction

- **Layout**: log 10 — 1,024 rows: 132 semantic + 892 pad slots. Within
  the vendored AIR's 1,024-request cap; no cap raise.
- **Pads**: 892 random valid rows (24 free input words, output =
  `permute(input)`), fresh OS CSPRNG per proof, never reused across
  proofs or components. Pads participate in the lookup boundary honestly
  (multiplicities absorbed by the claimed-sum accounting — measured in
  the pad probe).
- **Fixed public shape**: layout, pad count, and padded log sizes are
  public and identical for every statement. No secret-dependent topology.
- Soundness is untouched: pads are honest rows; no constraint, degree,
  transcript, or parameter changes.

## 3. The measured accounting

| Quantity | Value | Source |
| --- | --- | --- |
| Deterministic delta family Φ(Δ) | 6,528 coordinates (68 × 96) | rank probe: matrix rank 68 across 24/24 pairs |
| Delta-space containment in the pad-reachable span | **contained** (zero-residual elimination, both pairs) | rank iteration 4 |
| Expansion-manifold span at 892 pads | 666 of 1,172 (saturating) | rank iteration 4 |
| Channel span of pad slots | 96 = full | rank probe |
| Noise free-dimension | 892 × 24 = **21,408** M31 words | construction |
| Client cost | ~11 MiB base + pads → **~50–55 MiB** | pad probe |

## 4. The security argument — and its honest shape

### 4.1 What the containment gives

Because the delta space is contained in the pad-reachable span, **there
is no structural exposure**: every direction in which two statements'
observations differ is a direction the pad noise can occupy. The linear
consistency tests an attacker can run (does the implied-pad system's
solution space satisfy the linear relations?) all pass under any
hypothesis — verified by the containment measurement.

### 4.2 The attack surface the spec must confront

Working the attacker's algebra produces a concrete test family — the
**slot-decomposition analysis**:

- The observation decomposes (per column) as
  `obs = W_sem · cols_sem(θ) + W_pad · cols_pad` with all weight vectors
  public. Under a hypothesis `θ_hyp`, the implied pads are
  `W_pad⁺ · (obs − W_sem · cols_sem(θ_hyp))`.
- For the true statement the implied pads are the real ones (valid
  expansion rows). For a wrong hypothesis they are shifted by
  `W_pad⁺ · W_sem · Δcols_sem`.
- **Tests that fail to distinguish** (verified by measurement or
  dimension count): all linear relations (containment, above); all
  degree-2 AIR constraints (the implied-pad solution space has ~934,112
  free dimensions and absorbs the ~8,028 quadratic equations many times
  over).
- **The test that does not fail by construction**: the joint
  manifold-consistency — each implied pad row must be the expansion of a
  single 24-word input. Counting: the manifold imposes ~1,148
  constraints per row (1,024,624 total) against ~934,112 free dimensions
  — over-determined by ~90,512. Under a wrong hypothesis the consistency
  system is generically **infeasible**; under the true one it is
  satisfiable by the real pads.

### 4.3 The security assumption, stated precisely

The hiding claim therefore rests on:

> **Assumption H (pad-feasibility hardness).** Given the public layout,
> the public weight family, and the semantic contribution of any
> hypothesized statement, it is computationally infeasible to decide
> whether the implied-pad consistency system (the joint
> expansion-manifold membership of the implied pad rows) is satisfiable —
> and infeasible to find satisfying pad inputs for a wrong hypothesis —
> for adversary-scale hypotheses.

This is **not** a standard PRF assumption and the spec does not claim it
is. It is a multivariate feasibility/hardness assumption over the pinned
Poseidon2 expansion structure. Points the reviewer must weigh:

- The system is *over-determined* (~4.7× on the preimage formulation at
  K=1; the joint form above). Over-determination typically *helps*
  multivariate attacks (Gröbner degree falls); the assumption's
  plausibility must be argued against the actual constraint structure,
  not asserted.
- The Gauss–Newton probe falsified iterative solving (0/8), but that
  only rules out one attack class.
- Any low-degree relation family the pad rows satisfy that the shift
  violates and that the ~934,112 free dimensions cannot absorb would
  break the assumption; the span-saturation (666) means the linear part
  of this audit is complete, but the degree-3+ audit is open.

### 4.4 The simulator assembly

The simulator (for the FS-ZK argument) fabricates a statement `θ'`,
pads `P_θ'` from the same distribution, and runs the identical protocol.
The hiding claim is the indistinguishability of
`(θ, P_θ)`-transcripts from `(θ', P_θ')`-transcripts given the public
data, which reduces to Assumption H per §4.2. No mirror-pad/exact
equalization is required at this fork.

## 5. Fallbacks (documented, demoted)

- **Exact fork α** — big-layout copy-assignment: log ≥ 12 layout (cap
  raise to 4,096 required), pads as copies, equalization by subset-sum
  density over the weight family (~3,964 slots vs 2,976 needed for
  0/1 coverage). Info-theoretic-flavored; costs the density/completeness
  lemma and a v2 cap raise; client ~170 MiB (still browser-class).
- **Exact fork β** — small-layout nonlinear solve (B ≈ 136): blocked
  empirically (GN falsified, `results/solve-probe.md`); would need a
  structured algebraic solve with no known technique.

## 6. Soundness-preservation obligations (M-implementation)

- Pad rows are valid rows; the unblinded baseline stays byte-reproducible
  behind a feature flag.
- Padded trace log sizes ≤ lifting − blowup (the log-10 layout is
  comfortably within).
- Seed policy: fresh OS CSPRNG per proof; pads never reused; the pad
  inputs are witness data (never serialized into public fields).
- The negative battery (existing 16 mutations + padding-omission control)
  must still reject identically with pads present.

## 7. Open questions for the Math Reviewer

1. **Assumption H's plausibility** — the central question. Is the
   joint manifold-consistency feasibility problem hard for the pinned
   expansion structure? What is the status of over-determined multivariate
   feasibility for permutation-network images; are there Gröbner/
   interpolation attacks against the 892-row structure?
2. The degree-3+ relation audit: do there exist low-degree (degree-3,
   degree-4) relations of the expansion family, inside the 666-dim span,
   that (a) the delta shifts violate and (b) the free dimensions cannot
   absorb? The quadric audit is complete (absorbed); the cubic audit is
   open.
3. Does the FS-simulator assembly need the pads' distribution pinned
   beyond "uniform inputs" (e.g., rejection rules, canonicalization)?
4. The hypothesis space in Assumption H: the server's candidate
   statements are the tree's notes (small anonymity set) — does the
   smallness of the hypothesis set change the assumption's analysis?
5. Interaction with bounded-memory mode and the WASM randomness source.

## 8. Verdict criteria

- **Go** (conditional): Assumption H judged plausible for the pinned
  structure with the degree-3+ audit bounded, conditions enumerated; M
  implementation proceeds under the conditions.
- **No-go on γ**: the fork is demoted; the exact forks (α with its cap
  raise, or a revised β) become primary, or the compact client path is
  parked in favor of the documented trust posture.

As always: a passed empirical battery never constitutes the
qualification; the reviewed argument does.
