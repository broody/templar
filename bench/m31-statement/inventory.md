# Full-M31 payment statement — design inventory (exploration)

Status: **design inventory; no implementation, no measurements beyond cited
prior results.** This documents the statement that the "client-side hiding +
server heavy lifting" architecture needs if the client is to reach
browser-class cost: a payment statement whose arithmetic is **M31-native**
(Plonky3 width-24 Poseidon2, pinned and measured in
[m31-append](../m31-append/README.md) / [m31-tree](../m31-tree/README.md)),
with felt252 reduced to a thin chain-binding residue.

This is the design the recorded M31 decisions did **not** evaluate: the
"do not adopt" verdict in [m31-tree](../m31-tree/README.md) covered a
*tree-only* migration bolted onto the felt statement (mixed workload stays
~1.9 GiB; on-chain M31 hashing ~154× gas). The full redesign changes both
terms. It also does not cover the hiding question at all.

## 1. Measured anchors

| Fact | Value | Source |
| --- | --- | --- |
| M31 Poseidon2 AIR | width 24, **1,172 columns**, quadratic constraints (S-box via quadratic steps — **no lookup tables**), 1 LogUp yield → 4 interaction M31 columns | `bench/m31-append/client/src/m31.rs:23-29` |
| Native client cost (append workload) | **17–31 MiB cgroup peak**, 2.0–4.1 s, 192–223 KB proofs | `bench/m31-append/results/native-summary-v2.md` |
| Permutations per log-8 component | ~128 (two depth-32 tree paths), padded to 256 rows | native summaries |
| Felt statement comparison | ~1,228 committed columns, ~40–50k observables, 1.97 GiB | `bench/poseidon-membership/component-inventory.md`, `client-hiding/spec.md` |
| Cairo-program verification of an M31 proof | **blocked**: 8.06M-step verifier program → memory table ~2²³ > fixed log-20 Cairo trace / log-23 lifting → `Not enough twiddles!` | `bench/m31-append/results/outer/summary.md` |
| On-chain M31 hashing | ~154× felt-builtin gas — rejects contract-side tree hashing | `bench/m31-tree` |

## 2. The proposed v2 statement

**Components (all client-side):**

1. `m31_poseidon2` — the single wide short component (exists, measured):
   - membership: 2 × depth-32 paths = 128 permutations;
   - leaf preimage / ownership binding: ~2 permutations;
   - nullifier derivation: `N = Poseidon2-M31(secret, tag)` — ~1–2;
   - statement binding hash (chain/pool/version/roots/amounts): ~1–2.
   - Total ~134 permutations → log 8 (256 rows). ~1,172 + 4 columns.
2. `felt_binding_residual` — RESOLVED to ~zero by design
   ([results/binding-residual.md](results/binding-residual.md)): with a
   **word-tuple facts convention** (public values as M31 words, each a
   trivial felt; the contract compares decompositions on-chain), the proof
   contains **zero felt252 arithmetic** — no limb ingestion, no range-table
   ladder. Amounts bind into leaf preimages (**measured**: +0 cost — same
   132 requests, ~11 MiB); the remaining pieces are a small in-proof range
   component (~2 MiB est.) and carry-free conservation constraints (~0).
3. Amounts (v2 options): < 2³⁰ single-M31 with carry-free conservation
   (measured shape); wider via QM31-represented addition — design option.

**What disappears vs the felt statement:** the width-27/cube_252 limb-mul
machinery, the 2²⁰ range-check ladder, and the felt Poseidon component
family (342+126+169+141 columns of it). The M31 S-box needs no tables at
all — the reason the measured client cost is 17 MiB, not 2 GiB.

**What stays:** the Blake2s Merkle/channel layer (cheap in the M31 prover;
see §4 for the transport consequence), the 28-limb felt binding (~30–60
MiB), and the observation inventory.

## 3. Client cost and the hiding premium (corrected; step 1 measured)

- **Public client proof — MEASURED (`results/measurements.md`):** the
  payment-shaped statement (2 notes, depth-32 merged paths, leaf preimages,
  nullifiers — 132 sponge requests, 256 rows, log 8) proves in **~11 MiB
  RSS / 0.11 s**, proof ~170 KB, three byte-identical runs, 16 mutations
  rejected. The earlier "~50–150 MiB" estimate was conservative; the felt
  binding residual (below) is the only remaining unmeasured client cost.
- **Observation inventory:** the column count is **comparable to felt**
  (~1,180 vs ~1,228) ⇒ D_obs ≈ **~40k functionals — not smaller**. An
  earlier exploration note claimed "M31 makes hiding ~10× cheaper via fewer
  columns"; that was wrong and is corrected here.
- **Why the hiding premium collapses — corrected budget model
  (`results/rank-analysis.md`):** the pad budget is governed by the
  equalization target's **matrix rank**, not by D_obs/free-params. The
  rank probe measured every statement-pair delta at **matrix rank exactly
  68** (96-point-space × 1,172 columns), identical across 12 pairs — so
  the honest full-coverage budget is **B ≈ 68–100 pads**, not ~1,700, and
  the vendored AIR's 1,024-request cap comfortably suffices (the earlier
  cap-raise concern dissolves).
- **Client with hiding (pads at the measured budget): ~11 MiB + ~4–6 MiB
  ≈ **15–20 MiB** — browser/phone-trivial.** Preconditions that remain for
  the lemma: dim span(M) ≥ 68 (measured ≥ 36, sample-limited — next probe
  iteration resolves it), the constructive manifold-valid decomposition,
  and the statistical fork's smoothing bound.

## 4. Transport — who verifies the thin proof

- **Route (a), Cairo program (measured, blocked):** running an M28-proof
  verifier program in the virtual OS costs 8.06M Cairo steps because
  re-verifying the proof's ~4.6k Blake2s Merkle compressions is ~1.7k Cairo
  steps each → the memory table exceeds the fixed log-20 Cairo trace →
  twiddle panic. Fixing it by switching the inner proof's Merkle to
  felt-Poseidon returns the limb tax to the client (~4.6k permutations) —
  not attractive. Route (a) stays blocked.
- **Route (b), circuit-DSL mini-verifier (viable):** the M1-reviewed path
  ([compact-recursion](../client-hiding/compact-recursion-design.md)) with
  its E2 sample-structure work. Outer cost ~2.9–4.5 GiB — but **server-side**
  under this architecture, which is the point.

**The architecture that falls out:**

```
Client (~0.2–0.3 GiB, browser-class):
  thin M31 statement AIR + C1-style pads → self-hiding artifact
    ↓ (safe to hand to an untrusted server)
Server (untrusted for privacy; heavy):
  mini-verifier circuit (E2-extended) → V1-style wrap → PROOF1 → chain
```

The original division of labor — client-side hiding, server heavy lifting —
becomes affordable here because the thing the client must hide is thin.

## 5. What must be built (gated)

1. **The v2 statement components** — nullifier/ownership/binding on M31
   (the tree AIR exists; the rest is new AIR work + review).
2. **E2 sample-structure extension** (from the compact-recursion M1 review)
   — blocking for any mini-verifier adapter.
3. **The L2 lemma** for the thin statement — same D_obs accounting; cheap
   pads make the construction qualifiable rather than merely plausible.
4. **Crypto review of Poseidon2-M31 parameters** (pinned Plonky3
   construction) — a different hash than Starknet's felt Poseidon; new
   security analysis.
5. **Protocol changes**: deposit/tree-update moves into proofs (deposit
   carries a proof; contract swaps roots by fact), note-format v2,
   nullifier-domain change.

Sequencing note: (1) and (2) are cheap enough to measure before any format
decision; (5) is the expensive organizational step and must not start
before (1)–(4) land numbers.

## 6. Immediate next steps (pathfinding, no format commitment)

1. ~~Extend the m31-append client to a multi-permutation statement~~ —
   **DONE**: ~11 MiB / 0.11 s measured ([results/measurements.md](results/measurements.md)).
2. ~~Pad-cost probe~~ — **DONE**: 11.6 → 48.1 MiB across the sweep,
   ~80–85 MiB extrapolated full coverage
   ([results/pad-probe.md](results/pad-probe.md)).
3. ~~Felt binding residual~~ — **RESOLVED to ~zero by the word-tuple facts
   convention; amounts-in-preimages measured at +0**
   ([results/binding-residual.md](results/binding-residual.md)).
4. **Mini-verifier floor with the real M31 inner** (after E2) — sizes the
   server-side outer.
5. ~~Rank harness~~ — **ITERATION 4 DONE (structural closure)**
   ([results/rank-analysis.md](results/rank-analysis.md),
   [results/solve-probe.md](results/solve-probe.md)): the equalization
   target's matrix rank is **68 (identical across 24 statement pairs)**;
   `dim span(M) ≥ 128`. The numeric Gauss-Newton probe falsified iterative
   solving over F_p (0/8 from distant starts — no metric, no descent) and
   produced the **copy-assignment reformulation**; iteration 4 measured
   the decisive structural facts: the expansion span **saturates at 666
   dims** and the statement-delta space is **fully contained in it**
   (zero-residual elimination, both pairs tested) — no structural
   exposure. The primary hiding fork is now the **computational one**:
   pads as random valid rows at the log-10 layout (892 slots, no cap
   raise), noise dimension 21,408 vs target family 6,528 (3.3× margin),
   argument = Poseidon2-M31 pseudorandomness + entropy accounting —
   standard review territory. Client-with-hiding estimate: **~50 MiB**.
   Exact forks (big-layout copies, nonlinear solve) are fallbacks.
   Lemma spec written: [hiding-spec.md](hiding-spec.md) — the honest
   shape is **Assumption H** (pad-feasibility hardness: the
   slot-decomposition analysis shows the joint manifold-consistency test
   is over-determined ~90,512 under wrong hypotheses, so the hiding claim
   reduces to a multivariate feasibility-hardness assumption, NOT a
   standard PRF claim). Next: Math Review on that assumption + the
   degree-3+ relation audit.
