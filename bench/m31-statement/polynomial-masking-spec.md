# Polynomial masking: M0 protocol mapping

2026-09-22. **Conditional approval for a local algebra/oracle diagnostic only;
not qualified client privacy.** The [review](polynomial-masking-review.md)
covers the initial candidate; the clarifications below implement its prerequisites.
This instantiates the [experiment plan](polynomial-masking-plan.md)
for a deliberately small relation. It does not qualify gamma, R0, LogUp, the
existing serialized proof, or PROOF1. No performance estimate is made.

## 1. Scope and source anchors

M0 proves that two private M31 vectors `a,b` of length 256 satisfy
`a[i] * b[i] = c[i]` for a **fixed public vector** `c`. The public statement also
pins the experimental relation/version and all parameters. There are no lookup
sums, private branches, shifts, output commitments or token amounts. This tests
nonlinear private arithmetic, not payment semantics.

Primary sources, downloaded and read from their original ePrint PDFs:

- [Circle STARKs](https://eprint.iacr.org/2024/278.pdf), title-page date
  2024-12-17: circle spaces and their MDS property (§3), quotient divisibility,
  FFT spaces (§4), AIR and circle FRI (§§5–6), ZK direction (§5.4).
  PDF SHA-256 `8e60498a671ff147c211ac7733435057dff27b31b8bd3211485b85b4035d296d`.
- [Haböck–Al Kindi](https://eprint.iacr.org/2024/1037.pdf), title-page date
  2025-02-20 (ePrint metadata last revision 2025-02-22): §2 Protocol 2 and
  Lemmas 1–2; §3's accounting for quotient observations; Appendix A's caveat
  about private permutation/lookup exceptional events.
  PDF SHA-256 `b6bd98453a64b26c7a08bf02fe9f82f3bde7dd730ecaa3fe9769b1e0f15cf270`.
- [Interactive Oracle Proofs](https://eprint.iacr.org/2016/116.pdf), §3.2
  private Merkle trees, §6 compiler, Theorem 7.1 and Lemma 7.5: honest-verifier
  IOP privacy does not by itself qualify our existing Fiat–Shamir artifact.

The circle adaptation and the concrete protocol below are **proposed reasoning
to review**, not theorems asserted by those papers for this implementation.
The pinned dependency APIs are catalogued in [masking-api-inventory.md](masking-api-inventory.md).

## 2. Polynomial spaces and degree table

Let `F=M31`, `E=QM31`, and `H` be the canonical 256-point circle coset.
Write `L_t(F)` for the full circle space of total degree at most `t/2`,
dimension `t+1`, for even `t`. Write `V_512=L'_512` for the 512-dimensional
FFT space. Unlike `L_512`, it excludes one top-degree direction.

Interpolate the three vectors over H in `L'_256`, obtaining `a,b,c`.
For each private column independently, sample a **uniform full-space**
`r in L_64(F)` and form `a_hat=a+Z_H*r_a`, `b_hat=b+Z_H*r_b`.
One explicit basis for `L_64` is `1,x,...,x^32,y,xy,...,x^31*y`.
There are 65 independent base-field coefficients per mask, not 65 valid rows.
Use fresh local CSPRNG randomness, with unbiased field sampling.

| Object | Honest space / total-degree bound |
| --- | --- |
| `a,b,c` | `L'_256`, degree at most 128 |
| `Z_H` | degree 128, vanishes on H |
| `r_a,r_b` | `L_64`, degree at most 32 |
| `a_hat,b_hat` | `L_320`, degree at most 160 |
| `Q=(a_hat*b_hat-c)/Z_H` | `L_384`, degree at most 192 |
| Conjugate-pair DEEP quotients | degree at most 191 for these honest inputs |
| Independent FRI randomizer R | uniform `V_512(E)`, 512 extension coefficients |
| Batched FRI polynomial h | `V_512(E)` |

Divisibility follows from the relation on H; circle domain-quotient theory
must justify the indicated degree drop. Every honest trace/quotient polynomial
is strictly below degree 256 and hence embeds into `V_512` without losing the
dimension-gap direction. Do not discard a coefficient to force membership.
The FRI randomizer itself is sampled directly in the FFT basis of `V_512`.

All committed input polynomials use the **same** advertised FFT bound 512 and
the same canonical evaluation domain `D`, of size 4096. H and D are disjoint.
This removes multi-size lifting and periodicity from M0. Advertised bounds are
larger than honest bounds: soundness must cover malicious polynomials up to
the advertised bound, not just the smaller honest construction.

Keep the baseline FRI knobs (blowup log 3, 23 draws, fold step 4, last-layer
log 0) as a comparison starting point. The oracle diagnostic has independently
sampled verifier coins; hash-based PoW is not part of its privacy claim. Retain
the existing PoW 27 as the starting requirement for the later compiled mapping.
The configuration's bit-count
heuristic is **not** a security proof for the new protocol. No production
security level or approved compiled parameter set is claimed here.

## 3. Proposed oracle transcript

This is a public-coin IOP first. `Commit` below denotes an oracle message,
not a claim that the current unsalted Merkle implementation is hiding.

1. Fix the canonical public statement and verifier-owned parameters. Commit
   `a_hat,b_hat` on D, then the **unsplit base-field Q** on D. There is only
   one constraint, so no random composition coefficient is needed.
2. Draw one uniform OOD circle point `z in C(E)` with the required public
   exclusions. Specifically reject `z in H union D` and candidates with
   `z.y == sigma(z.y)`, where `sigma(u)=u^(p^2)` is the pinned PCS involution
   over CM31. This is distinct from the full p-Frobenius orbit in §4.
   Uniform rational-parameter sampling in E with rejection of its poles and
   these excluded points gives the specified conditional uniform distribution.
   Such rejection depends only on z and
   public parameters. Return `a_hat(z),b_hat(z),Q(z)` and check
   `a_hat(z)*b_hat(z)-c(z) == Z_H(z)*Q(z)`.
3. Sample independent uniform `R in V_512(E)` and commit its evaluations on D.
   Only **after this message** draw independent batching challenge lambda.
4. For each `f in [a_hat,b_hat,Q]`, form its conjugate-pair DEEP quotient `K_f`
   from the evaluation claim at z. Use the same circle line-interpolation and
   pair-vanishing construction as the pinned PCS, accounting for its nonzero
   scale factors. The conjugate value is derived, not separately transmitted.
   Precisely, for `z=(zx,zy)` and claim v, set
   `A=sigma(v)-v`, `C=sigma(zy)-zy`, `B=v*C-A*zy` and
   `d(P)=(zx.0-P.x)*zy.1-(zy.0-P.y)*zx.1`, embedding the CM31 coordinates
   into E. Use `K_f(P)=(C*f(P)-A*P.y-B)/d(P)`, the pinned PCS normalization.
   Its d is a nonzero scalar multiple of the pair-vanishing line; it must be
   checked nonzero on D. No input-dependent exception may be hidden by division.
5. Form

   `h = R + lambda*a_hat + lambda^2*b_hat + lambda^3*Q`
   `    + lambda^4*K_a + lambda^5*K_b + lambda^6*K_Q`.

   Raw-polynomial terms explicitly include degree testing of the inputs;
   quotient terms bind their OOD claims. Each has a distinct positive power.
   **Do not add R to the existing zero-based batch unchanged:** an unchallenged
   first quotient could cancel against a malicious R committed before lambda.
6. Commit/prove h with the existing single-domain Circle FRI primitive and
   its normal commitment-before-challenge order, including all complement
   values, intermediate layers and last-layer coefficients, followed by the
   verifier's uniform query draws. A local oracle harness must separate these
   supplied coins from the existing hash-based channel/PoW implementation.
7. At each of the at most 23 distinct sampled positions P in D, open
   `a_hat(P),b_hat(P),Q(P),R(P)`, reconstruct h(P), and supply it as the
   corresponding first-layer FRI answer. Fold complements are **h values**,
   not additional raw witness-column openings. Enforce exact lengths,
   canonical encodings and consistent duplicate-query treatment.

No seed, unmasked polynomial, private vector, randomizer coefficients or
unrequested raw row may be serialized. M0 uses one OOD sample per base column;
it must not inherit a spurious periodicity claim from an unrelated adapter.

## 4. Proposed hiding argument and review obligations

For fixed OOD/query coins, let S contain the queried D points and the full
Frobenius orbit of z. Then `|S| <= 23+4=27`, and `S intersect H` is empty.
The MDS property of full circle spaces suggests evaluation of `L_64` onto
these at most 27 coordinates is surjective over a splitting field. Frobenius
descent gives the corresponding surjectivity onto the compatible base-field
evaluation image. Multiplication by the nonvanishing `Z_H` preserves this
image. Thus each masked column's queried values should be uniform in that
image and independent of its unmasked witness, for this same public c.
Review must check this descent, not replace it with a dimension count.

Because Q is **unsplit and base-field-valued**, its values at S are determined
pointwise by the two masked columns and public c. There are no extra component
samples requiring a hidden query-preimage argument. This ceases to be the
complete accounting after adding shifts, extension-valued interactions or
quotient splitting.

Condition on these queried values and lambda. The non-R part of h is a fixed
element of `V_512(E)`. R is uniform in that entire space, so h is uniform in it.
At queried positions the required R values follow from h and the already
known polynomial values. This is the proposed circle-space version of the
decoupling lemma: the **joint** view of R openings and the whole h polynomial
depends only on already simulated values. All subsequent FRI messages are
functions of h and public coins, including its fully revealed last layer.

A candidate honest-verifier simulator, given only c and parameters, samples
the verifier coins, samples compatible uniform masked-column values on S,
derives Q values there, and interpolates small base-field polynomials matching
those values. It then runs the masked batch/FRI on these interpolants with
fresh R and the preselected verifier coins. The interpolants need not satisfy
the relation on H; observed quotient identities and all queried values must
have the same joint distribution as the real proof. Review must establish
efficient interpolation/descent and the distributional statement, including
the OOD public rejection policy. No alternative private witness is needed.

Soundness is a separate obligation: raw and quotient batching, consistency of
FRI's queried h values, degree bounds, DEEP binding, OOD identity error, and
the circle FRI proximity/knowledge reduction must all be checked. For genuine
advertised-degree polynomials the identity has total degree at most 512,
hence at most 1024 circle zeros unless identically zero; this only supplies
one term in the analysis, not the complete soundness bound.

## 5. Compiling a server-visible artifact is a separate required proof step

The pinned hash commitments and Fiat–Shamir channel are not automatically
covered by the oracle simulator. The BCS compiler uses private Merkle leaves
and an explicitly programmable random-oracle model; §3.2 specifies per-leaf
randomness as part of the authenticated opening. Its theorem also requires
state-restoration soundness/knowledge hypotheses.

Before emitting an artifact advertised as private to an untrusted server,
map this IOP to that compiler (or another precise proved compiler): oracle
packing, private leaf randomness, domain separation, canonical transcript,
challenge sampling, grinding, error bounds, and fresh independent proofs.
Pin an actual security parameter and compute the theorem's concrete bound.
For example, Theorem 7.1's conservative privacy term is proportional to
`p(x)*2^(-lambda/4+2)`; a 256-bit hash does not by itself justify a 128-bit
statistical privacy claim. Do not silently equate hash width with that bound.
Repeated/adaptive use requires fresh masks and leaf randomness plus an explicit
composition argument; local retries must not upload abandoned transcripts.

**Open at submission:** compiled-transcript mapping, its concrete parameters,
and the complete soundness reduction. These cannot be closed by successful
native verification or sampled output histograms.

## 6. Private lookup extension and R0 boundary

The next lookup experiment should put both private sides in one algebraic
component with one global accumulator and fixed public sum zero. For
denominators dA,dB, include constrained inverses `uA*dA=1`, `uB*dB=1` and
cyclic recurrence `Z(P)-Z(T^-1 P)=uA(P)-uB(P)`. This avoids publishing the
two private partial sums. The trace for Z, its starting freedom, all inverse
coordinates and any range/multiplicity columns need their own fresh masks.
Private lookup challenges arrive after the corresponding base commitment.

This is a **follow-up design obligation**, not an approved extension. Zero
denominators depend on the witness; any retry/abort policy needs a statistical
privacy bound (at most a union bound over the actual denominators per run,
and across the allowed runs), and no private diagnostic may leave the client.
Do not publish masked partial sums without constraining their relationship.
Multiple denominators require explicit nonzero inverses; clearing denominators
alone must not quietly permit degenerate invalid witnesses.

Z's shifted OOD samples and Q observations require a larger observation closure
and a new degree table. QM31 interaction columns represented in four M31
coordinates need joint accounting. No numeric lookup mask budget is selected.
R0 remains the [full payment relation](privacy-contract.md): this vector-product
toy proves none of its ownership, membership, conservation or delivery rules.

## 7. Implementation status and remaining adapter work

The [mapping review](polynomial-masking-review.md) gives conditional approval
for local algebra/oracle diagnostics only. The first implementation is narrower
than the complete adapter below: [masking_diagnostic.rs](client/src/bin/masking_diagnostic.rs)
checks exact polynomial identities, the declared algebraic view, same-public-c
coupling, witness-free view simulation and PCS normalization.
Its [source review](polynomial-masking-algebra-review.md) excludes FRI execution,
commitments, soundness and compiled privacy. All four fixtures pass in the
[recorded execution](results/polynomial-masking-algebra/README.md).
The remaining transcript-order,
batching and malformed-FRI controls below are not implemented by that diagnostic.

A later CPU-only oracle adapter must retain verifier input
`(public c, proof/view, fixed params)` and cover the following scope. Review
its soundness-sensitive changes before implementing them; keep local diagnostic
approval separate from compiled-private-proof approval.

- Mask construction and exact preservation on H; independent finite-field
  checks of quotient divisibility, degree embedding and the observation map.
- Honest oracle transcript and simulator traces exercising identical public c;
  no statistical test substitutes for the argument.
- Invalid relations, altered public c, altered OOD values, R-after-challenge,
  batch-exponent collision, malformed FRI and wrong-degree controls. Bypass
  honest witness validation in negative tests.

Use coefficient/FFT and FRI primitives, but a dedicated unsplit composition
and batch adapter. Do not modify `FrameworkComponent` globally just to overload
`log_size`: constraint-domain size, polynomial capacity and evaluation-domain
size are separate parameters in this diagnostic. The native top-level STARK
verifier's hard-coded quotient split does not implement this protocol.

No wrapper adapter, WASM benchmark, or production change belongs to this first
milestone. Any diagnostic must be labeled according to its actual achieved
scope; the compiled artifact gate above and the actual PROOF1 route remain open.
