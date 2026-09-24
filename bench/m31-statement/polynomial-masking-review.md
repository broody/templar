# M0 polynomial masking review

2026-09-22. Reviewed [polynomial-masking-spec.md](polynomial-masking-spec.md),
SHA-256 `16b49d19219f77b57b9ed22768e9a0daee59a59936e42030bcfb2e77e3ddc3d4`,
against the cached primary papers and narrowly relevant pinned PCS/FRI source.
Applied the STWO soundness checklist, ZK foundations and divergence guidance.
No implementation, tests, probes or benchmarks were performed.

**Local algebra/honest-verifier oracle diagnostic: CONDITIONAL GO**, with the
prerequisites below. The proposed masking argument is sufficiently grounded to
justify that bounded diagnostic. This is not approval of a sound argument
system or cryptographic implementation for external use.

**Server-visible compiled private proof: NO-GO.** Complete soundness, compiled
BCS/Fiat–Shamir mapping, concrete security bounds and private-lookup extension
remain open. Successful diagnostics cannot close those gates.

## 1. Mask evaluations and degrees

The proposed full-space mask basis has 65 independent coefficients. By
[Circle STARKs Proposition 2 and §3.2](https://eprint.iacr.org/2024/278.pdf),
evaluation of `L_64(E)` on any at most 65 distinct affine circle points is
surjective: extend the point set to 65 points and use the 64-zero bound for
injectivity of the square evaluation map. This is stronger than a dimension
count.

For the Frobenius-stable set S of at most 27 points, compatible values descend
to F. Given an E-coefficient interpolant, average its coefficient conjugates
over the four automorphisms of `E/F`. Compatibility ensures that each conjugate
interpolant has the same prescribed values after reindexing S. Division by four
exists in M31. The average lies in `L_64(F)` and matches the data. Consequently
the F-linear evaluation map is surjective onto compatible values. A uniform
mask maps uniformly there, with equal-size fibers. Multiplication by `Z_H`,
nonzero throughout S, is invertible on this image. Each masked-column view is
therefore exactly independent of its original witness, for the same public c.

The honest degree table is consistent: the masked inputs have total degree
160; their product minus c lies in `L_640`; divisibility by the 256-point
zerofier yields `Q in L_384` by Proposition 3. The distinct conjugate-pair
line has two affine zeros and removes one total degree, giving K degree at
most 191. Strict degree below 256 places these honest objects in `L'_512`:
its monomial description includes every polynomial of smaller total degree.
No truncation of a top coefficient is allowed.

## 2. Joint distribution and simulator

Keeping Q unsplit is essential to this accounting. At every observed point,
`Q=(a_hat*b_hat-c)/Z_H`; hence its observations add no independent witness
information. This does not extend automatically to quotient components or
shifted/lookup columns.

Let `g=h-R`. For every honest witness realization, g belongs to `V_512(E)`.
For fixed disclosed values v and lambda, independent uniform R makes h
uniform in that entire space, even after averaging over undisclosed witness
polynomials. At each raw query P, `R(P)=h(P)-g_v(P)`, where the OOD claims
and disclosed raw values determine `g_v(P)`. Thus the **joint distribution**
of h and R's disclosed values depends only on v. All subsequent FRI data can
be generated from h and verifier coins. This establishes the proposed
decoupling, not merely uniformity of h's marginal. It follows the distinction
formalized in [Haböck–Al Kindi Lemmas 1–2](https://eprint.iacr.org/2024/1037.pdf).

The same-public-c honest-verifier simulator is viable for the declared oracle
view: preselect independent verifier coins, sample compatible masked-column
values on S, derive Q values there, and interpolate each in `L_64(F)`.
These interpolants need not satisfy the relation on H. Their honest OOD
claims give polynomial pair quotients, so their g also lies in `V_512(E)`.
Fresh R gives the same joint view by the argument above. Interpolation can use
exact linear algebra over F, representing extension coordinates explicitly.
No alternative private witness is required.

This is perfect honest-verifier **bounded-query oracle-view** simulation under
the stipulated sampling and access rules. It does not simulate disclosure of
the complete a/b/Q/R tables or their coefficients. Merkle roots and hash-oracle
behavior are not part of this argument.

## 3. Diagnostic prerequisites and limits

Before implementation, make the following explicit in its contract:

1. Distinguish the PCS conjugation `sigma(u)=u^(p^2)` over CM31 from the
   full p-Frobenius orbit used for descent. Reject `z in H union D` and
   `z.y=sigma(z.y)` using public rules. Frobenius stability keeps the full
   orbit outside H and D. Pin the sampling distribution and pair-quotient
   normalization, including nonzero scale factors.
2. Freeze each oracle before its subsequent challenge, especially R before
   lambda. The honest verifier gets only declared evaluations. FRI complements
   must reveal h alone; opening extra raw input/R positions requires enlarging
   S and rechecking the proof. Logs containing private tables are local-only
   diagnostic artifacts, never simulated verifier data.
3. Use exact coefficient/domain checks for divisibility and FFT embedding,
   consistent duplicate handling, and independent supplied verifier coins.
   Test same-c real/simulated views and adversarial mutations, bypassing honest
   witness validation. Histograms and sampled ranks do not prove privacy.

Distinct positive powers of lambda correctly remove an unchallenged quotient
that malicious precommitted R could cancel identically. They do **not** prove
soundness: cancellation can occur at particular lambda values, including zero,
and arbitrary oracle words require a correlated-agreement/DEEP/FRI reduction.
Account for these events, or publicly restrict challenges with revised bounds.
Soundness must use advertised 512-dimensional bounds, not honest smaller
degrees. The stated 1,024-zero identity bound supplies only one term once
genuine bounded-degree polynomials have been established.

The diagnostic is worthwhile for checking this algebra, access model and
adapter behavior. It must not claim a concrete security level, knowledge
soundness or malicious-verifier privacy. Do not retrofit the top-level STARK
verifier's split composition or silently inherit PCS periodicity.

## 4. Remaining external-use gate

The BCS compiler's private-leaf randomness, programmable-oracle simulator and
state-restoration requirements must be mapped to the concrete protocol;
[Interactive Oracle Proofs §6/Theorem 7.1](https://eprint.iacr.org/2016/116.pdf)
does not certify the current serializer/channel automatically. Concrete
privacy/soundness bounds, grinding, repeated/adaptive use and public sampling
exclusions require an explicit composition analysis.

The proposed LogUp extension is unreviewed. Inverses, accumulator freedom,
shifted openings, extension coordinates and witness-dependent denominator
failures require a new joint argument. R0 and PROOF1 are outside M0. This
conditional diagnostic approval authorizes none of those extensions or a
server-visible privacy claim.
