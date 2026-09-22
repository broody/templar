# M0 exact-algebra diagnostic: source review

2026-09-22. Reviewed `client/src/bin/masking_diagnostic.rs`, SHA-256
`9c52f46f3fdef89437ddaa1cabd0bcd69b2cd2dcf2c9992117cfcf067fd78495`, against
the approved algebra argument and the clarified
[specification](polynomial-masking-spec.md). Scope is the isolated diagnostic,
not a complete oracle protocol. No builds or tests were run by this reviewer.

**Source verdict: algebraically acceptable for the narrowed diagnostic,
conditional on successful execution evidence below; source findings resolved.**
**Compiled private proof: not approved.** FRI, commitments, Fiat–Shamir,
soundness and security levels are neither implemented nor established here.

## Resolved source findings

1. The available `target/m31-masking-algebra/build.log` reports five compile
   errors in the initial source: four unsupported `QM31::from(CM31)`
   conversions and a `u64` exponent where `pow` requires `u128`. The final
   source uses `QM31(v, CM31::zero())` and `u128`, as checked by this reviewer.
   These are mechanical API corrections, not algebra changes.
2. The original header promised that no arrays/coefficients leave the process,
   but failing `assert_eq!` diagnostics can print field values or vectors.
   The final comment correctly distinguishes successful check output from
   synthetic failure diagnostics, which must remain local. This resolved
   labeling issue was not evidence of a privacy vulnerability.

## Algebra and view checks

The `a(x)+y*b(x)` arithmetic correctly reduces `y²=1-x²`. Componentwise
division by the x-only zerofier checks both remainders. The generated c is
the canonical remainder of `a*b`, so it interpolates the product over H.
The 65-coordinate mask basis is the full `L_64` basis, including `x^32`.
Preservation on all 256 trace points and degree bounds of 160/160/192 match
the reviewed construction.

The FFT adapter uses four base-field coordinate polynomials and reconstructs
extension values consistently. Its 4,096-point raw and pair-quotient identity
checks compare monomial evaluation with the FFT representation on a domain
larger than the applicable zero bounds. They therefore check exact identities
for these fixtures, rather than a few random evaluation coincidences. Pair
normalization is additionally compared against the pinned PCS helper on every
declared raw query.

The public OOD exclusions enforce the nondegenerate PCS conjugate pair. The
explicit p-squared identity distinguishes that involution from full Frobenius.
The linear systems use four coordinates for the OOD value and one for each
distinct base-field query. Base-field coefficients impose the remaining orbit
compatibility implicitly. The duplicate-query fixture exercises deduplication.
These finite fixtures support implementation checks; universal surjectivity
comes from the prior mathematical review, not the sampled full ranks.

The second witness scales a and inversely scales b, preserving exactly the
same c. Solved affine mask translations preserve the complete declared input
observations. Recomputed Q and `R2=R+g-g2` then preserve OOD claims, raw samples,
R samples and all h coefficients, which the code compares explicitly. This is
a distribution-coupling diagnostic, correctly labeled as such; R2 is not an
honest prover randomness-generation procedure.

The simulator receives public c, zerofier, domains and verifier coins without
private a/b arguments. It samples small base-field polynomials, derives Q's
observed values and interpolates them with exact elimination. This matches the
reviewed witness-free algebra-view construction. `check_view` sees only that
view and public data, including the intentionally stronger disclosure of h's
entire coefficient representation. Private tables remain outside its input.

Although g is computed after query draws, `batch` takes no query-dependent
input: it uses the fixed polynomials, z, lambda and full public domain. This
ordering is harmless for the exact algebra assertions. The tool makes no
oracle-commitment timing claim, and its query-aware coupling/simulation must
not be repurposed as honest online proving.

## Controls and acceptance conditions

The five negative assertions cover four mutation families: altered c fails
both the view identity and polynomial divisibility; undersized interpolation
fails domain agreement; altered Q's OOD claim fails the identity; and altered
R's query value fails batch consistency. These are meaningful algebra checks,
not five distinct cryptographic attack classes or invalid-STARK tests.

The view checker is not an adversarial wire verifier: it assumes internally
constructed lengths, domains and encodings, and can panic on malformed input.
That is acceptable only within the stated local diagnostic boundary. It does
not test FRI, oracle binding/order, arbitrary polynomial degree soundness or
batching security.

Acceptance requires a successful build and a
successful four-fixture run recording all positive checks and five negative
assertions per fixture. The inspected first build log contained errors; a
second build/run is pending after the verified fixes. No successful run is
claimed. Root may discharge those execution conditions without reopening
the algebra review if source remains at the final hash above. Mathematical
or observation-model changes require review.

The successful diagnostic remains evidence of this implementation's exact
algebra, not privacy qualification for a server-visible artifact, the complete
M0 IOP, R0, LogUp or PROOF1.
