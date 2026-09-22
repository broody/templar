# Private M31 membership: proposed end-to-end experiment

2026-09-22. Draft submitted for independent pre-implementation review.
This is an isolated research proof, not a pool-format change or production
qualification. The deliverable is a private proof accepted by a separate
native process, measurements of that complete relation, and an exact wrapper
compatibility assessment. No partial algebra result substitutes for it.

## Statement and AIR

Public input: fixed experimental circuit/version, canonical chain and pool,
and nine canonical M31 words for a depth-32 root. Private input: nine M31
secret words, 32 nine-word siblings, and 32 direction bits. The leaf is
`sponge(frame(1,0,secret))`. At each level, conditionally order current node
and sibling using its bit, then `sponge(frame(3,level,left||right))`.
Use the existing independently vector-checked width-24 Poseidon2 constants,
15-word overwrite rate and nine-word digest. This experimental leaf omits
amounts; it is not the production note commitment or a payment relation.

Use a single fixed H of 128 rows in cyclic coset order. Each row is one full
permutation with the existing 1,172-column quadratic internal trace, plus
`cur[9], sibling[9], bit` (W=1,191). No LogUp/lookup or private claimed sum.
Row0 hashes the 13-word leaf frame with input13=1, input14..23=0.
For each level l, row(1+2l) absorbs the first15 words of the 22-word node
frame, with capacity zero; row(2+2l) absorbs the remaining7 words, then1,
then seven zero rate words, preserving the previous permutation's capacity.
The final nine output words of row64 equal the public root. Padding rows
65..127 are valid zero-input permutations. Fixed public selector polynomials
identify row roles, levels and row64; their degree is at most64.

At first node rows, cur equals the previous row's output digest; at second
node rows, cur/sibling/bit copy the preceding row. Constrain bit*(bit-1)=0
on first node rows. Define left=cur+bit*(sibling-cur) and
right=sibling+bit*(cur-sibling). Input framing/padding/capacity and output
equality are all AIR constraints. Only the leaf's nine preimage words are
free; they are the extracted secret. All permutation constraints hold on
all rows. Constraints are quadratic in private columns, multiplied at most
once by a fixed selector. The previous-row rotation T is fixed by H.
The ordered constraint count is fixed by the verifier and must be at most
2^20; the implementation records and checks its exact count.

The native verifier constructs selectors and parameters itself. A proof may
not choose the circuit, constants, depth, domains or preprocessing root.

## Spaces, masks and compositions

F=M31, E=QM31. H=canonical128, polynomial capacity V1024=L'_1024,
D=canonical8192. Use the actual FFT/circle ordering conversions; logical H
rows are cyclic powers, which must not be confused with FFT bit reversal.
Independent full-circle masks r_j in L256(F), dimension257, give
fhat_j=f_j+ZH*r_j. Sample with OS CSPRNG and unbiased field draws.
Full L256 is V256 plus a nonzero top-degree direction (the canonical256
zerofier); it must not be replaced by V256 alone.

| Object | Honest total degree |
|---|---:|
| Original columns / public selectors / ZH | 64 |
| r_j | 128 |
| fhat_j | 192 |
| Selector times quadratic constraint | at most448 |
| Unsplit composition Q_j | at most384 |
| DEEP pair quotients | at most383 |
| Uniform independent R, batch h | V1024 (dimension1024) |

Commit the masked base columns first; draw alpha in E. For ordered constraints
C_i with base-field coefficients, expand alpha^i into four F coordinates
a_{i,j}. Commit four **unsplit base-field** quotients
Q_j=sum_i a_{i,j} C_i(fhat(P),fhat(TP),selectors(P))/ZH(P).
This is not coordinate extraction of an extension evaluation: Q_j(z) is
evaluated as its own base-field polynomial. The verifier checks all four
identities from fhat(z), fhat(Tz), public selectors and alpha coordinates.

## Commitments, DEEP and FRI

After Q commitment, draw OOD z. Reject poles of rational circle sampling,
points in H or D, and either z or Tz with y=sigma(y), sigma(u)=u^(p^2).
All exclusions are public. Mask accounting uses the full p-Frobenius orbits.
Provide both OOD values for each base column and one for each Q_j; commit
this complete claim vector before committing independent R and drawing lambda.

The batch consists of R with coefficient1, then distinct consecutive positive
powers of lambda multiplying, in fixed order: each base column's raw value
and its two normalized pair DEEP quotients; each Q_j's raw value and its one
pair DEEP quotient. Thus L=1+3W+8=3,582 fixed words. Pair normalization is
exactly that in the source-reviewed M0 spec. No zero-exponent non-R term.
The two OOD claims must bind the same base-column polynomial.

Run ten single folds: first circle-to-line, then nine line folds, from
capacity1024 to a constant. Use the pinned S-two CPU fold primitives and
match their unnormalized factor-two convention. Commit each layer before
its independent challenge. Send/commit the final constant; check the exact
degree and every authenticated query chain. No multi-fold challenge powers.
The query invariant includes equality between the batch reconstructed from
trace/Q/R openings and the committed first FRI layer at every sampled point.

Use120 uniform draws from D only after ALL commitments and the final constant,
with canonical duplicate
deduplication. At positions P, open base columns at P and TP, Q only at P,
and R only at P. Each FRI layer opens its required pairs, solely of h and its
folds. Trace, Q and R are separate trees: opening trace(TP) MUST NOT open
Q(TP). No raw trace columns are packed into FRI leaves.

## Privacy mapping proposed for review

Per base column, all actual or simulation-required observations lie at
P,TP for120 draws and z,Tz with their Frobenius orbits: at most248 distinct
points outside H. Full L256 has257 dimensions and the reviewed circle-MDS
descent argument applies. Q_j observations are determined by these values
and the public selectors/alpha, including Q_j(z); there is no hidden quotient
splitting or lookup exception. Given those observations, uniform independent
R in V1024 makes the entire h polynomial and queried R values jointly
simulatable. All FRI data are functions of h and independent public coins.

Compile using the BCS private-Merkle/Fiat-Shamir construction, including all
oracle messages (also claims and final constant). Use a768-bit random-oracle
output and independent1536-bit salt for EVERY leaf. An implementation may
instantiate domain-separated RO calls with SHAKE256 output96 bytes; the
security theorem is in the ideal explicitly programmable ROM, not an assertion
that the concrete hash itself is information-theoretically random.
Tree leaves contain fixed-size row blocks with canonical31-bit field data;
the compiler adaptation from bits to fixed blocks needs explicit review.

Follow BCS sigma0=H_public(x), sigma_next=H_state(root,sigma), verifier
coins=H_coins(x,sigma), with injective domain separation, fixed phase framing,
and output extension by an indexed block prefix as BCS Remark2.1 permits.
All direct messages have authenticated single-leaf commitments. Proof bytes
contain fixed roots, required leaf values/salts/authentication paths and
final sigma; nothing else from the witness or RNG state. Independent proofs
use fresh masks, salts and R. Rejection sampling is bounded; exhausting a
fixed public candidate budget aborts locally, with its negligible probability
included in the bound rather than silently mapping biased values.

The underlying oracle length is below2^30 bits for this fixed relation,
including all base, quotient, R, claim and FRI oracles. Subject to the compiler
mapping, BCS privacy overhead is then below2^(30-768/4+2)=2^-160 per proof.
Bound repeated transcripts explicitly by composition; never reuse randomness.

## Soundness route and parameter gate

Use **unique decoding**, not the coarse Johnson-regime estimate used in the
initial M0 analysis. Primary source: Ben-Sasson et al., Proximity Gaps for
Reed-Solomon Codes, Theorem6.1 (curve degree ell gives exception ell*D/|E|),
and its weighted specialization from section7.1. Circle codes are generalized
RS under the established parameterization. A conservative full-circle
supercode for capacity1024 has dimension1025; include any degree slack for
the DEEP identities in choosing the strict agreement threshold.

Proposed alpha_agreement=0.564, strictly above(1+1027/8192)/2. Candidate
polynomials for base columns are uniquely determined before composition
randomness; Q candidates before OOD. Joint raw+DEEP agreement forces each
normalized quotient identity by the circle zero bound. Base-field descent
holds because agreement exceeds the relevant zero bound. Composition and
OOD bad challenges have root-count bounds. Weighted single-fold CA controls
each FRI reduction; final query error is0.564^120 (~2^-99).

Initial batching error is at most3581*8192/|E| (~2^-99.2). Fold terms are
bounded conservatively by10*(8192+1)/|E| in total, including first-layer
consistency. With advertised private-column degree512 and selector degree64,
the OOD constraint identity has degree at most1088 and at most2176 circle
zeros. Include the composition term(C-1)/|E| for the fixed C≤2^20.
These are candidate estimates, NOT a completed proof or96-bit claim.
The reviewer must establish the exact round-by-round knowledge invariant,
restricted state-restoration bound and resulting BCS error as a function of
adversary RO queries. Only then pin the96-bit computational work target.
This candidate replaces the earlier27-bit grind/23-query heuristic with120
queries and no grinding credit; it must be accepted only if the reviewed
concrete bound meets or exceeds that intended security target. This is not
permission to lower security to obtain a successful or smaller proof.

## Implementation and acceptance

Astra owns a new isolated bench crate/CLI and AIR. Reviewer signs off before
proof-system implementation and reviews the final source. K3 runs defined
tests and measurements. Retain the old diagnostic and public benchmark.
Use a fixed-layout bounded decoder, canonical field checks, explicit expected
public input and trailing-byte rejection. Separate prove/verify processes;
verification must run with no witness file present. Tests must include invalid
AIR traces bypassing honest witness checks, changed public root/context,
nonboolean directions, bad framing/capacity/chain/root constraints, changed
claims/layers/paths and malformed byte lengths. Differential-test real folds
and hash vectors against the pinned independent references.

Measure one-thread peakRSS, full prove time, verification time and artifact
size after source review and valid/invalid proof acceptance checks. A WASM
attempt follows native correctness. The existing recursive adapter has fixed
hash/shape assumptions; actual PROOF1 compatibility is a distinct result and
must not be claimed from native verification.
