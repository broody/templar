# Private membership protocol: implementation authorization

2026-09-22. **GO for isolated native research implementation** of
[`bench/m31-private-e2e/protocol.md`](../m31-private-e2e/protocol.md), SHA-256
`c6a5174037d354447eb15db4bce4eef92648abe1f29d2f68c272166ec5fbf60e`.
This authorizes the Crypto Specialist to implement the specified protocol;
source review and positive/negative execution evidence remain mandatory before
accepting its artifacts as private proofs. It does not authorize production,
payment semantics, or a PROOF1 compatibility claim.

This review applies the nested STWO Math Reviewer requirements and reuses the
completed masking/algebra reviews. No implementation, builds or benchmarks
were performed. It supersedes this file's earlier pending checkpoint.

## 1. Protocol and privacy invariant

Approved parameters: H=128, W=1,191, full masks L256(F), capacity V1024,
D=8,192, four unsplit F-valued quotients, batch curve degree3,581, ten single
FRI folds and120 independent query draws. Agreement threshold a=141/250=0.564
is an analysis parameter, not a prover input.

The proposed relation binds the leaf preimage,32 direction bits, ordered
framing, sponge capacities, permutation transitions and public root through
selector-controlled constraints. The verifier owns selectors, constants and
domains. Source review must check the enumerated wiring; the permutation-only
benchmark does not supply it automatically.

Honest private-column degree is at most192. A selector times a quadratic
constraint has degree at most448; division by ZH yields degree at most384.
These and their pair quotients fit strictly inside V1024. Sample full L256,
not V256; do not discard its additional full-circle direction.

Each column's observation closure contains at most248 points: P,TP for120
draws and both four-point Frobenius orbits z,Tz. Trace, Q and R trees retain
separate query sets; Q(TP) is not disclosed. The previously proved
circle-MDS/Frobenius-descent lemma gives uniform, witness-independent masked
values on this closure. Every Q_j observation is a function of these values
and public alpha/selectors. This requires base-field coordinate coefficients
of alpha^i, not coordinate extraction after extension-valued evaluation.

Given these observations, uniform independent R makes the joint view of the
entire h polynomial and queried R values simulatable. All folded polynomials,
complements and the final constant depend on h and public coins. The prior
fixed-public-statement honest-verifier simulator therefore extends to this
relation, without another membership witness.

## 2. Round-by-round knowledge argument

Use full L1024(E), dimension1,025, as a conservative supercode of V1024.
The selected a exceeds its unique-decoding threshold and the dimension1,027
slack threshold. Decoded raw polynomials have total degree at most512.
A decoded pair quotient times its denominator has degree at most513.
Common agreement exceeds4,620 points, so equality there forces the quotient
identity globally by the1,026-zero bound. Both OOD claims bind the same
trace polynomial. Agreement with F-valued words at more than1,024 points
forces Frobenius descent to F.

Bad-state reductions:

1. **Before alpha:** individually decodable base oracles have unique
   candidates fixed independently of alpha. Missing candidates force later
   correlated-agreement failure except at a batching/FRI bad challenge.
   Otherwise their H evaluations give the only extractable trace. If an AIR
   constraint fails, the random combination at a deterministically chosen
   violated row vanishes for at most C−1 alpha values. Require C≤2^20.
2. **Before z:** Q candidates are fixed by their raw words and unique if they
   exist. If any of the four polynomial identities fails, choose one failing
   coordinate before z. Its degree is at most2*512+64=1,088 and it has at
   most2,176 circle zeros. Checking all four requires no extra factor four.
3. **Before lambda:** R and all raw/DEEP words are fixed. A malicious R is an
   arbitrary E-valued word, never assumed uniform. The degree3,581 curve
   theorem gives a common agreement set for all3,582 words, except with
   probability at most3,581*8,192/|E|. Raw terms and positive distinct powers
   are required. Decoded identities establish the preceding state.
4. **Each fold:** track weighted density of original D positions whose
   authenticated chain remains consistent. Include equality between the
   reconstructed batch and committed first layer, not assumed globally.
   For single folds, weight denominators are at most2^j and projected
   domains have8,192/2^j points. The conservative exception per fold is
   at most(8,192+1)/|E|.
5. **Queries:** all oracles, direct messages and the final constant are
   already committed. Without a previous bad reduction, a false chain passes
   at density at most a. The120 independent draws pass with probability at
   most a^120. Deduplicated authentication paths preserve this draw event.

Primary justification:
[Proximity Gaps, Theorem6.1](https://eprint.iacr.org/2020/654.pdf).
Its unique-decoding weighted specialization follows from §7.1 (S'=S) and
Lemmas7.5–7.6: successful challenge count at least ell*(M*n+1) gives weighted
common agreement. Circle transfer and folding use
[Circle STARKs §§3,6 and Appendix B](https://eprint.iacr.org/2024/278.pdf).
The factor-two fold convention is harmless only when consistent: invertible
constant scaling preserves the codes.

Extraction uniquely decodes the committed base words in polynomial time,
evaluates candidates on H and checks all AIR constraints. It obtains the
preimage, siblings and bits for the same public statement. This is a knowledge
argument, not merely language soundness for trivial M0.

## 3. Concrete bound and state restoration

Let Q=|E|=(2^31−1)^4. A conservative allowed-OOD-set bound is
Z=Q−1−4*(2^31−1)^2−8,192−128, covering both conjugation exclusions and H,D.

`delta = (2^20−1)/Q + 2176/Z + 3581*8192/Q`
`        + 10*(8192+1)/Q + (141/250)^120`
`      < 2.856553e−30 < 2^(−98.1435)`.

These are bounds, not measured attack probabilities, and use no grinding
credit. Failure of the unnecessary coarse Johnson bound was not an attack.

Every bad-challenge bound holds conditionally for each fixed preceding state
and every continuation. A state-restoring execution with at most b fresh
verifier-round opportunities is bad with probability at most b*delta by a
union bound. Replaying a sampled challenge adds no fresh opportunity. Outside
that event, decode the base oracle selected by the accepted history. This
gives restricted state-restoration knowledge error at most b*delta,
conservatively using the sum of round errors.

[BCS Theorem7.1](https://eprint.iacr.org/2016/116.pdf) bounds compiled knowledge
error against m RO queries by

`m*delta + 3*(m²+1)*2^(−768) + sampling_failure`.

At m=2^96 the first term is below0.227; the remaining terms must be negligible
under the fixed sampling policy. This supports at least96 bits of classical
RO work for constant success: even success probability one-half requires
more than2^96 queries. It does not claim probability2^-96 against an adversary
already allowed2^96 queries, nor QROM security.

## 4. Fixed-block private Merkle compilation

The bit-to-fixed-block adaptation is permitted with fixed canonical payload
lengths and domain-separated leaf/internal/state/coin encodings. An opening
reveals the whole declared block, whose field values all enter the oracle
view. Lengths and query locations are verifier-owned. Claims and final
constants are fully read authenticated oracle messages.

Explicit privacy adaptation: for a fixed b-bit payload v,768-bit output y,
and uniform1,536-bit salt, the number of salts hashing to y has mean2^768.
Chernoff bounds deviation greater than2^576 by
`2*exp(−2^384/3)`. Union over every bounded payload prefix of length b≤2^30
and every output remains below2^-768. Outside that exceptional oracle set,
each payload's salted-leaf output is within2^-192 statistical distance of
uniform, uniformly over payload choice. The private-tree hybrid/simulator
of BCS §3.2 therefore applies to fixed blocks. Internal nodes and extracted
block authentication follow the same binding analysis. This avoids assuming
payload choice is independent of previous RO access.

With underlying oracle data below2^30 bits, the conservative BCS Lemma7.5
overhead remains below2^-160 per proof. Use independent salts on every leaf,
including direct/public-message leaves. SHAKE256 outputting96 bytes
instantiates a stated ideal-RO model, not an information-theoretic claim about
the concrete hash. Real CSPRNG use adds its computational replacement
assumption to the ideal uniform-randomness argument.

Implement the BCS state schedule exactly, with indexed coin expansion and
canonical phase framing. Pin the public rejection budget. Twelve independent
four-coordinate candidate groups give field-draw exhaustion at most2^-348;
include OOD rejection and a union over the fixed maximum draw count. Abort
locally, without witness-dependent retries/uploads. Multiple proofs need
fresh masks/R/salts and explicit composition of privacy and RO-budget bounds;
one-proof2^-160 is not an unchanged arbitrary-transcript guarantee.

## Acceptance boundary

GO requires this exact protocol, fixed decoder limits, independent randomness,
canonical fields, complete authenticated fold/claim checks, and post-source
review of AIR wiring, degree conversions, transcript ordering and private
leaves. Run the separate-process and adversarial-trace tests after source
review. Retain an unqualified research label until these checks complete.
The recorded [wrapper incompatibility](../m31-private-e2e/wrapper-compatibility.md)
remains: native acceptance is not PROOF1 acceptance; a new wrapper needs its
own reviewed implementation.
