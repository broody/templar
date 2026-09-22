# Independent challenge review: private membership

2026-09-22. **GO for an isolated research wrapper that actually verifies the frozen proof.** No concrete native acceptance bypass or single-proof disclosure leak was found in this review. This is not a production-security certification, a calibrated “90% safe” probability, or approval to substitute a host-verification flag or receipt for inner verification. Wrapper cost and exact verifier equivalence remain separate gates.

Two qualifications are material. The numerical result below is a **knowledge-error bound in a classical programmable random-oracle model**, not an unconditional practical-forgery work estimate. Also, the single-proof BCS theorem does not, by itself, establish an unrestricted online, adaptive, multi-proof service theorem. The permitted research scope must retain those distinctions.

Only this report was written. No implementation, tests, proof runs, benchmarks, private-fixture inspection or further delegation was performed. The review independently read the client and primary papers; prior protocol/source approvals were comparison material, not premises. Nested S-two soundness-review, field-arithmetic, ZK-foundations and divergence instructions were applied.

## Primary basis and one citation correction

The relevant results are Circle STARKs Proposition2, Theorem1, the FFT-space description, and AppendixB's round-by-round folding relations; Proximity Gaps Theorem6.1; and BCS Definitions3.3/5.1, Lemmas3.4/7.5, Theorem7.1 and Remark2.1. Primary references: [Circle STARKs](https://eprint.iacr.org/2024/278), [Proximity Gaps](https://eprint.iacr.org/2020/654), and [Interactive Oracle Proofs](https://eprint.iacr.org/2016/116).

The cached Proximity Gaps text has VSS in section7.1 and does not contain the cited Lemmas7.5–7.6. Thus that particular citation in the earlier review is not reproducible from this cache. Circle AppendixA states a weighted theorem in the list-decoding regime, which cannot simply be substituted with the proposed unique-decoding numerical bound. The direct unique-decoding derivation below supplies the needed statement. The current ePrint metadata notes a revised Polishchuk–Spielman appendix without changes to the main statements; this review identifies the exact cached files at the end instead of silently mixing versions.

## Single-proof joint privacy

Let F=M31, E=QM31, and let T be the fixed previous-row rotation. For any honest verifier randomness, the union of the disclosed base positions is

`S = {P_i, T P_i : i=1..120} union Orb_p(z) union Orb_p(Tz)`.

It has at most248 distinct points. H and D are preserved by T; the public OOD exclusions keep this whole Frobenius-stable set outside H. Repeated positions impose repeated values, not additional independent observations.

Full L256 has dimension257, and a nonzero member has at most256 circle zeros. Evaluation on any at most257 distinct points is therefore surjective: extend to257 points and apply the zero bound to the square evaluation map. For Frobenius-compatible prescribed values, average an E-coefficient interpolant over the four coefficient automorphisms. Division by4 exists in F, so the average is an F-coefficient interpolant with the same values. This proves descent and equal-sized fibers, rather than merely counting mask coefficients. Multiplication by the nonzero values of ZH preserves surjectivity. Independent uniform masks consequently make each column's complete observation vector uniform on the compatibility subspace and independent of the witness, for fixed public input.

The source samples256 FFT coefficients plus an independent canonical256 zerofier coefficient (`poly.rs:83`). This is the required full L256, rather than its codimension-one FFT subspace. Honest degrees are192 for masked columns and at most384 for each unsplit quotient. These are strictly below512 and hence fit V1024; pair division lowers the degree by one.

There are **four F-valued quotient polynomials in one Q tree**, not four independent Q roots. At every observed P and at z, their values are determined by the observed base values, their shifted values, public selectors/root and the F coordinates of alpha powers. The source computes those coordinate coefficients before combining constraints. It does not extract coordinates from an extension-valued polynomial evaluation. In particular Q(TP) is not opened.

For fixed alpha,z,lambda and the observed base values v, put g=h−R. Honest g belongs to V1024(E). Independent uniform R in that entire space makes h uniform and independent of the complete masked witness, including v. Moreover every disclosed R(P) equals `h(P)−g_v(P)`, where the already simulated local values determine g_v(P). This proves the joint distribution of h, Q observations and R observations; marginal uniformity of h alone would not suffice. All FRI pairs, folds and the final constant are functions of h and public coins.

A witness-free honest-verifier simulator can therefore sample the raw verifier coins first, derive all query positions and OOD exclusions, sample compatible column observations on S, derive the Q observations and OOD claims, sample a uniform whole h, and derive R(P) and every FRI disclosure. It need not construct a new membership witness or globally consistent fake quotient table. Sampling coins first is legitimate for this honest-verifier oracle view: the queries use independent public randomness and fixed public rejection rules. Raw random blocks, including rejected candidates and unused bits, can be sampled before their deterministic field decoding.

This argument covers the actual finite disclosure pattern. It does **not** permit an interactive server to request arbitrary additional base/Q openings from the same masking instance. Reusing masks across proofs would invalidate the bound.

## Salted fixed-block BCS compilation

BCS Lemma7.5 asks for honest-verifier oracle-view simulation and yields single-proof zero knowledge in the explicitly programmable ROM. Its distinguisher can adaptively inspect the random oracle after receiving the proof. An arbitrary malicious IOP verifier with unrestricted table access is not the premise and is not a property established here.

The implementation has15 typed trees, including authenticated single-leaf claim and final-constant messages. Leaves use independent1536-bit salts; the output is768 bits. All six hash domains have injective length framing. Tree identifiers, row indices and internal depths are bound. Phase and indexed coin blocks distinguish the BCS state/coin calls. The constant code-fingerprint subdomain can be conditioned on independently of the leaf/state/coin subdomains. Dummy rounds with no needed challenge and deduplicated openings can be modeled as ignored coins and lossless compression of repeated authenticated queries; neither changes the underlying query event.

For any fixed payload and output, the salted-leaf preimage count has mean2^768. Relative error2^-192 has Chernoff failure at most `2 exp(−2^384/3)`. A union over all bounded payload strings, fixed prefixes and outputs remains negligible even under the loose payload bound2^30 bits. Thus the regularity property can hold simultaneously for payloads selected using previous RO information, not just for one independently selected payload. The same hidden-node replacement argument used in BCS applies to typed fixed blocks; internal nodes retain two768-bit children. Leaf/block extraction similarly parses the typed children rather than assuming an unframed bit encoding.

The underlying oracle payload is316,711,296 serialized bits, below2^30, with40,946 leaves and81,877 total tree nodes. Salts and authentication paths are compiler randomness/output, not additional witness oracle coordinates. The conservative single-proof ideal-RO privacy overhead `p*2^(-768/4+2) < 2^-160` is consistent with this mapping. SHAKE256 producing96 bytes is the specified concrete instantiation of that ideal model, not a theorem that concrete SHAKE is a truly random768-bit function. OS randomness introduces the separate CSPRNG assumption. Public sampler exhaustion contributes a negligible abort term; conditioning on a returned proof must include that term.

## Weighted unique-decoding lemma, derived explicitly

Let a linear RS/GRS code have length n and rate rho. Let `a > (1+rho)/2`, and fix words u0,...,u_ell and weights `mu(x)=m_x/M` with integer `0<=m_x<=M`. Normalize weighted agreement by n. Let S be the challenges lambda for which `sum lambda^i u_i` has weighted agreement strictly greater than a with some codeword.

**Claim:** if `|S| > ell*M*n`, the words have common agreement with fixed codewords on a set of weighted density strictly greater than a.

Proof: weighted agreement implies ordinary agreement. Since `|S| > ell*n`, actual Proximity Gaps Theorem6.1 gives coefficient codewords v_i and ordinary common agreement at least a. Their combinations are the unique decodings: two codewords each agreeing with one word on more than half of n plus half the degree bound must coincide. Write A for the maximal common agreement set of all u_i/v_i. If `sum_A m_x <= a*M*n`, each lambda in S must gain at least one **integer unit** of weight outside A, because its total integer agreement weight exceeds a*M*n. At each x outside A, the nonzero polynomial `sum lambda^i (u_i(x)-v_i(x))` has at mostell roots. Summing the accidental integer weights over S gives at most `ell*sum_x m_x <= ell*M*n`, a contradiction. The ell0 constant case is immediate. This also handles a not lying on the weight grid; the integer-unit argument avoids a rounding gap.

Circle Theorem1's pointwise nonzero multipliers preserve agreement sets, weights and these challenge-polynomial combinations, so the lemma transfers to the full circle supercode. This is a derivation from the primary theorem, not a quotation of a missing weighted theorem.

For each single FRI fold, the two even/odd words are fixed before the challenge. Following Circle AppendixB, weight each projected point by the fraction of original D positions whose earlier batch/fold checks still hold. At fold j, `M<=2^j`, `n=8192/2^j`; hence `M*n<=8192`. Use the claim with ell1, giving at most8192 bad challenges; the earlier8193 bound is conservative. Agreement density must include the first-layer equality with the reconstructed batch. It is not legitimate to assume that equality globally, and the source checks it at every sampled point.

The relation after each fold is: there exists a codeword of the prescribed next degree such that more than an a fraction of original positions pass every earlier consistency check and agree with that codeword after projection. The weights depend only on the fixed preceding transcript. Outside the exceptional challenges, a next-round relation implies the preceding relation by lifting the two decoded even/odd polynomials. This is a per-prefix, all-continuations reduction, which is what state restoration needs. The invertible factor2 in the pinned unnormalized fold does not alter these code spaces. The final relation is a constant on the remaining8-point domain, checked through the authenticated chains.

## Degree binding, extraction and the numerical claim

For the initial lambda curve, ell=3581 and n=8192. The common agreement threshold a=141/250 lies strictly inside unique decoding even for the conservative dimension1027 slack. Correlated agreement fixes candidates for every raw and normalized-DEEP word. A decoded pair quotient has degree at most512; multiplying by its line gives degree at most513. Equality on more than4620 common points forces the identity by the1026-zero bound. Both OOD samples consequently bind the **same** decoded raw column. Agreement of a decoded polynomial with F-valued words at more than1024 base points forces F-coefficient descent by applying Frobenius and the zero bound.

Before alpha, any decodable base candidates are uniquely fixed. If their H trace violates a constraint, fix one violated row; its nonzero alpha polynomial has at most C−1 roots. Before z, any decodable Q candidates are also fixed. Outside that alpha exception at least one coordinate polynomial identity must fail, regardless of Q choice; choose one before z. Its degree is at most `2*512+64=1088`, so it has at most2176 circle zeros. Missing raw candidates cannot be repaired except through a later correlated-agreement failure. Raw+DEEP positive lambda powers, the constant R term, and all four coordinate identities are present in the source.

Outside these bad events, uniquely decode the base words, evaluate them on H, and extract row0's nine secret words and each first-node row's sibling/boolean direction. The1273 AIR equations enforce framing, carry/copy, capacity, all permutations and the final public root. This is a polynomial-time oracle-model knowledge extractor. It uses the advertised degree bounds, not the smaller honest degrees, and is distinct from an efficient practical witness-recovery algorithm.

Writing `Q=(2^31−1)^4` and `Z=Q−1−4*(2^31−1)^2−8192−128`, the conservative earlier budget is

```text
delta = (2^20−1)/Q + 2176/Z + 3581*8192/Q
        + 10*8193/Q + (141/250)^120
      = 2.8565520171963917... * 10^-30
      < 2^-98.143568.
```

The four constraint-coordinate checks need no factor4 when one failing coordinate is fixed before z. Duplicate query authentication does not reduce the120 independent draw event. For a fixed bad final chain, its acceptance density is at most a and its probability is at most a^120.

Since the reductions hold for each fixed preceding state and every continuation, at most b fresh state-restoration opportunities incur at most b*delta. On a good accepting history the described decoder extracts a witness; revisiting an already sampled state does not create another independent opportunity. BCS Theorem7.1 then supplies the fixed-instance ideal-ROM **knowledge error**

`e(m) <= m*delta + 3*(m^2+1)*2^-768 + sampling term`.

At m=2^96, the leading term is0.22631936745, not2^-96. This bounds extraction loss. It does not itself bound arbitrary successful verification: honest proofs pass, and an existing same-statement proof can be replayed. Turning it into a concrete application-forgery work bound needs a stated application hardness/replay model and extraction-cost reduction. No claim of practical96-bit payment security follows from this benchmark. The AIR proves experimental secret-preimage membership only; amounts, ownership rules, nullifiers and funding are absent.

## Repeated proofs: explicit scope and remaining lemma

Fresh independent masks, R and **every** leaf salt are mandatory for every invocation, including retries. Native and WASM public entry points use OsRng; the exported prover requires CryptoRng but cannot prevent a caller from restoring or cloning generator state. Replaying identical proof bytes adds no new algebraic disclosures but remains a replay, not fresh possession evidence.

For a fixed finite list of valid public statements, the oracle-view simulator composes with independent per-proof randomness, even if witnesses are correlated or identical. A joint BCS simulation additionally has to keep one shared programmed oracle and consistent answers for coincident keys. Its ordinary fresh-key hybrid gives an additional collision/programming term; it is not correct simply to repeat a one-proof simulator with a newly sampled oracle each time.

For an online adaptive service, use the following **declared boundary**: a finite t proof requests, a bounded classical adversary making m RO queries across the entire interaction, and no masking-state reuse. Honest work is conservatively fewer than2^20 RO calls per proof, so a joint argument can charge fresh-address collisions against `B=m+2^20*t+1`. The required joint lemma should explicitly show a bound of the form `t*epsilon_private + O(B^2/2^768) + t*epsilon_abort`, maintaining a single oracle/programming table and refusing to overwrite previously visible answers. Root/state hiding must justify freshness of each new coin address before programming. Uniform fixed-block regularity above is relevant to adaptively chosen payloads, but is not by itself that complete online lemma.

That concrete online composition theorem and its constants are **not established by the current repository reviews or claimed complete here**. In particular, single-proof EPRO with an unbounded post-proof distinguisher is not an unbounded interactive multi-proof theorem: such a distinguisher could record oracle answers before later programming. Adaptive simulation-extractability, nonmalleability, reset security and proof-oracle-assisted knowledge claims are also absent. This is an explicit labeled gap for the prototype, not evidence of a discovered privacy attack. Do not advertise a per-proof2^-160 term as an unchanged guarantee for unlimited sessions.

## Wrapper gate and reviewed identities

An actual wrapper must execute every native verifier check over the same public input and complete proof bytes. Hash truncation, reduced-to-M31 output, altered coin expansion, skipped authentication paths, or a host-only acceptance decision are protocol changes. The exact SHAKE256 public-message differential/cost component is separately suitable as a feasibility probe; its successful execution would not establish the whole wrapper.

Frozen SHA256 identities independently matched during this review:

```text
protocol.md       c6a5174037d354447eb15db4bce4eef92648abe1f29d2f68c272166ec5fbf60e
client/src/air.rs  aa0adfcdad4405dddc1d0e43ab3b942fa26e445ab3590a2ee2dcdbaa55db64f6
src/constants.rs  46ea8e2ffb0149af567fd09622d3ddfc73ce08f6c7f3f64ef3960f929ce064f3
src/crypto.rs     d357c7b4f02d54e619e3b10fd36c85cf971574e993055536f4a65d60a767dca2
src/hash.rs       fdffbfcc63170def2dd98a7663bd60b272c9f667e31f35b02b0e15f6df03914c
src/lib.rs        9bf78080317654e8894a5b1d18915cdcce0e887dd1d3c588b59cfb78da5d91b7
src/main.rs       42cb5699427f67481f021e87bd94d11f4354f11214ceb054fd9132a74f0ab45c
src/poly.rs       add368607576f12f582a69937495ce2ebe8c983fb094c74b19f738a69b86bbb7
src/proof.rs      9b461c574a62296540b2b80f68b07868b2e9e4435106a46d508e40018626e2f5
client/Cargo.toml 4620086f5bfa31f081742d490354647eef8fec6db8c1dfb7d12711e886db7114
client/Cargo.lock 64310f2d59d9b18ddeee9792990746498e5d6c3b1e63acba4985a0d7ab61f3ea
```

`src/` entries are under `bench/m31-private-e2e/client/`. Cached primary PDF hashes under `target/client-privacy-contract/papers/`:

```text
2024-278.pdf      8e60498a671ff147c211ac7733435057dff27b31b8bd3211485b85b4035d296d
proximity-gaps.pdf 40429b4f6ceb9fcf100791e26291673059fee00b0d4c665056e886ef02cec842
2016-116.pdf      a2dc9bd042665081664287281b9bcf64735be2c818ce9207cce57cc43939fa2f
```
