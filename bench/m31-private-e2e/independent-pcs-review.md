# Independent PCS implementation challenge

2026-09-22. Read-only review by the delegated Crypto Specialist. The only
written file is this report. No builds, proof generation, verifier reruns,
benchmarks, private-fixture reads, or source changes were performed. I read
the root/nested agent guidance, AIR and divergence skills, Circle STARK
degree/DEEP/FRI anchors, the frozen protocol/source review, native implementation,
retained public artifacts, and the existing Cairo/recursive adapters.

## Blocker-first verdict

**No concrete invalid-proof acceptance or serialized private-witness recovery
was found in the inspected native implementation.** This is an independent
implementation finding, not a replacement for the Math Reviewer's challenge
of the masking, correlated-agreement, extraction, and BCS theorems. Those
arguments and their classical programmable-ROM/CSPRNG assumptions remain
conditions of the result.

**There is no unchanged-proof path through the existing Cairo or recursive
verifier.** They have incompatible hashes, root/sample layouts, composition
splitting, transcript scheduling, and FRI structure. A direct Cairo port can
be implemented as a new verifier after Math GO, under the obligations below.
It must not reinterpret this proof as an ordinary S-two proof. That conditional
implementation GO is not PROOF1 acceptance or a server-capacity GO.

**Exact SHAKE256 authentication is a concrete missing implementation and cost
gate.** The unchanged proof requires 96-byte SHAKE256 outputs and 192-byte
leaf salts. A 32-byte Keccak/SHA3/syscall output, concatenated independent
hashes, reduced Blake hash, or unchecked host hash does not implement it.
The root team's existing-outer-prover capacity failure is a separate known
integration obstacle; it was not rerun here. Do not invest in the complete
port before an exact-hash cost probe and supported outer-trace capacity check.

Finally, the proven relation is this experimental secret-preimage membership
relation. It does not prove payment balance, nullifier uniqueness, note
ownership semantics, pool append history, or that an arbitrary client-chosen
root is an accepted pool root. A later application must bind the verified
public context/root to its own state and bind the verifier program identity.

## What was challenged in the native code

**Mask/disclosure accounting.** `poly.rs:83–104` samples 256 independent FFT
coefficients plus an independent canonical-256 zerofier direction, giving
full L256, dimension 257. It multiplies that mask by the H=128 zerofier and
adds the original column. It does not accidentally use only V256 or share a
mask across the 1,191 columns. `proof.rs:112–128,224–238` discloses exactly
trace(P,TP), Q(P), R(P), the OOD claims, FRI pairs, and the final constant.
Q(TP) is not opened. The FRI leaves contain only four coordinates of h/folds,
not raw witness columns. All four coordinates of each extension OOD value
count toward the full Frobenius-orbit closure; counting only two scalar
observations would be wrong.

The closure has at most 240 base-field points and eight OOD-orbit points per
column, hence at most 248, below 257. Four Q observations do not independently
add arbitrary private-column measurements: for an honest proof, their values
are functions of these same masked row/previous-row values and the public
selectors/alpha. This last conclusion depends on the unsplit construction
and the reviewed interpolation/descent lemma, not merely on counting bytes.
Uniform independent R is sampled with 1,024 QM31 coefficients. Its role is
the reviewed joint simulation of h and queried R values, not an assumption
that a malicious prover must choose R honestly.

**Four quotients and binding.** There are four unsplit F-valued quotient
polynomials in **one** Q Merkle tree, ID 1, not four separately rooted trees.
`composition_weights` expands alpha^i into four base-field coefficients
before constraint combination. `check_ood` checks all four identities.
It does not extract coordinates from an extension-valued evaluation and
mistake them for Q_j(z). Each Q column's raw value and DEEP value occurs in
the batch; each base column's raw value and both DEEP values occur as well.
The 3,581 positive lambda powers are distinct and ordered, with only R at
exponent zero. There is no missing Q coordinate or unbatched base OOD claim.

**Composition/degree transforms.** Logical rows use cyclic H order;
`from_cyclic` explicitly converts them to the FFT's bit-reversed twin-coset
order. The previous-row map is subtraction of H's step, not an adjacent
array index or a shift by D's step. Original columns/selectors have degree
at most 64, full masks degree at most 128, masked columns at most 192,
selector-controlled quadratic constraints at most 448, and honest Q at most
384. Their interpolation capacity 1,024 therefore has genuine headroom.
The constraints reset intermediate permutation states to stored columns,
preventing a hidden high-degree substitution through many rounds.

The sampler excludes rational poles, H/D membership, and degenerate y values
at both z and Tz. `Pair` uses the pinned CM31 embedding and QM31 outer
conjugation, the p² involution. Substituting ordinary complex conjugation of
a differently represented field, or using z in both claim slots, changes the
quotient identity. The verifier checks these claims through the batch and
FRI; checking Q(z) alone would not establish the claimed low-degree witnesses.

**Actual FRI checks.** `proof.rs:295–342` reconstructs the scalar batch from
authenticated base/Q/R openings, checks it against the first authenticated
FRI layer, then checks all ten folds and equality to the authenticated final
constant. Each layer is committed before its own challenge. The sparse fold
uses the same unnormalized factor-two convention as the pinned CPU fold.
The base TP-only values are authenticated but are not directly read by the
batch equation; their disclosure supplies the honest Q observation closure.
This is not evidence of an omitted verifier identity: native soundness links
constraints at OOD and binds those claims to the raw words through DEEP/FRI.

**Parser/transcript completeness.** Roots, claims, the final constant, every
queried value/salt/path, and final sigma are checked. Dimensions and index sets
come from the verifier. Reader offsets are checked, M31 values must be below
p, input is capped at 16 MiB, and trailing bytes fail. Public chain/pool
strings have canonical nonzero lowercase encodings and separate field/address
bounds. Unknown public JSON fields fail; parsed public values are reserialized
canonically before hashing. No proof-supplied circuit identifier or parameter
tuple becomes authority. Both supported entry points use OsRng; the public
Rust proving API requires CryptoRng and documents fresh independent state.

I considered whether zero alpha/lambda or sampled collisions constitute a
bypass. Zero challenges are not excluded, and a degenerate challenge can erase
checks, as in a probabilistic polynomial protocol. That is a bad-challenge
event covered by the theorem's root-count/RO-work analysis, not a practical
counterexample found here. Query collisions are legitimate: exactly 120
draws occur, then authentication indices are sorted and deduplicated. Do not
redraw for 120 unique positions. Likewise, changing OOD claims and hoping to
cancel them using R requires defeating the pre-lambda commitments or the
reviewed batching bound; no adaptive late-R insertion exists in the code.

## Independent retained-format inspection

Without running the prover or verifier, I recomputed the circuit fingerprint,
canonical public encoding, all 15 root-to-sigma updates, and the final 120
query draws using Python's SHAKE256. I independently derived the rotation map
using the pinned circle-group exponent/coset order and checked the exact
serialized byte-count equation. This is transcript/layout inspection, not a
new execution of the mathematical proof verifier.

| Retained native proof | Bytes | Unique draws | Trace(P,TP) leaves | Per-column closure upper bound |
|---|---:|---:|---:|---:|
| proof-1.bin | 3,586,428 | 120 | 239 | 247 |
| proof-2.bin | 3,580,832 | 120 | 238 | 246 |
| proof-3.bin | 3,555,140 | 119 | 237 | 245 |

The claim leaf contains 9,544 M31 values = 2,386 QM31 claims, including all
1,191 values at z, all 1,191 at Tz, and four Q_j(z). Its opening takes 38,368
bytes. The final-value opening takes 208 bytes. The fixed header is 1,544
bytes: magic8, fifteen roots96 each, final sigma96. A base opening takes
6,204 bytes; a Q or R opening takes 1,456. FRI layer j openings take
208 + 96*(13-j) bytes. All three proof lengths agree with this exact layout.

Proof 1 has FRI opening counts
`[240,230,224,212,186,152,106,62,32,16]`. The current uncached authentication
loop therefore checks 1,941 leaf hashes and 20,919 internal-node hashes.
Exact framed SHAKE messages have lengths 285 bytes for a node, 305 for a
four-field leaf, 5,053 for a base leaf, and 38,465 for the claims leaf.
At SHAKE256's 136-byte rate these require 3, 3, 38, and 283 Keccak-f
permutations respectively: **77,225 permutations for authentication alone**
on this proof, excluding transcript hashing. This is a source-derived work
count, not a Cairo step/gas measurement or an impossibility proof. Sound
internal caching could reduce repeated work without changing the wire format,
but is a separate implementation requiring equivalence checks.

## Minimum obligations for a direct Cairo verifier of unchanged bytes

1. **Trusted statement and circuit.** Fix W=1,191, C=1,273, H=128,
   capacity=1,024, D=8,192, ten folds, 120 draws, field bases, all six selector
   polynomials, and the Poseidon constants/round/constraint order. Fix the
   existing circuit fingerprint below, rather than hashing Cairo source or
   accepting a fingerprint from the proof. Reconstruct exactly
   `TMPZK001 || fingerprint96 || canonical_json(public)`, with JSON field order
   `chain,pool,root`, no spaces, minimal lowercase hex strings, and decimal
   root words. Alternatively validate supplied bytes against that exact typed
   reconstruction; unchecked supplied public bytes are insufficient.

2. **Byte decoder and canonicality.** Preserve the original 16 MiB cap,
   magic, fixed header, query-derived lengths and final end-of-input check.
   If carrying bytes through felt calldata, enforce byte ranges and exact
   byte length. M31 payloads are four-byte little-endian canonical words;
   QM31 is four such coordinates in the native order. Roots/salts are raw
   bytes, never reduced modulo M31/Stark felt. Every expected path must be
   consumed; no proof-provided allocation/column/query length is trusted.

3. **Exact RO.** Implement SHAKE256 with rate 136 bytes, capacity 512 bits,
   SHAKE domain suffix 0x1f, pad10*1 and little-endian lanes, returning all
   96 output bytes. The RO preimage is the ASCII prefix
   `Templar-private-membership-BCS-v1`, u64-LE tag length, tag, u64-LE part
   count, then each u64-LE part length and part. Preserve all six domains:
   circuit, leaf, node, public, state, coins. The circuit hash can be a trusted
   precomputed constant; every proof-dependent hash must be enforced by the
   proved Cairo execution or an independently sound authenticated subproof.

4. **Private Merkle trees.** Fix IDs/dimensions exactly:

   | ID | Meaning | Leaves | M31 words/leaf |
   |---|---|---:|---:|
   | 0 | masked base | 8,192 | 1,191 |
   | 1 | four Q polynomials | 8,192 | 4 |
   | 2 | all OOD claims | 1 | 9,544 |
   | 3 | R | 8,192 | 4 |
   | 4+j, j=0..9 | FRI layer j | 8,192 >> j | 4 |
   | 14 | final constant | 1 | 4 |

   Leaf parts are id-u32-LE, index-u64-LE, canonical field bytes, salt192.
   Parent parts are id-u32-LE, depth-u32-LE, left96, right96. Depth starts at
   zero next to leaves; path orientation comes from the index bits. Claims
   and final messages are salted single-leaf commitments, not unauthenticated
   direct values. Preserve authentication of TP-only base leaves too.

5. **BCS schedule and sampling.** Start sigma=RO(public,[x]), phase0.
   Each commit updates sigma=RO(state,[phase-u32-LE,root,sigma]), then
   increments phase. Coin block k is RO(coins,[x,sigma,phase-u32-LE,k-u32-LE]);
   a new Coins stream starts at block0. Read u32-LE words. An extension draw
   masks each of four words by 0x7fffffff, accepts the entire group only if
   all are below p, and aborts after twelve rejected groups. OOD applies the
   exact rational map/exclusions and twelve-candidate budget. No modular
   reduction, silent biased fallback, or extra draw is interchangeable.
   Draw alpha after ID0; z after ID1; lambda after IDs2 and3; a fold challenge
   after each ID4..13. Commit ID14 and compare final sigma before drawing
   exactly 120 words masked by 8191, then sorting/deduplicating them.

6. **OOD/AIR checks.** Use H's negative step for T and the exact bit-reversed
   circle-domain mapping. Evaluate all 1,273 constraints with the trusted
   selectors and root; expand alpha^i into the native four F coordinates;
   check each sum_i coord_j(alpha^i)*C_i = Z_H(z)*Q_j(z). H's zerofier has
   log7, not the advertised capacity log10 or LDE log13. There is no stock
   two-half/eight-column composition extraction and no LogUp sum here.

7. **Raw/DEEP batch.** At each sampled P use R(P) with coefficient1, then
   native ordered positive lambda powers for all base raw/Pairs(z)/Pairs(Tz),
   followed by four Q raw/Pairs(z). Reproduce `Pair::new`, its CM31 embedding,
   p² conjugation, numerator and denominator exactly. Both OOD claims must
   refer to the same base raw polynomial. Missing raw terms, shifting powers,
   or allowing an uncommitted R changes soundness. Compare this result with
   the authenticated first FRI layer before any fold.

8. **All ten folds.** Derive paired indices from the original query set at
   every layer. First use the paired circle y; later use the exact projected
   line-domain x, with its bit-reversed order. Compute
   `a+b+challenge*(a-b)/x` without introducing a factor1/2. Enforce every
   authenticated consistency edge, including duplicate folded-index equality.
   After ten folds the residual domain has eight points but the degree bound
   is zero: every checked endpoint equals the single authenticated constant.
   A final commitment or an OOD check alone does not replace this chain.

9. **Proved output/context authority.** The Cairo program must constrain the
   entire verification, not trust a host `accepted=true`, hint-only SHAKE
   results, or native-computed unconstrained OOD/FRI values. Bind its accepted
   public statement and fixed verifier identity into the outer public output.
   Where used with a pool, independently require the expected chain, actual
   pool, and allowed root. The server only needs this proof and public input;
   no secret/path or native private fixture belongs in its input package.

10. **Acceptance before wrapping.** Differential fixtures must cover exact
    SHAKE messages (including padding boundaries), circuit/public bytes,
    sigma/challenge/query checkpoints, sampler rejection branches, all tree
    types, selectors, arbitrary and genuine OOD values, batch reconstruction,
    and all fold-domain transitions. Retained proof3 already exercises a
    duplicate query. Require unchanged native/browser proof bytes to pass
    Cairo, and systematic root/salt/value/path/claim/fold/final/public/parser
    mutations to fail. Test malicious AIR traces through the verifier, not
    only the honest witness constructor. Only then attempt the unchanged
    outer prover and actual PROOF1 verification with the expected outputs.

The existing generic Cairo `verify<Air>` is not a shortcut around these
obligations: its body fixes composition splitting and the stock PCS schedule.
Existing QM31/circle utilities may be reused only after representation and
formula differentials. Likewise `proof_from_stark_proof` accepts the specific
reduced-Blake ExtendedStarkProof layout, not this byte proof.

## Frozen identities

The SHA-256 values below were independently recomputed; they match the prior
source-review manifest. No source identity changed during this review.

```text
client/src/air.rs       aa0adfcdad4405dddc1d0e43ab3b942fa26e445ab3590a2ee2dcdbaa55db64f6
client/src/constants.rs 46ea8e2ffb0149af567fd09622d3ddfc73ce08f6c7f3f64ef3960f929ce064f3
client/src/crypto.rs    d357c7b4f02d54e619e3b10fd36c85cf971574e993055536f4a65d60a767dca2
client/src/hash.rs      fdffbfcc63170def2dd98a7663bd60b272c9f667e31f35b02b0e15f6df03914c
client/src/lib.rs       9bf78080317654e8894a5b1d18915cdcce0e887dd1d3c588b59cfb78da5d91b7
client/src/main.rs      42cb5699427f67481f021e87bd94d11f4354f11214ceb054fd9132a74f0ab45c
client/src/poly.rs      add368607576f12f582a69937495ce2ebe8c983fb094c74b19f738a69b86bbb7
client/src/proof.rs     9b461c574a62296540b2b80f68b07868b2e9e4435106a46d508e40018626e2f5
client/Cargo.toml       4620086f5bfa31f081742d490354647eef8fec6db8c1dfb7d12711e886db7114
client/Cargo.lock       64310f2d59d9b18ddeee9792990746498e5d6c3b1e63acba4985a0d7ab61f3ea
native proof-1.bin      ef2735e10988a2704be45f999e37f258df79e50d819e774b21b9508a8bcc2f37
native proof-2.bin      db898b3db5f6ce7c080445fd7e14c0a60d41290057f0a3f8cacefc15f8dd351e
native proof-3.bin      16781bc09ced9765ede481619af21097b5ca93c4049476402f1db99d275c2a95
```

The **96-byte circuit RO value**, distinct from a SHA-256 source digest, is:

```text
5cfcb5be3af51f5fb0fdb4e634d85bc5c04b5b1fc8fcfcf5fd93c0dcc9725c0f051130d5cfba7b1a0af27d1fa19e3c6990147cdfae0fa5c8dcfc4cf94f1085a8585a189ec65874188682400f21bd31c8d1fea006b99ebb2543f15db4d873f83e
```

Relevant pinned semantic/adapter SHA-256 anchors:

```text
stwo core/constraints.rs                    90ccce4db3839ac519a53367462b6f788ad4053b1799a59bab3f34705532854b
stwo prover/backend/cpu/circle.rs           89167682b3c217c5b6954c566e0112967f4508a6b9878edb35e0d58c540e27d1
stwo prover/backend/cpu/fri.rs              4d40c7ec631fad610db25083a0b17699503c80abd105b15c3a5784e72d3a44a6
recursive proof_from_stark_proof.rs         1641b575715a1b86930d12969837f7c9092106ce512011e6568e65cdb8200e53
recursive channel.rs                       1e4c7f4555c666453d4c6aec55add663f5dc5e933ce595a629eed01818a9bed7
m31-append Cairo verifier_core/verifier     056b0f2c90758463c55e470282dc34ca53c42ac4d30aa82dc27610c2bb010df8
m31-append Cairo bridge/lib                 f76aaef4e17803b49b0b2d7e384c6436203f13bad5ab60047baba7f6719602fa
```

References for the mathematical acceptance boundary remain
[the frozen protocol](protocol.md), [prior source review](source-review.md),
and [independent theorem/compiler review](../m31-statement/end-to-end-protocol-review.md).
This report neither changes their security assumptions nor upgrades native
execution evidence into production, payment, or PROOF1 qualification.
