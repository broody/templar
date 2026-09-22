# Private membership source review

2026-09-22. **Source GO for the isolated native research milestone**, conditional
on the execution gate below. No unresolved implementation blocker was found in
the frozen sources recorded here. This is the independent Math Reviewer's
post-implementation review under the nested STWO soundness checklist and
zk-stark-foundations guidance. Only this report was written; no implementation,
build, test, benchmark or delegation was performed by the reviewer.

The approved [protocol](protocol.md) and
[theorem/compiler review](../m31-statement/end-to-end-protocol-review.md) remain
the security basis. This source verdict does not strengthen their explicit
programmable classical ROM/CSPRNG assumptions, turn the work bound into a
fixed failure probability, or approve production/payment/PROOF1 use.

## Protocol correspondence

**AIR and extracted witness.** `air.rs:108` enumerates 1,273 constraints over
1,191 columns. The permutation trace resets intermediate states after each
round's equations, keeping private degree quadratic. Leaf framing, node levels,
conditional left/right order, first-row carry, second-row copied path data and
capacity, boolean directions, final root and padding inputs are constrained.
Rows 0 through 64 implement the specified preimage and 32 membership steps.
Unconstrained auxiliary padding values do not enter the extracted path. No
lookup or hidden claimed sum is introduced. Constants and golden-vector files
are byte-identical to the append benchmark references.

**Spaces and composition.** `poly.rs:64` explicitly maps cyclic H rows into
the bit-reversed circle evaluation order. Rotation uses H's negative step.
`mask` samples all 256 FFT coefficients plus the independent canonical256
zerofier direction, hence full L256, and multiplies by ZH. Honest masked
degree is at most192; selector-controlled quadratic equations have degree at
most448; four unsplit F-valued quotients have degree at most384. All fit
strictly in capacity1024. Alpha powers are expanded into F coefficients
before combining constraints; extension evaluations are never mistaken for
those coefficients. `check_ood` checks all four quotient identities.

**DEEP and FRI.** The normalized pair uses the pinned line coefficients,
explicit CM31 embedding and QM31 outer conjugation, which is the p²
involution. Public OOD exclusions prevent its degenerate lines and query
poles. Base raw values and both DEEP claims bind the same column. Batch order
is R with coefficient1, then 3,581 distinct positive powers; the fast formula
only collects common denominators. The verifier reconstructs the scalar batch
and checks equality against authenticated first-layer values. Every one of
ten folds and the final constant is checked. Its sparse formula matches the
pinned CPU's unnormalized factor-two circle/line folds and domain progression.
No proof-supplied degree or FRI parameter is trusted.

**Compiled transcript and observations.** Fifteen distinct tree IDs cover
base, Q, claims, R, ten FRI layers and final constant. Every leaf, including
the two single-leaf messages, gets a fresh 1,536-bit salt. SHAKE256 produces
96-byte outputs with injective length framing and separate leaf, node,
public, state and coin domains. The phase/indexed coin stream follows the
approved BCS schedule. All roots enter sigma before the 120 uniform query
draws; claims are authenticated and committed before lambda. Final sigma is
recomputed. Deduplication changes authentication volume, not the draw event.

The actual disclosures are precisely claims, trace(P,TP), Q(P), R(P), FRI
pairs/final value, and salted authentication material. Q(TP) is never opened,
and FRI leaves contain no raw witness columns. Thus the at-most248-point
closure and the joint whole-h/R simulation from the protocol review apply.
Canonical field words occupy four serialized bytes rather than packed31 bits;
this does not alter their values or exceed the reviewed 2^30-bit oracle cap.

**Parser, randomness and external boundary.** All proof dimensions and query
locations are verifier-owned. Reads use checked offsets, reject noncanonical
M31 words, enforce the 16MiB cap and reject trailing bytes. Context comparison
implements nonzero canonical lowercase hex, full Stark-field chain range and
the separate pool bound. Public input is validated and bound with the circuit
source fingerprint. Native file reads are bounded. CLI output contains the
proof/public metadata or timing/size; fixture secrets go only to the explicitly
named private file, created with mode0600 on Unix. The verifier takes no
witness input. Public `prove` now requires `CryptoRng` and documents fresh
independent state; CLI and WASM entry points use OsRng. Seeded fixtures remain
tests only. Masks/R use unbiased range sampling; transcript field and OOD
rejection have fixed public budgets and local aborts.

## Review fixes and execution gate

Integrated fixes: explicit RNG contract; ten sponge-vector assertions;
fast/scalar batch checks at eight spread D points; exact non-tautological
coefficient-tail checks for all masked columns and Qs; and direct AIR/ZH
checks on D, separate from quotient construction. The pinned FFT basis has
degree floor((i+1)/2) at coefficient i, justifying tails385 and769.

I read pass1's report and pass2's 7/7 test log. Those precede the final RNG
and degree assertions and are **not final-hash execution evidence**. Before
qualifying retained proof artifacts, require:

1. Final-hash locked native build and all seven tests pass, including the
   malicious trace that bypasses both honest trace and OOD gates and is then
   rejected by the verifier.
2. Fresh-OsRng proof acceptance by a separate native verifier process with no
   witness file present; changed public statement and malformed/tampered
   artifact rejection, with exact source/binary/artifact provenance.
3. Requested full-relation timing, peak memory and proof size are collected
   only after correctness succeeds. WASM execution is a separate result.

Root may discharge these conditions from K3's results without another review
if the frozen sources stay unchanged. Existing
[wrapper incompatibility](wrapper-compatibility.md) remains in force.

## Audited SHA-256 manifest

Paths below are relative to `bench/m31-private-e2e/client/`.

```text
src/air.rs       aa0adfcdad4405dddc1d0e43ab3b942fa26e445ab3590a2ee2dcdbaa55db64f6
src/constants.rs 46ea8e2ffb0149af567fd09622d3ddfc73ce08f6c7f3f64ef3960f929ce064f3
src/crypto.rs    d357c7b4f02d54e619e3b10fd36c85cf971574e993055536f4a65d60a767dca2
src/hash.rs      fdffbfcc63170def2dd98a7663bd60b272c9f667e31f35b02b0e15f6df03914c
src/lib.rs       9bf78080317654e8894a5b1d18915cdcce0e887dd1d3c588b59cfb78da5d91b7
src/main.rs      42cb5699427f67481f021e87bd94d11f4354f11214ceb054fd9132a74f0ab45c
src/poly.rs      add368607576f12f582a69937495ce2ebe8c983fb094c74b19f738a69b86bbb7
src/proof.rs     9b461c574a62296540b2b80f68b07868b2e9e4435106a46d508e40018626e2f5
Cargo.toml       4620086f5bfa31f081742d490354647eef8fec6db8c1dfb7d12711e886db7114
Cargo.lock       64310f2d59d9b18ddeee9792990746498e5d6c3b1e63acba4985a0d7ab61f3ea
golden-vectors.json 4c461658f5d4e23cdfdc3ed7a79e7a2fdac33d4d1346f7a31151ce595867920e
```

Pinned upstream semantic anchors under `target/m31-append/stwo/crates/stwo/src/`:

```text
core/constraints.rs          90ccce4db3839ac519a53367462b6f788ad4053b1799a59bab3f34705532854b
prover/backend/cpu/fri.rs    4d40c7ec631fad610db25083a0b17699503c80abd105b15c3a5784e72d3a44a6
prover/backend/cpu/circle.rs 89167682b3c217c5b6954c566e0112967f4508a6b9878edb35e0d58c540e27d1
```
