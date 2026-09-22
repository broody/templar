# Blake candidate source review

2026-09-22. **GO for this separately versioned research source, subject to
final-hash execution evidence.** No implementation blocker was found. This
bounded independent Math Reviewer pass compares the candidate against the
frozen SHAKE client and the approved
[Blake parameter review](../m31-private-wrapper/blake-parameter-review.md)
(SHA-256 `2875634cd783044a27fe4da60d48e2f4320b6976375a86a888261a7b5fabe240`).
It applies the existing STWO soundness checklist without reopening the original
algebraic review. No tests/builds were run, private fixtures accessed,
implementation changed, or work delegated. Only this report was written.

## Correspondence and findings

`crypto.rs` uses ordinary unkeyed `Blake2s256`, retaining its complete 32-byte
digest. The prefix is exactly `Templar-private-membership-BLAKE2S-v1`.
The six existing domains and little-endian length/part framing are unchanged.
`HASH=32` and `SALT=96` govern generation, authentication paths, leaf opening
and parsing consistently. Application-level salts remain independent fresh
random bytes for every leaf, including direct-message trees.

Digests, roots, sigma and siblings remain byte arrays throughout; none is
converted into M31 or a Starknet felt. Merkle comparison checks all 32 bytes,
including bits 31 and 255. The only high-bit masking is the unchanged explicit
interpretation of transcript words as sampled field candidates. Fixed-width
field payloads retain canonical M31 validation independently of digest bytes.

`TMPZK002` is checked before root parsing. The public transcript uses the same
new magic and hashes the candidate source files, giving an independently bound
circuit fingerprint. The old verifier and source hashes remain unchanged.
Final sigma now reads `crypto::HASH` bytes; searches found no stale 96/192-byte
digest/parser assumption. Remaining 192 references describe the Stark-field
bound, and 96 denotes the approved salt length. Checked offsets, the 16MiB input
cap, fixed verifier-owned dimensions and trailing-byte rejection are preserved.

Coin buffers and refill conditions derive from `HASH`. Each block contains
eight little-endian words and has its own incrementing framed index; 120 words
therefore consume 15 distinct blocks. Counters cannot approach overflow under
the fixed field/OOD rejection budgets. Phase binding, commitment order,
all-oracles-before-queries scheduling and deduplication are unchanged.

AIR, application Poseidon2 constants/hash, masking and polynomial code, and
native CLI are byte-identical to the frozen client. The proof implementation
diff consists only of magic and sigma width. Thus the approved degrees,
four-coordinate unsplit Q, both OOD samples, positive-power batching,
first-FRI equality and all 120-query fold checks are preserved. Native/WASM
entry points still use OsRng; the public prover retains `CryptoRng` and its
freshness contract. The lockfile only removes SHA3/Keccak, makes the already
locked Blake2 dependency direct, and updates the package version to 0.2.0.

The new vector file identifies Python `hashlib.blake2s` as its independent
source. Read-only inspection confirms six full-output domain cases and 16
transcript phases, each containing 120 expected words. The test compares all
digest bytes, sigma and all those words, including repeated stream creation.
I did not recompute the vectors. Existing semantic/negative tests remain;
mutation offsets now derive from `HASH`, and a new root-bit-31 mutation is
checked. No test is interpreted as proving privacy.

## Execution gate and limits

Before accepting candidate artifacts, root must record final-hash native tests
and separate-process valid/invalid proof verification, unchanged semantic
mutations, canonical/truncated/trailing-byte rejection, actual old-format
rejection, and root mutations at both bits 31 and 255. Require WASM/native
cross-runtime parity for that target, with fresh randomness and exact binary,
source and artifact provenance. Root may discharge these conditions without
another specialist review if the audited source remains unchanged.

The approved 256-bit ideal-RO compiler analysis and its finite/adaptive-use
limits apply; the former 768-bit bound does not carry over. This is research
source approval, not production or PROOF1 membership qualification. The
separately approved public Blake component and 954-compression PROOF1 cost batch
do not implement the full private wrapper. Its recorded fixed trace-capacity
gate remains unresolved.

## Audited SHA-256 manifest

Paths are relative to `bench/m31-private-blake/client/`.

```text
src/air.rs       aa0adfcdad4405dddc1d0e43ab3b942fa26e445ab3590a2ee2dcdbaa55db64f6
src/constants.rs 46ea8e2ffb0149af567fd09622d3ddfc73ce08f6c7f3f64ef3960f929ce064f3
src/crypto.rs    3ad0c0f0d782441b3b0876da9e1b27ca16a35beff7ee8c9b8fbae6166a9295a9
src/hash.rs      fdffbfcc63170def2dd98a7663bd60b272c9f667e31f35b02b0e15f6df03914c
src/lib.rs       74f72ec637648d1763429cd3f23ac07eec040b7c60458e908b546eeff7c70d5b
src/main.rs      42cb5699427f67481f021e87bd94d11f4354f11214ceb054fd9132a74f0ab45c
src/poly.rs      add368607576f12f582a69937495ce2ebe8c983fb094c74b19f738a69b86bbb7
src/proof.rs     592598493876793e4a0540eec3cbc5cfced4416c1895597631ac5250277b482a
Cargo.toml       a108c5530a98e4884a264554c9ffd2c4f1f2f6e4368365f63dfec815268f9c22
Cargo.lock       6ddb841af1dc5b67eeb46d1dd2681cc96d0f1369e1d3a43b4a40a8a9cfecfa89
blake-vectors.json c589b6791265e004d34139afe3c491cd6d000b3558bb11793381cf018d117353
golden-vectors.json 4c461658f5d4e23cdfdc3ed7a79e7a2fdac33d4d1346f7a31151ce595867920e
```
