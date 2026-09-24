# Private M31 membership end to end

**Membership milestone passed, 2026-09-22.** Native proving takes 1.17–1.20 s
at 63–64 MiB peak RSS. Three proofs in one Chrome worker take 1.89–2.12 s,
with WASM linear memory holding at 79.94 MiB. All six proofs pass the separate
native verifier; the browser also accepts a native proof. See the
[measurements and acceptance record](results/README.md).

This isolated experiment proves knowledge of a secret leaf preimage and its
depth-32 M31 Merkle path. The verifier receives the public chain, pool and root,
plus the proof. It has no witness input. This is the first complete private
membership proof in this pathfinding track with the reviewed construction and
retained execution evidence.

The relation contains 65 active Poseidon2 permutations in a 128-row AIR, with
1,191 columns and 1,273 constraints. The leaf is an experimental nine-word
preimage commitment. Amounts, ownership derivation, nullifiers, conservation,
outputs, encrypted delivery, controlled notes and ReturnNotes are outside this
relation. It is not an ordinary payment benchmark.

## Construction and review

This is a custom proof protocol built with S-two's fields, circle FFTs and CPU
FRI folds. It is not the stock S-two `StarkProof` format. It adds full polynomial
masking, an independent random batching polynomial, salted private Merkle
commitments and a BCS transcript covering every oracle message.

The frozen [protocol](protocol.md), independent
[theorem review](../m31-statement/end-to-end-protocol-review.md) and
[source review](source-review.md) specify the assumptions and exact source
identity. The review supports the isolated research milestone under the stated
classical explicitly programmable random-oracle and CSPRNG assumptions, with a
96-bit classical RO-work target. This is neither a 128-bit security claim nor
a production cryptographic audit. Tests establish implementation behavior;
they do not themselves prove zero knowledge.

Every proof uses fresh masks, batching randomness and 1,536-bit leaf salts.
The native CLI and browser exports use `OsRng`. Rust callers of `prove` must
supply a cryptographic RNG with fresh independent state; resetting or cloning
the same seeded RNG across proofs violates the contract. Deterministic seeds
are confined to synthetic unit tests.

## Server boundary

A standalone Rust verifier is implemented. The current recursive adapter is
[not directly compatible](wrapper-compatibility.md). Its hash, transcript,
sample layout and composition format differ. No PROOF1 artifact or Starknet
payment has been generated from this private proof.

The next architecture gate is to implement and measure the verifier inside an
actual server proving route. That result should precede a production format
commitment. Server wrapping and a complete private payment relation are both
required before claiming the intended wallet architecture works end to end.

## Reproduce native behavior

Run from the repository root, with the existing S-two dependency snapshot at
`target/m31-append/stwo`. The lockfile pins registry dependencies; the source
review records the critical S-two semantic hashes. The dependency directory
is an extracted snapshot, not a separate Git checkout.

```sh
CARGO_BUILD_JOBS=4 RAYON_NUM_THREADS=1 cargo +nightly-2026-01-15 test \
  --release --locked --offline --manifest-path bench/m31-private-e2e/client/Cargo.toml \
  --lib -- --test-threads=1
CARGO_BUILD_JOBS=4 cargo +nightly-2026-01-15 build --release --locked --offline \
  --manifest-path bench/m31-private-e2e/client/Cargo.toml --bin templar-private-membership
```

The binary is
`bench/m31-private-e2e/client/target/release/templar-private-membership`:

```text
fixture PUBLIC PRIVATE
prove PUBLIC PRIVATE PROOF
verify PUBLIC PROOF
```

Output paths must not exist. `fixture` creates synthetic data and a mode-0600
private file on Unix. Run proving with `/usr/bin/time -v`, then copy only PUBLIC
and PROOF to a separate directory and launch `verify` there. The process has no
witness argument and does not read a witness; this test is not an OS-level
filesystem access sandbox. Keep fixture generation and compilation outside
timed runs. Proofs of the same statement are randomized and should differ.

The seven unit tests cover independent hash/sponge vectors, AIR wiring,
context/field canonicality, exact degree tails, direct quotient identities,
fast/scalar batching, every actual FRI fold, fresh proof roundtrips, transcript
and artifact mutations, and an invalid trace whose prover deliberately bypasses
both honest trace and OOD checks before verifier rejection.

## Browser harness

`run-browser.mjs` loads the built web package into one Chrome worker, accepts a
native proof, creates three fresh browser proofs, verifies them, rejects changed
root/tampered/truncated/trailing-byte variants, and saves only the proofs and
measurements. A separate native process must also accept each browser proof.
The synthetic fixture is served on loopback only. The private JSON is never
included in saved reports or uploaded to another machine.

```text
node bench/m31-private-e2e/run-browser.mjs PKG PUBLIC PRIVATE NATIVE_PROOF OUTPUT 3
```

The output directory must be new. This reuses the installed Playwright tooling
at `target/wasm-membership/browser-tools` and `/usr/bin/google-chrome`. WASM
linear-memory high-water size and sampled browser process RSS/PSS are distinct
metrics. All runs on the development workstation remain separate from physical
consumer-device qualification.
