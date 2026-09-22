# Context binding repair — transcript version 2

Recorded 2026-09-22. **The public benchmark's context-binding bug is fixed.**
This does not implement private payment semantics, establish hiding, or
demonstrate PROOF1 compatibility.

The old encoder advanced by 32 bits but kept only 28, discarding seven groups
of four bits. A fresh build of the original source reproduced acceptance of
two different contexts with exactly the same cryptographic proof suffix:

| Mutation | Version-1 verifier | Repaired version-2 verifier |
| --- | --- | --- |
| Chain `0x434841494e` → `0x435841494e` | Accepted | Rejected |
| Pool `0x456` → `0x10000456` | Accepted | Rejected |

Each row was tested against the corresponding version's own fresh proof.
The mutation changed only the bincode context string/length framing; the
remaining bytes were identical. Both new rejections are ordinary verifier
errors (`interaction PoW`, exit 1), not crashes, timeouts or parser failures.
The in-process mutation checks also establish that the changed contexts are
semantically valid and produce different transcript words.

## Change and compatibility

The encoder now extracts nine consecutive 28-bit limbs, matching the append
experiment. Context strings must use canonical hexadecimal notation. Chain IDs
are nonzero field elements; pool addresses separately satisfy
`0 < pool < 2^251 - 256`. The misleading bit-255 guard is removed.

The verifier fixes the benchmark transcript version at 2, and new summaries
record that version. There is no legacy fallback. Envelope serialization is
unchanged, so an old proof may deserialize but fails cryptographic verification.
The preserved [version-1 proof](baseline-proof.bin), previously accepted by the
fresh baseline binary, was rejected by the repaired verifier. This is a
benchmark compatibility break, not a change to deployed pool formats.

## Validation and review

- **5 unit tests passed:** independent Plonky3 vectors, permutation AIR
  constraints/witness, full-field radix reconstruction, canonical parser
  rejection, and distinct chain/pool bounds. Reconstruction covers every bit
  0–251, radix boundaries, field maximum and deterministic varied inputs.
- A fresh [version-2 proof](v2-proof.bin) verified natively.
- **72 mutation cases rejected:** the existing 16 and all 28 formerly dropped
  bit positions in each of chain and pool. The existing omitted-padding
  control passed on this 132-request fixture.
- Both explicit context changes above rejected on the fresh V2 proof, and the
  actual preserved V1 proof rejected under V2.
- The missing golden-vector fixture required by the pre-existing unit test was
  restored byte-for-byte from `m31-append`; SHA-256
  `4c461658f5d4e23cdfdc3ed7a79e7a2fdac33d4d1346f7a31151ce595867920e`.

The independent [pre-review](pre-review.md) and [post-review](post-review.md)
cover this repair only. Astra checked the execution evidence against the exact
source hashes in the post-review and found all its conditions satisfied. Kimi
K3 performed the bounded builds and executions in one reused session. Source,
binary and artifact hashes are in [summary.json](summary.json); detailed
rejection names are in [negative-tests.json](negative-tests.json).

From the repository root, rebuild/test with:

```sh
CARGO_BUILD_JOBS=4 RAYON_NUM_THREADS=1 cargo +nightly-2026-01-15 test --release --locked --offline --manifest-path bench/m31-statement/client/Cargo.toml --lib -- --test-threads=1
CARGO_BUILD_JOBS=4 RAYON_NUM_THREADS=1 cargo +nightly-2026-01-15 build --release --locked --offline --manifest-path bench/m31-statement/client/Cargo.toml
```

The CLI's `--verify-tests` accepts the saved V2 proof. Generating another proof
uses the saved [synthetic fixture](fixture.json) and a fresh output directory.
The same CLI's `--verify` must reject the saved V1 proof. The pinned local
dependency checkouts are still required by this experiment's Cargo manifest.

No heavy benchmark or new memory qualification was run. Proof byte lengths may
differ after transcript changes and are not evidence of a performance gain.
The outstanding private-relation and hiding requirements remain in the
[privacy contract](../../privacy-contract.md) and
[review intake](../../hiding-review-status.md).
