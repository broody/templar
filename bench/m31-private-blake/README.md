# Blake2s private-membership candidate

2026-09-22. The separately versioned Blake candidate works natively and in
Chrome WASM. This is a private leaf-preimage/depth-32 membership experiment,
not a complete payment or a private proof verified inside PROOF1.

The change replaces proof authentication and transcript SHAKE with full
Blake2s-256, uses 96-byte independent leaf salts and `TMPZK002`, and preserves
the application M31 Poseidon2 tree hash, AIR, masks, OOD checks, batching,
FRI and 120 independent query draws. The frozen
[SHAKE implementation](../m31-private-e2e/README.md) remains unchanged.

## Results

Three fresh randomized proofs per runtime, on the existing i9-10980XE/125GiB
development host. Native uses one thread. Different fixtures and transcript
queries mean this is a before/after observation, not a controlled CPU speedup
benchmark. Decimal MB denotes proof bytes; MiB denotes memory.

| Metric | Frozen SHAKE candidate | Blake candidate |
| --- | ---: | ---: |
| Native proving | 1.17–1.20 s | 0.98–1.03 s |
| Native peak RSS | 63–64 MiB | 52.7–54.5 MiB |
| Native verification | 0.163–0.173 s | 0.137–0.139 s |
| Native proof | 3.55–3.59 MB | 2.04–2.08 MB |
| Chrome WASM proving | 1.89–2.12 s | 1.71–1.92 s |
| WASM linear-memory high water | 79.94 MiB | 63.25 MiB |
| Browser proof | 3.59–3.63 MB | 2.026–2.054 MB |

The browser high water remains stable across three proofs. Whole-browser
sampled peaks are separately recorded: summed RSS 1,137,717,248 bytes and
PSS 464,080,896 bytes. Shared pages can be counted multiple times in summed
RSS. These are development-host samples, not a physical desktop or whole-wallet
qualification. The WASM binary uses SIMD, an 8MiB stack and a 2GiB memory maximum.

Evidence: [native report](results/native/report.json),
[browser report](results/browser/result.json),
[browser proofs checked natively](results/browser/native-crosscheck.json),
and [WASM build provenance](results/wasm-build/report.json).

## Checks and review

- Eight native unit tests pass on the final reviewed source, including the
  unchanged AIR/degree/fold checks and malicious invalid-trace proof rejection.
- Independent Python vectors cover all six full-byte RO domains, 16 transcript
  phases and 120 words per phase; the Rust tests check all of them.
- All six native/browser artifacts pass a separate native verifier receiving
  public input and proof only. The browser also accepts the native artifact.
- Ten external native negatives and twelve browser negatives reject; the
  native cases include changes to digest bits31/255, canonicality, public
  context, truncation, trailing bytes and old magic.
- Both verifiers reject the other format's actual retained proof:
  [version controls](results/native/version-rejections.json).
- The exact Cairo Blake component matches 21 full-output cases, including
  all six actual candidate domains, and rejects four invalid encodings:
  [Cairo parity](results/cairo-hash-parity/report.json). This is hash parity,
  not a Cairo implementation of the full private verifier.
- All twelve source/manifest/vector hashes match the independent
  [source review](source-review.md): [hash check](results/source-check.json).

The [parameter review](../m31-private-wrapper/blake-parameter-review.md)
approves this isolated research format. Its sharper fixed-block analysis gives
a single-proof ideal-RO privacy bound; it is not the old 768-bit hash bound.
Concrete hash/CSPRNG assumptions and the unfinished adaptive multi-proof
composition argument remain explicit. Passing tests does not establish privacy.

## Wrapper boundary and next work

The [Blake wrapper experiment](../m31-private-wrapper/README.md) produced and
independently verified genuine PROOF1 for a representative 954-compression
public hash batch. It checks the actual Cairo hash results, not a native
acceptance flag. It does not verify this complete membership proof.

The retained Blake proof needs 89,315 compression calls in the uncached
authentication loop, or 43,166 after sharing identical internal nodes.
Shared-node reuse has been counted and checked by an independent public-proof
inspector; it has not been added to the Rust verifier. The direct Cairo
implementation would require a Blake-G component larger than the preserved
outer configuration supports, even before AIR/FRI arithmetic.

Blake is therefore the useful candidate for further wrapper experiments,
but switching the hash alone does not finish the wrapper. Budget a dedicated
server verification circuit and its Cairo bridge, or reduce the AIR's wide
authenticated rows, before constructing the full direct Cairo port. Existing
recursive adapters still require the custom transcript and full-digest format
to be implemented; their reduced-M31 hash representation is not interchangeable.

## Reproduce

Build commands and environment are retained in `results/native/final-build.json`
and `results/wasm-build/report.json`. Native CLI syntax is unchanged:

```text
templar-private-membership fixture PUBLIC PRIVATE
templar-private-membership prove PUBLIC PRIVATE PROOF
templar-private-membership verify PUBLIC PROOF
```

`measure-native.py BINARY OUTPUT` makes fresh synthetic private data under an
ignored `target/` directory; only public input, proofs and measurement logs
belong in retained results. It uses separate client/verifier directories,
not a filesystem sandbox. `run-browser.mjs PKG PUBLIC PRIVATE NATIVE_PROOF
OUTPUT 3` runs the local Chrome experiment. Private fixture contents are not
retained in this directory. `SHA256SUMS` covers sources and retained evidence.
