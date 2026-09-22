# M0 polynomial masking: exact-algebra diagnostic

Recorded 2026-09-22. **Four deterministic fixtures pass the reviewed algebra
checks.** This is a local synthetic diagnostic, not a STARK proof, payment
prover, privacy-qualified server artifact or performance measurement.

The [specification](../../polynomial-masking-spec.md) maps polynomial witness
masking and an independent FRI randomizer to S-two's circle spaces. Its
[mathematical review](../../polynomial-masking-review.md) supports the bounded
honest-verifier oracle-view argument. The
[source review](../../polynomial-masking-algebra-review.md) approves the narrower
implemented algebra diagnostic conditional on successful execution. Astra
checked the successful K3 build/run and exact reviewed source hash; those
execution conditions are satisfied. Neither review approves a compiled private
proof.

## What passed

For each fixture, the private relation is `a[i] * b[i] = c[i]` on 256 rows,
with fixed public c. All computations use the pinned S-two M31/QM31 fields.

- Masks preserve every original trace value on all 256 rows. Exact polynomial
  division has zero remainder, with masked-input degrees at most 160 and
  quotient degree at most 192.
- The FFT representation and conjugate-pair quotient identities agree on all
  4,096 evaluation-domain points. The quotient normalization also agrees with
  S-two's PCS helper at every declared raw query.
- Two distinct witnesses for the same c admit mask translations that preserve
  the complete declared algebraic view, including all 512 coefficients of the
  randomized batch h. This is an exact distribution-coupling diagnostic; the
  coupling procedure is not honest online prover code.
- A separate simulator takes public c and supplied verifier coins, with no
  private a/b argument, and produces a view accepted by the algebra checker.
  Finite test success is not the distributional proof; that argument is in the
  mathematical review.
- Five negative assertions pass per fixture: altered c is rejected by both
  the view identity and divisibility check; insufficient FFT capacity fails
  domain agreement; altered quotient OOD claim and altered R opening are
  rejected. These span four mutation families, not five cryptographic attacks.

Fixtures 0–2 have 23 distinct raw queries plus four OOD coordinates. Fixture 3
forces a duplicate query, leaving 22 distinct queries plus four coordinates.
The [summary](summary.json) contains counts and success flags, without private
polynomials or field arrays. Fixed seeds make these synthetic fixtures
reproducible; they must never supply randomness for a real prover.

## Reproduce and provenance

From the repository root, with the existing pinned local dependency checkouts:

```sh
CARGO_BUILD_JOBS=4 cargo +nightly-2026-01-15 build --release --locked --offline --manifest-path bench/m31-statement/client/Cargo.toml --bin masking_diagnostic
RAYON_NUM_THREADS=1 bench/m31-statement/client/target/release/masking_diagnostic
```

Kimi K3 ran the bounded build and execution; Astra owns implementation and
integration. Both exited zero. Source, manifest, lockfile, executable and
artifact hashes are recorded in [report.json](report.json). The reviewed source
SHA-256 is `9c52f46f3fdef89437ddaa1cabd0bcd69b2cd2dcf2c9992117cfcf067fd78495`.
After that build, Astra added only `package.default-run` to preserve the
original CLI's `cargo run` selection now that a second binary exists; a locked,
offline metadata check and final manifest hash are in
[integration.json](integration.json). No dependency or source changed afterward.
See [build.log](build.log) and [run.log](run.log). The build's dead-code warning
concerns the existing `check_sponge` helper. An earlier build caught field
embedding/exponent API mismatches; corrected source passed this recorded run.

No FRI execution, Merkle commitments, Fiat–Shamir transcript or proof serializer
is implemented here. Complete soundness, concrete security bounds, compiled
transcript privacy, private lookups, R0 and actual PROOF1 wrapping remain open.
The checker is an internal algebra diagnostic, not a parser for adversarial
wire inputs. No RSS/time benchmark was taken, and these results do not predict
the memory of a complete private payment prover. See the
[remaining gates](../../polynomial-masking-plan.md).
