# Direct felt252/Poseidon membership experiment

Status: completed bounded pathfinding milestone, 2026-09-21. This is a synthetic,
validity-only performance experiment.
It does not establish witness privacy, a payment proof, browser suitability,
PROOF1 compatibility, or a change to Templar's accepted architecture.

## Outcome

The exact felt252/Poseidon membership arithmetic proves and verifies without
Cairo CPU execution. Both paths use depth 32. Existing coefficient-backed
storage and 16-column FRI batching reduce peak RSS from **4.28 to 1.97 GiB**,
with byte-identical proof envelopes and unchanged security settings.

The **2 GiB cap is unreliable**: the bounded mode passed once, then was
OOM-killed on a fresh repeat. Three fresh bounded runs pass a **3 GiB cap with
zero swap**, taking **14.08–14.14 seconds** including the measurement harness;
the matched baseline takes 8.67 seconds. This is approximately 54% less RSS
and 63% longer elapsed time. The failure means that a 1.97 GiB successful
sample must not be advertised as a reliable 2 GiB budget.

All eight completed proofs match byte-for-byte. Three unit tests pass; the
native verifier rejects 13 altered-proof/statement cases and all three lookup
boundary controls. The STARK is 258,621 binary bytes; the complete public
envelope is 334,307 bytes. See [measurements](results/measurements.md), the
[review](review.md), and [component inventory](component-inventory.md).

**Decision:** do not expand this implementation into a full private payment
prover yet. There is no substantial headroom below 2 GiB, and the client privacy
route is not qualified. The remaining memory work should target fixed
range-check tables and simultaneous trace expansion before adding payment
features. This result does not establish a lower bound for a redesigned AIR.

The measured relation is two depth-32 binary Merkle paths, using exactly the
existing felt252 `poseidon_hash_span([left, right])` format. Each parent hash
requires two Hades permutations, including even-length sponge finalization:
64 parent hashes and 128 permutations total. Test indices exercise both child
orders throughout the tree. All fixture data is public and synthetic.

Reuse the pinned Cairo prover's felt252 Poseidon components while excluding the
Cairo CPU and virtual OS. The bounded implementation uses a **public-transcript
membership statement**: native verification checks canonical values, pair
padding, path chaining, child selection, leaf/index/root binding, then derives
the public permutation/memory lookup boundary itself. The STARK proves all 128
permutations with the original AIR. The verifier must bind the transcript before
sampling challenges, check every lookup balance, and reject transcript changes
with an unchanged proof; it must not trust a prover-supplied expected boundary.

This is useful membership arithmetic/cost evidence, but its paths and
intermediate states are public. A private payment proof would also need to
constrain that bookkeeping over hidden values. This experiment does not supply
those hidden-path constraints or estimate a privacy wrapper's total cost.

## Scope and decision

- Measure preprocessing, witness generation, proving and native verification
  in a fresh process under a one-thread cgroup cap with zero swap. Record phase
  times and the whole-process peak, proof size, component dimensions, security
  parameters and source/build identities. Build separately from timed runs.
- Compare valid outputs against the existing Python and independent Rust
  felt252/Poseidon references, and require rejection of altered membership data
  and proofs. Keep existing security settings; do not tune them down for memory.
- A small validity-only result is preliminary cost evidence. It is not the
  complete private client footprint, and a privacy wrapper may add substantial
  cost. A design-level review of supported privacy routes is separate; further
  disclosure/recovery diagnostics remain deferred.
- Substantial headroom below 2 GiB warrants a later complete 2-in/2-out prototype
  only alongside a credible reviewed client privacy route. The current payment
  prover remains the working reference. Sepolia deployment is not part of this
  experiment.

`environment.json` identifies the dependencies and earlier accepted artifacts.
Preserve the previous `bench/direct-air` archive unchanged. New work belongs
here and in `target/poseidon-membership`.

## Reproduction

The standalone client crate is described in [client/README.md](client/README.md).
Its baseline source is preserved in `baseline-client/`. The optional
`--bounded-columns=16` changes storage only, using the existing reviewed library
API before the first commitment. Dependency sources remain unchanged. Source
manifests and build/test commands are archived under `results/`.

Run a fresh bounded process from the repository root (choose a fresh run name):

```sh
python3 bench/poseidon-membership/measure.py --name bounded-demo --cap-gib 3 --threads 1 \
  --scope 'Public synthetic membership; no private wallet qualification' -- \
  "$PWD/target/poseidon-membership/client-target/release/templar-poseidon-membership" \
  "$PWD/bench/poseidon-membership/fixtures/two-paths.json" \
  "$PWD/bench/poseidon-membership/results/bounded-demo/proof" --bounded-columns=16
```

The Rust build uses the pinned nightly with `target-cpu=native`; this does not
qualify portable CPU or browser behavior. Builds and timed processes must not
overlap. All path values and intermediate states are public synthetic data.
