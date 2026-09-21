# Native spend capacity: native-counted-shapes

This is synthetic native PROOF1 pathfinding, separate from the funded
[controlled push lifecycle](../controlled-push-e2e/README.md). It evaluates whether
4/4/2 is an inherent proving limit. It does not change any deployed pool verifier,
move pool tokens, or establish acceptance of larger funded spends.

The statement and transition hashes process only active entries, with explicit counts and fixed-width legs. The same program still enforces maxima of 64 inputs, 64 outputs and 32 withdrawals. No unused slots or ambiguous trailing witness are accepted.

A new statement account is declared/deployed through sncast on Sepolia. It uses
the same pinned, unmodified native V1 prover, local verifier, four CPU cores,
16 GiB process cap and zero swap as the controlled run. Each case starts a fresh
prover process. Synthetic notes form their own Merkle root; that root is not a
funded root in the live pool, so these proofs must not be submitted as pool spends.

Cases include 1/2/0, 4/4/2, 8/8/4, 16/16/8, 32/32/16, 64/64/32,
32-input consolidation and a 32-output payment. All cases use the controlled
statement's transition checks. The pool's signature verification and settlement
are outside this measurement. Local verification checks the proof and exact
expected public message. Two further executions must reject an over-cap count
and the prior protocol version.

Request time includes virtual execution and RPC reads. Proof generation time,
virtual OS steps, peak RSS, cgroup memory and proof bytes are recorded separately.
Each result is one run, not a distribution or physical desktop qualification.
An OOM result is an enforced resource failure, not an invalid ownership proof
or evidence of a cryptographic note-count ceiling. The local verifier runs
separately and is excluded from the prover RSS.

## Reproduction

Use the pinned dependencies from the controlled experiment. The runtime pointer
and manifest select a dedicated private runtime. `deploy.py` declares/deploys
only the benchmark statement, `bench.py` runs the sequential sweep, and
`report.py` archives allowlisted proofs, logs, receipts and measurements. Requests
with synthetic note openings remain in the runtime. Never point this experiment
at the controlled lifecycle's runtime or change its pool verifier.

Results are in [measurements](results/measurements.md),
[summary](results/summary.json), and [evidence](results/evidence.json).
The project-level [review](../../docs/native-shape-review.md) compares both
encodings and records what is still needed before changing a product limit.
