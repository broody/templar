# Next experiment: polynomial masking for the M31 client

2026-09-22. **The M0 mapping and isolated algebra diagnostic have passed
mathematical/source review and scoped execution checks.**
The [M0 review](polynomial-masking-review.md) approves only local algebra and
honest-verifier bounded-query diagnostics. It does not approve a compiled
private proof. The [independent gamma review](hiding-review.md)
closes gamma's current qualification attempt with a no-go. Preserve its source
and measurements as public-arithmetic research; do not increase its padding
budget or run more rank sweeps as a substitute for a hiding argument.

The question to resolve next is narrow: **can a complete, literature-backed
zero-knowledge protocol be mapped to the pinned S-two circle polynomial and
lookup pipeline with a bounded implementation scope?** The M31 arithmetic
results remain useful, but they do not answer this question or predict the
memory of the resulting private prover.

The [candidate specification](polynomial-masking-spec.md) now pins a toy
256-row private vector-product relation, full-circle witness masks, an unsplit
quotient and an independent FRI randomizer. The
[source-reviewed diagnostic](polynomial-masking-algebra-review.md) checks exact
algebra using the pinned S-two field, FFT and PCS primitives. It does not
execute FRI, commit or serialize a proof, or establish soundness. All four
deterministic fixtures passed; see the
[execution evidence](results/polynomial-masking-algebra/README.md). FRI,
soundness and compilation remain open, alongside the compiled-transcript
privacy argument.

Implementation baseline ([masking API inventory](masking-api-inventory.md),
2026-09-22): no ready-made random-polynomial masking or independent FRI-mask
mechanism was found in the searched pinned stwo paths; the generic circuit
`add_zk_blinding` helper appends random *valid* rows (a different mechanism),
and the measured compact-recursion M0 does not invoke it.
The PCS can accept caller-provided polynomial coefficients, but the constraint
framework couples trace degree bounds to the constraint-domain size. The first
mapping must explain how masking slack changes that contract and its verifier.

## 1. Specify the construction before choosing a mask budget

The starting references are [Circle STARKs §5.4](https://eprint.iacr.org/2024/278.pdf)
and Haböck–Al Kindi's
[A note on adding zero-knowledge to STARK](https://eprint.iacr.org/2024/1037.pdf),
2025-02-20 revision, §§2–4. The former calls for randomized trace encoding and
randomized FRI. The latter analyzes polynomial witness randomization, a
separate FRI mask, and quotient components. Neither reference automatically
qualifies our implementation: the ordinary univariate construction must be
mapped to the actual circle spaces and compiled proof transcript.

Conceptually, witness randomization adds a random polynomial times a zerofier
of the constraint domain. This preserves trace values on that domain while
adding freedom elsewhere. Unlike valid random permutation rows, these mask
coefficients are not constrained to the permutation's internal row manifold.
This is a design direction, not a proof that a particular masking formula,
degree budget or FRI change is sufficient.

Produce one reviewable specification with these deliverables:

| Deliverable | Required content |
| --- | --- |
| Polynomial spaces | Exact circle trace space, constraint domain and zerofier; mask sampling distribution and dimension; allowed shifts; public/preprocessed versus private columns. Account for circle FFT-space conventions explicitly. |
| Degree accounting | Bounds before and after masking for trace, shifted interaction and composition polynomials, quotient splitting, DEEP quotients, FRI and last layer. Distinguish constraint-domain size from polynomial degree and commitment-domain size. |
| Full hiding protocol | Every commitment, challenge, claimed sum, OOD opening, query opening, FRI message and exceptional event in order; randomizer independence and refresh policy. Map each step to a proved hypothesis, or mark the missing lemma. |
| Private lookups | Balance requests inside constraints; account for intermediate claimed sums and component boundaries. Specify how any exposed sums are simulatable. The present host reconstruction of private requests cannot survive this conversion. |
| Security argument | Simulator for the same real public statement, with no witness; full joint transcript, auxiliary data, repeated proofs, Fiat–Shamir and commitment assumptions. Keep completeness and soundness accounting separate from hiding. |
| Implementation map | Exact pinned source interfaces that must change, proof-format/version changes, native verifier changes and recursive-verifier implications. A changed inner protocol must later be verified by the actual wrapper. |

Use the [R0 privacy contract](privacy-contract.md) as the eventual application
boundary and the [observation inventory](server-observation-inventory.md) to
avoid omitting existing messages. Do not pick a mask size from the old 96-channel
rank surrogate or treat a count of observed coordinates as a complete theorem.
Do not weaken soundness parameters to offset extra masking cost.

**Specification pass:** an independent reviewer accepts the mapping, including
all required lemmas and the implementation scope, for a bounded prototype.
**Specification fail:** a central simulation, circle-space or lookup argument
remains conjectural. Record that precise gap and reconsider the prover route;
do not proceed by labeling the assumption standard or by measuring more pads.

## 2. Small implementation gate, only after specification approval

Start with an isolated toy relation that privately computes a public value
using nonlinear arithmetic. Its verifier must take only public inputs, proof
bytes and trusted parameters. It is deliberately not a payment benchmark.
This stage exercises polynomial randomization and the complete ZK low-degree
protocol without adding the payment's hash/range/lookup complexity at once.

Acceptance requires the approved degree/domain identities, honest-proof
verification, rejection of invalid witness constraints and altered public
inputs, exact proof-format parsing, and agreement between prover and verifier
transcript traces. Include tests that bypass honest host witness validation.
Small-field enumeration may check a specifically stated algebraic lemma; a
statistical test or failed witness-recovery attempt cannot qualify ZK.

Next add a minimal **private two-component lookup** and its exposed-sum policy.
Review that change before extending to real Poseidon2 and R0. This isolates the
lookup issue identified in the gamma review instead of rediscovering it after
building a full payment circuit.

## 3. Payment and measurement gates

After those gates, implement the complete R0 ordinary 2-in/2-out relation:
ownership, arbitrary depth-32 paths, nullifiers, both outputs, bounded integer
conservation and public binding. Measure only after this relation and its
hiding integration pass review and meaningful negative tests.

Record client and wrapper separately. Client measurements must include fresh
randomness generation, the complete private relation, all proof stages and
serialization. Report native single-thread peak RSS, time and proof size,
followed by a WASM build and browser memory/time measurements. Retain the
sub-2-GiB engineering target, but make no memory forecast from the existing
11-MiB/48-MiB public fixtures.

The actual M31-to-unchanged-PROOF1 round trip remains an independent gate. A
compatible public-only wrapper experiment can proceed separately when useful;
neither successful recursion nor server-side masking can repair a client
artifact that already discloses its witness.

## Ownership and stop conditions

Astra owns protocol mapping, implementation decisions and integration. Reuse
the frontier math reviewer at the completed specification milestone and after
soundness-sensitive implementation. K3 handles bounded source inventory and,
once approved, routine builds, tests and measurements. Leave Cairo performance
and bounded-PCS specialists idle until a specific measured blocker needs them.

The next protocol milestone is to complete M0's soundness and compiled-transcript
mapping, with concrete parameters and an independent review before implementing
a server-visible private proof. A bounded FRI/oracle adapter diagnostic may be
reviewed separately, but passing it cannot discharge those obligations. Keep
private lookups, the full payment relation and memory qualification as distinct
later gates.
