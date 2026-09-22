# M0 masking integration: source map

2026-09-22. K3 gathered the source inventory; Astra checked the interfaces below
and corrected its draft's coefficient-extension and denominator descriptions.
This is an implementation map, not security approval. Recorded provenance is
S-two `489a0f3` with local storage patches under `target/m31-append/stwo`;
these are unpacked sources, not an independently clean Git checkout.
All paths below are relative to that source directory unless stated otherwise.

## Polynomial and degree interfaces

| Interface | Current behavior | M0 implication |
| --- | --- | --- |
| `crates/stwo/src/prover/poly/circle/poly.rs:30` | `CircleCoefficients::new` accepts a power-of-two vector in the bit-reversed FFT basis. | Full-circle monomial masks need an exact conversion/evaluation-and-interpolation step. These are not ordinary monomial coefficients. |
| Same file, `:47–52` | `extend` raises the representational degree bound while preserving evaluations. | Extending with zeros supplies capacity, not randomness. |
| `crates/stwo/src/prover/pcs/mod.rs:407–430` | `extend_evals` interpolates supplied columns; `extend_polys` accepts caller-provided coefficients. | Polynomial entry points exist, but no masking or security qualification is added. |
| `crates/constraint-framework/src/component.rs:232–266` | Trace degree bounds derive from `eval.log_size`; OOD shifts use the verifier's global degree-domain step. | M0 uses a dedicated adapter with separate H, polynomial capacity and D. It does not change these global semantics. |
| `crates/constraint-framework/src/prover/component_prover.rs:109–134` | Prover divides constraints by the trace-domain vanishing polynomial. | Preserve constraints on the original H after allocating larger polynomial capacity. |
| `crates/constraint-framework/src/component.rs:292–298` | Verifier denominator uses the global `max_log_degree_bound`. | In the existing M31 config this equals trace `log_size`: lifting is `log_size+3`, blowup is 3. There is no demonstrated baseline mismatch. A new degree-slack adapter must explicitly supply H instead. |
| `crates/stwo/src/prover/poly/circle/ops.rs:147–170` | `split_at_mid` satisfies `p(z)=left(z)+pi^(L-2)(z.x)*right(z)`. | This is a circle FFT-basis split. The first candidate avoids splitting Q entirely. |

The existing top-level prover splits composition into two halves, then four
base coordinates each (`crates/stwo/src/prover/mod.rs:73–77`); the verifier
expects eight columns (`crates/stwo/src/core/verifier.rs:17,75–79`). Supplying
one unsplit M0 quotient requires its own top-level verification adapter.

## PCS and FRI boundary

`crates/stwo/src/core/constraints.rs:95–134` derives a line through the OOD
value and its extension-field conjugate. `crates/stwo/src/core/pcs/quotients.rs:251–277`
evaluates the corresponding circle-line denominator in CM31. This is not the
ordinary univariate expression `(X-z)(X-conjugate(z))`. Its exceptional-point
assertion must become an explicit public sampling policy in a new protocol.

The quotient batching code starts at power zero
(`quotients.rs:298–302`). The M0 proposal gives R the constant coefficient
and all other terms distinct positive powers; copying the old batch unchanged
would violate that requirement.

For two-sample columns, the PCS derives an extra periodicity equation from an
already transmitted value (`quotients.rs:313–326`). This is not an extra
independent sample. M0 has equal-sized columns and one OOD point per column.

`crates/stwo/src/prover/fri.rs:106–114` commits the first layer of its supplied
polynomial, then commits/folds later layers. The verifier accepts externally
reconstructed first-layer query values (`crates/stwo/src/core/fri.rs:210–240`).
Thus a dedicated adapter can supply h(P) from R and the new batch equation;
the FRI folding equations themselves need not be redesigned for this mapping.
This observation does not approve the new batching reduction.

FRI complement values and the entire last-layer polynomial are exposed
(`prover/fri.rs:196–213,371–397`). They must be covered jointly by decoupling.
The current raw trace Merkle decommitment contains queried rows plus sibling
hashes (`crates/stwo/src/core/vcs_lifted/verifier.rs:100–183`); FRI's packed
leaves/complement rows must not be mistaken for extra raw trace openings.

## Private lookup boundary

`LogupAtRow::new` sets the per-row shift to `claimed_sum/N`
(`crates/constraint-framework/src/logup.rs:30–40`). The final recurrence is

`(cur - prev_row - prev_col + claimed_sum/N) * denominator - numerator = 0`

(`crates/constraint-framework/src/lib.rs:233–243`). The prover returns that
sum from `finalize_last` (`prover/logup.rs:109–148`); the M31 experiment sends
it in its envelope and balances it against host-reconstructed private requests.
It is an application-level field, not an intrinsic `StarkProof` field.

Each framework component instance owns its accumulator and claimed sum. Sharing
the constraint-composition accumulator does not share the LogUp accumulator.
The proposed follow-up combines both private lookup sides in one component;
it still requires reviewed inverse, shift, mask and exceptional-event handling.
It is excluded from M0.

See the [candidate specification](polynomial-masking-spec.md) for the proposed
oracle protocol and the distinct compiled-artifact gate.
