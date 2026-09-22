# Hiding review status

Recorded 2026-09-22. **The independent review is complete: NO-GO for
implementing gamma as client privacy** — see
[hiding-review.md](hiding-review.md). This is a qualification failure (the
complete-transcript coverage, fixed-`x` simulator, and private relation
semantics are absent), not a claim of a practical attack. No alternative
construction is approved by that verdict.

The sections below retain the earlier partial-log intake as historical
provenance. The user supplied `/tmp/opencode/kimi-review.log` as the latest
external review at intake time. The inspected file is 12,782 bytes, SHA-256
`a2f671ab1355cc21981b91c11a07a944e1d4d340e3ae818629815093483dcc82`.
It ends during analysis of quadratic constraints and contains no final verdict,
completed simulator argument or implementation approval; its preliminary
findings were carried into the completed review. It was never equated with
the completed, separately scoped context-binding review.

## Findings carried into the completed review (historical intake)

The log identifies arithmetic inconsistencies in [hiding-spec.md](hiding-spec.md).
Under its hypothetical rank-96-per-column observation model, direct integer
calculation gives:

| Count | Correct arithmetic |
| --- | ---: |
| Pad input words | `892 * 24 = 21,408` |
| Expanded pad coordinates | `892 * 1172 = 1,045,424` |
| Codimension count from the stated expansion dimensions | `892 * (1172 - 24) = 1,024,016` |
| Linear kernel dimension if each column has rank 96 | `(892 - 96) * 1172 = 932,912` |
| Difference of those last two counts | `91,104` |

These correct arithmetic errors; they do not establish independent constraints,
generic infeasibility, attack complexity, or hiding. The rank-96 model itself
must not be substituted for the actual proof's observation geometry.

The log also distinguishes the probe's generic extension-field sample points
from actual base-field query openings. The source-checked
[server inventory](server-observation-inventory.md) records the actual
variable-lifting M31 configuration, two-sample interaction columns, query
deduplication and transmitted versus derived FRI values. Counts copied from the
fixed-lifting-23 felt252 experiment are not a substitute. A complete argument
must cover the joint transcript, including commitments, claimed sums,
interaction/composition columns, FRI and transcript-derived challenges.

Additional requirements established by the takeover are in the
[privacy contract](privacy-contract.md): keep spent commitments private, replace
host reconstruction of private semantics with in-proof constraints, preserve
push ownership, and prove real output accounting and bounded integer
conservation. The existing permutation-only cost fixture does not contain that
complete relation. Its padding measurements cannot qualify the added components.

## Recorded decision

The completed independent review records **NO-GO** for gamma as client privacy
([hiding-review.md](hiding-review.md), reviewed 2026-09-22 at HEAD
`0f5448bafe2885199482b8d5a512dc98745c5692`): the fixed-`x` simulator, the
complete-transcript argument, and the private relation semantics are absent,
and the rank/equation counts do not close that gap. Gamma remains an
**unqualified research proposal**, not a selected client privacy construction.
This is a qualification decision, not a claim to have broken the proposed
computational assumption.

The [polynomial masking path](polynomial-masking-plan.md) now has a separately
reviewed M0 mapping and a passing
[exact-algebra diagnostic](results/polynomial-masking-algebra/README.md).
This scoped approval covers neither complete soundness nor a compiled private
proof; those remain the next protocol gates. It does not qualify gamma or the
exact-padding forks.

The public statement-binding repair is **complete under its own scoped review**
([results/context-binding/README.md](results/context-binding/README.md)):
five unit tests, a fresh V2 proof, 72 mutation rejections, and rejection of
the preserved V1 proof. It does not close the hiding gate or establish PROOF1
compatibility.
