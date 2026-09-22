# Independent hiding qualification review

**Verdict: NO-GO for implementing gamma as client privacy.** Its current
assumption and argument do not establish zero knowledge for the required public
statement and complete proof. This is a qualification failure, not evidence of
a practical attack or a proof that every gamma variant is insecure.

Reviewed 2026-09-22 at repository HEAD
`0f5448bafe2885199482b8d5a512dc98745c5692`, including the current working-tree
privacy contract and observation inventory. Original artifacts remain intact:

- `hiding-spec.md` SHA-256: `8d420bce6512d2296b99848234d38e71269cd25fc2889f4fea1c561fe39e615c`.
- `results/rank-analysis.md`: `8989b144af03f095b3003bb15b169e8eac2b9cabb601bc0e9e7dac949a0ed65b`.
- `client/src/rank_dump.rs`: `cb916fad1ff7903a6a12cddd7181a5d60302ef32637f4963339e18ab93564e33`.
- `/tmp/opencode/kimi-review.log`: `a2f671ab1355cc21981b91c11a07a944e1d4d340e3ae818629815093483dcc82`.

The partial log supplies preliminary analysis, not an approval. I applied the
nested STWO soundness checklist, ZK foundations guidance, and divergence log.
No implementation, build, expensive probe, or binding re-review was performed.

## 1. The security claim is missing

The target is an efficient simulator given the **same fixed public input** `x`
from [privacy-contract.md](privacy-contract.md), permitted auxiliary/public
data, and the specified transcript-model access, without private witness `w`.
Its output must be indistinguishable from the server's complete view of an
honest proof for `(x,w)`.

[Hiding spec §4.3](hiding-spec.md) instead posits difficulty of deciding pad
feasibility, without defining its challenge distribution, promise, quantifiers,
advantage bound, or reduction from arbitrary transcript distinguishers. A
statistical bias may distinguish distributions without deciding exact support
membership. Search hardness is weaker still; finding a witness for an
infeasible wrong hypothesis is impossible and provides no hiding evidence.
Poseidon2's usual permutation/hash assumptions do not automatically supply this
new assumption about correlated internal expansion coordinates.

Section 4.4's fabricated `θ′` is not a simulator. If it changes the public root,
nullifiers or other public fields, the statements are visibly different. If it
must preserve `x`, efficiently finding another valid witness is unestablished.
Even witness indistinguishability for two witnesses of one `x` would not alone
give simulation from `x`; it can be vacuous for unique witnesses.

Exact hiding requires identical view distributions, not merely existence of
matching pads. Statistical hiding requires an explicit statistical-distance
bound, including exceptional events. Computational hiding requires defined
ensembles and a justified reduction against all efficient distinguishers, with
auxiliary information, adaptive requests and repeated proofs. Gamma establishes
none. A small candidate set can amplify a candidate test's usefulness, but does
not itself prove such a test exists or is efficient.

## 2. Rank and equation counts do not close the gap

For fixed weights, write `Y=S_w+W_pad E(U)`. Hiding would require the relevant
noise distribution to withstand witness-dependent shifts. Containment in its
linear span only addresses linear separation; a sparse or biased distribution
can span every direction and remain distinguishable after translation. Random
input count does not establish uniformity of this projected distribution.

The reported rank-68 matrices do not establish that *all* witness deltas lie in
one fixed 6,528-dimensional family. Matrix rank, dimension of a family, and its
linear-span dimension differ. Two sampled containment checks and empirical
rank saturation do not prove universal containment or a structural upper bound.

[rank_dump.rs:29–55](client/src/rank_dump.rs) uses a log-8 trace and 24
extension-field points. Multiplying a generic circle point by `2^11` does not
select an actual base-field query from the commitment coset. Actual base-column
observations contribute at most four base-field coordinates per OOD sample and
one per distinct base-field query: at most 27 here before considering other
proof components, not 96. Thus the rank-68 surrogate matrix cannot retain that
rank in a 27-row base-observation matrix. The probe also compares different
synthetic public statements (lines 64–68), not witnesses conditioned on fixed
`x`. Neither surrogate counts nor fixed-lifting C1 counts describe the complete
gamma transcript.

Under the hypothetical independent rank-96-per-column model, the corrected
counts are 1,024,016 row-image codimension, 932,912 linear-kernel dimension,
and difference 91,104. These are not independent-constraint or genericity
proofs. Constraints may be redundant on the observation fiber; special shifts
need not behave generically. Neither the spec nor partial log establishes
wrong-hypothesis infeasibility. Conversely, more variables than quadratic
equations does not establish a finite-field solution. The “quadratics absorbed”
claim is unsupported; the actual expansion already uses quadratic relations
among its intermediate witness columns ([m31.rs:230–285](client/src/m31.rs)).

A right-inverse reconstruction selects only one point in an affine fiber:
`W_pad^+ y + ker(W_pad)`. Even for the true hypothesis it need not recover the
real pads. Feasibility must range over the whole fiber. Failed Gauss–Newton
runs exclude no general distinguisher. No attack complexity follows here.

## 3. The actual transcript and relation remain uncovered

[lib.rs:40–46,90–129](client/src/lib.rs) serializes private fields and verifies
a host-reconstructed lookup boundary. Its sequence commits the base trace,
checks PoW, derives lookup challenges, checks and mixes the claimed sum, then
commits the interaction trace and invokes STARK verification. Weights therefore
depend on preceding witness-dependent commitments and transcript values.
Conditioning on those values cannot silently restore independent uniform pads.

A proof must cover commitments/decommitments, claimed sums, shifted interaction
samples, composition samples, all FRI layers/complements/final polynomial,
nonces, and challenges jointly, as catalogued in
[server-observation-inventory.md](server-observation-inventory.md). Merkle
binding is not a hiding theorem. A fixed-weight calculation does not provide
an adaptive Fiat–Shamir simulator or justify random-oracle programming.

Moreover, valid independent permutations do not establish ownership, private
membership/hash wiring, output commitments or bounded integer conservation.
Those are R0 obligations in [privacy-contract.md §3](privacy-contract.md).
Publishing spent leaves contradicts its spend-linkage requirement. Privatizing
pad/request rows also removes the verifier's present ability to reconstruct
their LogUp boundary ([m31.rs:203–215](client/src/m31.rs)). A replacement must
balance private lookups and hide intermediate sums. “Soundness untouched” is
therefore not justified for the necessary client-privacy conversion.

## 4. Required next specification and review gates

1. Pin R0, public encoding, private semantic/range components, lookup wiring,
   fixed shape, verifier authority and the exact server view.
2. Specify one complete hiding protocol, randomizer distributions, degree
   spaces, exceptional-event policy and every prover/verifier transcript step.
3. Prove fixed-`x` simulation, full-transcript composition and the stated
   Fiat–Shamir/commitment model, including repeated/adaptive use. If gamma is
   retained, replace H with a precise assumption and prove the reduction;
   plausibility discussion or more ranks cannot substitute.
4. Recheck completeness, AIR degrees/domains, lookup balance/multiplicities,
   FRI, trusted parameters and soundness under that protocol. Only then review
   an implementation and its negative tests, followed by workload measurements.

**Polynomial witness masking plus a proved ZK low-degree protocol is an
appropriate next specification path**, without implementation approval.
[Circle STARKs §5.4](https://eprint.iacr.org/2024/278.pdf) explicitly combines
randomized trace encoding with randomized FRI. Haböck–Al Kindi,
[A note on adding zero-knowledge to STARK, §§2–4](https://eprint.iacr.org/2024/1037.pdf)
(2025-02-20 revision), gives `ŵ=w+v_H r`, extension-field query accounting,
a separate FRI mask and decoupling lemma, and quotient-component analysis.
Its univariate protocols do not by themselves qualify this circle/LogUp
implementation: map the exact polynomial spaces, shifted queries, quotient
split, private lookups and compiled transcript to proved hypotheses.

The local paper anchors `Circle_STARKs.llm.md:thm:AIR:soundness` and
`Stwo_Whitepaper.llm.md:thm:NIROP:soundness:general` concern soundness; they
cannot fill a missing privacy proof. No alternative, including exact-padding
forks, is automatically approved, and no memory projection is endorsed.

**SECURITY-ESCALATION:** `hiding-spec.md`, full server-visible proof: the
claimed simulator/reduction is absent and the private relation is incomplete.
Keep gamma unqualified and proceed only with the specification/proof gates
above before selecting a client-privacy implementation.
