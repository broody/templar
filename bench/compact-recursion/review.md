# Math Review: compact-recursion M0 floor measurement and design gate

Status: **conditional-go for M2 (the membership-AIR `Statement` adapter, the driver, the
floor measurement with the REAL inner proof, and the measurement harnesses) under the
enumerated conditions; blinding integration is NOT approved as part of M2 and stays
behind the shared blinding-qualification gate from `bench/client-hiding/review.md`
(conditions 1-8 there).** The M0 record is verified accurate on every claim I checked
except the corrections in §5 (one material cost-model inconsistency, one unsound
cheapening as specified, one structural adapter gap, three bookkeeping items). The
two soundness-critical findings are E1 (trusted-preprocessed-root skip) and E2
(multi-mask-offset OOD samples are not representable in the current in-circuit proof
structures — the M0 template cannot host the membership AIR as-is). Neither blocks
starting M2; both block specific design commitments inside it.

## 0. Review basis

- Role per `target/direct-air/stwo/AGENTS.md` (Math Reviewer: reviews and escalates
  only; this document is the sole artifact written). The
  `soundness-review-checklist` (`.codex/skills/`), the paper distillations
  `INDEX.llm.md`, `Circle_STARKs.llm.md`, `Stwo_Whitepaper.llm.md` were read before
  judging. Paper anchors used below: `thm:AIR:soundness`, `prop:deep:quotients`,
  `rem:DEEP:quotients:batching` (Circle_STARKs); `e:flat:AIR:consistency`,
  `thm:IOPP:soundness`, `rem:IOPP:soundness`, `thm:NIROP:soundness:general`,
  `s:STARK` (Whitepaper).
- Pinned trees: stwo `489a0f3`, stwo-circuits `5ef951a` (revs as recorded in bench
  metadata and prior reviews; the tree contents match every line anchor those
  reviews cite — `circuit_common/src/finalize.rs:154`, `core/pcs/quotients.rs:313-326`,
  etc. — so the trees are the pinned revisions by content).
- Reviewed objects: `bench/client-hiding/compact-recursion-design.md` (primary),
  `bench/compact-recursion/results/measurements.md` + the machine-readable summary,
  `bench/compact-recursion/client/src/main.rs`, and the consistency anchors
  (`bench/client-hiding/review.md`, `bench/client-privacy-feasibility/review.md`,
  `bench/direct-air/privacy-review.md`, `bench/client-hiding/spec.md`).
- **Verified directly in pinned code:** the entire M0 harness data flow
  (`proof_from_stark_proof` → `verify` → `Circuit::check` → topology equality →
  `finalize_context` → `prove_circuit_assignment_with_channel` → outer native
  verify → mutation control); the canonical outer-circuit verification routine it
  mirrors; the in-circuit channel/PoW/Merkle/FRI/OODS machinery at the cited lines;
  the fixed-table floor (xor_10 = 2^20 rows, 45 preprocessed columns); blake_g_gate
  column widths (52+52); the claimed-sum/DEEP-ALI fold-in; the relation-use bound
  check; PoW nonce canonicality; the output-hash chaining; the multi-sample
  limitation of `Proof`/`proof_from_stark_proof` (E2); unreferenced-preprocessed
  OOD behavior and query dedup in core stwo.
- **Assessed analytically (no measurement exists):** the forged-preprocessed attack
  (E1), the corrected memory projection (§5, C1), the compression-count and row
  estimates (5,450-6,060 → 750-900k rows), the mini-verifier D_obs ≈ 21-23k, the
  duplicate-draw probability, and the felt252-port adequacy judgment (E3).

## 1. M0 result claims — verification (task item A)

### 1.1 In-circuit verification and the topology-equality assert — MEANINGFUL

The harness (main.rs:126-145) builds the value-free topology from
`empty_proof(&config)` (config-derived only), runs the generic
`stark_verifier::verify` with real proof values, then asserts
`novalue_circuit.check(context.values())` and
`assert_eq!(context.circuit(), &novalue_circuit)`. Both checks are substantive:

- `Circuit::check` (circuits/src/circuit.rs:449-454) re-executes **every gate's
  semantics** against the recorded wire values (independent re-evaluation of the
  Blake2s hashes, FRI folds, Merkle recomputations, and `eq` assertions), not a
  replay of the build pass. A failing inner proof surfaces as a gate-level failure.
- The topology equality rules out value-dependent gate sequences; for this config
  the gate shapes are config-derived (chunking in `fri.rs:93-103` depends on
  `log_layer_size`/`step`, both config values), and the assert passing empirically
  confirms it.
- Decisively: the **outer STARK proves this exact circuit**
  (main.rs:150-162 → `prove_circuit_assignment_with_channel`), so "the inner proof
  was verified in-circuit" is a proof-backed statement, not a host-side
  re-computation. The M0 claim is sound.

Gap vs the design's own M0 done-criterion (§9: "a native-verified proof is **also**
circuit-verified"): the harness never runs the native stwo verifier on the inner
proof (main.rs has no `verify` call on `create_proof()`'s output). The in-circuit
check plus outer proof subsume it semantically, but the record should not claim the
done-criterion met. C6.

### 1.2 Outer proof natively verified — FAITHFUL MIRROR

`verify_outer` (main.rs:64-115) is a line-by-line mirror of the canonical
`stwo_verify` (circuit_prover/src/prover_test.rs:185-252): channel salt →
`pcs_config.mix_into` → commit preprocessed tree (`commitments[0]`) →
`CircuitClaim::mix_into` (output values) → commit trace (`commitments[1]`) →
interaction PoW (20 bits, circuit_verifier/src/statement.rs:26) → mix nonce →
`CircuitInteractionElements::draw` → `interaction_claim.mix_into` → commit
interaction (`commitments[2]`) → `CircuitComponents` → `verify_ex(..., true)` →
`lookup_sum == 0` (circuit_claim.rs:66-101). The `include_all_preprocessed_columns =
true` flag matches the prover (prover.rs:240). The lookup-sum check is the
native-side boundary check (`validate_logup_sum`'s runtime counterpart) and is
present. Claim verified.

### 1.3 Mutation control — VALID rejection; battery adequate for M0, insufficient for M2

The control zeroes `commitments[1]` (trace root) with the original
`interaction_pow_nonce` (main.rs:178-206). The trace root is mixed into the channel
*before* the interaction PoW check (main.rs:87-88), so the grinded nonce no longer
verifies and rejection surfaces at the PoW gate. That is a **valid rejection**: the
PoW check is part of the transcript binding (Whitepaper `s:STARK`,
`thm:NIROP:soundness:general` — round-by-round binding including grinding), and any
failed check is a rejection. The M0 record's explanation ("as expected for a
transcript-root mutation") is correct.

However, this control does **not exercise** the Merkle decommitment, FRI fold,
OODS-identity, or claimed-sum checks of the outer verifier. For M0 (wiring demo)
this is adequate; the upstream in-circuit battery
(stark_verifier_examples/src/verify_test.rs:30-127: wrong trace auth path, wrong FRI
auth path, wrong FRI witness) is the template for what M2 must add (condition 4).

### 1.4 Floor numbers — verified, with one material correction (C1)

Verified against the JSON record and code:

- trace log 20, lifting 22: forced by the fixed `bitwise_xor_10` table
  (circuit_common/src/preprocessed.rs:539-553 — columns of size 2^20;
  `trace_log_size` = max preprocessed column log size, :525). The "DSL hard floor"
  claim is verified. 45 preprocessed columns: 8 qm31_ops + 2 eq + 5 triple_xor +
  3 m31_to_u32 + 11 blake + 16 fixed (:387-419) = 45 ✓.
- `blake_g_gate` log 15 = 32,768 rows ✓; width 52+52 = 104 M31 columns
  (circuit_verifier/src/components/blake_g_gate.rs:5-6) ✓ — the design's "~1M rows ×
  104 M31 columns ≈ ~1.7 GiB LDE" arithmetic is correct (2^22 LDE domain at blowup
  2 × 104 × 4 B ≈ 1.74 GB).
- The scaling interpretation is sound in kind: 242 compressions → log 15 (padded),
  ≈ 135-144 rows/compression including support; the real membership inner proof's
  ~5,450-6,060 compressions (23 queries × 9 trees, 16-column leaf batching per the
  pinned client) × ~144 ≈ 785-873k rows < 2^20 ✓ — consistent with the design's
  750-900k and its 15-25% headroom estimate. This part is arithmetic, not a
  measurement (M2 measures it).
- Wall 1.07-1.08 s ✓ (1.084 s recorded); native verify 2.7 ms ✓; context stats
  (13,121 add, …, 242 blake_updates) ✓.
- **But the stage-level memory projection is internally inconsistent** — see §5 C1:
  the design's own +1.7 GiB blake delta on top of the measured 2.88 GiB M0 floor
  gives ≈ 4.3-4.6 GiB for the real mini-verifier, not the tabulated 2.6-3.5 GiB.

## 2. The design's five open questions (task item B)

### Q1 — trusted-preprocessed-root skip: UNSOUND as specified; sound only with content binding

Pinning the preprocessed root as a caller constant while skipping the preprocessed
tree's Merkle verification does **not** bind the proof's preprocessed values to
anything. In `stark_verifier/src/verify.rs` the preprocessed OOD samples
(`proof.preprocessed_columns_at_oods`) feed `compute_composition_polynomial`
(:132-150) and the FRI input (`collect_oods_responses`, oods.rs:212-217;
`compute_fri_input`, oods.rs:352-428), and the preprocessed query values feed both
the constraint numerator terms and the FRI accumulation; the **only** check tying
them to the pinned root is `decommit_eval_domain_samples` with `roots[0]`
(verify.rs:179-190). Skip it, and an adversarial inner prover can forge the
preprocessed column values (consistently at the OOD point and at the query
positions), commit a self-consistent composition/FRI column, and pass every
remaining check — the pinned root is only *mixed* into the transcript
(verify.rs:63-65), which binds nothing to the values. For the template statement,
forging `row_const` at both points makes any trace satisfy the squared-Fibonacci
AIR. This is a soundness break of the inner verification layer. Escalation E1.

The design's justification is also inaccurate: the client driver
(bench/poseidon-membership/client/src/main.rs:256-259) pins the root **and still
performs the native Merkle decommitment of the preprocessed tree against it** (the
root is committed into `CommitmentSchemeVerifier` and the stwo verifier checks
preprocessed query openings against it; it additionally rejects proofs whose
`commitments[0]` differs from the trusted root). Root-pinning (anti-substitution)
and decommitment-skipping (content freedom) are different trust steps; the driver
does only the first.

Two acceptable forms for the cheapening:

1. In-circuit Merkle verification of the preprocessed tree against the pinned root
   (the ~600 compressions are not saved — no cheapening).
2. **Content re-derivation / constant substitution**: the circuit derives the used
   preprocessed columns' values at the OOD point and at query positions from the
   pinned defining data (structured columns: sequences and xor tables are cheap
   closed forms; generic tables need in-circuit tables), mixes exactly the values
   the honest prover mixed, uses them in `compute_composition_polynomial` and
   `compute_fri_input`, and performs no preprocessed decommitment. The one-time,
   off-circuit obligation is proving that the compiled constants and the pinned
   root coincide. This is the form the design's "content re-derivation obligation"
   hints at; it must be made explicit before any adapter code relies on the skip,
   and the row budget must be re-projected with the skip's actual availability.

### Q2 — n_padding minimum: no numeric minimum is defensible today; inventory-derived, gated

Given the shared unqualified status (design §5, honest), the same discipline as C1
applies: the defensible minimum is `n_padding` such that total pad free-parameters
across the five blinded components ≥ D_obs of the mini-verifier's own outer proof
(≈ 21-23k by my independent count; the design's ~21k is consistent) under the
eventually accepted lemma fork, with a documented margin, exact per-component
accounting, and public fixed padded log sizes — i.e., the output of the standing
shared gate (`client-hiding/review.md` conditions 2/4; escalations E1/E2 there),
not a constant chosen now. Since blinding is out of M2 scope (approved), M2 should
carry only a **placeholder** `n_padding` equal to the upstream precedent (outer
query count = 35) explicitly labeled as carrying no privacy claim; the design's own
accounting (~35 units ≈ 700 free M31 ≪ ~21k) already concedes the placeholder is
under-padded. One note on framing: with the real inner proof, blake rows are
~99.996% verifier-derived public work, so "blake is one of the five blinded gates"
(design §5) is a weak mitigant; the under-padding concession is the operative fact.

### Q3 — query-count fixing (reject duplicate draws): SOUND, one-directional; probability figure wrong

The native verifier deduplicates (`core/queries.rs:41-49`, `Queries::new` via
`BTreeSet`), and the current in-circuit translation shares values across duplicate
slots (`proof_from_stark_proof.rs:107-127`). Requiring 23 **distinct** positions in
the circuit accepts a subset of what the native verifier accepts — strictly
strengthening, so the outer proof's statement ("inner proof verifies AND queries
distinct") is sound. The cost is a completeness loss: P(any duplicate among 23
draws of 2^23 positions) ≈ C(23,2)/2^23 ≈ **3·10⁻⁵**, not the design's "p ≈ 3·10⁻³"
(§3 cheapening 2 — off by ~100×; matches the `client-hiding/review.md` O2 note). A
rejected (valid) inner proof is simply re-proved with fresh randomness; no
soundness or availability issue at this rate.

Circuit and verifier must agree on: the identical inner `FriConfig` (23 queries,
fold 4, blowup 3, lifting 23), the identical query-draw semantics (31-bit channel
draws masked to `log_evaluation_domain_size`, select_queries.rs:45-76), the
identical consumption of the selection input, and the distinctness predicate defined
over the masked positions. M2 needs a differential test proving the intended
semantics: a transcript with duplicate draws is natively accepted but circuit-
rejected. "Pre-merge FRI subsets per layer" is sound iff equality-preserving (same
folded value per query); it must be differentially tested against the unmerged path,
including on duplicate-coset inputs.

### Q4 — circuit-size headroom: arithmetic confirmed; if it overflows, take pure-dedup first

Verified: floor (xor_10 → 2^20), widths (104 blake columns), rows/compression
(≈ 135-144 from the M0 run), compression count class (~5,450-6,060) ⇒ ~750-900k
rows against the 2^20 = 1,048,576 ceiling ⇒ ~17-28% headroom; the design's 15-25%
is fair. If the budget overflows, ranked by headroom per soundness cost:

1. **FRI subset pre-merging + duplicate rejection** (Q3): pure deduplication of
   redundant coset work; no soundness cost; equality-preserving with a differential
   test.
2. **Preprocessed content re-derivation** (Q1 form 2): ~598 compressions ≈ 86k rows
   ≈ 8-10% of blake rows — available only under the re-derivation discipline; not
   available for free.
3. Witness-supplied inverses and mask-aware DEEP-ALI terms (cheapenings 3-4): save
   inv-guess and qm31 rows, not blake rows — small.
4. **Parameter reduction (n_queries/blowup/PoW of the inner proof) is not an
   acceptable lever** (checklist §7); neither is weakening the outer config.

Note C1 interacts here: the row ceiling is fine, but the corrected memory
projection (not rows) is what threatens the 3.5 GiB target; M2's real-inner
measurement decides.

### Q5 — adapter's felt252 constraint port: right net, incomplete plan; plus a structural blocker

The differential-testing-against-native-verifier + mutation-battery plan is the
correct shape, and the precedent is real (`cairo_verifier/src/components/` has
`cube_252.rs`, `range_check_252_width_27.rs`, and `subroutines/mul_252.rs` /
`verify_mul_252.rs` as `CircuitEval`-style evaluators). But as stated it is
incomplete, and it omits a structural prerequisite:

- **Structural (E2):** the DSL `Proof` carries **one** OOD sample per preprocessed
  and per trace column (`proof.rs:392-394`, validated at :431;
  `proof_from_stark_proof.rs:50-51` `as_single_row` hard-asserts singletons), and
  `at_prev` exists only for cumulative-sum interaction columns
  (proof.rs:435-439). The membership AIR's chain components read ±1 rows, so their
  OOD responses include prev/next-row points (`core/pcs/quotients.rs:313-326`,
  `core/air/components.rs:39-49`, per the verified O1 inventory in
  `client-hiding/review.md`). The M0 template cannot express them: the translation
  panics on multi-sample columns. M2 must extend the proof-carrying structures
  (`Proof`, `proof_from_stark_proof`, `collect_oods_responses`, and the OODS
  mixing) to per-column sample lists **in exactly the native prover's mixing
  order** — a soundness-critical transcript-parity change needing Crypto
  Specialist implementation with Math Review sign-off.
- Plan additions required (E3): (i) exact port of all 12 components' constraint
  expressions including mask-offset sample consumption; (ii) `public_logup_sum`
  reproducing the AIR's public lookup accounting (the host-derived boundary of
  `client-privacy-feasibility/review.md:47` — the inner AIR must enforce it, and
  the adapter's public sum must match it exactly); (iii) correct
  `relation_uses_per_row` declarations so `check_relation_uses`
  (stark_verifier/src/verify.rs:213-287) covers the adapter's lookup counts;
  (iv) felt252 limb constraints with exact limb widths (28 nine-bit limbs per the
  M1 review) and box constraints, each mutated in the battery; (v) differential
  matrix: same proof bytes natively accepted and circuit-accepted; per-component
  constraint mutation → both reject; OOD-value mutation → both reject; and the
  Q3 duplicate-draw semantics test.

## 3. Soundness disciplines (task item C) — verified

- **Statement binding:** the design (§7) requires the server wrap to bind the
  mini-verifier's public output to chain/pool/version/roots/nullifier, citing
  `circuit_verifier/src/verify.rs:40-42` and `statement.rs:58-63`. Verified in
  code: `build_verification_circuit` hashes the preprocessed root + output values
  into reserved output wires (verify.rs:63-72, with the "outer-most verifier must
  reconstruct the whole chain" comment), and the preprocessed root/output values
  enter the output hash as guessed variables (statement.rs:58-63). The
  `CircuitStatement` wrap mixes the outputs as claims (statement.rs:97-99). The
  discipline exists and the design states the obligation correctly. The M2 driver
  must actually place the statement-identity fields in the mini-verifier's output
  gates ("Statement binding" row of design §3) — carried as a condition.
- **Relation-use bound check:** `check_relation_uses` verified at
  stark_verifier/src/verify.rs:213-287 (host-side overflow sanity at :224-233;
  in-circuit `extract_bits` range check at :273-285 with the DIV=2^16 shift
  analysis). The design's requirement that it cover the adapter's lookup counts is
  correct and mandatory (Q5 (iii)).
- **PoW nonce canonicality:** verified channel.rs:114-152: the mask
  `(0,0,1,1)` multiply + `eq 0` forces limbs 2,3 = 0 (canonical `(lo,hi,0,0)`
  u64 form), `extract_bits` checks the n_bits LSBs of the first word, and the
  nonce is mixed into the channel afterward. Matches the design's claim, including
  the documented PoW bias note.
- **Claimed sums in the DEEP-ALI identity (not skippable):** verified — the
  per-component logup constraint folds the claimed sum in as
  `cumsum_shift = claimed_sum / n_instances` and the result is accumulated into the
  composition evaluation (constraint_eval.rs:186-210 → `add_constraint` →
  `accumulate`), and the total is separately checked against the public logup sum
  (verify.rs:35-45, :90-91). Removing the claimed-sum check would break the OODS
  identity the FRI phase attests. The design's "not skippable" list is correct;
  the boundary check (≈ 12-15 rows) and both PoW checks are likewise present and
  not skippable.
- **Honest trust-level statement:** confirmed. Design §1/§5 states route 2 is
  accepted exactly as `bench/direct-air/privacy-review.md:12` assessed it ("adds
  another client proving stage; does not solve the masking question for the outer
  client circuit"), claims no new hiding argument, concedes under-padding, and
  routes qualification to the shared standing gate. I found no hiding over-claim.
  One wording nit: the "first observer sees only the blinded artifact" line is
  acceptable only jointly with the unqualified-status disclosure the design makes
  two paragraphs later; keep them together in any downstream summary.

## 4. Escalations

SOUNDNESS-ESCALATION:
  File: bench/client-hiding/compact-recursion-design.md (§3 cheapening 1; §8 Q1)
  Change: skip preprocessed-tree Merkle verification, pinning the preprocessed root as a caller constant
  Invariant at risk: soundness of the inner STARK verification performed by the mini-verifier (constraint semantics depend on preprocessed column content)
  Paper reference: Stwo_Whitepaper.llm.md `thm:IOPP:soundness` (round-by-round knowledge soundness requires every committed column's openings checked), `thm:NIROP:soundness:general`; Circle_STARKs.llm.md `thm:AIR:soundness`
  Code location: stark_verifier/src/verify.rs:179-190 (sole binding of preprocessed values via decommit_eval_domain_samples), :132-150 (composition eval consumes proof-supplied preprocessed OOD values), stark_verifier/src/oods.rs:212-217, 352-428 (FRI input consumes the same values); driver contrast: bench/poseidon-membership/client/src/main.rs:256-259 (pins root AND decommits natively)
  Confidence: 92% that the skip as specified is unsound; 90% that form-2 (content re-derivation) is sound
  Reason: with the decommitment removed, an adversarial inner prover can forge preprocessed values consistently at the OOD point and query positions and pass composition/FRI checks against a self-consistent commitment — the pinned root binds nothing; either in-circuit decommitment or circuit-side re-derivation of the used columns from pinned defining data (with transcript-identical mixing) is required

SOUNDNESS-ESCALATION:
  File: bench/client-hiding/compact-recursion-design.md (§6 item 1 "evaluation at the OOD point only"; §8 Q5)
  Change: build the membership-AIR Statement adapter on the current stark_verifier Proof/DSL structures
  Invariant at risk: completeness of the adapter (the membership AIR's constraint expressions cannot be evaluated at the OOD point with the available samples); transcript parity if extended ad hoc
  Paper reference: Stwo_Whitepaper.llm.md `e:flat:AIR:consistency` (constraint evaluation consumes per-mask-offset samples); client-hiding review O1 (verified: one sample point per mask offset, chain components ±1 rows; `core/pcs/quotients.rs:313-326`)
  Code location: stark_verifier/src/proof.rs:392-394, 431, 435-439 (one sample per preprocessed/trace column; at_prev only for cumulative-sum columns); stark_verifier/src/proof_from_stark_proof.rs:50-51, 83-91 (as_single_row asserts singletons — panics on multi-sample columns); stark_verifier/src/oods.rs:211-267 (response order)
  Confidence: 90% that the current structures cannot express the membership AIR's multi-mask-offset trace columns
  Reason: M0's template AIR has single-sample columns only; the membership chain components require prev/next-row OOD samples that the DSL proof structures do not carry. M2 must extend Proof/proof_from_stark_proof/collect_oods_responses and the OODS mixing with per-column sample lists in exactly the native prover's order — soundness-critical, Crypto Specialist + Math Review sign-off required

SOUNDNESS-ESCALATION:
  File: bench/client-hiding/compact-recursion-design.md (§6 item 1; §8 Q5)
  Change: adapter correctness plan stated as "differential-tested against the native stwo verifier on the same proofs"
  Invariant at risk: correctness of the ported felt252/membership constraint expressions (a wrong-but-consistent adapter would verify proofs of a different AIR)
  Paper reference: Stwo_Whitepaper.llm.md `e:flat:AIR:consistency`; felt252 limb model per client-hiding review §2 (28 nine-bit limbs, memory_id_to_big.rs:23,67)
  Code location: construction-level (adapter not yet written); precedent cairo_verifier/src/components/{cube_252.rs, range_check_252_width_27.rs, subroutines/mul_252.rs}
  Confidence: 65% that the plan as stated is sufficient; ≥ 90% that plan + the enumerated additions is sufficient
  Reason: must additionally cover (i) mask-offset sample consumption, (ii) exact public_logup_sum matching the AIR's public lookup boundary, (iii) relation_uses_per_row declarations feeding check_relation_uses (verify.rs:213-287), (iv) per-limb felt252 mutation cases, (v) the duplicate-draw semantics test; without these a transcription error yields a self-consistent wrong verifier that differential testing on full valid proofs cannot distinguish

## 5. Corrections summary (design/M0 record vs verified reality)

| # | Claim | Finding |
| --- | --- | --- |
| C1 (material) | §4 stage table "Mini-verifier circuit proof (log 20) ~2.6-3.5 GiB"; §1 "target ≤ ~3.5 GiB"; "sequential peak ~3-3.5 GiB" | Internally inconsistent with the design's own arithmetic: M0 measured 2.88 GiB with blake at log 15, and the design's own blake delta is ~1.7 GiB LDE (2^22 × 104 × 4 B). Corrected estimate ≈ **4.3-4.6 GiB** for the real mini-verifier (sequential peak ≈ 4.5-4.6 GiB): ~1.3× under V1 (5.7-6.3 GiB), not ~2×, and above the 3.5 GiB target. Confidence ~90% (analytical; M2's real-inner measurement is decisive). No decision document may carry the 2.6-3.5 GiB figure; the route's motivation statement must be amended. |
| C2 | measurements.md links `results/m0-summary.json` (sibling) | The harness writes `bench/results/m0-summary.json` (main.rs:230-235, `../../results/`); the sibling file does not exist. Fix the link or the write path. |
| C3 | measurements.md "Peak RSS ~2.88 GiB (3,077,108 KB)" | 3,077,108 KiB ≈ **2.93 GiB**; the GiB label and the KiB figure disagree by ~2%. |
| C4 | §3 cheapening 2 "reject duplicate draws, p ≈ 3·10⁻³" | ≈ **3·10⁻⁵** (253/2^23; consistent with client-hiding review O2). Direction unchanged. |
| C5 | §7 "Component log sizes and the preprocessed root are guessed into the circuit and mixed into the transcript" | The preprocessed root is mixed (verify.rs:63-65); component log sizes are **not** directly mixed — they are bound through the verification geometry (periodicity sample points oods.rs:191-199, query sorting merkle.rs:157-161, tree heights) plus the lifting size via `mix_pcs_config` (proof.rs:336-356). Binding is real; the mechanism in the design's wording is not. |
| C6 | Design §9 M0 done-criterion "a native-verified proof is also circuit-verified" | The harness never natively verifies the inner proof (no `verify` call on the inner `ExtendedStarkProof`). In-circuit + outer-native subsume it semantically; add the inner native check to the M2 harness and reword the M0 record. |
| C7 | §5 "review condition C2/C5-adjacent" | The shared rank/recovery diagnostic maps to `client-hiding/review.md` conditions 2 (L2 lemma) and 7 (M3/M4 battery); the "C2/C5" label is off. |

All other M0/design claims verified: harness structure and checks (§1.1-1.3),
floor numbers and component log sizes (§1.4), the §2 DSL-capability survey (all
cited anchors confirmed), cheapenings 2-5 structure (dedup semantics
core/queries.rs:41-49; periodicity-only-for-2-sample-columns core/pcs/quotients.rs:
313-326; unreferenced-preprocessed OOD behavior core/verifier.rs:25,
core/air/components.rs:39-49; witness-supplied inverses ~160 — plausible count,
analytical; last-layer-nearly-free fri.rs:184-189), the "not skippable" list
(§3), the D_obs ≈ 21k order of magnitude (my independent count ≈ 23k), the direct
-air floor citation (2.605 GiB, bench/direct-air/results/measurements.md:9-12),
and the config citations (inner pow 27/blowup 3/23 queries/fold 4/lifting 23;
outer circuits config pow 26/blowup 2/35 queries/fold 4; interaction PoW 20).

## 6. Verdict and conditions

**CONDITIONAL-GO for M2**, scoped as: the membership-AIR `Statement` adapter
(CircuitEval constraint expressions + structural sample extension), the driver,
the floor measurement with the REAL inner proof, and the measurement harnesses.
**Blinding integration is not approved as part of M2** (the design's own §9 M2
must be amended accordingly); the n_padding pinning and any hiding claim remain
behind the shared standing gate.

Conditions:

1. **Preprocessed-root handling (blocking for adapter design):** the naive skip is
   rejected (E1). Adopt either in-circuit decommitment or the re-derivation form
   with the one-time constants↔root binding proof and transcript-identical mixing;
   re-project the row budget with the skip's actually-available savings.
2. **Sample-structure extension (blocking for adapter code):** M2 includes the
   multi-mask-offset OOD-sample extension of `Proof`/`proof_from_stark_proof`/
   `collect_oods_responses` with transcript-order parity tests against the native
   prover (E2). Implemented by the Crypto Specialist under Math Review sign-off.
3. **Adapter correctness plan (E3 additions):** the differential matrix and
   mutation battery must cover the five enumerated items (mask offsets, public
   logup sum, relation uses, limb mutations, duplicate-draw semantics) before the
   adapter is declared done.
4. **M2 soundness battery:** add outer-verifier mutation controls that pass the
   interaction PoW (trace/FRI auth path, FRI witness, OOD value, claimed sum), a
   statement-binding control (wrong output preimage), and the inner native
   verification step (C6).
5. **Blinding/n_padding:** placeholder only (upstream precedent, explicitly
   unqualified); no hiding claim on any M2 artifact; qualification work remains
   the shared gate.
6. **Cost record:** adopt C1; the real-inner floor measurement is the decisive M2
   deliverable and its numbers supersede all current projections.
7. **Statement binding (M5):** the driver must place chain/pool/version/roots/
   nullifier in the mini-verifier's output gates so the output-hash chaining binds
   the pool's statement identity (design §7 obligation, unchanged).

Consistency with the prior reviews is maintained: no qualification is implied by
any M0/M2 measurement; the M0 record's "no privacy claim" framing is correct and
kept.
