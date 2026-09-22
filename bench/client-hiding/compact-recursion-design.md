# Compact recursion: mini-verifier circuit design (exploration)

Status: **design exploration — no implementation.** Companion to
[spec.md](spec.md) (option C1/P2) and [measurement-plan.md](measurement-plan.md).
This is "direct-air route 2 taken seriously": verify the compact client AIR
proof inside a circuit-DSL verifier circuit, blind it with the existing
`add_zk_blinding`, and hand only the blinded outer artifact to the server.
Position vs the M1 review (`review.md`): the reviewer assessed route 2 as
"adds another client proving stage; does not solve the masking question for
the outer client circuit" — this design **accepts** that verdict. Its claim
is narrower: reduce client peak memory ~2× while keeping the **same
blinding-based trust level as the V1 pipeline** — not a new hiding argument.

## 1. Architecture and trust boundary

```
Client (desktop, target ≤ ~3.5 GiB peak):
  1. compact membership AIR proof      (transparent, never leaves device)
  2. mini-verifier circuit             (verifies step 1 + binds statement;
                                        zk-blinded via add_zk_blinding)
  → blinded circuit proof (~0.6 MB)    → SERVER (first observer; sees only
                                          the blinded artifact)
Server:
  3. V1 privacy pipeline wraps the     (machinery exists: CircuitStatement /
      circuit proof → PROOF1            build_verification_circuit recursion)
  → on-chain spend (sequencer-native
      PROOF1 verification, ~0 contract gas)
```

Trust model: identical to V1 — the posted artifact is blinding-protected
(unqualified, same shared gap); the inner transparent proof never crosses the
trust boundary. Upstream comparison: starknet-privacy's operator sees
plaintext keys; this design's server sees only a blinded proof.

## 2. Why the DSL can host this (verified in pinned sources)

`target/direct-air/stwo-circuits/crates/stark_verifier/` is a **complete
STARK verifier written in the gate DSL**, parameterized by a generic
`Statement` trait (`statement.rs:33-67`), driven by `verify()`
(`verify.rs:47-204`), with:

- a working custom-AIR template: `stark_verifier_examples/src/simple_statement.rs:65-188`
  (squared-Fibonacci AIR, own preprocessed column, public logup sum) —
  the direct template for the membership AIR adapter;
- in-circuit Blake2s Merkle paths with packed FRI leaves
  (`stark_verifier/src/merkle.rs:77-135`, `fri.rs:90-119`);
- an in-circuit Blake2s Fiat–Shamir channel with PoW checks
  (`stark_verifier/src/channel.rs:55-152`);
- QM31 ops at 1 gate row per operation (`circuits/src/ops.rs:67-140`);
- recursion precedent: `circuit_verifier/src/verify.rs:44-79`
  (`CircuitStatement` — proof-of-execution-of-another-circuit), which is
  also the server-side wrap path (step 3 above).

## 3. The mini-verifier's obligations (for the membership config)

Verification checklist per the pinned verifier (all counts from the
source; config: pow 27, blowup 3, 23 queries, fold 4, lifting 23,
9 Merkle trees):

| Part | Work | In-circuit rows (est.) |
| --- | --- | ---: |
| Merkle decommitments, 9 trees | ~5,450–6,060 Blake2s compressions; **trace-tree leaves alone = 52 compressions × 23** (818-col rows); preprocessed tree ~598 (skippable, below) | ~730–850k (96 G + 8 xor + ~40 support rows per compression) |
| DEEP-ALI numerators (`fri_answers`) | ~1,300–1,700 line-coefficient terms (5 QM31 muls each) + ~240–320k M31 muls over 23 queries | ~15–35k |
| FRI fold chain | 5 layers × 23 queries: 15 QM31×M31 + 15 QM31×QM31 muls per query (~27.6k M31 muls) | ~5–8k |
| OODS constraint evaluation | membership AIR's ~12 component constraint expressions at one point (Horner) | ~2–5k |
| Transcript + PoW | ~34 channel hashes + 2 PoW checks (2 hashes each) | ~5k |
| Statement binding | root/nullifier/commitments → Blake output preimage; boundary + Σsums = 0 check (12 QM31 adds) | ~1k |
| add_zk_blinding | `n_padding` units × (14 qm31 + eq + xor + m31 + G rows) | ~15 × n_padding |

**Total ≈ 750–900k rows → trace log 20** — which coincides with the DSL's
hard floor (fixed `bitwise_xor_10` table at 2^20; 45 preprocessed columns
always present, `circuit_common/src/preprocessed.rs:387-419`). Headroom is
~15–25% with the legitimate cheapenings below; budget overflow → log 21 →
measurably worse. This tightness is a design constraint, not a detail.

### Applied cheapenings (verified legitimate)

1. Skip the preprocessed-tree Merkle verification (~600 compressions): pin
   the preprocessed root as a caller constant — the client driver already
   treats it as trusted (`bench/poseidon-membership/client/src/main.rs:256-259`);
   unreferenced preprocessed columns already get no OOD samples
   (`core/verifier.rs:25`, `core/air/components.rs:39-49`).
2. Fix query count at 23 distinct (reject duplicate draws, p ≈ 3·10⁻³) and
   pre-merge FRI subsets per layer (deep layers collapse to ~20/~8 blocks).
3. Column-mask-aware DEEP-ALI terms (1-mask columns contribute 1 term, not
   3; periodicity samples only for 2-mask columns,
   `core/pcs/quotients.rs:313-326`).
4. Inverses supplied as claimed witnesses + 1-multiply checks (fold
   twiddles, DEEP-ALI denominators — all public, ~160 total).
5. Last layer is nearly free (poly length ≤ 1 → equality checks only).

**Not skippable** (soundness): trace/interaction/composition/FRI-tree
Merkle verification, the OODS mix, both PoW checks, claimed-sum constraints
(part of the DEEP-ALI identity), the boundary check (depends on proof
values: `boundary(&lookup) + Σ sumsᵢ == 0`, in-circuit ≈ 15 rows).

## 4. Cost model and client budget

Evidence for the floor: the 35-gate direct-air circuit (same fixed tables,
trace log 20, lifting 22, pinned circuits config pow 26 / blowup 2 / 35
queries / fold 4 / interaction PoW 20) measured **2.605 GiB RSS, 5.7–6.0 s,
1 thread** (`bench/direct-air/results/measurements.md:9-12`).

Scaling to the mini-verifier: the dominant delta is `blake_g_gate` growing
from 64 rows to ~780k (log 20): 1M rows × 104 M31 columns (52 trace + 52
interaction) ≈ ~1.7 GiB LDE for that component alone; everything else is
floor-class. Proving the membership AIR itself is a measured 1.97 GiB under
bounded-memory mode.

| Stage | Peak RSS (est.) | Wall (est.) |
| --- | --- | --- |
| Inner compact AIR proof (bounded-memory) | ~2.0 GiB | ~14 s |
| Mini-verifier circuit proof (log 20) | ~2.6–3.5 GiB | ~7–10 s |
| **Sequential client peak** | **~3–3.5 GiB** | **~21–25 s** |

vs the current V1 pipeline under bounded memory: 5.69–6.31 GiB, ~23 s
(`bench/bounded-memory`). Net: **~2× peak-RSS reduction, similar wall**.
Above the 2 GiB browser target still — the DSL floor (2^20 fixed tables +
FRI machinery at the pinned config) is the binding constraint, and the
blake_g component's row count is structural (~5–6k compressions cannot be
reduced without changing the inner proof's lifting/blowup or upstream's
leaf packing constant).

## 5. Honest trust-level statement

This option does **not** advance the hiding qualification. The outer
artifact is protected by `add_zk_blinding` — the same mechanism, with the
same gaps the M1 review documented (no hiding theorem; under-padding by the
observation accounting: ~35 units × ~20 free M31 ≈ 700 ≪ D_obs ≈ ~21k for
the mini-verifier's own proof). Two mitigating facts, stated without
spin: the circuit's dominant component (Blake gates) is one of the five
blinded gates; and the inner transparent proof never crosses the trust
boundary. The qualification task (rank/recovery diagnostic against the
actual V1-class circuit, review condition C2/C5-adjacent) covers this
construction's outer artifact identically — it is shared work, not
duplicated.

## 6. What is new vs reused

**Reused (pinned sources):** `stark_verifier` verify/FRI/Merkle/channel
machinery; `simple_statement.rs` adapter template; `add_zk_blinding` +
`finalize_context`; circuit proving frame + bounded-memory mode; the
server-side `CircuitStatement` wrap (step 3).

**New (the build):**
1. **The membership-AIR `Statement` adapter** — the largest piece: express
   the 12 components' constraint expressions as `CircuitEval` (evaluation
   at the OOD point only — one point, not per-row), including the felt252
   limb-level constraints. Precedent for the felt-level parts exists as
   `cairo_verifier` CircuitEvals (`mul_252`, `cube_252`,
   `range_check_252_width_27`, `subroutines/*`). Differential-tested
   against the native `stwo` verifier on the same proofs.
2. **The driver**: compact AIR proof → adapter → `verify()` →
   `add_zk_blinding(n_padding)` → `finalize_context` → prove (pinned
   circuits config) → serialize with the output preimage.
3. Measurement harnesses (M3 battery reused from the C1 plan).

## 7. Soundness-relevant disciplines (from the pinned verifier code)

- Component log sizes and the preprocessed root are guessed into the
  circuit and mixed into the transcript; the outer-most verifier
  reconstructs the output-hash chain
  (`circuit_verifier/src/verify.rs:40-42`, `statement.rs:58-63`) — the
  server wrap must bind the mini-verifier's public output to the pool's
  statement identity (chain/pool/version/roots/nullifier), per the
  established binding requirements.
- Relation-use bound check (`check_relation_uses`,
  `stark_verifier/src/verify.rs:213-287`) must cover the adapter's lookup
  counts (the membership AIR's components have their own use counts).
- PoW nonces are witnesses extracted in-circuit with canonicality checks
  (`channel.rs:114-152`, `extract_bits.rs`).

## 8. Open questions for review (gate before implementation)

1. Is the trusted-preprocessed-root skip sound at this layer (caller
   pins the root; content re-derivation obligation), or must the circuit
   verify the preprocessed tree?
2. The n_padding choice for the mini-verifier: fixed public value sized
   by the same observation-accounting discipline as C1 (inventory-derived,
   not arbitrary) — what minimum satisfies review given the shared
   unqualified status?
3. Query-count fixing (reject duplicate draws) — protocol deviation from
   dedup semantics; confirm acceptance criteria.
4. Circuit-size headroom: confirm the ~750–900k row estimate lands within
   log 20 after implementation, and the fallback plan if it exceeds
   (which cheapening gives the most headroom per soundness cost).
5. The adapter's felt252 constraint port: correctness plan (differential
   testing matrix vs the native verifier, mutation battery).

## 9. Milestones

- **M0**: build the adapter against `simple_statement.rs`; verify a real
  compact AIR proof in-circuit; measure the floor (RSS/wall/proof size).
  *Done when*: a native-verified proof is also circuit-verified, with the
  floor measured on the pinned config.
- **M1**: Math Review of this design + the adapter's constraint
  expressions (soundness checklist; the C2/L2 obligations do not apply —
  this is a route-2 construction with route-1-class blinding).
- **M2**: blinding integration + n_padding pinning; driver.
- **M3**: recovery/uniformity battery on the outer artifact (shared with
  the V1 diagnostic); soundness regression.
- **M4**: cost deltas vs the V1 pipeline (RSS/wall/proof size, bounded
  memory, WASM probe).
- **M5**: server-wrap integration (CircuitStatement path) and statement
  binding review.
