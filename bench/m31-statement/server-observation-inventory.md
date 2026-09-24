# Server observation inventory — source facts

Scope: `bench/m31-statement/client/src/{lib.rs,statement.rs,m31.rs}`, pinned
deps under `target/m31-append/{stwo,stwo-cairo}`, `bench/m31-statement/hiding-spec.md`.
Prepared by Kimi K3; source-checked and corrected by Astra. This is an
implementation inventory, not an independent mathematical review.

Baseline HEAD: `0f5448bafe2885199482b8d5a512dc98745c5692`. Working tree clean at
start (`git status --porcelain` empty). Facts only; the measured public
benchmark is distinguished from the proposed hiding spec throughout. C1
felt252 observation counts are NOT used here; all counts below come from this
benchmark's own source or `results/summary-amounts.json`.

The source locations and encoding defects below refer to that baseline. The
[version-2 context encoding repair](results/context-binding/README.md) does not change this inventory's conclusions
about disclosed witnesses and missing private semantic constraints.

## 1. Serialized Envelope fields reaching the wrapping server

`Envelope` (`client/src/lib.rs:40-46`), bincode fixint encoding with trailing
bytes rejected (`lib.rs:133-138`):

- `statement: PaymentStatement` (`statement.rs:52-79`), containing:
  `chain_id` (hex String), `pool` (hex String), `root` ([u32;9]),
  `nullifiers` ([Digest;2]), `leaves` ([Digest;2]), `indices` ([u64;2]),
  `secrets` ([Digest;2]), `siblings` ([[Digest;32];2]), `amounts` ([u32;2]),
  `pad_seed` (u64), `pad_count` (usize). Note the in-code comments at
  `statement.rs:61-64` mark indices/secrets as "in the clear for this
  measurement".
- `interaction_pow: u64` (24-bit interaction PoW, `lib.rs:43,47`).
- `claimed_sum: QM31` (LogUp claimed sum, `lib.rs:44`).
- `proof: StarkProof<Blake2sMerkleHasher>` (`lib.rs:45`), i.e.
  `CommitmentSchemeProof` (`target/m31-append/stwo/crates/stwo/src/core/pcs/quotients.rs:27-35`):
  `config: PcsConfig` (`core/pcs/mod.rs:31-42`: pow_bits 27,
  FriConfig `new(0,3,23,4)` → log_last_layer_degree_bound 0, log_blowup 3,
  n_queries 23, fold_step 4 — confirmed by `results/summary-amounts.json`),
  `commitments: TreeVec<Hash>`, `sampled_values: TreeVec<ColumnVec<Vec<QM31>>>`,
  `decommitments: TreeVec<MerkleDecommitmentLifted>`,
  `queried_values: TreeVec<ColumnVec<Vec<M31>>>`, `proof_of_work: u64`,
  `fri_proof: FriProof`.

Recorded amount-bearing shape (`results/summary-amounts.json`): 132 requests, 256 rows, log_size 8,
lifting_log_size 11 (variable: `log_size + 3`, `lib.rs:53`), 1,172 trace
columns, envelope 170,854 bytes. This reads existing evidence; no benchmark was rerun.

## 2. Host `validate()` checks vs. what the AIR proves

Host-side (all in `statement.rs:104-175`), no proof involved:

- Felt parsing for chain_id/pool (`statement.rs:25-29,105-106`). The subsequent
  `byte[31] & 0x80 == 0` check tests bit 255, so it does **not** implement the
  advertised `< 2^251` bound. Context canonicality/range checks need correction;
  M31 canonicity of root/nullifiers/leaves/secrets/siblings
  (`statement.rs:107-114`, `m31.rs:37-40`); `indices < 2^32`
  (`statement.rs:115`).
- Amount range: `amounts[p] < 2^30`, host-only, in-proof range enforcement
  deferred to v2 (`statement.rs:67-70,120`).
- Leaf preimage: `leaf = H(frame(KIND_LEAF,0,secrets[p] ++ amounts[p]))`
  recomputed and equated (`statement.rs:121-125`); nullifier preimage
  (`statement.rs:126-128`); both depth-32 paths from leaves to root using
  `indices` bits and `siblings` (`statement.rs:130-139`).
- Host reconstruction of ALL permutation requests: every sponge permutation
  along both preimages and both paths is appended to `requests`
  (`statement.rs:118-139`), then `pad_count` random valid rows derived
  deterministically from the serialized `pad_seed` (`statement.rs:140-152`),
  then power-of-two padding by duplicating row 0 (`m31.rs:191-202`).
- Public lookup boundary: host recomputes `boundary(d.rows, lookup) =
  Σ_rows 1/combine(RELATION_ID‖input‖output)` (`m31.rs:203-215`) and requires
  `boundary + claimed_sum == 0` (`lib.rs:122-125`). All rows — semantic,
  pad-seed pads, and duplicated padding — enter this sum, so the verifier-side
  request multiset is fully public and recomputable from the serialized
  statement.

AIR-proven (`m31.rs:230-287`): each committed row is a correct width-24
Poseidon2 permutation (quadratic S-box constraints plus MDS equalities,
`m31.rs:234-279`); each row yields `(RELATION_ID, input, output)` with
multiplicity −1 (`m31.rs:280-285`); `finalize_logup_in_pairs` constrains the
running-sum interaction columns (`m31.rs:285`, framework semantics at
`target/m31-append/stwo/crates/constraint-framework/src/lib.rs:221-245`).
The AIR has no explicit leaf/nullifier/path, amount, index or public-word
canonicality constraints; the link between trace rows and the
statement exists only because the host reconstructs the identical request set
and enforces the boundary equality. Relation is `CommonLookupElements`
(`stwo-cairo .../cairo-air/src/relations.rs:24-25`, size 128) drawn from the
channel (`lib.rs:121`; `constraint-framework/src/lib.rs:305-335`).

## 3. Complete proof-observation categories in the artifact

From `CommitmentSchemeProof` (`quotients.rs:27-35`) plus verifier flow
(`core/verifier.rs:19-116`, `core/pcs/verifier.rs:59-116`):

1. **Commitments** — 4 Merkle roots: `commitments[0]` empty preprocessing root
   (host-enforced equal to `empty_root()`, `lib.rs:94-97,65-68`), `[1]` base
   trace (1,172 cols, `lib.rs:111-115`, `m31.rs:26`), `[2]` interaction
   (4 cols, `lib.rs:127`), `[3]` composition (8 = 2·4 QM31-coordinate cols,
   read in `core/verifier.rs:75-79`; `COMPOSITION_LOG_SPLIT = 1`,
   `verifier.rs:17`). Total root count enforced at `lib.rs:95`.
2. **Base OOD samples** — `sampled_values[1]`: 1,172 columns × 1 point
   (masks all offset 0, `m31.rs:231-277`).
3. **Interaction OOD samples** — `sampled_values[2]`: 4 columns at offsets
   {−1, 0} (running-cumsum constraint, `constraint-framework/lib.rs:234-235`;
   the four-column count is asserted at `m31.rs:371-372`). The PCS adds a
   periodicity constraint for two-sample columns by reusing an existing sample
   value (`core/pcs/quotients.rs:313-326`); it is not another transmitted OOD value.
4. **Composition OOD samples** — `sampled_values[3]`: 8 columns at the OODS
   point; recombined by `extract_composition_oods_eval`
   (`core/proof.rs:25-57`) and DEEP-ALI-checked (`core/verifier.rs:99-114`).
5. **Query openings** — `queried_values`: M31 values at **at most 23 distinct**
   FRI query positions per tree (drawn after PoW, `core/pcs/verifier.rs:76-81`;
   duplicates removed at `core/queries.rs:41-49`). Shared/folded positions can
   also reduce decommitment sizes; 23 draws do not imply 23 unique openings.
6. **Decommitments** — per tree, `MerkleDecommitmentLifted { hash_witness:
   Vec<Hash> }` (`core/vcs_lifted/verifier.rs:19-22`; verified at
   `core/pcs/verifier.rs:104-116`).
7. **FRI first-layer + inner-layer proofs** — `FriProof { first_layer,
   inner_layers, last_layer_poly }` (`core/fri.rs:367-371`); each
   `FriLayerProof` carries `fri_witness` (complementary evaluations the
   verifier cannot recompute), `decommitment`, `commitment`
   (`core/fri.rs:392-399`). First-layer values at query positions are derived
   from OOD/query data by the verifier, rather than an additional transmitted
   copy (`core/pcs/verifier.rs:126-135`). Layer count depends on the actual
   variable lifting size; the fixed-lifting-23 C1 counts do not apply here.
8. **FRI final polynomial** — `last_layer_poly: LinePoly`, bit-reversed QM31
   coefficients (`core/poly/line.rs:115-123`), log_last_layer_degree_bound 0.
   Last-layer query evaluations are derived by folding and compared to this
   polynomial (`core/fri.rs:271-291`), not separately serialized evaluations.
9. **Claimed sum** — envelope-level `claimed_sum: QM31`, host boundary check
   (`lib.rs:44,122-126`).
10. **Config/shape/nonces** — `proof.config` (host-equality check,
    `lib.rs:93`), `proof.proof_of_work` (27-bit FRI PoW,
    `core/pcs/verifier.rs:76-79`), envelope `interaction_pow` (24-bit,
    `lib.rs:116-120`), channel binding of `d.words` + config
    (`lib.rs:57-63,107-110`).

## 4. What must change before the artifact hides inputs/positions/secrets/amounts/pad randomness

Measured benchmark facts that block hiding (contrasted with the spec):

- `leaves` publishes the commitments being consumed (`statement.rs:59-60`).
  Even the proposed hiding spec deliberately lists them as public; that conflicts
  with hiding which ledger notes are spent.
- `secrets`, `indices`, `siblings`, `amounts` are serialized verbatim in
  `PaymentStatement` (`statement.rs:61-70`) — the spec assumes the server
  learns only root/nullifiers/leaves/chain/pool/version/amounts-bound-in-preimages
  (`hiding-spec.md:17-25`).
- Host `validate()` reconstructs semantic rows from those clear fields
  (`statement.rs:121-139`); the boundary check (`lib.rs:122-125`) forces the
  proof's row multiset to equal the host's reconstruction, so the artifact
  proves statements about in-the-clear witnesses.
- Transcript binding mixes only `words` = domain, version, chain, pool, root,
  amounts, nullifiers, leaves, indices (`statement.rs:154-166`,
  `lib.rs:57-60`); secrets/siblings enter only via validate() equalities and
  the boundary sum.
- `felt_words` masks each 32-bit byte chunk to 28 bits instead of extracting
  consecutive 28-bit limbs (`statement.rs:33-49`), so distinct contexts can
  have identical transcript words. This must be fixed before binding qualification.
- Pad rows are deterministic from the **serialized** `pad_seed`
  (`statement.rs:75-78,140-152`) — the spec requires fresh OS CSPRNG pads,
  never serialized (`hiding-spec.md:151-153`).
- Amount range check is host-side (`statement.rs:120`); in-proof enforcement
  is a stated v2 component (`statement.rs:67-70`).
- Layout is currently statement-derived (variable lifting `log_size+3`,
  `lib.rs:53`; `padded()` next-power-of-two, `m31.rs:191-202`); the spec
  requires a fixed public log-10 / 1,024-row / 892-pad shape
  (`hiding-spec.md:37-46`).

No hiding claim is made or evaluated here; per `hiding-spec.md` the
construction rests on Assumption H (pad-feasibility hardness,
`hiding-spec.md:97-123`), pending Math Review.

## Drift check

Start of task: HEAD `0f5448bafe2885199482b8d5a512dc98745c5692`, working tree
clean. End of task: HEAD unchanged, but the tree shows `M AGENTS.md` (the
Sol→K3 worker-policy edit) and an untracked `bench/m31-statement/privacy-contract.md`
— both were made by the lead agent during this inventory, not by K3 or the
independent math reviewer; neither touches the inventoried sources.
`target/client-privacy-contract/k3-inventory.md` is this task's only output.
Astra integrated this source-checked copy as
`bench/m31-statement/server-observation-inventory.md`. No inventoried source
drifted. Note:
`bench/m31-statement/inventory.md` is the pre-existing design inventory
(companion doc), not duplicated here.
