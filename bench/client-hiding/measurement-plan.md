# Client-side hiding for custom S-two AIRs — plan

Status: **PLAN ONLY. No implementation.** Per the repo policy this is
soundness-critical crypto work: the construction spec and its lemmas require
Math Reviewer sign-off (gate M1) before any proof-system code is written.

## Problem

The compact client proof path (custom S-two AIR, e.g. the poseidon-membership
family) is **not hiding** today:

- Pinned stack: stwo `489a0f3` (2.2.0) + stwo-cairo `9b6be27` + stwo-circuits
  `5ef951a` (storage-only patches; proof format unchanged). No zk feature
  exists anywhere in stwo itself.
- Upstream `add_zk_blinding` (stwo-circuits only) appends random rows to **five
  circuit gates** (QM31, eq, triple-XOR, M31→u32, Blake G). It does not apply
  to AIR columns. Source review verdict: no-go as an existing supported AIR
  masking construction (`bench/client-privacy-feasibility/review.md`).
- Empirical leak: the direct-air diagnostic recovered **all four coordinates**
  of a synthetic private value from query+OOD observations
  (`bench/direct-air/privacy-review.md`).
- The server-side PROOF1 wrapper cannot restore privacy of an already-leaked
  client artifact; hiding must exist at the client layer.

## Root cause (from the pinned-source review)

Every committed column of every tree (preprocessed, original, interaction,
composition, and each FRI layer) is opened **in the clear**:

| Observation | Where |
| --- | --- |
| OOD evaluations of every committed column (more points for mask-offset reads) | `crates/stwo/src/prover/mod.rs:83`, `constraint-framework/src/component.rs:253-265` |
| Query evaluations of every committed column incl. **multiplicity columns** and **LogUp cumulative sums** | `prover/pcs/mod.rs:275-283`, `core/pcs/quotients.rs:120-160` |
| FRI inner-layer witness values (challenge-dependent linear functionals) | `core/fri.rs:365-399` |
| FRI last layer sent in full (degree log 0 → single QM31 coefficient) | `prover/fri.rs:196-213` |
| Claimed LogUp sums, roots, log sizes, PoW nonces (public) | `prover.rs:228-255` |

Openings are linear functionals of the trace rows. A column whose real (private)
content is sparse — few rows — is recoverable exactly: a single-row column `x`
opened at ζ gives `obs = L_j(ζ)·x`, and `L_j(ζ)` is computable for every
candidate row, so `x = obs / L_j(ζ)`. Conversely the direct-air failure showed
pads must be **independent per column**: the eq blinding row puts the *same*
random value in both compared columns, so the attacker's difference
`colA(ζ) − colB(ζ)` cancels the pad and exposes real content.

## Construction: random valid rows with per-column unknowns ("C1")

Append `B` random **valid** rows to each component of the client AIR:

1. **Pad rows satisfy every constraint** of their component, including
   participating in lookups with random values (random permutation inputs for
   Poseidon rows, uniform random limb values for range requests, random
   positions for table multiplicities). Soundness is unchanged: pads are honest
   auxiliary rows; no constraint, degree bound, transcript message or parameter
   changes.
2. **Every committed original column receives attacker-unknown entries** at pad
   rows (independent across columns; no eq-style shared pads). Poseidon
   components are bijections on their state, so random inputs make every state
   column exactly uniform; range-check value/limb columns are uniform by
   construction.
3. **Interaction columns are randomized via the pad lookups**: multiplicities
   receive `+1` at uniform-random table positions (the *position* is the
   randomness), cumulative sums are shifted by unknown fractions of random
   values.
4. **`B` is derived from the observation inventory**, not picked arbitrarily
   (the direct-air review forbids arbitrary padding as a privacy fix). Working
   estimate: `B ≈ #linear observation functionals per column` ≈
   `1 (OOD) + n_queries (23) + n_queries·#FRI layers (~6)` ≈ 160-256, to be
   computed exactly in M0. Upstream precedent supports `B ∝ n_queries`
   (`add_zk_blinding` is called with `n_padding = n_queries`).
5. **Fixed public shape**: `B`, padded log sizes, and the blinding scaffold are
   public and identical for every statement instance. No secret-dependent
   topology.
6. **Fresh OS CSPRNG seed per proof**; pads never reused across proofs or
   components.

### Why this can be exact rather than statistical

Working hypothesis to be proven (M1) and validated empirically (M3): the pad
rows parameterize a family of achievable "pad observations". Pad row `b` at
position `i_b` contributes `L_{i_b}(·) ⊗ row_b` — a rank-1 term — to the
`(observation-point × column)` matrix of openings. The Lagrange family at
random positions spans the observation-point space, and the valid-row manifold
of a wide component (e.g. Poseidon state rows) linearly spans the full column
space. Hence with `B ≥ #observation points`, the achievable pad matrices have
full rank, so **for any two valid traces there exist pads making the complete
observation set (OOD + queries + all FRI layers + last layer + claimed sums)
identical**. That is the existence half of a simulator argument; the remaining
half (commitments/transcript, Fiat–Shamir) follows the standard FS-ZK
compilation, anchored on Haböck–Al Kindi, ePrint 2024/1037 (witness
randomization + separate FRI masking), which the source review already
identified as the theory target requiring an explicit circle-domain/LogUp
mapping.

Known hard spots that M1 must resolve explicitly:

- **Multiplicity columns**: pad values are fixed `+1` (not uniform), so hiding
  rests on random positions + the public claimed-sum equation carrying unknown
  blinding fractions. Needs its own lemma (subset-sum ambiguity + claimed-sum
  entropy accounting).
- **Composition/quotient columns**: pad contributions enter through products
  of column evaluations; the rank lemma must extend to these columns.
- **Memory-table components**: pad reads must respect the memory model
  (which cells may be re-read); per-component design decision.
- **Table capacity**: verifier-checked multiplicity bounds must accommodate
  `+1` pads (verify in code; spread pads over 2^20 rows).
- **DEEP-ALI / FRI consistency** with padded traces (pads are valid rows, so
  consistency should hold by construction; confirm against the pinned code).

## Alternative paths (documented, not primary)

- **P2 — witness-polynomial masking** (masks vanishing on the constraint
  domain, à la Haböck–Al Kindi): exact ZK with strong theory, but requires
  degree slack / stwo component changes (bigger engineering + review). Fall
  back to this if C1's lemma fails review.
- **Fixed-Cairo privacy recursion wrapper**: measured at 4.59-4.78 GiB and its
  own privacy qualification is unresolved — not a shortcut.
- **zk-native SNARK fallback** (e.g. Groth16 native-BN254 desktop path): ZK by
  construction and already proven end-to-end, but a different server
  integration than the compact-STARK client path.

## Milestones

- **M0 — inventory + spec.** Derive the exact per-column observation
  inventory from the pinned code (OOD points, query openings, FRI layer
  openings, last layer, claimed sums); compute the required `B`; pick the
  target AIR (start with a tiny same-family membership relation, e.g. depth-8
  single path, for fast iteration; the real two-path depth-32 relation is the
  scaling target). Write the construction spec + lemma statements.
  *Done when:* inventory table with file:line refs, `B` derivation, spec and
  lemma statements exist.
- **M1 — Math Review gate (before implementation).** Independent review of the
  construction, the span/equalization lemma, multiplicity and composition
  accounting, soundness preservation, seed/position policy, and applicability
  to the actual component family (the client-privacy-feasibility gate).
  *Done when:* signed review with an explicit go/no-go.
- **M2 — implement pad generators** per component (poseidon chain/aggregator,
  range checks, memory table), `B` parameter, fresh-seed policy, behind a
  feature so the unblinded baseline stays byte-reproducible.
- **M3 — diagnostics battery** on the tiny relation:
  - rank harness: numerically measure achievable-pad-span rank vs observation
    dimension on the actual components;
  - recovery battery (extends the direct-air harness): OOD-only, query-only,
    combined, FRI-layer, multiplicity inference, cross-proof linkage; report
    ranks and recovery, never just "proofs differ";
  - statistical uniformity of openings vs simulator samples;
  - soundness regression: verifier accepts all padded proofs; existing
    mutation suites still rejected; unblinded baseline unchanged.
- **M4 — cost measurement** vs the unblinded baseline on pinned configs
  (rows added, log-size bumps, RSS, wall time, proof size), including
  bounded-memory mode composition and a WASM-randomness probe.
- **M5 — scale to the real depth-32 two-path relation**, re-run M3/M4.
- **M6 — decision.** Client-privacy qualification verdict for the membership
  family. The complete constrained payment statement and its binding remain
  separate work per TODO.md.

## Acceptance criteria

- Reviewed simulator/equalization argument covering the actual circuit family,
  all exported information and the randomness policy (the standing gate).
- Recovery battery: no extraction on the target relation; any finding reported
  as a blocked gate, never spun as success.
- Soundness suites unchanged and passing; proofs verify with the unchanged
  pinned verifier.
- Cost deltas published against the unblinded baseline.
