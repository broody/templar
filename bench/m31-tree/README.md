# M31 tree hash pathfinding

2026-09-21. Isolated, user-authorized performance experiment. Existing note
formats, deployed pools, accepted prover and earlier benchmark archives remain
unchanged. This experiment uses public synthetic inputs and does not establish
zero knowledge or a complete private payment relation.

The question is whether replacing felt252 Merkle-tree hashing with a reviewed
M31-friendly construction materially reduces S-two client resources, and what
that costs in contract execution and storage. Hash selection, exact parameters,
encoding and new AIR constraints are reviewed before implementation. The bundled
S-two Poseidon demonstration with placeholder constants is not a candidate.

The selected application hash is pinned Plonky3 Mersenne31 Poseidon2, width 24,
8 full and 22 partial rounds, wrapped in its `Pad10Sponge<24,15,9>` construction.
The nine-element digest is represented by two canonical Starknet felts. Exact
framing, constants, encoding and review boundaries are specified in the review.
The S-two proof's own Blake2s commitments and transcript remain unchanged;
changing the application's note tree is distinct from changing the proof system's
internal commitment hash.

## Comparison

1. Preserve the existing two-depth-32-path felt252 native/browser measurements
   as the baseline, with explicit security settings and memory accounting.
2. Prove two public depth-32 paths using the selected M31 construction with
   independent permutation/hash vectors and full public path binding.
3. Add the felt252 hashing that remains in an ordinary 2-input/2-output payment
   to the same measured client. This tests whether fixed tables erase the
   isolated tree benchmark's memory gain. It is a hash-workload comparison,
   not a complete payment implementation.
4. Measure equivalent Cairo contract insertions, including zero-tree
   initialization, node/root-history storage, digest encoding and batches of
   1/2/4/8 leaves. Distinguish cold initialization from steady-state inserts;
   local resource estimates are not Sepolia or mainnet fee quotes.

The latest ordinary reference is
`bench/return-note-e2e/cairo/src/statement.cairo`, using ordinary `ctrl=0`,
two inputs, two outputs and no withdrawals or external return. It retains
ownership derivations, input/output commitments, nullifiers and a padded public
binding. Their exact hash-call inventory belongs in the reviewed workload
description. No private fixture from prior funded flows is used.

For that ordinary shape, the retained hashes require 62 felt252 Hades
permutations across 17 hash-span calls: 32 for the two inputs' ownership,
commitment and nullifier work, 14 for output commitments, and 16 for the padded
public binding. The mixed benchmark is an explicit union of these arithmetic
requests and the new tree. The original binding's one-felt root remains an
independent public workload value; this experiment does not define a new
two-felt-root payment ABI or claim a complete payment proof.

The [measurement plan](measurement-plan.md) records the run sequence and memory
accounting before timed proofs. The [construction review](review.md) records the
exact hash, framing, AIR boundary, security scope and verification requirements;
the [Cairo plan](cairo-plan.md) fixes the matched append/storage algorithm.

## Acceptance evidence

- Exact source/parameter provenance, digest strength and lossless canonical
  encoding are recorded; native, independent reference and Cairo vectors agree.
- Proofs bind the public paths, direction bits, leaf/root endpoints and all
  arithmetic requests. Malformed encoding, changed claims and corrupted proofs
  are rejected. Valid proof creation alone is insufficient.
- Native and WASM outputs agree for the same workload; browser measurements
  include real worker execution, repeated proofs, memory high-water use and
  whole-browser process accounting. Native RSS is a distinct metric.
- Timed prover runs do not overlap builds or other benchmarks. Record CPU
  budget, caps, swap/OOM events, latency, proof size, fixed/dynamic table shape
  and which allocations coexist.
- Contract comparisons use the same tree and root-history algorithm and
  distinguish hashing, packing and storage consequences where tooling permits.
- Preserve old archives and report a decision without silently migrating the
  protocol or claiming a supported privacy construction.

## Status

Complete for this scope; decision recorded 2026-09-21. Construction review in
[review.md](review.md) is frozen by the Math Reviewer, who independently checked
all 16 measured proof artifacts. Full data: [results/measurements.md](results/measurements.md)
and [results/aggregate.json](results/aggregate.json).

**Decision (Astra): do not adopt a tree-only hash migration on this evidence.**
M31 arithmetic sharply reduces the isolated public tree proof's cost, but the
mixed union workload retains the large felt252 lookup tables and leaves little
browser headroom, and the straightforward Cairo M31 tree carries a severe
execution-cost penalty. This is promising evidence for M31-native client
arithmetic; the client privacy construction, complete constrained payment
logic, and affordable contract integration remain unresolved.

**Verification evidence:** 6/6 native unit tests; 36/36 Cairo correctness tests
(golden, packing, rejection, history, snapshot); 16/16 Cairo cost cells
measured; 8/8 native proofs verify in runtime; all 8 browser proofs
byte-identical to native references; native `--verify-tests` on browser exports
rejects 19 mutations + 2 boundary controls (tree) and 17 + 3 (mixed); archive
integrity final passed. The failed v1 run (pre-fix empty-preprocessing verifier
mismatch) and the default step-budget Cairo failures are preserved alongside
the reviewed v2 fix and the explicit raised local test budget.

**Native (1 pinned CPU, no swap):** tree-only 0.480–0.491 s, 0.017 GiB RSS,
envelope 197,320 B (bare STARK 166,809 B), lifting log 11, sha256 `d8f4881c…`,
×3 at a 1 GiB cap. Mixed 16.108–16.352 s, 1.899 GiB RSS / 1.897 GiB cgroup,
envelope 464,900 B (bare 404,305 B), lifting log 23, sha256 `d069e307…`, ×3 at
3 GiB plus two fresh 2 GiB probe passes. Prior felt252 two-path baseline
(`bench/poseidon-membership`): 1.97 GiB RSS, 14.08–14.14 s — kept as a separate
session's metric.

**Browser (headless Chrome 153, one worker):** tree 4.19–4.28 s, WASM linear
high-water 20,709,376 B, browser+harness cgroup ≤ 0.314 GiB, ×3+fresh at 1 GiB.
Mixed 75.8–77.2 s, linear high-water 2,040,070,144 B, cgroup ≤ 2.168 GiB,
PSS ≤ 2.138 GiB, ×3+fresh at 3 GiB. Prior felt252 browser baseline
(`bench/wasm-membership`): 2.150 GiB linear, 40.93–41.72 s, group 2.21–2.23 GiB.

**Cairo `append_batch` per-selector L2 gas** (snforge 0.63.0, local VM
resources, not network fee quotes or on-chain executability): felt cold
1/2/4/8 = 8.00M/13.09M/23.24M/43.47M; felt warm = 5.12M/10.18M/20.27M/40.38M
(seed_snapshot 6.90M separate); M31 cold = 1.571B/2.359B/3.934B/7.084B; M31 warm
= 0.788B/1.575B/3.150B/6.300B (seed_snapshot 12.39M separate). M31 batch-8 first
OOM-killed at the 8 GiB cgroup cap (failures preserved) and passed at 16 GiB —
a passing cap, not a measured minimum — in one authorized retry per cell. M31 warm-1 append is ~154× the felt warm-1
append gas in this straightforward port.

**Limitations:** repeated deterministic fixtures (including the same grinding
search) measure runtime stability, not latency distributions. The 128-bit
application-hash design target is separate from the configured 96-bit PCS
metric. The mixed workload is a labeled hash union retaining its independent
one-felt binding root; no new ABI is adopted. The M31 prefix-8 warm fixture is
oracle-derived; genuine Cairo snapshot comparisons cover prefixes 1/2 (felt
baseline 1/2/8). Physical consumer desktops, full-wallet memory, other browsers
and mobile remain open qualification work. This does not migrate the protocol.
