# Templar priorities

Current tracker, updated 2026-09-22. This is the implementation backlog;
[the specification](docs/push-payment-spec.md) and [ADRs](docs/adr/README.md)
define the architecture. Keep this checklist current as work lands.

The baseline is native S-two/PROOF1 proving, reusable push-payment addresses,
viewing and seed recovery, and optional controlled notes, validated in isolated
Sepolia experiments. The maintained production packages still need integration.
See [ordinary payments](bench/push-e2e/README.md),
[controlled payments](bench/controlled-push-e2e/README.md), and the
[capacity measurements](docs/native-shape-review.md) for evidence and limits.

## First priorities

**Active focus: proving memory.** Evaluate a compact client proof with server
wrapping alongside portable allocation-lifetime and buffer-reuse improvements
on the pinned PROOF1 pipeline. Browser/WASM proving is a strategic target, not
a release requirement yet; preserve that path while qualifying native desktops.
Record native-only workarounds separately. The server-wrapped design is recorded
in [Proposed ADR-0024](docs/adr/0024-compact-client-proofs-and-server-wrapping.md);
the accepted local proving architecture is unchanged.

- [ ] **1. Reduce desktop memory consumption.** Profile the prover's peak
  allocations and test changes to allocation lifetimes, trace construction, and
  concurrency without weakening proof security. Measure the whole wallet and
  prover together, with OS/browser headroom. Start qualification on a physical
  16 GiB desktop and report whether an 8 GiB profile is feasible. Current runs
  on the larger host do not qualify either physical desktop profile.
  **Done when:** repeated ordinary and controlled proofs, including the proposed
  maximum shape, fit an explicit desktop memory budget without swap or OOM;
  peak memory, latency, hardware, and any tradeoffs are published.
  **Working budgets:** first target an 8 GiB prover cap for a 16 GiB desktop,
  then a 4 GiB cap toward 8 GiB desktops. These are engineering targets, not
  qualified minimum hardware. For a future wasm32 browser build, aim below
  2 GiB of live proving memory to leave room for the runtime and wallet; track
  linear-memory high-water use separately from native RSS. Audit filesystem,
  networking, randomness, SIMD and thread dependencies before claiming WASM
  support. Physical desktop/browser qualification remains separate from caps
  imposed on this larger host.
  **Progress 2026-09-21:** [coefficient-backed proving](bench/bounded-memory/README.md)
  passes the first **8 GiB prover cap** with zero swap: three successive release
  proofs each for ordinary, controlled, ReturnNote and synthetic 8/8/4 workloads.
  Peak RSS is 5.84–6.31 GiB; proving takes 22.69–23.92 seconds on four physical
  cores of the development host. A matched fresh ordinary comparison in the same
  binary falls from 9.00 to 5.69 GiB while proving rises from 16.74 to 23.07
  seconds. All 15 completed proofs, including baselines, match earlier proof
  bytes and pass the original verifier; 45 mutations are rejected. Both Cairo
  and recursive stages retain coefficients and regenerate evaluations as needed.
  This follows the archived [stage-local](bench/prover-memory/README.md) and
  [Cairo commitment](bench/cairo-memory/README.md) reductions.
  **Still open:** the 4 GiB cap fails during Cairo base-trace expansion, before
  hashing. Expand columns in bounded batches during commitment and opening, and
  connect the tested streaming Merkle provider. One full tree is still built in
  the measured implementation. Then remeasure both stages toward 4 GiB and the
  browser budget. Add a minimal WASM build probe and remove filesystem coupling;
  qualify the whole wallet on physical desktops and portable CPU targets.
  Details and measurement limits are in the [memory review](docs/prover-memory-review.md).
  **Client-side ZK pathfinding 2026-09-22:** three tracks, all on this
  branch. [Client hiding](bench/client-hiding/measurement-plan.md): the C1
  construction spec (random valid rows, observation-inventory-derived B)
  received **conditional-go for investigation infrastructure only**; its
  hiding lemmas remain unproved ([review](bench/client-hiding/review.md)).
  [Compact recursion](bench/compact-recursion/README.md): the mini-verifier
  route measured an **unblinded** toy M0 floor of ~1.1 s / ~2.9 GiB at trace
  log 20; corrected full estimate ~4.3–4.6 GiB; conditional-go for M2 with a
  sample-structure extension blocking the adapter
  ([review](bench/compact-recursion/review.md)). The existing
  `add_zk_blinding` helper is the planned blinding route but was **not**
  called by the measured M0 ([inventory](bench/m31-statement/masking-api-inventory.md)).
  This is a generic toy recursion result; real M31-to-unchanged-PROOF1
  compatibility remains unverified.
  [M31 statement](bench/m31-statement/inventory.md): the public two-input
  hash/membership fixture measured **~11 MiB / 0.11 s**; the 892-pad workload
  measured roughly 48 MiB. The fixture has no output or conservation
  constraints, and its verifier receives the private data in clear. These
  figures do not measure a complete private payment. Rank/containment probes
  do not establish hiding or a sufficient pad budget. Gamma introduces a new
  pad-feasibility assumption; it is not qualified by a standard PRF argument.
  The independent [hiding review](bench/m31-statement/hiding-review.md) is
  complete: **NO-GO** for gamma as client privacy — the fixed-`x` simulator,
  complete-transcript argument and private relation semantics are absent; no
  practical attack claimed. The [private statement contract](bench/m31-statement/privacy-contract.md)
  and [server observation inventory](bench/m31-statement/server-observation-inventory.md)
  define the missing private relation and complete server boundary.
  The [context-binding repair](bench/m31-statement/results/context-binding/README.md)
  passed scoped review, five unit tests, a fresh V2 proof, 72 mutation
  rejections and rejection of the actual preserved V1 proof.
  **Polynomial masking M0:** the toy vector-product
  [mapping](bench/m31-statement/polynomial-masking-spec.md) and
  [source](bench/m31-statement/polynomial-masking-algebra-review.md) passed
  scoped mathematical review. The
  [exact-algebra diagnostic](bench/m31-statement/results/polynomial-masking-algebra/README.md) passes four
  deterministic fixtures: trace preservation, degree/FFT identities,
  same-public-input coupling, witness-free algebra-view simulation, pinned
  PCS normalization and five negative assertions per fixture. This is not
  FRI execution, a compiled private proof or a memory measurement.
  **Private membership milestone passed:** the
  [reviewed custom M31 proof](bench/m31-private-e2e/README.md) proves a private
  leaf preimage and depth-32 path. Three native proofs take **1.17–1.20 s /
  63–64 MiB peak RSS**; three Chrome WASM proofs take **1.89–2.12 s /
  79.94 MiB linear-memory high water**, stable across repeats. All six pass
  a separate native verifier given only public input and proof; browser
  verification also accepts a native artifact. Seven unit tests, seven
  external native negatives and twelve browser negatives pass. Proofs are
  roughly **3.4 MiB**. Research protocol/source review supports the stated
  96-bit classical RO-work target under its explicit assumptions; this is
  not a production audit or a full payment. Exact evidence is in the
  [results](bench/m31-private-e2e/results/README.md).
  **Independent review checkpoint complete:** the fresh
  [math challenge](bench/m31-private-e2e/independent-math-review.md) and
  [bounded PCS review](bench/m31-private-e2e/independent-pcs-review.md) found
  no concrete native acceptance bypass or single-proof witness disclosure.
  The math review corrects the weighted-theorem citation and qualifies the
  numerical claim as classical programmable-ROM knowledge error; an unrestricted
  adaptive multi-proof service theorem remains open.
  **Blake wrapper pathfinding:** the separately reviewed
  [Blake client](bench/m31-private-blake/README.md) preserves the membership AIR
  and M31 tree. Native proofs use **52.7–54.5 MiB / 0.98–1.03 s** and are
  **2.04–2.08 MB**; three Chrome WASM runs use **63.25 MiB** linear-memory
  high water. Native/browser cross-checks and version/mutation controls pass.
  A representative [954-compression Blake batch](bench/m31-private-wrapper/README.md)
  produces genuine unchanged PROOF1, accepted by the original verifier with
  exact facts, in **28.22 s / 29.05 GiB server RSS**. This proves hash work,
  not complete membership verification. Full cached authentication still
  exceeds the preserved direct-Cairo trace capacity.
  **Server circuit capacity checkpoint:** a
  [public hash circuit](bench/m31-private-wrapper/server-circuit/README.md) now
  proves in **6.75 s / 3.53 GiB** and verifies natively and in Cairo; seven Cairo
  mutation controls pass. The final unchanged PROOF1 attempt fails
  `Not enough twiddles!` after **7,301,958 OS steps / 34.35 GiB** under a64GiB
  cap, with no OOM. No PROOF1 was produced. Profile/reduce the Cairo bridge or
  establish supported larger final-wrapper capacity before porting the full
  client verifier; keep the working private client unchanged.
  **Capacity experiments completed:** [checked M31 inversion](bench/m31-private-wrapper/bridge-capacity/README.md)
  lowers bridge steps by **15.37%** and OS steps by **15.01%**, with all seven
  rejection controls passing. Actual padded Blake work still needs log22.
  The enlarged configuration builds, but proving is **OOM-killed at96GiB**;
  no new outer proof. The log20 PROOF1 ceiling is superseded by PROOF2 below.
  **PROOF2 large path 2026-09-23:** Starknet v0.14.4's
  [large-proof path](bench/m31-private-wrapper/proof2-large/README.md)
  (`privacy_recursive_prove_large`, Cairo traces log25–29) proves the same
  optimized bridge workload in **138 s / 61.4 GiB**. The V2 verifier accepts it,
  and 3 rejections pass. StarkWare's own sample transaction costs 87 s /
  42.1 GiB, which is the path's floor. Sepolia runs 0.14.4, but its gateway
  rejected PROOF2 on 2026-09-20; mainnet's 0.14.4 upgrade is scheduled for
  2026-10-05, pending governance.
  **Client verifier port (circuit A) 2026-09-23:** the
  [complete TMPZK002 verifier](bench/m31-private-wrapper/client-port/README.md)
  now runs as one stwo-circuits circuit (transcript, all openings, OOD from the
  client's own `air::constraints`, DEEP, FRI) and accepts all 6 retained proofs
  with one topology. A retained client proof goes **end to end** on
  `starkware-libs/proving@5a7c5ed`:
  - circuit A proves in **67 s / 39.9 GiB** (log23);
  - the unmodified upstream Cairo `circuit_air` verifier (FRI changed to
    blowup 2, 35 queries) checks it in 5.80M steps and pins circuit A's
    circuit hash;
  - the virtual OS emits the exact statement digest;
  - PROOF2 takes **142 s / 66.0 GiB** and is verified.

  Checks: 19 circuit tests, 8/8 bridge checks (pool, chain, root, digest, body,
  trailing, truncated) ([results](bench/m31-private-wrapper/client-port/results/proving-stack/README.md)).
  Synthetic fixture only.
  **Next architecture gate:** independent math review of circuit A (items in
  its PLAN.md), the pool-side `statement_digest` check, then a real Sepolia run
  through the user's node once the gateway accepts PROOF2.
  **stwo-circuits client route (parallel track) 2026-09-23:** the membership
  relation as a blinded stwo-circuits client proof reaches a verified PROOF2
  with no circuit A, both with the stock components
  ([2.75 GiB client, PROOF2 140 s / 63.1 GiB](bench/m31-private-wrapper/client-port/results/stwo-client-stock/README.md))
  and with our **arithmetic-only profile** (eq + qm31_ops, fork
  `broody/proving` branch `templar/arithmetic-profile`):
  - client **0.56 GiB**, 1 thread, or **0.28 GiB** with the bounded-memory
    PCS mode (ported onto the fork; the proof is identical); timing is
    PoW-dominated, 2.5–10 s;
  - the statement is output directly as limbs, with no hash;
  - the bridge takes 3.38M steps, 10/10 checks, including a claimed sum moved
    onto an absent component;
  - the OS takes 4.93M steps, exact message; the account is 49,851 felts;
  - PROOF2 takes **116 s / 52.2 GiB**, verified
    ([results](bench/m31-private-wrapper/client-port/results/stwo-client-arith/README.md)).

  **R0 payment up to submission 2026-09-23:** an ordinary 2-in/2-out
  payment (`src/payment.rs`, experimental Poseidon2-M31 formats) goes client
  → bridge → OS → PROOF2 locally:
  - client **2.2 GiB / 2.5–3.8 s**, or **1.1 GiB / 4.4–5.2 s** bounded, on 4
    threads; the original client-proves-everything pipeline measured
    9.00 / 6.12 GiB and 16.7 / 22.7 s on the same cores;
  - bridge 3.77M steps, 15/15 checks;
  - OS 5.42M steps, exact binding message;
  - PROOF2 **139 s / 64.2 GiB**, verified
    ([results](bench/m31-private-wrapper/client-port/results/stwo-client-r0/README.md)).

  **Lane-packed hashing:** four Poseidon2 permutations per QM31 row
  halves the trace to log19 (295k rows), with the same statement:
  - client **1.1 GiB / 2.0–3.6 s**, or **0.54 GiB / 2.4–2.6 s** bounded
    (4 threads);
  - bridge 3.53M steps, 15/15 checks;
  - OS 5.13M steps;
  - PROOF2 117.5 s / 55.0 GiB, verified
    ([results](bench/m31-private-wrapper/client-port/results/stwo-client-r0-lanes/README.md)).

  **Single-permutation tree nodes (experimental format):** a truncated
  Poseidon2 permutation per Merkle node, with the tree still 32 deep, takes
  R0 to 175k rows (log18):
  - client **0.58 GiB**, or **0.30 GiB / 1.7–2.0 s** bounded (4 threads);
  - bridge 3.39M steps, 15/15 checks;
  - OS 4.96M steps;
  - PROOF2 120.3 s / 54.4 GiB, verified
    ([results](bench/m31-private-wrapper/client-port/results/stwo-client-r0-compress/README.md)).

  The node format needs review before adoption.
  **Reviews 2026-09-23** (`client-port/reviews/`): math, bounded PCS,
  binding and Cairo performance are all CONDITIONAL GO for research use;
  `Tree::Compress` is NO-GO as laid out.
  - **Hiding H1, fixed:** blinding is now sized for every FRI coset
    opening (2,390 iterations, was 45), with no measurable cost
    ([results](bench/m31-private-wrapper/client-port/results/stwo-client-r0-blinding/README.md)).
  - **Fix list done**
    ([results](bench/m31-private-wrapper/client-port/results/stwo-client-r0-fixes/README.md)):
    - account CASM 82,828 → 59,152, under the 81,920 limit (absent
      components pruned by a feature), with a build-time check;
    - bridge 3.33M → 1.99M steps; OS 4.89M → 3.32M;
    - absent-sum forgery negatives in Rust, Cairo and the OS;
    - compressed-node fixed words moved to capacity positions;
    - per-format statement tags and liveness checks;
    - negative OS captures.
  - **Tree strategy: option A measured** ([bench/m31-pool](bench/m31-pool/README.md)).
    An on-chain Poseidon2-M31 tree against the felt252 reference pool, warm, same
    harness (snforge local VM):
    - 2-in/2-out spend: 101.6M L2 gas (8.8×) with single-permutation nodes, or
      207.0M (17.9×) with sponge nodes, against 11.5M;
    - deposit: 57.7M (9.2×) against 6.3M;
    - L1 data gas: similar to the reference.

    Hashing is over 90% of it. With the batched two-output append, at mainnet
    median prices:
    - transfer 1.11 STRK vs 0.24 (4.6×; 2.12 unbatched);
    - deposit 1.20 vs 0.13;
    - partial withdrawal 1.08 vs 0.14;
    - full withdrawal 0.039 vs 0.029, since it appends nothing.

    R0 V2 adds withdrawals (one circuit for all shapes), end to end through
    PROOF2 ([results](bench/m31-private-wrapper/client-port/results/stwo-client-r0-withdraw/README.md)).
    Not yet measured: the real fact check and whole-transaction cost.
  - **Next: server on the log20 small path.** The live transfer's PIE has
    three components at 2²¹ (`blake_g` from 13,616 Blake compressions;
    `cube_252` and `range_check_252_width_27` from the OS Poseidon hash of the
    29,866-felt calldata). Everything else is ≤ 2²⁰. Levers: client FRI
    queries/blowup/PoW, calldata packing.
  Not yet measured: the pool's on-chain `apply_spend` with an M31-tree
  append.

  - **Open notes on the compact path (2026-09-24):** R0 V3 adds a public
    execution intent and an optional identity handle; the M31 pool gains
    `apply_spend_with_invoke` (INVOKE for Ekubo/Vesu-style adapters, COMPUTE
    for shadow accounts). A local end-to-end run settles a real client proof
    and real PROOF2 through the PROOF2 adapter
    ([results](bench/m31-pool/results/open-note-e2e.json)). Spec:
    [open-note-spec.md](docs/open-note-spec.md). **Pending:** the math review
    and adversarial tests (deferred until after implementation, per the
    user), a shadow-account end-to-end with upstream's unchanged anonymizer,
    and inclusion on Sepolia (blocked on PROOF2 gateway acceptance). Sepolia
    2026-09-24: deposits on chain; the proof-carrying Ekubo swap into an open
    note succeeds in simulation (299 B funded, 3.80 STRK); the gateway rejects
    PROOF2 ([evidence](bench/m31-sepolia/results/v3-open-note/)).
  Open for this route:
  - review of the fork's profile;
  - the hiding question (broody/templar#2), under test per
    [hiding-test-plan.md](bench/m31-private-wrapper/client-port/reviews/hiding-test-plan.md).
    **H2 found and fixed:** add-only qm31 blinding left `dst − op0 − op1`
    unblinded (~156 witness-only values per proof). Fork `4de7408a6` adds a
    mul blinding row; the rank audit finds 0 unblinded combinations
    ([results](bench/m31-private-wrapper/client-port/results/hiding-leak/README.md)).
    Upstream's blinding has the same structure; draft in broody/templar first.
    Done since: per-point rank test (openings exactly uniform), seed-invariant
    search over base and interaction trees, and a full-transcript search
    with pinned challenges (0 witness-dependent invariants at 35 queries;
    the pre-fix control finds H2). Draft argument in
    [hiding-argument.md](bench/m31-private-wrapper/client-port/reviews/hiding-argument.md),
    which reduces to open items O1–O5: composition and deep-FRI values are the
    missing piece (a FRI masking polynomial would close it). **H3:** blinding
    limbs are u32 mod p (~2⁻¹⁶ statistical distance per proof), unfixed.
    **Upstream (stock `5a7c5ed`, full profile, production config):** H2
    confirmed end to end (70/70); new **H4**, an unblinded `blake_g_gate`
    LogUp batch (unused blinding outputs, multiplicity 0)
    ([stock-hiding](bench/m31-private-wrapper/stock-hiding/README.md)). These
    affect StarkWare's privacy-proof blinding; disclose privately (draft in
    broody/templar#2);
  - the payment relation written once for both routes;
  - a WASM measurement.
  **Remaining client gates:** R0 payment constraints and any required private
  range/lookup machinery, then complete ordinary 2-in/2-out native and WASM
  client measurements.
  No format migration or production change is approved by these
  experiments; the accepted local-proving architecture is unchanged.
  **Compact-client pathfinding:** the [synthetic Cairo bridge](bench/direct-air/README.md)
  accepts two saved Rust circuit proofs, rejects nine altered inputs, and passes
  four serialization/transcript tests. VM verification takes 2.03–2.12 seconds
  and 0.77–0.78 GiB RSS; this is not PROOF1 wrapping time. The upstream circuit
  baseline fails a 2 GiB client cap and completes at 2.61 GiB under an 8 GiB cap.
  Fixed lookup tables still dominate this tiny relation. That baseline's
  client privacy is not qualified; its further disclosure diagnostics are
  deferred at the user's request.
  **Poseidon/membership follow-up:** the [public two-path benchmark](bench/poseidon-membership/README.md)
  proves the real felt252 hash at depth 32 without Cairo CPU/OS execution.
  Existing bounded storage cuts RSS from 4.28 to 1.97 GiB; three fresh runs pass
  a 3 GiB cap at 14.08–14.14 seconds on one thread. A 2 GiB cap passes once then
  OOMs, so it is unreliable. All eight completed proofs are byte-identical;
  three unit tests, 13 verifier rejections and three boundary controls pass.
  **Browser follow-up:** the [WASM membership port](bench/wasm-membership/README.md)
  generates and verifies four proofs in Chrome 153, all byte-identical to the
  preserved native artifact. Three proofs in one worker take 40.93–41.72 seconds
  each with stable 2.150 GiB linear-memory capacity. A fresh browser also passes
  a 4 GiB process-group cap; browser plus harness peaks at 2.21–2.23 GiB with
  zero swap. Page heartbeat remains active and the preserved native verifier
  accepts the browser output. This qualifies the public arithmetic's browser
  portability, not the complete private client or consumer hardware.
  **Privacy feasibility review:** [source inspection](bench/client-privacy-feasibility/README.md)
  found the concrete fixed-Cairo privacy workflow, but did not establish a
  supported hiding construction for the custom AIR or a new verifier-circuit
  topology. The relevant blinding helper is unchanged in the current upstream
  monorepo. Public membership's host-side path and lookup checks must also
  become constraints before those inputs can be hidden. An upstream upgrade or
  successful recursive verification alone does not close these requirements.
  **Isolated wrapper cost:** the unchanged fixed-Cairo recursion alone takes
  4.78 GiB RSS / 11.50 seconds on four workers and 4.59 GiB / 35.17 seconds on
  one worker; both configurations fail a 4 GiB cap. Three final synthetic
  proofs match byte-for-byte and verify with the original libraries. This is
  a native reference cost, not the cost of a new compact private construction.
  **M31 tree hash pathfinding 2026-09-21:** the [public M31 experiment](bench/m31-tree/README.md)
  replaced felt252 tree hashing with pinned Plonky3 Poseidon2-M31 for two public
  depth-32 paths. The isolated tree proof drops to 0.48–0.49 seconds and 0.017 GiB
  RSS natively (browser 4.2 seconds, 20 MiB linear memory), versus the felt252
  baseline's 14.08–14.14 s / 1.97 GiB. But the mixed union workload (tree plus the
  ordinary residual 62 felt252 permutations) still peaks at 1.899 GiB RSS and
  1.900 GiB browser linear memory, and the straightforward Cairo M31 tree costs
  ~154× the felt append gas per warm single insert. **Decision: do not adopt a
  tree-only hash migration on this evidence.** It is promising for M31-native
  client arithmetic; client privacy construction, complete constrained payment
  logic and affordable contract integration are unresolved. The mixed binding
  retains its independent one-felt root; no ABI or production change.
  **Public append integration 2026-09-21:** the [append experiment](bench/m31-append/README.md)
  produces one/two-append proofs with roughly 17–31 MiB client RSS and verifies
  them in Cairo. The unchanged virtual OS executes the one-append verifier,
  but PROOF1 generation remains blocked: 16 GiB server OOM, then a 64 GiB run
  reaches 29.27 GiB RSS and fails with `Not enough twiddles!` against the
  preserved fixed domain parameters. No verified outer artifact or local
  settlement result exists. Profile and reduce the largest Cairo verifier trace
  components before retrying this outer route; increasing RAM alone does not
  establish compatibility. This public experiment does not close client privacy
  or complete private-payment memory requirements.
  **Next decision:** obtain construction-specific review covering the actual
  circuit family, exported information and randomness policy, then implement
  the complete constrained statement and measure its client cost. Continue fixed-table/trace-expansion
  memory work with that total budget in view. Recommended follow-ups from the M31
  pathfinding: resolve the supported client privacy construction and full
  constrained statement first; investigate removing the remaining felt252 table
  overhead (for example a separately reviewed smaller-table AIR while preserving
  hashes, or a broader hash redesign only with a viable contract-cost plan).
  Neither option is implemented or approved. Full 2-in/2-out, PROOF1 wrapping
  and complete private-payment WASM remain open; public-path or synthetic bridge
  measurements do not qualify a private-wallet memory budget.

- [ ] **2. Build a shared public-data indexer for wallets.** Index commitments,
  positions, encrypted deliveries and authenticated return amounts, roots, spent
  nullifiers, and canonical block
  metadata. Add bulk downloads, incremental cursors, local caching, reorg
  handling, and cold restore. Decrypt and match ownership/spent status locally;
  do not upload keys or use wallet-specific address/nullifier queries. Verify
  returned data against chain commitments where possible, and document the
  remaining completeness, RPC, and access-pattern trust assumptions. Support
  provider fallback and self-hosting.
  **Done when:** incremental sync and seed restore agree with chain fixtures
  across reorgs, missing data, and provider failure; benchmarks at increasing
  pool sizes separate download, decryption, and spent-status costs. Historical
  ciphertext retention must be part of the service contract.

- [ ] **3. Increase the supported limit to 8 inputs / 8 outputs / 4 withdrawals.**
  Adopt counted active entries and version the statement, pool binding,
  controller approval format, and SDK together. Preserve note/nullifier
  semantics and define compatibility with existing deployments. Private change and funded return notes
  are included in the total output slots; the current one-token and controller constraints
  still apply. Keep wallet batch sizes adjustable below the protocol ceiling.
  **Done when:** funded maximum-size ordinary and controlled transactions pass
  on Sepolia using `sncast`, including viewing, recovery, withdrawals, and
  adversarial rejection checks; proof transport, fees, and desktop memory are
  qualified. Synthetic proof success is already measured; the live pool remains
  at 4/4/2 until this work is implemented and validated.

Memory profiling and indexer development can proceed independently. Production
integration below is needed to ship these improvements together; desktop
qualification gates the default wallet batch size.

## Architecture pathfinding before formats are frozen

- [x] **Re-evaluate open notes and atomic DeFi returns.** Start with one swap
  through an adapter to an existing protocol, returning the actual proceeds to
  a recipient-owned tree note. Use ordinary notes; controller approval is not a
  dependency of this experiment. Investigate
  proof-bound swap terms/executor, a recovery-compatible receipt for an unknown
  output amount, and atomic rollback. See the [reassessment](docs/defi-return-review.md).
  **Done when:** a scoped prototype passes adversarial settlement and seed-restore
  tests, works against a supported DeFi deployment on Sepolia using `sncast`, and
  records a go/no-go decision with memory, fees, privacy, and trust implications.
  The current protocol stays unchanged while this is evaluated.
  **Completed 2026-09-21:** the [ordinary-note experiment](bench/defi-return-e2e/README.md)
  passed four native spends, ten on-chain rejection checks, real Ekubo settlement,
  fresh recovery, and spending of the returned note. [Decision and confidence](docs/defi-return-review.md):
  proceed to a reviewed integration design; desktop/production qualification is open.

- [x] **Specify return notes and the upstream adapter boundary.** Adopt `ReturnNote`
  internally and retain `OpenNoteDeposit` at the compatibility boundary.
  [ADR-0023](docs/adr/0023-return-notes-and-adapter-compatibility.md) and the
  [return-note specification](docs/return-note-spec.md) define atomic funding,
  exact intent binding, recovery, and combined output limits.
  The [reference](bench/return-note-e2e/README.md) passes unchanged upstream Ekubo
  execution, fresh recovery and a private payment on Sepolia: two native spends,
  six rejected transactions, 11 Python tests and 24 Cairo tests. Vesu supply/redeem
  is covered against a mock vault only.

- [ ] **Qualify the return-note integration before freezing formats.**
  Independently review the versioned return receipt and bound intent; qualify
  production adapters/tokens and wallet failure/fee handling. Resolve the security and
  interoperability questions in the experiment's review before promoting it into
  maintained packages. Controller support is not a prerequisite.

## Next: turn the validated flows into a wallet

- [ ] **4. Integrate the experiments into maintained contracts and SDK packages.**
  Establish one canonical implementation of note encoding, delivery encryption,
  statement and execution-intent serialization, return receipt funding, controller
  approval hashing, and native proof
  submission. Carry over golden vectors and adversarial tests into CI.
  **Done when:** a reproducible end-to-end flow uses maintained packages rather
  than benchmark-only implementations, with compatible versioned artifacts.

- [ ] **5. Make transaction submission reliable.** Exercise the intended wallet
  transport, proof attachment, fee estimation, and gas funding. Handle stale
  roots, expired controller approvals, nonce conflicts, interrupted submissions,
  and receipt reconciliation with bounded retries that cannot silently pay twice.
  Document the privacy implications of the transaction sender and any relayer.
  **Done when:** users can resume after each failure without guessing whether
  payment occurred, and see the expected fee before submission.

- [ ] **6. Finish wallet storage, receiving, viewing, and recovery UX.** Add secure
  seed storage, a versioned receiving-address format, recipient verification,
  backup/restore, and explicit incoming/full viewing exports. Preserve controller
  conditions after restore and distinguish unspent value from value currently
  spendable with available approvals. Include note selection, change, voluntary
  consolidation, and bounded handling of unsolicited notes.
  **Done when:** a fresh wallet can receive offline, restore from backup and
  public history, show accurate balances and conditions, and spend recovered
  ordinary and controlled notes without benchmark tooling.

- [ ] **7. Define and implement controller operations.** Specify policy decisions,
  approval expiry, minimal retained metadata, availability expectations, and
  behavior when approval is denied or the service is unavailable. Decide key
  rotation, revocation, and whether any escape mechanism is permitted by a note's
  policy before committing to an implementation; recovery alone does not remove
  a controller condition.
  **Done when:** the approved lifecycle has a documented trust model and tests
  for downtime, refusal, rotation/revocation, and replay, as applicable.

## Before a production release

- [ ] **8. Review cryptography and freeze interoperable formats.** Obtain independent
  review of key derivation, spending/viewing separation, encrypted delivery and
  commitment binding, controller authorization, and proof/public-input binding.
  Define address, backup, viewing-export, and protocol version compatibility.
  Start this alongside integration, before users depend on durable formats.
  **Done when:** material findings are resolved and published test vectors cover
  every supported format and compatibility boundary.

- [ ] **9. Qualify contracts, tokens, and deployment governance.** Validate intended
  production tokens and adversarial token/callback behavior, conservation and
  amount bounds, verifier/configuration authority, historical data availability,
  and deployment or migration procedures. Pin and qualify the native prover and
  verifier versions, then complete independent contract review and a release
  checklist with an explicit mainnet decision.
  **Done when:** the supported environment and trust assumptions are documented,
  release checks pass, and outstanding findings have an explicit disposition.

## Deferred until measurements or product needs justify them

- [ ] Explore larger or asymmetric shapes, especially many outputs versus many
  inputs. The native experiments show materially different costs; 16/16/8 and
  larger are not desktop-qualified product promises.
- [ ] Revisit payment channels only if a concrete use case needs properties that
  reusable push payments do not provide. They are not required for repeated
  payments to the same receiving address.
