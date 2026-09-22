# Templar priorities

Current tracker, updated 2026-09-21. This is the implementation backlog;
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
Record native-only workarounds separately. The server-wrapped design remains an
experiment; the accepted local proving architecture is unchanged.

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
  passed Math Review as **conditional-go** with the L2 two-stage lemma as
  the blocking condition ([review](bench/client-hiding/review.md)).
  [Compact recursion](bench/compact-recursion/README.md): the mini-verifier
  route (verify a custom-AIR proof in-circuit, blind with the existing
  helper) measured an M0 floor of ~1.1 s / ~2.9 GiB at trace log 20;
  corrected full estimate ~4.3–4.6 GiB; conditional-go for M2 with a
  sample-structure extension blocking the adapter
  ([review](bench/compact-recursion/review.md)).
  [M31 statement](bench/m31-statement/inventory.md): the full-M31 payment
  statement (Plonky3 width-24 Poseidon2, byte-identical vendored AIR)
  measured **~11 MiB / 0.11 s** for the payment shape, pad-cost curve
  measured, the felt-binding residual resolved to ~zero by a word-tuple
  facts convention, and the rank probe measured the equalization target at
  **matrix rank 68** (24/24 statement pairs) with `dim span(M) ≥ 128` —
  an honest hiding budget of **B ≈ 68–100 pads**, client-with-hiding
  estimate **15–20 MiB**. The remaining gate is the L2 lemma itself
  (bounded nonlinear solves per pad position, or the statistical
  smoothing bound), then Math Review. All measurement-grade; no format
  commitment; the accepted local-proving architecture is unchanged.
  **Compact-client pathfinding:** the [synthetic Cairo bridge](bench/direct-air/README.md)
  accepts two saved Rust circuit proofs, rejects nine altered inputs, and passes
  four serialization/transcript tests. VM verification takes 2.03–2.12 seconds
  and 0.77–0.78 GiB RSS; this is not PROOF1 wrapping time. The upstream circuit
  baseline fails a 2 GiB client cap and completes at 2.61 GiB under an 8 GiB cap.
  Fixed lookup tables still dominate this tiny relation. Client privacy is not
  qualified; further disclosure diagnostics are deferred at the user's request.
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
