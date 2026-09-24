# Client SDK: protocol and engineering review (pre-implementation)

- **Reviewer role:** independent protocol and engineering reviewer. I did not write the design.
  The cryptographic constructions (key derivation, address and viewing-key formats) are left to
  the separate Math Reviewer and are not reviewed here.
- **Date:** 2026-09-24.
- **Document:** `docs/sdk-spec.md`, revision 1 ("design, revision 1, for review"), the
  uncommitted working-tree copy on `feat/hidden-assets`.
- **Method:** nothing is implemented, so every finding is reasoned from the spec and checked
  against source:
  - the pool: `bench/m31-pool/cairo/src/{pool_v2,spend4,spend,assets,tree,adapter}.cairo`;
  - the client: `client-port/Cargo.toml`, `src/lib.rs`, `examples/wallet.rs`,
    `examples/support/mod.rs`;
  - the proving stack's manifests under `target/proving-arith/crates`;
  - the server: `server/prover/src/{api,main,pipeline,ohttp}.rs` and `server/README.md`;
  - the bench flows: `bench/m31-sepolia/{hidden_asset_flow,simulate_spend}.py` and the Sepolia
    README;
  - specs: `docs/hidden-asset-spec.md` §6–7, `docs/prover-server-spec.md` and `TODO.md` items 2
    and 4–6;
  - starknet.js `develop` (v11.0.2) and the v10.8.0 docs, read through the GitHub API:
    `src/account/default.ts`, `src/channel/rpc_0_10_2.ts`, `src/provider/rpc.ts`,
    `src/utils/stark/index.ts`, `src/wallet/accountV6.ts`, `CHANGELOG.md` and
    `www/docs/guides/account/proofs.md`.
- **Output:** this file is the only change I made.

## Verdict: CONDITIONAL GO

The layering is right: one Rust core, a thin WASM façade, a TypeScript layer over starknet.js,
and local paths from a full leaf list. So are the bulk-events receiving rule and the use of the
pool's own checks (nullifiers, root history, adapter age bound). The claims I checked against
the deployed contracts hold:

- `apply_spend(spend, proof)` with `Spend ‖ 0`, because the adapter asserts `proof.is_empty()`;
- the `NotePublished`, `NullifierSpent`, `AssetRegistered` and `PolicySettled` fields;
- `get_leaf_count`, `get_root` and `get_verifier`;
- the ciphertext word bounds;
- the facts layout and message hash;
- `submit_after = base + 11` and `valid_until = base + max_proof_age`.

Three things are not ready:

- WASM feasibility of the actual prover stack is unproven, and the helpers cannot move
  "unchanged" (SDK-P1).
- The retry and double-submit story is incomplete. It can pay twice, and it collides with the
  server's per-note deduplication (SDK-P2, SDK-P3).
- The starknet.js submission path does not do what §9 says (SDK-P4).

**Conditions:**

- SDK-P1 must pass as a gating spike before core work starts.
- SDK-P2, SDK-P3 and SDK-P4 must be resolved in the spec before the submission code is written.
- SDK-P5 to SDK-P11 must be resolved before any release.

## Findings

### SDK-P1 — High — §2, §7.3, §13: the WASM prover build is unproven and has concrete blockers

**Problem.** Neither earlier browser experiment used this stack:

- `bench/wasm-membership` is a felt252 relation on another stwo.
- `bench/m31-private-e2e` is a custom protocol on the `target/m31-append` stwo snapshot.

`client-port` and its circuit stack (`circuits`, `circuit_prover`, …) have never been built for
wasm32. The client-port result notes still list "WASM portability of the circuit prover" as
open. Concrete blockers in what §7.3 says moves "unchanged" into the library:

- **Runtime file reads.** `support::bridge_fri()` (`examples/support/mod.rs:31`) reads
  `circuit_fri_config.json` from the filesystem at run time. `production_targets()` (`:50`)
  parses a Cairo source file. `config()` calls the first, so every proof depends on a file that
  does not exist in a browser.
- **An environment override of the FRI parameters.** `bridge_fri()` accepts `TEMPLAR_FRI`
  (`:37`). An SDK must not accept it, on native builds either.
- **Panics as control flow.**
  - `native_verify` panics.
  - `negatives` (`:142`) and `forgery_negative` use `catch_unwind`. Under wasm32's
    `panic=abort` this cannot work, and the instance traps.
  - `prove_relation` asserts the blinding budget and uses `Instant::now()`
    (`wallet.rs:330`), which panics on `wasm32-unknown-unknown`.
- **The dependency graph.**
  - `templar-private-membership` (the "oracle") is a non-optional dependency on a third stwo
    snapshot (`target/direct-air`). It is compiled into every build, even though the `oracle`
    feature it is gated on does not exist in `[features]`.
  - `src/lib.rs` pulls `air.rs`, `hash.rs` and `constants.rs` from `bench/m31-private-blake`
    by `#[path]`.
  - `circuit_prover` depends on `stwo_cairo_prover`, which pulls `stwo-cairo-adapter` and
    `cairo-vm`. That crate carries wasm32 cfgs (it drops sonic-rs and overrides getrandom),
    which is encouraging but untested here.
- **Cost unknowns.** Single-threaded grinding of the 26-bit FRI PoW plus the interaction PoW,
  the `.wasm` size, and SIMD (`+simd128`) are all unmeasured. §12.4 measures but sets no
  thresholds.

**Required change.**

- Add a milestone-0 spike, gating the rest of the SDK:
  1. build `payment4` proving for `wasm32-unknown-unknown`;
  2. prove an R4 spend in a Web Worker;
  3. check that the proof is byte-identical to the native proof under a seeded RNG;
  4. pass it through `templar-prover check`.
- Rewrite §7.3:
  - The FRI config and component targets become compile-time constants, with a native test that
    they equal the pinned files.
  - No `TEMPLAR_FRI`, no `negatives` or forgery runs, no `Instant`.
  - Every check returns `Result` (including the blinding-budget and self-verification checks).
  - The oracle becomes an optional dev dependency.
  - The `#[path]` sources are vendored into `sdk/core`.
- Add pass/fail thresholds to §12.4:
  - proof time and peak linear memory, in Node, in desktop Chrome and in one mobile browser
    (the product goal is a phone client);
  - `.wasm` size;
  - the grinding share of proof time.

### SDK-P2 — High — §7.2, §9 (Reconcile, Window), §10.3: retries can pay twice; there is no in-flight state

**Problem.** §9 says an interrupted submission is resolved by syncing, and "the same nullifiers
cannot settle twice". That holds only while every retry spends the **same** input notes. Nothing
in the spec guarantees that.

- **Double payment.** Spent status comes only from `NullifierSpent` (§6). Between proving and
  inclusion, the inputs look unspent. A re-plan can therefore select different notes, for example
  after "re-prove from the start" (§9), a page reload, or a second `transfer` call. The old
  transaction can still land until `valid_until`, because the adapter accepts
  `current − base ≤ max_proof_age`. If it does, the recipient is paid twice.
- **Reverted exit.** Re-selecting the same in-flight note for another spend passes simulation on
  `latest` and reverts at inclusion. That costs a fee and publishes an exit's calldata (HA-M11).
- **Nothing to resume from.** `WalletStore` (§10.3) holds none of this: the plan, the
  ciphertexts needed for the calldata, the job id, the result, the signed transaction and its
  nonce. The server cannot submit for the wallet, so a lost `proved` object makes a finished
  large proof useless.

TODO item 5's condition ("resume after each failure without guessing whether payment occurred")
is not met.

**Required change.** Add a normative in-flight record to `WalletStore`, written before each
network step:

- plan id and input nullifiers;
- the proved statement, binding, ciphertexts and calldata;
- the server URL, the job id and the exact submission body;
- the result;
- the signed transaction hash, nonce and `valid_until`.

Rules:

- Notes named in a live record are not selectable.
- A spend that re-plans a record must reuse exactly its input notes until the earlier attempt is
  provably dead. That means one of:
  - the latest block is past its `valid_until`;
  - the transaction is `REJECTED`;
  - the transaction is `REVERTED` and the nullifiers are still unspent.
- A record closes when its nullifiers appear in `NullifierSpent` (settled) or when it is dead
  (the notes are released).
- Document that two devices on one seed cannot coordinate this.

### SDK-P3 — Medium — §8, §9: interaction with the server's per-note deduplication and backoff

**Problem.** The server keys deduplication on input 0's nullifier (`statement.rs:177`):

- Any different body for that note gets **409** while a job is queued, running or **done**,
  until retention ends (default one hour, `limits.retention_secs`).
- Each refusal sets an exponential backoff (`api.rs:242`, `backoff << min(count, 10)`).
- The backoff is checked **before** the identical-resubmission shortcut. Once refused, even the
  exact original body returns 429 until the backoff lapses.

Consequences for the SDK:

- "Re-prove from the start" (§9) with a fresh client proof is refused.
- "A failed check discards the result" (§8), followed by a retry, is refused.
- A naive retry loop locks the note out for longer and longer.

A done job whose proof became unusable blocks that note at that server for up to the retention
window. This happens, for example, when its root is evicted from the 256-root ring before
submission, or when the facts check fails.

**Required change.**

- Persist the job id and the exact body (SDK-P2). Recover by polling, never by resubmitting.
- On 409 or 429, do not retry automatically. Surface the retention time from `/v1/info`, and
  offer another server or a wait.
- Specify which server-side conditions free a note.
- Recommend a server change: release deduplication when a done job's root is no longer known,
  or when its `valid_until` has passed.

### SDK-P4 — Medium — §9, §13: `account.execute` does not simulate the exact signed transaction; account types

**Problem.** In starknet.js v10 and v11, `Account.execute(calls, {proof, proofFacts})` works as
follows (`default.ts` `prepareInvoke`):

1. it calls `estimateInvokeFee`, which sends `proof_facts` and `proof`;
2. it signs a **new** transaction with the estimated bounds;
3. it broadcasts that transaction.

It never simulates. `Account.simulateTransaction` and `channel.simulateTransaction` default to
`skipValidate: true` and `skipFeeCharge: true`. So §9's "simulate the exact signed transaction,
then send with `account.execute`" sends a different transaction, with a new signature and
possibly different bounds, from the one simulated.

A caller-supplied `WalletAccount` or `WalletAccountV6` (browser extension wallets) has no
`getSignedTransaction`, so it cannot give the SDK a signed transaction before broadcast. It
attaches proofs only through the STRK20 wallet-API path (`executeWithProof`).

§13 says "starknet (v10)", but v11.0.0 shipped on 2026-09-14. If the package bundles its own
starknet copy, it will not match an `Account` built from the application's copy.

**Required change.** Specify this sequence:

1. `estimateInvokeFee(calls, {proof, proofFacts, skipValidate: false})`;
2. apply the fixed margin (SDK-P10);
3. `account.getSignedTransaction(calls, {proof, proofFacts, resourceBounds})`;
4. a raw `starknet_simulateTransactions` with empty `simulation_flags` on that exact object;
5. `provider.invokeSignedTx(signedTx)` of the same object.

Both `getSignedTransaction` and `invokeSignedTx` exist since v10.x.

Also:

- State that v1 supports signer-backed `Account` only, and that `WalletAccount` is out of scope
  (or a documented weaker path simulated with `SKIP_VALIDATE`).
- Make `starknet` a `peerDependency` with a tested range, and pick v10 or v11 explicitly.
- Warn when the submitting account's class is older than Sierra 1.7: it is billed in Cairo steps,
  about 2.7× the fee (`bench/m31-sepolia/README.md`).

### SDK-P5 — Medium — §6, §8, §14: targeted reads that the privacy rules do not forbid

**Problem.** The rule "bulk events only" is achievable. Every pool event has only the selector as
a key, so `starknet_getEvents{address: pool, keys: [[selectors…]]}` with continuation tokens
fetches everything without naming a note. But several reads the spec implies are targeted:

- **ERC20 metadata.** §6 says "read in bulk and cached (HA-P10)", but ERC20 assets have no
  on-chain registry. The first `decimals()` or `symbol()` for a token just received in a hidden
  transfer tells the RPC provider that the wallet holds it.
- **NFT metadata.** Fetching an NFT's `token_uri`, and then the URI itself over HTTP or IPFS,
  reveals ownership to third parties.
- **The base-block hash check** (§8) reads one specific recent block right after a job
  completes. That is a timing marker for the coming submission. It protects nothing essential:
  the sequencer verifies the base-block hash, and a mismatch is rejected statelessly.
- **Transaction-status polling** (`waitForTransaction`) on a provider other than the one that
  received the submission links the two.
- **Incremental `from_block`** values link sessions across IP changes.

**Required change.**

- Metadata comes only from a pinned token list, or is fetched for the **whole** asset universe
  (bulk `Deposited` and `AssetRegistered`), independent of what the wallet owns.
- No automatic `token_uri` resolution. Make it opt-in, through a proxy.
- Drop the base-block hash read, or take it from a block range already fetched by sync.
- Poll transaction status only through the submitting account's provider.
- Round `from_block` down to the checkpoint boundary.
- Add these to §14.

### SDK-P6 — Medium — §8 (OHTTP): the bootstrap defeats OHTTP; transport details

**Problem.** The key configuration comes "from `info()` over a direct connection", and `info()`
is verified "before first use". A client then contacts the server directly, from its real IP,
moments before its OHTTP-wrapped job. The timing links the two, which is what OHTTP exists to
prevent (PS-13 already requires polling over OHTTP).

Other gaps:

- Relays forward to a gateway they are configured for; an arbitrary relay URL does not work.
- The client proof is about 30,234 felts, about 2 MB as hex JSON. The result is about 340 KB
  base64. Relays may cap body sizes.
- The `ohttp` crate's default crypto backend is NSS, which does not build for wasm32.

**Required change.**

- Pin the key configuration in the network constants. Otherwise fetch it directly only on a
  schedule decorrelated from jobs, and cache it.
- When OHTTP is configured, send every server request (`/v1/info`, jobs, polls) through the
  relay, and make no direct request in the same session.
- Accept a key configuration only from a pin or a direct TLS fetch, never unencapsulated through
  the relay.
- On a decapsulation error, re-fetch at a decorrelated time.
- Name the relay requirements (target gateway, body limits), or use a compact binary encoding.
- Build `ohttp` with the `rust-hpke` backend.

### SDK-P7 — Medium — §8, §10.1: `/v1/info` verification and result checks as specified are incomplete

**Problem.**

- `Proof2Adapter` has **no getters** (`adapter.cairo`). Its `pool`, `statement`,
  `statement_class`, `os_program`, `max_proof_age` and `account_tag` can only be read with
  `getStorageAt(adapter, sn_keccak(name))`, as the server's startup does (`main.rs`). Such reads
  mean nothing unless the adapter's class hash is also pinned.
- `check_result(…, info, …)` takes the server's `info` as an input, which lets untrusted data set
  the expected values.
- The result checks omit several fields the server returns and the SDK can check.

**Required change.**

- Read adapter storage by `sn_keccak` and pin the adapter's class hash.
- Compare everything to the SDK's pinned constants. `info` only has to agree with them, and the
  info circuit hash must equal the pinned one.
- Pass pinned constants, not `info`, into `check_result`.
- Add these result checks:
  - `relation == "r4"`;
  - `facts[4] == base_block`;
  - `base_block ≤ latest`;
  - `result.binding` equals the SDK's own binding;
  - `result.asset` equals the plan's exit asset, or zero;
  - the proof is valid base64 and no larger than a pinned maximum;
  - `submit_after = base + 11` and `valid_until = base + max_proof_age` are computed locally,
    never taken from the server.
- Re-read `get_verifier` immediately before simulating. The pool's owner can re-point it.

### SDK-P8 — Medium — §5, §6 (Completeness, Reorgs), §7.3: sync and tree mechanics are underspecified

**Problem.**

- **No rollback path.**
  - The `Tree` API (`new`, `append`, `root`, `len`) has no truncate or rollback.
  - Checkpoints do not record the leaf count, spent-set position or owned notes, so a rollback
    cannot undo spent marks or credited notes.
- **"Pending" does not match RPC 0.9/0.10.** `latest` is already `ACCEPTED_ON_L2`. The not-yet
  state is `pre_confirmed`, which has no block hash and cannot take part in the same-block
  completeness check.
- **Root selection** (HA-P8.5) and a requirement that a spend be planned only on a `complete`
  sync at the latest block are missing. An incomplete tree gives a root the pool never had, so
  the proof would be wasted.
- **Duplicate events.** "Repeated event credits once" must also treat *conflicting* duplicates
  for one index as incomplete.
- **The worker and the tree handle.** A WASM handle cannot cross instances. `prove_spend(seed,
  plan, tree)` in a worker cannot use a `Tree` owned by the main thread's instance.

**Required change.**

- Add `Tree.truncate(n)`, or rebuild from stored leaves.
- Checkpoints store the leaf count, the per-block spent and credited deltas, and the block hash.
- Define the tree and the completeness check on `latest` = N only: events up to N, and
  `get_leaf_count`, `get_root` at N. Show `pre_confirmed` notes as pending and never append
  them.
- Make notes spendable only after a stated confirmation depth.
- Before planning, always sync to latest and use the latest complete root.
- Treat conflicting duplicates as incomplete.
- Either make `prove_spend` pure, with the plan carrying the root and paths, or run tree and
  proof in the same worker.
- Document provider constraints: page limits, block-range caps, and historical state reads at N.

### SDK-P9 — Medium — §10.3: the store is a plaintext transaction history by default

**Problem.** Owned notes (asset, amount, `rho`) together with their nullifiers identify every
on-chain spend the wallet made. Once SDK-P2 is applied, the store also holds in-flight
statements. The spec leaves encryption "the application's choice", so the shipped IndexedDB store
is plaintext, exposed to device access, profile theft or XSS. The store also has no schema
version and no guard against several tabs syncing at once.

**Required change.**

- The shipped persistent stores encrypt at rest by default (AEAD, with a key derived from the
  seed under its own label, subject to the Math Reviewer).
- Add a store schema version and migrations.
- Take a Web Locks (or equivalent) lock per chain and pool.
- Store the highest account index created, and a local sent-payment history, documented as not
  recoverable from the seed.

### SDK-P10 — Low — §7.2, §9, §14: fingerprints and linkability should be fixed by the SDK, not left open

**Problem.**

- HA-P8.5 asks wallets to converge on root selection and fee policy. The SDK is the reference
  implementation, but it fixes neither exactly:
  - bounds are "1.5×" of what, for which resources and prices?
  - what tip?
  - which root? (see SDK-P8)
- Output and input ordering must use the core CSPRNG. The spec does not say where the shuffle
  happens.
- v1 submits only from the caller's own account, which is public and often also the depositor.
  The API gives no signal that the spend is linkable.

**Required change.**

- Specify the fee rule: which resources, the margin, `tip = 0`, and the price bound source.
- Specify root selection (latest complete root).
- Shuffle in the core.
- Have `submit` return, or require acknowledgement of, `linkable: true` in v1. Warn when the
  submitting account has deposited into this pool.

### SDK-P11 — Medium — §13: the release is gated on the H2 disclosure; more inputs need pinning

**Problem.**

- The WASM prover is built from the private `broody/proving-private` fork carrying the H2 fix.
  Publishing `@templar/sdk` publicly ships that code in compiled form. A binary diff against
  upstream reveals the fix, which amounts to disclosure before the private process completes.
  A private dependency also prevents independent reproducible builds.
- §13 pins one source. The build also consumes:
  - `target/direct-air` stwo (oracle);
  - `bench/m31-private-blake` sources by `#[path]`;
  - the `stwo_cairo_prover` and `cairo-vm` chain;
  - `wasm-bindgen-cli`, whose version must equal the crate's;
  - `wasm-opt`;
  - getrandom 0.2 (`js`) and 0.3 (which needs `--cfg getrandom_backend="wasm_js"`).

**Required change.**

- State the release gate: no public package before H2 is disclosed; a private registry until
  then.
- Pin every source input by commit or sha256.
- Publish a reproducible build recipe with the `.wasm` sha256 and SRI.
- Configure both getrandom backends.
- Enable npm provenance for releases.

### SDK-P12 — Low — §2, §12.2: seeded-RNG tests contradict "never accept a caller seed"

**Problem.** §2 says WASM exports never accept an RNG seed. §12.2 needs a seeded WASM proof to
compare byte for byte. Comparing to the bench `wallet prove4` also needs the bench's `OsRng`
draws (seed, dummy input, dummy position) to be plumbed to a seeded RNG.

**Required change.**

- Put seeded exports behind a test-only cargo feature, with a separate artifact name.
- Add a CI check that the release `.wasm` does not export them.
- Plumb the RNG through the bench wallet for the vector run.

### SDK-P13 — Low — §12: the acceptance plan does not test the network-behaviour and failure rules

**Problem.** §12 tests formats and one happy path. Nothing verifies the privacy rules or the
recovery paths.

**Required change.** Add these tests:

- **Network trace.** A recording RPC and server proxy asserts that a full sync, a transfer and a
  withdrawal make:
  - only bulk `getEvents` calls and reads of public constants;
  - no per-note, per-nullifier, per-root or per-asset calls;
  - no direct server contact when OHTTP is configured.
- **Fault injection:**
  - an omitted or conflicting event gives `complete: false`;
  - a reorg across a checkpoint;
  - a crash and resume at each in-flight stage (SDK-P2);
  - a 409 or 429 from deduplication;
  - window expiry;
  - root eviction before submission;
  - OHTTP key rotation;
  - an attempt to re-plan with different inputs while a record is live.
- **Thresholds** for §12.4 (SDK-P1).

### SDK-P14 — Low — §3.2, §6, §7.2: recovery and exit guards

**Problem.**

- **Account indexes.** Recovery scans `0 ..= k + 3`, but nothing stops a wallet from creating
  index `k + 5`. Notes there would be missed on restore.
- **ERC721 withdrawals.** `pay_out` uses `transfer_from`, with no receiver hook. An NFT sent to a
  contract that cannot move it is stranded. Only ERC1155 recipients are checked.
- **Unknown ERC20 assets.** A received note of an arbitrary ERC20 (a spoofed "USDC") displays
  whatever the contract claims.

**Required change.**

- Refuse to create an index beyond the highest used index plus 3.
- For ERC721 withdrawals, warn when the recipient has no class or does not support `ISRC6_ID`.
- Identify ERC20 assets by address against the pinned list, and flag others as unverified.

### SDK-P15 — Info — §1, §9: scope realities

- Today no spend can be included anywhere. The Sepolia gateway returns
  `PROOF_VERSION_NOT_ALLOWED`, and mainnet 0.14.3 does not list PROOF2. §12.5 correctly accepts
  a signed-transaction simulation plus the recorded gateway response.
- Simulation does not verify the large proof. A bad proof from a server is caught only at the
  gateway (statelessly, with no fee), so a proof-encoding error cannot be caught before a gateway
  accepts PROOF2.
- **Fees.** Each spend costs about 3.1–3.5 STRK on Sepolia, including about 75M `gas_per_proof`.
  A spend of three or more notes needs `n − 1` consolidations, each with a server proof and a
  fee. Show the expected fee before submission (TODO item 5).
- If the pool's verifier stops matching the pin, the SDK fails closed. It should also refuse
  **deposits** in that state.
- Recovery cost is one X25519 per ciphertext per scanned index, from the deployment block. That
  is fine on Sepolia. At scale it needs TODO item 2 (the indexer), which is correctly out of
  scope.

## Answers to §15 (within this review's focus)

**Q1–Q2** are for the Math Reviewer. Two format-adjacent points are covered above: SDK-P14 (the
gap-limit guard) and the rule that a payer rejects addresses for another chain or pool (correct;
keep it).

**Q3 — The secret boundary.** Acceptable. A stateless core that takes the seed per call keeps
derived keys out of JavaScript. However:

- The seed itself necessarily lives in JavaScript: in the wallet object, and copied to the worker
  by `postMessage`.
- The core should zeroize derived material (`zeroize`).
- Terminate the proving worker after each proof: linear memory never shrinks, and it retains key
  material.
- Every error path must be a `Result`, not a panic. An abort traps the instance and loses the
  Tree and OHTTP handles (SDK-P1).
- The larger leak is the store (SDK-P9), not the WASM boundary.

**Q4 — Receiving, completeness and reorgs.**

- The receiving rules match HA-M5 and the pool. The ciphertext bounds equal `delivery_digest`'s,
  and the `AssetRegistered` source is the pool.
- The completeness criterion is sound and achievable: `getEvents` to block N, then `get_leaf_count`
  and `get_root` at N, with contiguous indexes.
- Reorg handling and "pending" need the mechanics in SDK-P8.
- Targeted metadata reads need closing (SDK-P5).

**Q5 — Spend planning.**

- The ordering rules are right, provided the shuffle is in the core (SDK-P10): outputs uniformly
  shuffled, a single real input always in slot 0 with a fresh dummy in slot 1 (required by the
  relation and by the server's deduplication key), two real inputs shuffled.
- The dummies follow `hidden-asset-spec.md` §6.
- The plan reveals nothing on chain beyond §7 of that spec. It fingerprints through root age and
  fee bounds (SDK-P10).
- The missing piece is in-flight locking (SDK-P2).

**Q6 — Result checks and the submission window.**

- The window (`submit_after ≤ latest ≤ valid_until − 20`) matches the adapter's
  `base < current ≤ base + max_proof_age`.
- Compute the window locally, and add the checks in SDK-P7.
- Reuse of a client proof is blocked by server deduplication for the retention period
  (SDK-P3).
- Re-planning must keep the same inputs until the earlier attempt is dead (SDK-P2).
- The exact-transaction simulation needs the starknet.js sequence in SDK-P4.

**Q7 — The supply chain.** See SDK-P11. The binding constraint is the H2 disclosure. After that
come the unpinned local snapshots and the WASM toolchain.

## Re-review (revision 2)

- **Date:** 2026-09-24.
- **Document:** `docs/sdk-spec.md`, revision 2 (working tree), with its §16 resolution table.
- **Scope:** only the text that changed, within this review's focus.
- **Also checked:**
  - `client-port/Cargo.toml`: the oracle is now `optional`, behind the `oracle` feature
    (default on for the bench).
  - starknet.js at tag `v10.8.0`, read through the GitHub API: `src/account/default.ts`,
    `src/channel/rpc_0_10_2.ts`, `src/provider/rpc.ts`, `src/global/constants.ts`,
    `src/utils/stark/index.ts`, `src/provider/types/response.type.ts`.
  - `npm view starknet dist-tags`: `latest` 10.8.0, `next` 11.0.2.
  - The four V4 Sepolia cases' `proof-facts.txt`. `facts[6]` is identical in all six retained
    proofs, so pinning it is sound. Proofs are 250–258 KB raw, about 344 KB as base64, under the
    480,000-byte cap.

### Verdict: CONDITIONAL GO

Revision 2 resolves most findings. Conditions:

- The notes-release rule in §9.1 still allows a double payment (SDK-P16). It must be fixed in the
  spec before the submission code is written.
- The fee and tip rule in §9.2 does not do what it says with starknet.js as it is (SDK-P17).
  It must be made precise before that code is written.
- SDK-P18 and SDK-P19 are editorial or low-severity.

### Status of SDK-P1 to SDK-P15

| Finding | Status |
| --- | --- |
| SDK-P1 | **Resolved in the spec.** §7.3 adds a gating milestone 0 with thresholds (≤ 30 s, ≤ 1.5 GiB linear memory, `.wasm` ≤ 16 MB) and a rewritten library `prove` module: compile-time constants, no `TEMPLAR_FRI`, `Instant`, `catch_unwind` or negatives, checks returning `Result`. The oracle is optional (verified). The departure (keeping `#[path]` sources in-repo, pinned by the repo commit and the check script) is acceptable: in one repository it pins the same thing. The spike itself is still open. |
| SDK-P2 | **Partly resolved.** In-flight records, locking, same-input re-plans and dummy reuse are right. The "provably dead" rule is not: see SDK-P16. |
| SDK-P3 | **Resolved on the SDK side** (§8: job persisted, no automatic retry, retention reported). The server change as decided is fine. §8 still describes the rejected root-eviction release: see SDK-P18. |
| SDK-P4 | **Resolved in approach.** Signer-backed `Account` only. The peer dependency `>=10.5 <11` is sound: `getSignedTransaction` and `invokeSignedTx` date from 10.3.0, and `latest` on npm is 10.8.0. The five-step sequence needs precise starknet.js usage: see SDK-P17. |
| SDK-P5 | **Resolved**, with one residual: re-reading the exact last-processed block's hash links sessions just as `from_block` did (SDK-P19). |
| SDK-P6 | **Resolved.** Pinned or application-supplied key configurations, every request through the relay, no fallback, `rust-hpke`, stated relay size requirements. |
| SDK-P7 | **Resolved.** The adapter class is pinned and its storage read by slot; `check_result` takes the pins; the checks are complete; the window is computed locally; the verifier is re-read. |
| SDK-P8 | **Resolved.** `Tree.truncate`, pure proving from plan paths, checkpoint deltas, `latest`/`pre_confirmed` semantics, a spendable depth, conflict handling. |
| SDK-P9 | **Resolved.** One nit is in SDK-P19 (store keys). |
| SDK-P10 | **Partly resolved.** The root rule, core shuffling and `linkable: true` are right. The fee rule is not implementable as written (SDK-P17). |
| SDK-P11 | **Resolved.** One wording error is in SDK-P19 (lock file). |
| SDK-P12 | Resolved. |
| SDK-P13 | **Resolved.** Tests for SDK-P16 and SDK-P17 should be added. |
| SDK-P14 | Resolved. |
| SDK-P15 | Resolved. |

### New findings

#### SDK-P16 — High — §9.1: `REJECTED` and `REVERTED` do not make an attempt dead; the proof can be replayed until `valid_until`

**Problem.** §9.1 releases a record's notes when:
- the transaction is `REJECTED`; or
- it is `REVERTED` and its nullifiers are unspent.

Neither makes the attempt dead. `apply_spend` does not check its caller. The adapter checks only
the facts' message and base-block age, not who submits. So anyone holding the calldata (including
the ciphertexts), the proof and the facts can land the same spend from their own account until
`valid_until`. Several parties hold all three:

- **The RPC provider** receives the complete signed transaction, proof included, at
  `estimateInvokeFee`, at simulation and at submission (§9.2 steps 1, 4 and 5). This happens
  whether or not the gateway rejects it. Today every proof-carrying transaction is rejected
  (`PROOF_VERSION_NOT_ALLOWED`) but was still seen.
- **The prover server** holds the proof and facts. After a revert, the calldata (with ciphertexts)
  is public on chain, so it can resubmit.
- **Anyone who observed the transaction's propagation.**

The rule then fails like this. The wallet releases the notes after a revert or rejection and
re-plans with *different* inputs. Someone replays the original before `valid_until`. The
recipient is paid twice: the SDK-P2 hazard, reintroduced.

A replay of the original spend is otherwise harmless, since its outputs are fixed. The danger is
only in releasing the notes early.

**Required change.**
- An attempt is dead only when the latest block is past the `valid_until` of **every** result the
  record has obtained. A record settles when its nullifiers are spent, as now.
- `REJECTED` and `REVERTED` only permit resubmitting the same result or re-proving with the same
  inputs, as §9.1 already allows for reverts.
- State that until `valid_until`, notes stay locked even when a spend cannot currently be
  included (about 4,096 blocks with today's adapter).
- Add a §12.6 fault-injection case: a rejected or reverted attempt, then a re-plan with other
  inputs, is refused before `valid_until`.

#### SDK-P17 — Medium — §9.2 steps 1–4: fee, tip and simulation details against starknet.js 10.8

**Problem.** Several details of §9.2 do not match starknet.js 10.8:

- **The estimate is already inflated.** `account.estimateInvokeFee` returns only
  `resourceBounds` (and `overall_fee`). Those bounds already carry the global
  `config.resourceBoundsOverhead`, by default +50% on every amount and price
  (`toOverheadResourceBounds`, `constants.ts`). "The estimate's amount × 1.5 and its price × 2"
  applied to them gives 2.25× the amount and 3× the price. With `starknet` a peer dependency, the
  application can also change that global config. The bounds, which §9.2 means to be uniform
  across SDK users (HA-P8.5), therefore vary per application.
- **The tip is not zero by default.** With no `tip`, `resolveDetailsWithTip` fetches
  `getEstimateTip()[defaultTipType]` (default `'recommendedTip'`). That gives a network-dependent
  tip in both the estimate and the signed transaction, contradicting "`tip = 0`".
- **There is no public raw RPC call.** `fetchEndpoint` is `protected` on the channel. The public
  paths are `provider.channel.fetch(method, params)`, which returns an HTTP `Response` to parse,
  and a plain JSON-RPC POST. `Account.simulateTransaction` and `channel.simulateTransaction`
  default to `skipValidate: true` and `skipFeeCharge: true`, so they cannot be used for step 4.
- **The simulation block is unspecified.** The signed transaction's nonce comes from
  `getNonceForAddress` at the provider's default block tag. Simulating at `latest` while the
  account has a transaction in `pre_confirmed` fails on the nonce.
- **"The provider" is ambiguous.** `Account` does not extend `RpcProvider` in v10.8; it holds
  `account.provider`. §9.2 must say which provider sends and polls.
- **Proof fields need RPC 0.10.1 or later.** On an older channel, starknet.js reports
  `snip36RequiresRPC010`.
- **Balance.** Starknet requires the account's balance to cover `Σ max_amount × max_price`. With
  ×1.5 on amounts and ×2 on prices, that is about 3× the expected fee: roughly 10 STRK for a
  spend on Sepolia.

**Required change.**
- Pass `tip: 0` explicitly in steps 1 and 3.
- Compute the bounds from the raw estimate fields (`l1_gas_consumed`, `l1_gas_price`,
  `l1_data_gas_consumed`, `l1_data_gas_price`, `l2_gas_consumed`, `l2_gas_price`). Obtain them
  either by:
  - `account.accountInvocationsFactory(...)` (with proof, proof facts and `skipValidate: false`)
    followed by `provider.channel.getEstimateFee(invocations, { skipValidate: false })`, which
    returns them unmodified; or
  - a raw `starknet_estimateFee`.
- Never use `resourceBounds` from `estimateInvokeFee`.
- Send step 4 as a raw JSON-RPC `starknet_simulateTransactions` at `pre_confirmed` (the nonce's
  view), with `simulation_flags: []`.
- Route steps 1–5, the `get_verifier` re-read, the recipient checks and status polling through
  `account.provider`, and assert that its spec version is 0.10.1 or later.
- Before signing, show the user the expected fee and the maximum fee, and check the balance.
- Add a §12.5 assertion that the signed transaction has `tip = 0` and the specified bounds.

#### SDK-P18 — Low — §8 contradicts §16 on server-side release; how "root has left" is detected

**Problem.**
- §8 says a note is freed at a server when a finished job's `valid_until` has passed "or its root
  has left the pool's history". The decided server change (§16, SDK-P3) releases on `valid_until`
  only.
- With the default one-hour retention, which is shorter than 4,096 blocks, a re-proof after root
  eviction still waits for retention at the same server.
- §9.2 re-proves "if the root has left the pool's 256-root history" but does not say how that is
  determined. §12.5 forbids per-root calls, so `root_is_known` is excluded.

**Required change.**
- Delete the root-eviction clause from §8. State the expected wait (the retention period, or
  another server).
- Define root-eviction detection: the simulation's revert reason `UNKNOWN_ROOT`, which is already
  a spend-specific read, or a local reconstruction of the 256-root ring from the grouped events.

#### SDK-P19 — Low — consistency nits

- **§6 events.** The filter lists only `NotePublished`, `NullifierSpent`, `AssetRegistered` and
  `PolicySettled`. Yet the metadata rule reads "every ERC20 that has ever been deposited (from bulk
  `Deposited` events)". Add the `Deposited` selector, and cap metadata reads against spam
  deposits.
- **§6 reorgs.** "Re-reads the last processed block's hash" asks the provider for exactly the
  previous session's tip, which links sessions like the old `from_block` did. Verify the hash of
  the checkpoint the incremental sync restarts from, and always roll back to that checkpoint
  before re-fetching.
- **§1 vs §7.2 and §10.1.** §1 still gives "note selection" to TypeScript; §7.2 and `plan_spend`
  put it in the core. Also state that `plan_spend` receives paths for every candidate note, or is
  split into select-then-path.
- **§10.3.** Encrypting record contents is not enough if IndexedDB keys or indexes are nullifiers,
  leaf indexes or assets. Keys must be opaque, or the state stored as sealed blobs.
- **§13.** "Through the fork's lock file" is wrong. Path dependencies into the fork resolve under
  the SDK workspace's own `Cargo.lock`, which must be committed and built with `--locked`.
- **§2.** "No panics on any input" can be enforced for the main-instance functions (scan, tree,
  decode, store, OHTTP). It cannot be guaranteed inside the proving dependencies. State that a
  proving trap is contained by the per-proof worker and reported as a failed proof.

## Re-review (revision 3)

- **Date:** 2026-09-24.
- **Document:** `docs/sdk-spec.md`, revision 3.
- **Scope:** only §9.1 (SDK-P16) and §9.2 (SDK-P17), as requested.
- **Checked against:**
  - `bench/m31-pool/cairo/src/tree.cairo` (`initializer`, `insert_leaf`, `insert_two`,
    `record_root`);
  - `pool_v2.cairo` (`publish`, `append_notes`);
  - starknet.js at tag `v10.8.0`: `src/account/default.ts`, `src/account/types/index.type.ts`,
    `src/provider/rpc.ts`, `src/provider/modules/responseParser/rpc.ts`,
    `src/channel/rpc_0_10_2.ts`.

### Verdict: CONDITIONAL GO

The model behind SDK-P16 is now right. Once a statement has left the wallet, neither a rejection,
a revert, a passed `valid_until` nor a nonce advance ends the record, because the server can
re-wrap the client proof. Only root eviction or a spent nullifier ends it. Re-plans share
nullifiers, so at most one settles.

The eviction arithmetic is wrong, and in the unsafe direction (SDK-P20). §9.2 step 1 relies on
fields `estimateInvokeFee` does not return (SDK-P21). Both must be fixed in the spec before the
submission code is written.

### Status

- **SDK-P16:** the concept is resolved; the arithmetic is not (SDK-P20).
- **SDK-P17:** resolved except step 1 (SDK-P21). The following names exist in 10.8:
  - `tip`, `proof`, `proofFacts`, `skipValidate` and `resourceBounds` on `UniversalDetails`;
  - `account.getSignedTransaction`;
  - `account.provider.invokeSignedTx`;
  - `channel.fetch`, which is public.

  Passing `tip: 0` explicitly correctly bypasses `resolveDetailsWithTip`'s network-recommended
  default. Simulating at `pre_confirmed` with empty flags through `channel.fetch` is sound.

### SDK-P20 — High — §9.1: the pool records one root per insert call, not per leaf; `m + 256` leaves can leave the root live

**Problem.** `record_root` runs once per `insert_leaf` and once per `insert_two`. `insert_two`
appends two leaves and records a single root ("the intermediate root is never recorded").

- `apply_spend` appends its two outputs with `append_notes`, which is one `insert_two` call.
- Deposits (`publish`) are one `insert_leaf` each.
- A policy spend with two outputs is one `insert_two`.
- An invoke with `2 + n` notes records `⌈(2 + n) / 2⌉` roots.

So a leaf count of `m + 256` may reflect as few as 128 recorded roots. The ring keeps a root until
**256 further roots** are recorded:
- `initializer` puts the empty root in slot 0 and sets `root_ring_index = 1`.
- `record_root` writes slot `r mod 256` and first evicts that slot's occupant once
  `r ≥ 256`.
- So the root written at ring index `r` is evicted exactly when ring index `r + 256` is
  written. That includes the empty root, evicted by the 256th insert call.

On a pool whose traffic is mostly spends, the wallet would declare a record dead, and release its
notes, while its root is still accepted. That reopens the double payment SDK-P16 closed.

**Required change.** Count evictions in **root records**, not leaves. Either:

- **Exact:** reconstruct the number of insert calls from the synced events. Per transaction, use
  the order of `NotePublished` against `Deposited` (one root per deposit leaf) and against spend
  and settlement events (roots are recorded for leaf pairs counted from the call's first index,
  plus a final single). The rule: dead once 256 or more roots have been recorded after the
  record's root. Or:
- **Conservative (simpler):** dead once a complete sync shows a leaf count of at least
  `m + 512`. Every insert call adds at most two leaves, so 512 leaves imply at least 256 roots.

In either case the triggering block must be at least the spendable depth (10 blocks) below
`latest`. A reorg that removes the appends would otherwise bring the root back.

Add a §12.6 case: 256 two-output spends after the record's root leave the record live; the rule
fires only after the required count.

### SDK-P21 — Medium — §9.2 step 1: `estimateInvokeFee` does not report the raw consumed amounts and prices

**Problem.** In 10.8, `Account.estimateInvokeFee` → `estimateFeeBulk` →
`provider.getEstimateFeeBulk` → `responseParser.parseFeeEstimateBulkResponse` returns only
`{resourceBounds, overall_fee, unit}`. Both `resourceBounds` and `overall_fee` have the overhead
already applied (`toOverheadResourceBounds`, `toOverheadOverallFee`). The fields `l1_gas_consumed`,
`l1_gas_price`, `l1_data_gas_consumed`, `l1_data_gas_price`, `l2_gas_consumed` and `l2_gas_price`
exist only in the raw RPC `FEE_ESTIMATE`, which the parser discards. As written, step 1 cannot
obtain them.

**Required change.** Obtain the raw estimate either by:

- `account.accountInvocationsFactory([{ type: 'INVOKE', payload: calls }], { versions: [<v3 query version>], proof, proofFacts, tip: 0, skipValidate: false })`
  followed by `account.provider.channel.getEstimateFee(invocations, { skipValidate: false })`.
  The channel method returns the RPC result unparsed. Or:
- a raw `starknet_estimateFee` through `channel.fetch`, as step 4 already does for simulation.

Add a §12.5 test that the bounds are identical under two different `resourceBoundsOverhead`
settings.
