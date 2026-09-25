# Account-bound notes, relayer fee output and M31 pool V3: protocol review (pre-implementation)

- **Reviewer role:** independent Protocol Reviewer. I did not write the design. Relation soundness
  and the cryptographic derivations belong to the separate Math Reviewer; I comment on them only
  where they change protocol behaviour.
- **Date:** 2026-09-25.
- **Documents:** `docs/account-bound-note-spec.md` (revision 1, uncommitted working-tree copy on
  `feat/sdk`) and `docs/adr/0026-account-bound-notes.md` (Proposed).
- **Method:** nothing is implemented. Every finding is reasoned from the spec and checked against
  the baseline specs, the V2 contracts, the server code, the P0b evidence and read-only calls to the
  local Sepolia node (details in section 3).
- **Output:** this file is the only change I made.

## 1. Verdict: CONDITIONAL GO

The architecture holds up at protocol level:
- A statement account that calls `is_valid_signature` in `__execute__` before its single message is
  covered by the existing adapter checks (`MESSAGE_COUNT = 1`, caller-0 guard, message tag).
- The SNIP-12 hash is computed from `statement.account`, so the signed account is the proven one.
  I found no pool-side path where they differ (§14 Q6).
- In-circuit `valid_until` checked by the pool closes F07.
- A fresh pool is the right way to add a third output.

What is not ready:
- Two pool rules would fail in operation. The root window expires the current root on a quiet pool
  (AB-P1). The timelock leaves the P1 verifier setter instant, so F01 stays open (AB-P2).
- The derivation signature, which is the product-1 seed, has no rule that keeps it off the network.
  The P0b code sends it to an RPC node (AB-P3).
- The relayer is made mandatory for both products, but it is specified only for its fee check, and
  the fee output cannot pay for ERC721 spends (AB-P6, AB-P8).
- The design does not state its amendments to the SDK and server specs. Several of those specs'
  rules become wrong under V5: the dead-record rule, the naming of `valid_until`, and the output
  order (AB-P15).

**Conditions.** Resolve every high and medium finding in revision 2 of the spec, before the phase
each one affects is implemented:
- **Pool V3:** AB-P1, AB-P2, AB-P4, AB-P5, AB-P14.
- **P3 (bridge and statement account):** AB-P9. It changes the signed struct, so real-wallet
  signing must be re-run.
- **P4 (server and SDK):** AB-P3, AB-P10, AB-P11, AB-P12, AB-P13, AB-P15, AB-P16.
- **Before any product relies on the relayer:** AB-P6, AB-P8.

No finding changes the relation's constraints. AB-P7 reorders outputs and AB-P13 changes how a
witness is chosen; both are client-side. As far as this review goes, P2 (the relation) can start
once the math review allows. Low and info findings should be resolved or recorded in revision 2.

## 2. Findings

| ID | Severity | Section | Title |
| --- | --- | --- | --- |
| AB-P1 | high | §8.3 | The root window expires the current root; a quiet pool freezes every spend |
| AB-P2 | high | §8.4, §8.1 | The P1 verifier setter is not timelocked, so F01 is not closed |
| AB-P3 | high | §6.4, §10 | Nothing keeps the derivation signature (the seed) off the network; the P0b code sends it to an RPC node |
| AB-P4 | medium | §8.4, §11 | The timelock and the immutable adapter freeze the pool on an OS rotation; "users can exit during T" is overstated |
| AB-P5 | medium | §8, §8.4 | Deployment bootstrap: the pool and the adapter cannot name each other under a timelock |
| AB-P6 | medium | §7 | The fee output cannot pay for ERC721 or unpriced assets, yet the relayer is the only submitter |
| AB-P7 | low | §7 | A fixed fee slot publicly marks a third of all spend outputs |
| AB-P8 | medium | §7 | Relayer acceptance, griefing, handoff and combined-operator view are unspecified |
| AB-P9 | medium | §5.3, §8.2 | `valid_until` in the signed struct lets wallet vendors match in-pool transfers |
| AB-P10 | medium | §9, §10 | RPC providers on both sides learn account ↔ spend |
| AB-P11 | medium | §8.2, §9 | Expiry against the server queue: lapsed statements are proven and hold their note |
| AB-P12 | medium | §6.4 | A key change leaves the SDK in a restore loop; backup is only offered |
| AB-P13 | medium | §6.4 | Product-1 seeds are multi-device by nature; per-store companions leak the real nullifier |
| AB-P14 | medium | §12 | No pool V3 phase or acceptance tests; the relayer is outside the phases |
| AB-P15 | medium | whole spec, ADR | Amendments to the SDK, server and hidden-asset specs are not stated; several of their rules break |
| AB-P16 | medium | §9 | Server bounds and retention: steps cap placement, artifacts that hold the signature |
| AB-P17 | low | §8.2, §5.4 | The pool does not enforce the uniform expiry; `salt = 0` is accepted in bound mode |
| AB-P18 | low | §8.5 | Cheap pool fixes not carried into the fresh pool; `MAX_NOTES` with three outputs |
| AB-P19 | low | §11 | Liveness omissions: server and relayer refusal, gateway, small path, block-time changes |
| AB-P20 | low | §10, §12 | The uniformity gate has no criterion; padding ordinary mode does not fix vendor differences |
| AB-P21 | info | §5.3, §8 | NFT exits show an opaque asset id; the third output's cost is not estimated |

### AB-P1 (high) — §8.3: the root window expires the current root

**Problem.**
- §8.3 accepts a root while `block_number − recorded_block ≤ W`, and records a root only when an
  append makes it current. So the current root expires W blocks after the last append, whether or
  not anything replaced it.
- With no append for W blocks, every spend and every P1 settlement fails, withdrawals included.
  Proposed W = 4,096 blocks, which is about 1.9 h at the measured 1.69 s per Sepolia block.
  The SDK always proves against the current root (sdk-spec §7.2), so no spend can succeed.
- The only way out is a new append, which means a public deposit of about 57.7M L2 gas (~1.2 STRK).
  A user who deposits junk to unfreeze their own spend links the depositing account to the spend
  that follows, by timing.

**Scenario.**
- The Sepolia V2 pool (`0x02da…37b9`) has 11 events in 5 blocks, and its last append was
  about 26.6k blocks (~12.5 h) before my read.
- Under §8.3 its current root would have been unusable for most of its life. A young mainnet pool
  would behave the same between bursts of activity.

**Required change.**
- Measure validity from supersession, not from recording:
  - always accept the current root;
  - when an append replaces root R, write `superseded_at[R] = block_number`;
  - accept R while `block_number − superseded_at[R] ≤ W`.
- Alternatively, never expire roots. F02 shows this is sound, and its only cost (a longer F07) is
  now closed by `valid_until`.
- Apply the same rule to `apply_policy_spend` (V2 reads `root_history` there too,
  `pool_v2.cairo:315`).
- Define the zero sentinel for "unknown".
- Add tests: current root after more than W idle blocks; junk deposits within W; W + 1 blocks after
  supersession.

### AB-P2 (high) — §8.4, §8.1: the P1 verifier setter is not timelocked

**Problem.**
- §8.4 timelocks `propose_verifier`, `apply_verifier` and `cancel_verifier`, with views
  `get_verifier` and `get_pending_verifier`. §8.1 says P1 "keeps its own adapter, deployed for the
  new pool", without saying how that adapter is installed or changed.
- V2 has a second setter, `set_policy_verifier` (`pool_v2.cairo:391-396`). It is instant, and V2
  starts with it unset (constructor `:164-170`).
- `apply_policy_spend` pays through the same `pay_out`, bounded only by `held` (`:312-314`,
  `:341-343`). That is F01's attack step 3: swap the P1 verifier, then settle a made-up policy
  spend through an owner-deployed controller.
- If V3 carries the V2 setter, the owner or a thief of the owner key can still drain every asset
  with no delay and no warning.

**Required change.**
- Every verifier the pool trusts (R0 V5 and P1) is either set at construction or changed only
  through the timelocked propose/apply/cancel path, with the same T and events.
- Name the P1 views, including the pending one.
- State in §8.4 that no other owner function can move funds. Shadow-class allowlisting cannot: a
  COMPUTE budget goes only to the adapter bound in the user's own intent.
- Add the P1 route to the F01 regression tests.

### AB-P3 (high) — §6.4, §10: the derivation signature has no rule keeping it off the network

**Problem.**
- `S_w = HKDF(chain ‖ A ‖ r ‖ s)`, so whoever sees the derivation signature can read every bound
  note, amount and spend.
- §6.4 asks that the account's "`is_valid_signature` accepts a test signature" through an RPC
  node, without saying which signature. At setup the only signatures the SDK holds are the two
  derivation signatures.
- The P0b page did exactly this. `bench/wallet-sig-spike/sign-live/index.html:190-222` sends each
  derivation signature to `starknet_call is_valid_signature`. Done the same way in the product,
  every user's RPC provider, typically a third party or the wallet's own, receives `(A, r, s)`.
- Two aggravating points:
  - §6.4 re-derives on every unlock. Users are trained to sign the one message whose leak exposes
    their history, on a SNIP-12 domain that any site can present (§10).
  - The §10 wallet-vendor row says vendors learn only the signed fields. A wallet that signs
    remotely (cloud or MPC signing, or a cosigner that receives the owner's typed-data signature)
    produces the derivation signature itself.

**Required change.**
- Make it normative that the derivation signature and `S_w` never leave the core. They are never
  sent to an RPC call, a simulation, the prover server, the relayer, logs, error reports or
  analytics. They are zeroized after HKDF, and the determinism check is local.
- The setup check signs and verifies a separate, non-secret message, such as a `TemplarSpend` with
  random fields or a dedicated `TemplarSetupCheck`.
- Add a network-trace test (sdk-spec §12.5) showing that no request carries a derivation `r` or `s`.
- Record in the compatibility matrix where each wallet signs. Setup refuses remote-signing wallets,
  or warns, and §10 gains that row.
- Cut the number of derivation prompts (see AB-P12 for key-change detection). For example:
  - wrap `S_w` per device under a non-extractable WebCrypto key, and re-derive only on new devices
    and restores;
  - add a human-readable warning field to `TemplarKeyDerivation`.

### AB-P4 (medium) — §8.4, §11: timelock against OS rotation; exit during T

**Problem.**
- The adapter pins the OS program, the PROOF version and `max_proof_age` in its constructor
  (`adapter.cairo:26-44, 60-62`).
- Suppose a sequencer upgrade stops accepting the pinned virtual-OS program. The battle test
  assumes it does (F01, impact); I did not verify it. Then every spend fails, exits included, until
  a new adapter applies, at least T (≥ 7 days on mainnet) after it is proposed. Unless the proposal
  predates the rotation, the pool is frozen for T.
- "Users can exit during T" holds only if all of these do:
  - the current adapter still works;
  - some prover server wraps for the user;
  - some submitter relays for them.
- At launch the owner is likely to run both the server and the relayer. The timelock then protects
  mainly users who can run a ~29 GiB server and submit themselves.
- The SDK refuses any adapter other than its pinned one (sdk-spec §8) and never reads pending
  proposals, so users are not told about a pending change.

**Required change.**
- §8.4 states the rotation procedure: propose as soon as StarkWare announces a new virtual-OS
  version.
- Consider an adapter that accepts a small set of OS programs (current and next), so the change can
  be applied before the switch. Record the freeze if the lead time is shorter than T.
- §10 and §11 state the exit assumption.
- The SDK reads `get_pending_verifier` (and the P1 one), shows the proposal and its eta, offers an
  exit, and ships new pins before eta.
- The SDK allows a fallback submitter: any non-owner account, marked `linkable: true`, when no
  relayer serves. §6.4's "owner never submits" should not leave a user with no way to exit.
- Mainnet owner is a multisig (F01 fix).

### AB-P5 (medium) — §8, §8.4: deployment bootstrap

**Problem.**
- The pool constructor requires a nonzero verifier (`pool_v2.cairo:166`), and the adapter
  constructor requires the pool address (`adapter.cairo:37`). Each address depends on its
  constructor arguments, so neither side can be precomputed to break the cycle.
- V2 broke the cycle with a placeholder verifier (the owner account, F45) and an instant
  `set_verifier`.
- Under §8.4 that pattern means a window of at least T in which deposits are accepted and nothing
  can be spent. An instant general setter kept for bootstrap reopens F01.

**Required change.**
- Specify the bootstrap. For example:
  - the constructor takes no verifiers;
  - a one-time `initialize_verifiers(r0, p1)` by the owner, allowed only while none is set and
    `tree_count == 0`, emits the change events;
  - deposits and spends revert until it has run.
- The P6 deployment record shows it was used once.

### AB-P6 (medium) — §7: the fee output cannot pay for ERC721 or unpriced assets

**Problem.**
- The fee is a note in the spend's single hidden asset.
- An ERC721 note holds amount 1 (hidden-asset-spec §3.1). Conservation gives
  `out₀ + out₁ + out₂ + withdrawn = 1`, so an ERC721 spend can pay no fee at all.
- A relayer cannot price ERC1155 ids or long-tail ERC20s, so it will refuse them or relay them
  free.
- §6.4 forbids the owner account from submitting, and §7 makes the relayer the submitter for both
  products. These spends therefore have no defined path. §7's "every spend keeps the same shape"
  and "exits pay the fee the same way" are false for them.

**Required change.** Choose one option and write it into §7, §10 and the ADR's consequences:
- (a) the relayer sponsors zero-fee spends under a stated policy, and learns that the spend is an
  NFT or unpriced asset;
- (b) a separate fee spend in an allowlisted asset goes in the same transaction, which gives a
  distinguishable two-spend shape;
- (c) the user submits from a non-owner account, marked `linkable: true`.

### AB-P7 (low) — §7: fixed fee slot

**Problem.**
- The fee always sits in slot 2, while payment and change share slots 0 and 1 in random order
  (sdk-spec §7.2).
- Every V3 spend's third leaf is therefore publicly either a relayer fee note or a zero dummy.
- Observers can drop those leaves from every user's anonymity set (a third of all spend outputs),
  and can pick out the relayer's notes.

**Required change.**
- Shuffle all three outputs uniformly. The relation's output slots are symmetric, so no constraint
  changes.
- The relayer tries all three ciphertexts (three sealed-box opens).
- Amend sdk-spec §7.2 to match.

### AB-P8 (medium) — §7: relayer acceptance and griefing are unspecified

**Problem.** The relayer becomes a required component, but §7 specifies only "open ciphertext 2,
recompute `cm₂`". Missing:
1. **Receive rules.** The check must apply the SDK receive rules in full (sdk-spec §6 rules 1–6:
   layout, canonical nonzero `rho`, amount range, receiver equal to its own). Otherwise a note that
   matches but cannot be spent is accepted (the F04 and F21 class).
2. **Griefing.** The relayer pays for a reverted transaction and earns nothing. A client can:
   - race one spend through two relayers, so that one reverts with `NULLIFIER_USED`;
   - choose a `valid_until` that is about to lapse;
   - use a root that is about to expire.
3. **Front-running (F06).** The relayer now sees every invoke spend before settlement, and can
   sandwich it down to `minimum`.
4. **Handoff.** Nothing says who hands the relayer the `Spend`, facts and PROOF2, over what
   transport (OHTTP), or what the relayer keeps.
5. **Fee pricing.** A fee that depends on the amount reveals the amount.
6. **One operator.** When one operator runs both the server and the relayer:
   - in product 1 it sees account ↔ spend ↔ asset ↔ fee;
   - in product 2 it can link the job and the submission by address and timing.

**Required change.**
- Add a normative relayer acceptance list to §7:
  - the receive rules on its ciphertext;
  - an allowlisted asset with a flat fee per asset;
  - `valid_until ≥ latest + margin`;
  - a valid root and unspent nullifiers;
  - simulation with validation;
  - deduplication by nullifier across its own submissions.
- Add the handoff, transport and retention rules.
- Add the combined-operator row to §10.
- For invoke spends through a relayer, require tight minimums, or bind a submitter into the intent
  (F06 option).
- Pricing and quotes can stay in `relayer-spec.md`. These rules belong here because the SDK
  depends on them.

### AB-P9 (medium) — §5.3, §8.2: `valid_until` in the signed struct

**Problem.**
- The salt keeps parties that see the typed data from matching `binding_commitment` to a spend.
  Those parties are the wallet vendor, the guardian service and transaction scanners.
- But `TemplarSpend` also shows `valid_until`, and every V5 spend publishes it. Such a party
  learns "account A made an in-pool transfer with `valid_until = X`" and matches it against the
  on-chain spends carrying X.
- With Q = 100 blocks (~2.8 min), the candidate set is the pool's spends in one bucket, which on a
  young pool is often a single spend. Quantization limits the set to one bucket; the displayed
  field tells the vendor which bucket.

**Required change.**
- Drop `valid_until` from `TemplarSpend`. It stays bound through `binding_commitment`, which commits
  to the binding and so to `valid_until`, and a user cannot judge a block number anyway.
- Re-run the KATs and the real-wallet signing.
- §10 states that on a low-traffic pool the signing time alone can still link, so the salt helps
  only at volume.
- If the field stays, §10 must say that the vendor learns the bucket.

### AB-P10 (medium) — §9, §10: RPC providers learn account ↔ spend

**Problem, client side.**
- In product 1 the web app's RPC provider knows A from setup checks and wallet reads; it is often
  the wallet extension's own provider.
- sdk-spec §9.2 sends the spend-specific traffic through that same provider: fee estimate,
  simulation, submission and status polling. §7.2 sends the exit recipient checks there too.
- Together these give the provider account ↔ spend. The design's stated boundary is that the
  prover server learns this; §10 lists only "the account" for the RPC node.

**Problem, server side.**
- The §9 pre-check calls `is_valid_signature(A, hash, sig)` through the server's configured node.
- The same node receives the job's `root_is_known` and `get_nullifier_spent` reads
  (`server/prover/src/pipeline.rs:79-92`), and the virtual OS's reads of A's class and storage.
- The server config accepts any RPC URL ("a local node is recommended"). With a third-party node,
  that provider links A to the nullifiers, and so to the on-chain spend.

**Required change.**
- In bound mode, spend-specific reads and the submission never use a provider that has seen the
  account in that session. Use the relayer's simulation, or a separate provider over OHTTP.
- The server serves bound mode only with an operator-controlled node, and says so in `/v1/info`
  and its privacy notice.
- Add both rows to §10.

### AB-P11 (medium) — §8.2, §9: expiry against the server pipeline

**Problem.**
- E = 600 blocks is about 17 min on Sepolia.
- The shipped server config queues 16 jobs with one concurrent job, each taking about 65–80 s
  (`server/deploy/prover.example.toml`; P0b measured 80 s at 8 cores).
- A job at the back of a full queue waits about 21 min (~750 blocks). It then still needs
  `submit_after = base + 11` and the relay.
- The server never reads the statement's `valid_until`, since V4 has none. It would prove
  statements that have already lapsed (80 s and 29 GiB each).
- It also releases deduplication at `base + max_proof_age` (`server/prover/src/api.rs:236-250`),
  not at the statement's expiry.
- Every lapse costs a product-1 user another wallet prompt.

**Required change.**
- The server refuses at admission, and drops at job start, a statement whose `valid_until` is below
  latest + expected wait + proving + 11 + a relay margin.
- The result reports the deadline `min(statement.valid_until, base + max_proof_age)`, under a name
  distinct from the statement field (see AB-P15). Deduplication is released at that deadline.
- Derive E from the measured worst-case pipeline, and record the expiry rate in P5.

### AB-P12 (medium) — §6.4: key changes and backup

**Problem.**
- §6.4: "The SDK re-derives on every unlock and, if the result differs from the stored seed,
  stops and tells the user to restore from the backup."
- After a key change the user restores `S_w` from the mnemonic. The next unlock derives
  `S_w′ ≠ S_w` and stops again, indefinitely.
- The same happens after a wallet update that changes its nonce derivation or s-normalization,
  with no key change at all.
- On a fresh device after a key change, the SDK derives `S_w′`, shows an empty wallet and issues
  new receivers, with no hint that older notes exist.
- Losing the seed after a key change freezes notes for good (§11, no escape path), so "setup offers
  the backup" is too weak.

**Required change.** Define the state after a key change. Either:
- (a) after a restore, spend every old note (old `sk_w` plus the account's current signature, which
  works) to receivers of the newly derived seed, then retire the old seed; or
- (b) keep seed generations: the old ones are stored encrypted under a key derived from the current
  derivation signature, and are scanned and spent until swept.

Also:
- Setup confirms the backup with a word check before the first bound address is shown.
- Specify the stored comparison value: a hash of `S_w`, never `S_w` in clear.
- On a fresh device, ask whether the account has been used with Templar before, and offer restore.

### AB-P13 (medium) — §6.4: product-1 seeds are multi-device

**Problem.**
- A product-1 seed can be re-derived in any browser that holds the wallet, so the same notes are
  routinely live on several devices, each with its own store.
- sdk-spec keeps companions and in-flight records per store (§3.3, §9.1), and says two devices
  "cannot coordinate".
- Device B does not hold the companion that device A sent with a note, so it builds a fresh dummy.
  The next statement for that note then shows the real nullifier beside a new dummy (the F05
  effect). In product 1 it shows this to a server that also knows the account.
- Two devices planning the same note produce two statements with the same nullifiers
  (F03 variant A).

**Required change.**
- Derive a note's companion deterministically from `S_w` and the note, for example HKDF over its
  commitment and index under a new label, rejection-sampled as today. This needs the Math
  Reviewer, since it changes HA-M6's "never seed-derived". Every device then builds the same
  companion.
- Treat a server's duplicate-nullifier refusal as "in flight elsewhere", and never re-plan on it.
- Document multi-device use for product 1.

### AB-P14 (medium) — §12: phases

**Problem.**
- Pool V3 has no implementation phase and no acceptance list. P3 is the bridge and account; P6
  only deploys. Yet V3 changes the root rule, the append, the spend check, the verifier path and
  the events.
- F28 (pool branches without committed tests) is not carried over.
- The relayer is outside §12, although §6.4 makes it the only submitter for product 1.

**Required change.** Add a pool phase whose acceptance covers:
- the root window: current root after idle, junk deposits within W, W + 1 after supersession, and
  the P1 path;
- `insert_three` equal to three `insert_leaf` calls at deep merges, in both storage modes;
- the expiry boundary: `block = valid_until` is accepted, one block later is rejected;
- the V5 binding field matrix, including slot 2 and `valid_until`;
- the timelock for both verifiers: apply before eta, cancel, re-propose, events, bootstrap
  (AB-P5);
- F28's tests, committed;
- the real statement account end to end;
- a protocol review.

Add a minimal relayer phase before P5, or an interim submitter rule.

### AB-P15 (medium) — consistency with the specs it extends and with the ADR

**Problem.** The design changes rules in three reviewed specs without listing the changes, and some
of those rules become wrong.

- **sdk-spec**
  - §9.1: the dead-record rule "leaf count `m + 512`" assumes the 256-root ring and at most two
    leaves per insert. Both change: with the block window it is wrong, and it would be `m + 768`
    with three-leaf spends. With `valid_until`, a record whose statement left the wallet is dead
    once `valid_until` is buried by 10 blocks. That is a large simplification the spec should
    claim.
  - §8 and §9.2: `valid_until` is `base_block + max_proof_age`, and the server result uses the same
    name (`pipeline.rs:195`). It now collides with the statement field. The send window must use
    `min(statement.valid_until, base + max_proof_age)`.
  - §7.2: output order and the three-output shape (AB-P7).
  - §8: the job body (salt and signature), and pins for the spend domain and type hashes, the
    relayer's address, E and Q.
  - §9.2: submission through a relayer; the owner never submits.
  - §10.2: network constants.
  - §11: versions (R0 V5, `TMR0_BIND_V5`, `KEY1`, 21-word mnemonics).
  - §14: the privacy table.
- **prover-server-spec**
  - §2: "it never receives keys" still holds, but the server now learns the account.
  - §4: the signature pre-check.
  - §5.3: calldata `(proof_data, salt, signature)`.
  - §5.7: result naming.
  - §10: logging (account, salt and signature never logged).
  - §8: the relation config.
- **hidden-asset-spec**
  - §5.7: V3's entry points and owner functions.
  - §7: the relayer learns the asset of every spend. Today no one but the recipient learns the
    asset of an in-pool transfer.
- **ADR-0026**
  - Its Context says the check "leaves PROOF2 in the same leaf bucket at the same cost". §13
    measured PROOF2 only with inline Stark ECDSA in the R4 account. The real account call has
    virtual-OS resource counts only: probe +172,285 steps (Ready) and +161,340 steps (Braavos).
    The ADR should say this is inferred.
- **Spec §1**
  - It puts the relayer out of scope, while §6.4 and §7 depend on it (see AB-P8, AB-P14).

**Required change.** Add a section listing each amended section of `sdk-spec.md`,
`prover-server-spec.md` and `hidden-asset-spec.md` with its new rule. Fix the ADR's evidence
wording.

### AB-P16 (medium) — §9: server bounds and retention

**Problem.**
1. **Steps cap.** It must be enforced between the OS run (~11 s) and proving (minutes, ~29 GiB),
   and tied to what keeps the proof in the measured log-25 leaf bucket:
   - Steps do not bound Blake compressions. P0b puts the headroom at ~12.3k before `blake_g` grows.
   - A larger bucket may not fit `job_memory`.
   - Today the only bound is the virtual transaction's 10^9 L2 gas (`pipeline.rs:123`), against
     about 3.4M baseline OS steps.
2. **Scrubbing.** "Scrubbed when a job finishes" does not cover where a bound job's account, salt
   and signature actually sit:
   - `bridge-args.json` (the statement);
   - `os-job.json` (the calldata);
   - `os.pie.zip` (the whole execution, including the account's storage reads and the signature);
   - `check.log` and `os.log`;
   - streamed commitment files and swap.

   Until PROOF2's hiding is established, the returned proof may itself carry the witness.
3. **Pre-check timing.** §9 runs the signature pre-check at the base block, but the base block is
   chosen at job start (`pipeline.rs:115`), not at admission.

**Required change.**
- Enumerate these artifacts and delete them as soon as proving ends, not at retention.
- Keep bound-mode inputs on tmpfs, and require swap to be encrypted or off.
- Cap OS steps and builtin and Blake counts, from P5 measurements, before proving starts.
- Run the signature check at admission (latest block) and again at job start (base block).
- Delete results after the first successful fetch, or after a short retention.

### AB-P17 (low) — §8.2, §5.4: the pool does not enforce the uniform expiry

**Problem.**
- E, Q and the salt are SDK conventions. A non-conforming client fingerprints its own spends.
- A far `valid_until` reopens F07 for that client's spends.
- In bound mode `salt = 0` is accepted. A vendor could then compute `Poseidon(binding, 0)` for every
  on-chain spend and match.

**Required change.**
- The pool requires `valid_until % Q == 0` and `valid_until ≤ block_number + E + Q`, as constructor
  constants. An honest statement always satisfies this at inclusion. A far-future one cannot land
  before `valid_until − E − Q`, which bounds withholding for every client.
- The statement account requires `salt ≠ 0` in bound mode.

### AB-P18 (low) — §8.5: carry the cheap pool fixes into the fresh pool

**Problem.** §8.5 keeps V2's other entry points unchanged, and a fresh pool is the only chance to fix
them:
- F17: a deposit should also check that the caller's balance fell by `amount`.
- F18: an INVOKE target must not be an allowlisted shadow class.
- F30: tie the tree format to R0C5 (Compress) in the constructor.
- F19: emit the verifier event in the constructor too.
- `MAX_NOTES = 4` (`open_note.cairo:30`, `pool_v2.cairo:235`) leaves one open-note destination
  once a spend creates three outputs (V2 allowed two).

**Required change.** Carry these fixes, or record why not. State `MAX_NOTES` for V3.

### AB-P19 (low) — §11: liveness omissions

**Problem.** §11 lists account-side freezes only. Missing:
- **Server and relayer refusal.** In product 1 the server knows the account, so it can censor
  selected accounts. §10 says only "delay or refuse".
- **Submission when no relayer serves** (AB-P4).
- **Gateway acceptance of PROOF2.** Sepolia rejects it, and mainnet 0.14.4 is pending.
- **The log20 small path.** It is ADR-0024's fallback, and V5 moves further from it: about +171k
  steps and +1.2k Blake for the account call, plus a 39-output statement.
- **Block-denominated constants.** E, Q, W and `max_proof_age` are counted in blocks, and
  `max_proof_age` is immutable in the adapter. Faster blocks shrink every window.

**Required change.** Add these to §11. Measure the small-path fit in P5. State how each constant is
changed if block time changes.

### AB-P20 (low) — §10, §12: the uniformity gate has no criterion

**Problem.**
- §10 says that if the PROOF2 object differs by mode, "ordinary mode gets padding".
- The P0b probes already differ by vendor: 172,285 steps and 1,203 OS Blake for Ready, against
  161,340 and 1,124 for Braavos. Padding ordinary mode cannot equalize Ready and Braavos.
- Human signing delay makes the gap between `valid_until` and inclusion follow a different
  distribution in product 1.
- The server sees each job's mode.
- The "not the mode" claim in §10 needs these qualifications.

**Required change.**
- Define the gate: the same leaf bucket (preprocessed root) and the same component log sizes for
  ordinary, Ready and Braavos spends. Otherwise, pad every mode to the maximum.
- Make it a P5 acceptance criterion in §12.
- Qualify the §10 row.

### AB-P21 (info) — §5.3, §8

- An NFT exit shows `token_out` as a `TEMPLAR_ASSET_V1` hash, which no user can check. Optional
  fix: the client supplies `(standard, contract, id)`, the statement account checks it against
  `token_out`, and the wallet displays it.
- The third output's cost is not estimated. Inferred:
  - about two more node hashes in `insert_three` (~3M L2 gas at 1.53M per hash);
  - one more ciphertext (10 calldata felts plus event data);
  - one more digest write;
  - roughly +5–8% on a 53M transfer.

  Every spend also adds a leaf that is never spent when there is no fee.

## 3. What I checked, and what I could not

**Read in full or in the relevant sections:**
- the design and the ADR;
- `hidden-asset-spec.md`, `sdk-spec.md` and `prover-server-spec.md`;
- ADR-0024 (decision, consequences and gates) and ADR-0025, skimmed;
- the battle-test report: F01–F28 in full, the info table, the disputed items and the coverage gaps.

**Code:**
- `bench/m31-pool/cairo/src/pool_v2.cairo`, `tree.cairo`, `adapter.cairo`, `spend4.cairo`;
  `MAX_NOTES` in `open_note.cairo`; `bench/m31-pool/README.md` costs;
- `server/prover/src/pipeline.rs`, the deduplication in `api.rs`, `server/os-runner/src/main.rs`
  and `server/deploy/prover.example.toml`.

**P0b evidence:**
- `target/wallet-sig-spike/measure/measure-summary.json`: bucket 25, 80 s, 28.4 GiB, message hash
  match;
- `e2e/summary.json`: baseline 3.39M OS steps, 13,719 Blake;
- `probe/runs/*/os-result.json` and `probe/live-analysis/analysis/*/result.json`: Ready and
  Braavos steps and Blake counts;
- `bench/wallet-sig-spike/sign-live/`: its README and `index.html`, which confirm that derivation
  signatures are sent to `is_valid_signature`.

**Read-only RPC to the local Sepolia node** (`starknet_specVersion` 0.10.3-rc.0; no writes, no
keys):
- Block time: 600 blocks in 1,015 s (1.69 s per block); 4,096 blocks ≈ 1.93 h.
- V2 pool `0x02da…37b9`: 11 events in 5 blocks, the last about 26.6k blocks before the read.

**Also checked:**
- The `INVOKE_TXN_V3` read schema in the pinned sequencer checkout's OpenRPC (V0_8) has
  `proof_facts` but no proof blob. The inference for 0.10 is that on-chain observers do not get the
  PROOF2 object, which matches §10's gateway row.

**§14 questions within protocol scope:**
- Q6: no path found. The statement account hashes with `statement.account` and calls that same
  address, and the pool never sees the account.
- Q5: the three-output interactions I found are AB-P6 and AB-P7. The companion rule is unaffected,
  except across devices (AB-P13).

**Not checked:**
- Relation soundness, S1–S3, and the key and seed derivations (Math Reviewer).
- Anything that needs a build, a proof or a contract test. `insert_three` was not prototyped.
- Whether the sequencer retires old virtual-OS programs on upgrade. AB-P4 takes this from the
  battle test's F01.
- How wallets handle guardian cosigning, and whether any wallet signs remotely or forwards
  typed-data signatures to a backend.
- Mainnet block times and fee levels.
- Live gateway behaviour for PROOF2.
- The relayer, which has no spec yet.
- The node-simulation discrepancy in §13. The server pre-check uses `starknet_call`, which P0b found
  to agree with the virtual OS.

## Re-review of revision 2

- **Date:** 2026-09-25.
- **Scope:** revision 2 of `docs/account-bound-note-spec.md` (§7, §8.2–§8.6, §9–§12, §14, §15 and
  §17) and the updated ADR-0026, in protocol scope only.
- **Method:** reading, checked against the V2 contracts I read for the first review. The hook
  argument handling in AB-P22 comes from `pool_v2.cairo:417-457` and F59. Nothing was built or run.

### Verdict: CONDITIONAL GO

Every prior finding is resolved in the spec. The new findings are all in §8.6 (protocol fees),
which is new in this revision. Two of them are medium:
- the NFT hook's flat fee can be pulled from a third party's allowance;
- fees are pushed to the collector inside every exit, so the collector can block exits.

**Condition:**
- Resolve AB-P22, AB-P23 and AB-P24 before P3b implements §8.6. Nothing else in P3b depends on
  them.

**Other phases:**
- P2, P3 and P4 may proceed from the protocol side.
- AB-P25 to AB-P27 can be resolved in the next revision.

### New findings

**AB-P22 (medium) — §8.6: the NFT deposit fee is pulled from a hook argument.**
- **Problem.**
  - ERC721 and ERC1155 push deposits pull `flat_deposit` in STRK "from `from` (prior approval)".
  - `from` is an argument of `on_erc721_received` and `on_erc1155_received`, and any contract can
    call those hooks. The hook needs no real token (F59), because it trusts the caller's own
    `balance_of` and `owner_of`.
  - So any party can drain another address's standing STRK allowance to the pool, one flat fee per
    call, into the collector. The attacker deploys a fake token contract that calls the hook with
    `from = victim`, and repeats.
  - Every address that has pre-approved the pool for STRK is exposed, and so is anyone who approves
    in one transaction and pushes in a later one.
  - A mint to the pool (`from = 0`) reverts once the fee is nonzero.
- **Required change.**
  - Never pull a fee from a hook argument. Pull it from the transaction's signer
    (`tx_info.account_contract_address`), or require the fee to be prepaid earlier in the same
    transaction.
  - The SDK approves exact amounts in the same multicall as the push.
  - P3b adds a test: a fake-token hook call naming a victim must not move the victim's STRK.

**AB-P23 (medium) — §8.6: fees pushed to the collector can block exits.**
- **Problem.**
  - A withdrawal pays `fee` to `fee_collector` inside the exit, under the pool lock.
  - For ERC1155 the fee transfer runs the collector's receiver check and hook.
  - For ERC20, a token that blacklists or pauses the collector address makes that transfer fail.
  - While `withdraw_bps > 0`, every exit of that asset then reverts. This can be triggered by the
    token issuer, or by the owner choosing a collector whose hook reverts or burns gas. A timelock
    delays that choice but does not prevent it.
  - Deposits are affected the same way (less critically).
- **Required change.**
  - Accrue fees in the pool (`fees_owed[asset]`), and let the collector claim them in a separate
    call. No deposit or exit ever calls the collector.
  - Skip zero fees.
  - Restate the solvency invariant (hidden-asset-spec §3.3): `held[a]` equals the unspent notes of
    `a` plus the unclaimed fees in `a`, or the fees are tracked separately.

**AB-P24 (low) — §8.6, §8.5, §11: the fee rules contradict each other.**
- **ERC1155 deposits.** The table applies `deposit_bps` to ERC1155 deposits, and the text says
  ERC1155 pushes pay only `flat_deposit`.
  - If a percentage were taken from a pushed value, the depositor's ciphertext would have to encrypt
    the net amount. Otherwise the pool's commitment would not match the ciphertext, and the note
    would be lost to its recipient.
  - Pick flat-only for ERC1155 (as the text says) and fix the table.
- **F17 check.** It says the caller's balance fell by `amount`. With the fee charged on top, it fell
  by `amount + fee`.
- **§11 amendments.** They miss the fee-related changes:
  - sdk-spec §7.1: `max_fee`, and STRK approvals for pushes and for the fallback submitter;
  - hidden-asset-spec §3.3, §5.1 and §5.3: the fee flows and the solvency invariant.
- **Wording.** "Spend or deposit whose lifetime (`valid_until`)": deposits have no `valid_until`,
  and `max_fee` covers them.

**AB-P25 (low) — §8.6: `withdraw_bps` can be avoided.**
- **Problem.**
  - Invoke budgets "stay gross", so a client can exit through `apply_spend_with_invoke` with a
    pass-through INVOKE adapter and pay only `flat_spend`.
  - The percentage then binds only clients that use plain withdrawals.
- **Required change.** Either charge invoke budgets as well, or state that the withdrawal
  percentage can be avoided.

**AB-P26 (low) — §7.1, §7.2: conditional sponsorship needs the asset.**
- **Problem.**
  - A relayer cannot tell an NFT or unpriced-asset spend from any other spend without learning the
    asset. A policy of "sponsor NFTs" is therefore unenforceable as written.
  - "A sponsored relayer learns neither the asset nor a fee" holds only for unconditional
    sponsorship.
- **Required change.**
  - Specify how the client proves the asset for conditional sponsorship: a zero-value output to the
    relayer's receiver. The relayer recomputes its commitment, and all outputs share one asset, so
    the commitment proves the asset.
  - Update the §12 row: a conditional sponsor learns the asset.
  - §7.2 step 3 should check `send_deadline`, not `valid_until`.

**AB-P27 (info) — ADR and §9: stale ADR wording; results deleted on fetch.**
- ADR-0026 decision 5 still says the spend message is built "from statement fields plus
  `valid_until`", which revision 2 removed from the signed message (AB-P9).
- §9 deletes results "after the first successful fetch". It should wait for an explicit client
  acknowledgment. Otherwise a client that crashes after the fetch has lost the result, and the note
  stays held by deduplication until `send_deadline`.
- The ADR's PROOF2 evidence is now stated precisely: it says the inline check was measured and the
  real account call is inferred, to be measured in P5.

### Prior findings

- **AB-P1:** resolved. §8.3 measures validity from supersession, applies it to P1 too, and P3b
  tests it.
- **AB-P2:** resolved. §8.4 timelocks every verifier, including P1's.
- **AB-P3:** resolved.
  - §6.2 adds the secrecy rule, the trace test, fewer prompts and the warning field.
  - §6.5 adds the setup-check signature: `pool = 0` can never match a spend, because the bridge
    requires a nonzero pool.
  - §12 and §13 cover remote signing.
- **AB-P4:** resolved. OS rotation is recorded as a known risk; the SDK shows pending proposals;
  §7.3 adds the fallback submitter.
- **AB-P5:** resolved. §8.4 adds the one-time `initialize`.
- **AB-P6:** resolved. The relayer fee is optional and can be sponsored, with a fallback submitter;
  AB-P26 covers how sponsorship is decided.
- **AB-P7:** resolved. Outputs are in random order.
- **AB-P8:** resolved. §7.2 adds acceptance and handoff, and §12 the combined-operator row; AB-P26
  covers step 3.
- **AB-P9:** resolved in the spec; the ADR wording is stale (AB-P27).
- **AB-P10:** resolved. §9 requires an operator-controlled node; §10 covers web-app reads.
- **AB-P11:** resolved. E comes from the pipeline; admission and job-start checks;
  `send_deadline`.
- **AB-P12:** resolved. Confirmed backup, a fingerprint instead of the seed, and the sweep.
- **AB-P13:** resolved on the protocol side. Companions are deterministic, pending the math
  re-review.
- **AB-P14:** resolved. P3b and P4b are added.
- **AB-P15:** resolved, except the fee amendments (AB-P24). The PROOF2 evidence is now precise in
  §16 and the ADR.
- **AB-P16:** resolved. Caps before proving, data locations, tmpfs and two signature checks.
- **AB-P17:** resolved.
  - The pool enforces `Q` and `E + Q`. An honest `ceil((latest + E)/Q)·Q` always passes.
  - `T > E + Q + margin` keeps any in-flight statement from meeting a fee change.
  - `salt ≠ 0` is required in bound mode.
- **AB-P18:** resolved. F17, F18, F30 and F19 are carried, and `MAX_NOTES = 5`; the F17 wording is
  covered by AB-P24.
- **AB-P19:** resolved. §14 adds service, gateway, small path and block-denominated constants.
- **AB-P20:** resolved. §12 adds the gate and its qualifications.
- **AB-P21:** resolved. The NFT display is noted, and cost is measured in P3b.

## Re-review of revision 4

- **Date:** 2026-09-25.
- **Scope:** only the sections revision 4 changes: §1, §4.1, §6, §7, §8.1, §8.5, §8.6, §9, §11,
  §12, §14, §15 and §17's revision-4 table. Also the updated ADR-0026.
- **Not in scope:** the user's decisions themselves are settled. This re-review covers how they
  are specified.
- **Method:** reading only. The handoff finding (AB-P28) relies on V2's `Spend` layout
  (`spend4.cairo`: every output carries its ciphertext) and on prover-server-spec §2.

### Verdict: CONDITIONAL GO

The simplification removes most of what revisions 2 and 3 had to defend: the fee output, the pool
fees and the derivation signature. The pool sections (§8.1–§8.6) are sound as specified, and the
random seed with `A` in every key context is a clear improvement.

Two gaps in the paid-service flow need fixing before P4 and P4b:
- **AB-P28:** the relayer cannot submit from what the server holds.
- **AB-P29:** the free full withdrawal can be claimed for an invoke.

P2, P3 and P3b are unaffected. AB-P30 to AB-P32 can go to P7 or the next revision.

### New findings

**AB-P28 (medium) — §7.3, §9, §11: the relayer cannot submit from the server's result.**
- **Problem.**
  - §7.3 has the relayer take "each result straight from the server that proved it".
  - A pool `Spend` carries each output's ciphertext, and an invoke also needs the `ExecutionIntent`
    preimage. P1 needs its `data` and ciphertexts.
  - The §9 job body has none of these, and prover-server-spec §2 states that the server "cannot
    submit the transaction itself" for exactly that reason.
  - As written, "the service submits every spend it proves" cannot be carried out.
- **Required change.**
  - The job body carries the full pool calldata: the `Spend` with both ciphertexts, and the intent
    preimage or P1 `data`.
  - At admission the server checks that the calldata's delivery digests, intent hash and binding
    match the statement.
  - §11 amends prover-server-spec §2: the service now holds everything needed to settle, and can
    choose when to settle, up to `send_deadline`.

**AB-P29 (medium) — §7.2, §14: the free full withdrawal rule is underspecified.**
- **Invoke loophole.** The openings check (both outputs hold zero under `asset = token_out`) also
  passes for an `INVOKE` or `COMPUTE` spend whose whole value is its budget. That makes a
  2-ticket, ~150M L2 gas spend free.
  - Require `intent = 0` and `identity = 0`, so that only `apply_spend` qualifies.
- **Minimum value.** "At or above a minimum value" is undefined for NFTs and assets the service
  does not price. Dust notes pay a ticket.
  - So §7.2's and the ADR's "no user is ever stuck" is false for those notes: their only route
    without tickets is self-hosting.
  - State that, or define the rule for unpriced assets.
- **Griefing.** Each free job costs the service a PROOF2 (~80 s at ~29 GiB) plus the relayer's
  gas. It costs the attacker one deposit, and the attacker gets the value back.
  - Specify a separate, lower-priority queue for free jobs and a rate bound on them. Otherwise free
    jobs can starve paid ones in a 16-slot queue.
- **What it leaks.** §12 is correct: the inputs held exactly `w_amount`. Revealing the dummy
  outputs' `inner` values reveals nothing further.

**AB-P30 (low) — §9, §7.2: the ticket reserve/spend/refund states are underspecified.**
- **Admission.** Merge the admission order with prover-server-spec §4:
  size → configuration → payment (reserve) → deduplication → expiry → chain state → bridge →
  signature.
  - A refusal for server-side or timing reasons releases the reservation.
  - A bridge rejection consumes the ticket: honest clients self-verify, and releasing it would let
    one ticket fund unlimited invalid jobs.
- **Job start.**
  - Spend the tickets only after the job-start checks pass. A job-start expiry failure is caused
    by the server's own queue.
  - OS reverts and cap violations are the client's fault and keep the tickets spent. Otherwise a
    hostile account class burns OS time for free.
- **Replacement tickets** must be issued blind: the job body carries blinded refund requests.
  Otherwise they link the job to the client's later spends.
- **Spent set.** "Recorded per issuer key" must mean one spent set shared by every redeemer of that
  key, including other server instances and any third-party relayer. Otherwise one ticket can be
  spent at two of them.

**AB-P31 (low) — §7.3, §7.4: the fallback races the relayer.**
- **Problem.**
  - The fallback fires if the spend is "not included by `send_deadline − margin`". The relayer's
    transaction may still be pending then.
  - Both transactions land. One reverts with `NULLIFIER_USED`, publishing the fallback account
    beside the spend, which spends the user's gas and privacy for nothing.
  - The relayer also reports nothing when its acceptance checks refuse a spend.
- **Required change.**
  - The relayer returns either its transaction hash or a refusal with a reason.
  - The SDK falls back at once on a refusal. At the deadline it falls back only when no relayer
    transaction is pending.
  - `margin` must be at least the expected inclusion latency.

**AB-P32 (info) — §12, ADR.**
- **Ticket issuer row.** Per-period issuer keys partition redemptions by claim period. On a small
  service, claim timing within a period is not the only link.
- **Missing row.** Pass holders are public on chain, because a soulbound NFT has a public owner.
  The SDK should let the pass sit in an account other than the owner or depositing account.
- **ADR decision 3.** It no longer says that an escape path would turn a leaked backup phrase or
  device store into theft. That remains the reason S4 holds, and it should stay stated.

### §17 revision-4 table

The table is correct:
- **AB-P3:** kept for `S_w` and spending keys, with the setup-check signature; the derivation
  signature is moot.
- **AB-P6:** moot. Tickets are asset-agnostic, so NFT spends are paid for.
- **AB-P7:** kept for two outputs.
- **AB-P8:** kept. The handoff it keeps is incomplete (AB-P28).
- **AB-P12:** backup kept. Sweep and fingerprint are moot, because a key change no longer changes
  the seed.
- **AB-P13:** moot. Second devices need the phrase, as for the Templar wallet.
- **AB-P18:** kept, with `MAX_NOTES = 4`.
- **AB-P21:** moot for the third output.
- **AB-P22–P25:** moot.
- **AB-P26:** sponsorship is moot; `send_deadline` is kept.
- **AB-P27:** still resolved. ADR decision 5 no longer claims `valid_until` is displayed, and §9
  deletes results on acknowledgement.

The ADR states the PROOF2 evidence precisely.
