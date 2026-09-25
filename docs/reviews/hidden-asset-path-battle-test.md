# Hidden-asset spend path: adversarial battle test

- **Role:** internal adversarial review by a swarm of independent agents (orchestrated by Claude). It is not
  an external audit. Each lane attacked one layer; every finding of low severity or above was re-tested by one
  to three verifiers that did not write it (reproduce, code-path and threat-model lenses).
- **Date:** 2026-09-25
- **Commit reviewed:** `cb6e2d3` (`feat/sdk` = `main`). Fork commit `250cc9c1e` in `target/proving-arith`
  (branch `templar/arithmetic-profile`, upstream base `starkware-libs/proving@5a7c5ede4`).
- **Scope:** the R0 V4 hidden-asset spend on the Compress tree: the client relation
  (`bench/m31-private-wrapper/client-port/src/payment4.rs` and shared gadgets), the proving fork, the Cairo
  bridge and statement account (`client-port/cairo-r4`, built as `target/bridge-r4`), the Proof2Adapter and
  M31 pool V2 (`bench/m31-pool/cairo/src`). `sdk/` and `server/` were excluded. PROOF2 and the virtual OS were
  not run.
- **Against:** `docs/hidden-asset-spec.md`, `docs/pool-v2-spec.md`, `docs/open-note-spec.md`,
  `docs/policy-note-spec.md`, and the prior reviews in `client-port/reviews/` and `bench/m31-pool/reviews/`.
- **Method:** 23 lanes (L01-L16, then gap rounds G21-G25 and G31-G32 chosen by a completeness critic).
  120 raw findings were merged into 69 (1 high, 3 medium, 24 low, 41 info; merge map in the appendix).
- **Changes made:** none, apart from this file. All PoCs ran in scratch copies.
- **Evidence:** lane PoCs, verifier work, `findings.json` (every raw finding with its votes, and each lane's
  assurances) and the workflow journal are in the local run directory
  `~/.local/share/templar/runs/battle-test-2026-09-25/`, written `swarm/` below. They are not in the
  repository (2.1 GB).
- **Embargo:** this record discusses the unreleased client-proof hiding work (H2 and H3). Scrub it before any
  public release, as for the other review records.

Evidence labels used below:
- **executed-poc**: an attack or forgery was built and run against the real code.
- **executed-test**: a measurement or test was run.
- **code-reading** and **reasoning**: not executed.

## 1. Verdicts

### 1.1 Soundness: no permissionless forgery, inflation, double spend or theft found (confidence: high for the code as built; the security level rests on stated assumptions)

No lane found a way for a client, prover, wrapping server, relayer or third party to:
- forge a spend,
- mint value,
- spend a note twice,
- redirect funds.

The one drain path is the pool owner's (F01, high). It is a trust assumption, not a bug.

This rests on executed evidence at every layer:
- **Circuit value rules.** Checked exhaustively over all 5,242,816 reachable carry cases and 16,384 real builds for each of five inflation witnesses. 400 random differential mutations showed the circuit never accepts a statement the native reference rejects.
- **Cairo verifier.** 1,854 mutations across 7 real proofs were all rejected, apart from 3 encodings that re-encode the same statement.
- **Gate-invalid proofs.** 17 proofs with a consistent transcript, one per gate family and each inflating the withdrawal, were all rejected by the pinned bridge.
- **Absent-sum forgery (M2).** Rejected.
- **Pool.** Field-by-field binding matrices were run through the real account code and the real Proof2Adapter with real client proofs. Real-fact end-to-end settlements pass, and replay fails.

The soundness level depends on five assumptions:
1. **FRI.** The pinned configuration gives 96 bits under the ethSTARK conjecture. The proven bound is only about 56 bits (Johnson) or about 50 bits (unique decoding), which is the same class as upstream (F08).
2. **Poseidon2.** Width-24 Poseidon2-M31 with RP = 22 is collision resistant, including in Tree::Compress mode. The generic node collision bound is 2^139.5. The algebraic analysis (G22) finds no attack below the generic bounds. The literature check was done from memory only (F16).
3. **The trusted sequencer.** It verifies PROOF2 and authenticates proof_facts (block hash, config hash, OS program).
4. **The pool owner.** The owner can replace the verifier (F01).
5. **Upstream stwo core.** It is unchanged by the fork and was exercised only as a black box.

Most important open soundness gap: lane G31 was cut off before any work, so no OODS-lie or FRI-level forgery (a non-low-degree DEEP quotient) was run against the Cairo FRI verifier. The fork's modified Cairo `fold_line`/`fold_circle` and batch inversions were checked only for equal values on honest data (L06).

### 1.2 Zero knowledge of the client proof: no leak found, and not proved for all of the transcript (confidence: medium)

**Proved part: T1/T2 openings, OODS values and claimed sums (1,132 M31 coordinates).**
- G32 proves a numeric bound. The statistical distance between two witnesses of one statement is at most 2^-62, or 2^-109.5 once alpha in F_{p^2} is excluded.
- The proof uses a per-iteration character bound (Kloosterman over F_{p^4}) and Hölder's inequality over 54 disjoint spanning groups of 44 iterations.
- The structural facts it relies on were measured at 21 challenge sets. Its model of the additive part matched re-proved iterations exactly (0/1132 mismatches).
- The numeric bound itself is reasoning.
- This settles open item O2.

**Unproved part: composition split pieces (T3) and FRI layers l0-l2 (open item O4).**
- No valid simulator route exists yet. The draft's routes for T3 are wrong (F24).
- The evidence here is empirical:
  - **Linear:** full-transcript tests at production size (35 queries, 2,390 iterations, 8,429 functionals) found no witness-dependent linear functional.
  - **Algebraic:** at production the transcript map is dominant onto the public variety. This was shown on subsets of up to 1,740 coordinates by exact Jacobian rank.
  - **Low-degree:** degree-2 and degree-3 searches found nothing.
  - **Character sums:** 68,400 production tests and 158,432 pinned-challenge tests found nothing.
  - **Positive controls:** the pre-H2 add-only build and a synthetic leak are both detected.
- G21 also showed that the linear and degree-2/3 tests cannot detect a real under-blinding, so they are weak evidence (F27). The dimension (Jacobian) test is the one with detection power, and production passes it with a 4.95x margin.
- H3 (blinding limbs reduced mod p) is still open. It costs at most about 2^-160 on the additive part, but it bounds the unproved part at about 2^-16 until O4 is proved or H3 is fixed.

### 1.3 Public-data privacy: structurally uniform on chain; wallet-policy and metadata leaks confirmed (confidence: medium-high)

**Established by execution.**
- An in-pool V4 transfer publishes no asset-dependent field.
- A real Sepolia ERC20 hidden transfer and an ERC721 hidden transfer have identical gas, event and storage structure.
- Proof size and structure do not depend on shape or asset (248 real proofs, 8 shapes).
- Dummy and real ciphertexts are indistinguishable over 20k samples each.
- All shapes share one circuit hash.
- No linear relation links two spends by the same key.

**What leaks:**
- **Re-plans and forced reverts.** They publish or hand out links between a note's nullifiers and the asset or recipient of another plan (F03, medium).
- **Bench wallet dummy input.** It is fresh on every proof, so re-proving exposes the real nullifier (F05, low; the SDK was not checked).
- **Fee payment.** Hidden-asset spends have no private way to pay a fee, so the fee payer links spends (F22).
- **ERC721 exits.** They reveal that both outputs are zero-value (F23).
- **COMPUTE.** It links a handle to an asset (F48).

---

## 2. Confirmed issues, by severity

| ID | Sev | Title | Original ids | Evidence |
|---|---|---|---|---|
| F01 | high | Pool owner can drain or freeze every asset by swapping the verifier | L07.1, L08.1, L10.1, L14.1, L15.2 | executed-poc |
| F02 | medium | Anyone can flush the 256-root ring and fail every in-flight spend | G25.1, L15.1, L08.2, L02.1, L07.3, L09.2 | executed-poc |
| F03 | medium | A statement that leaves the wallet ties its nullifiers to what it reveals; re-plans and forced reverts leak asset and recipient | L13.2, G25.2 | executed-poc |
| F04 | medium | Notes funded with an all-zero rho are credited but can never be spent | L16.1 | executed-poc |
| F05 | low | Bench wallet uses a fresh dummy per proof; spec §6 contradicts itself | L13.1, L12.2, L14.4, L16.4 | executed-poc |
| F06 | low | Verified invoke spends are bearer authorizations: third parties can settle and sandwich them down to `minimum` | L07.2 | executed-poc (on-chain half) |
| F07 | low | Plain spends have no expiry; a withholding server chooses when they settle | L15.4, G25.3 | executed-poc |
| F08 | low | FRI soundness is 96 bits conjectured, about 56 proven | G24.1, L05.4, L06.4, G24.3 | reasoning + executed cost |
| F09 | low | Inflation-critical circuit constraints are not killed by any committed test | L01.1, L14.2, L14.5, G23.2 | executed-poc (mutation) |
| F10 | low | Cairo absent-sum and LogUp-sum checks block inflation on their own, and committed tests pass without them | L06.1, G24.2 | executed-poc |
| F11 | low | Bridge-only statement rules have no real-proof negative tests (R4 and P1) | L14.7, G23.1 | executed-poc |
| F12 | low | Lane packing relies on an M31 pin applied by convention | L04.1, L02.4 | executed-poc |
| F13 | low | `verify_circuit_proof` takes root, config, outputs and salt from the proof | L05.1 | executed-poc |
| F14 | low | Client prover panics (aborts on wasm) on an inconsistent witness | L05.2 | executed-poc |
| F15 | low | Rust `bridge_checks` mirror accepts non-canonical felts | L03.1 | executed-poc |
| F16 | low | Compress node format undocumented; math-review NO-GO never closed on record | L04.2, L14.3 | code-reading + executed KAT |
| F17 | low | Fee-on-top ERC20 makes an asset insolvent | L09.1 | executed-poc |
| F18 | low | INVOKE can target an allowlisted shadow class | L10.2 | executed-poc |
| F19 | low | `set_verifier` emits no event; no owner view | L08.3, L15.3 | executed-poc |
| F20 | low | One hostile ciphertext aborts the reference V4 note scan | L16.2 | executed-poc |
| F21 | low | Non-canonical rho words (r+p) are credited but unspendable | L16.3 | executed-poc |
| F22 | low | No private fee path: a relayer fee forces the asset to be revealed | L13.3 | code-reading + tests |
| F23 | low | ERC721 exits reveal that both outputs are zero-value and nf0 is real | L13.4 | reasoning |
| F24 | low (ZK) | O4: no valid simulator route for T3 and FRI values | L11.1, G21.2, G21.4 | reasoning + executed-test |
| F25 | low (ZK) | Hiding argument §4.1 assumes independent rows (O2); now closed by G32 | L11.2, L12.1, G32.3 | executed-test |
| F26 | low (ZK) | Public claimed sums are masked only by the eq blinding rows | L11.3 | executed-test |
| F27 | low (ZK) | Hiding safeguards are not dimension-aware; no committed V4 hiding regression test | G21.1, G21.3, L11.4, G32.6, L14.8 | executed-poc |
| F28 | low | Pool V2 branches and real account path not covered by committed tests | L14.6, L02.5, L10.5, L07.7 | executed-test |

Info items F29-F69 are listed in section 2.4.

### 2.1 High

#### F01 (high): The pool owner can drain or freeze every asset by swapping the verifier

- **Where:**
  - `bench/m31-pool/cairo/src/pool_v2.cairo:381-385`: `set_verifier` checks only owner and nonzero, and emits no event.
  - `:391-396`: `set_policy_verifier`.
  - `:535` (V4) and `:312-314` (P1): the verifier's verdict is the only proof check.
  - `:164-170`: the owner is set once, with no transfer, renounce or getter.
  - `:559-581`: `pay_out` is bounded only by `held[a]`.
- **Impact:**
  - The owner, or anyone holding the owner key, can empty every ERC20, ERC721 and ERC1155 balance.
  - Installing a rejecting verifier instead freezes every withdrawal.
  - On Sepolia the owner is the deployer and relayer hot account (`bench/m31-sepolia/hidden_asset_flow.py:120,139`).
  - The owner cannot be moved to a multisig.
  - The role is also needed for liveness. `Proof2Adapter` pins one PROOF version and one OS program immutably (`adapter.cairo:60-62`), so a lost key freezes funds after the next sequencer rotation.
- **Attack:**
  1. The owner calls `set_verifier(MockVerifier(true))`.
  2. For each asset, the owner calls `apply_spend` with made-up nullifiers, the current root, arbitrary output commitments and a withdrawal of `held[a]` to themselves.
  3. The P1 path works the same way through `set_policy_verifier` and an owner-deployed controller.
- **Evidence (executed-poc):**
  - The strongest PoCs start from the production wiring: real R4 and P1 Proof2Adapters, real deposits, real S1/S2 settlements. A fabricated spend is rejected with `PROOF_BINDING` before the swap.
  - After the swap, the swap emits 0 events and all three standards are drained, with `held` going to 0. An honest note holder's exit then fails with `HELD_UNDERFLOW`.
  - A rejecting verifier makes a real S1 spend fail with `PROOF_REJECTED`.
  - A non-owner gets `NOT_OWNER`.
  - PoC files:
    - `swarm/verify/L10_1-reproduce/pool/src/tests/test_v101.cairo`
    - `swarm/verify/L14_1-threat-model/pool/src/tests/test_verify_l14_1.cairo`
    - `swarm/verify/L08_1-reproduce/pool/src/tests/v081.cairo`
    - `swarm/L08-pool-core/pool/src/tests/l08.cairo`
    - `swarm/L15-cross-layer-redteam/pool/src/tests/test_l15.cairo`
  - The L10.1 finder's own PoC was weak: its pool was deployed with an accept-all verifier. The verifier's PoC fixes that.
- **Known status:**
  - This is a documented trust assumption: `README.md:219` ("pool owners can currently change verifiers"), `docs/hidden-asset-spec.md` §5.7 (line 351ff lists the setters), and `docs/pool-v2-spec.md:361` (a production blocker, for the older package pool).
  - What is new:
    - Spec §5.6 (`docs/hidden-asset-spec.md:340-341`) justifies having no upgrade path because an upgrade "would let its owner replace the code holding all funds". The verifier setter already gives that power.
    - `set_verifier` emits no event (F19).
    - The owner can never be rotated.
    - `README.md:38` ("No privileged roles") is scoped narrowly, but it reads broadly.
- **Severity settled: high.** The task rubric names "an admin/owner path to drain" as high. Verifier votes were high x8, medium x3 and low x1; the lower votes argued that owner trust is documented. This is not a permissionless bug and not a proof-system bug.
- **Fix:**
  - Either (a) make verifier changes two-step with a timelock long enough for users to exit, with VerifierProposed and VerifierSet events on both setters, or (b) make the verifiers immutable and move OS-program and PROOF-version rotation into an append-only, timelocked allowlist read by the adapter.
  - Add two-step ownership transfer and a multisig owner.
  - State the owner's power in spec §5.6/§5.7 and fix the README wording.

### 2.2 Medium

#### F02 (medium): Anyone can flush the 256-root ring and fail every in-flight spend

- **Where:**
  - `bench/m31-pool/cairo/src/tree.cairo:11` (`ROOT_HISTORY_SIZE = 256`) and `:228-243` (`record_root` evicts the oldest root on every insert call).
  - `pool_v2.cairo:178-196`: `deposit` accepts any ERC20 and amount >= 1.
  - `:417-457`: ERC721 and ERC1155 hooks that any contract can call.
  - `:536`: `UNKNOWN_ROOT`.
- **Impact:**
  - One flush makes every in-flight V4 spend and P1 settlement of every user fail, withdrawals included.
  - Each victim must re-plan and pay for a new PROOF2 wrap (about 2-2.5 min on a 28-52 GiB server).
  - Repeating the flush keeps the pool closed for as long as the attacker pays.
  - If a flush lands between the wallet's simulation and inclusion, the victim's transaction is included REVERTED with its full calldata. That feeds F03.
  - Nothing is stolen, and funds are usable again once the attacker stops.
  - Honest traffic above about 1.6-2 inserts per second breaks spends the same way.
- **Measurements (G25.1, executed):**
  - Cost per recorded root in a mature pool, via snforge:
    - 57.86M sierra gas: direct ERC1155 hook from an attacker contract.
    - 58.25M: ERC721 hook.
    - 58.28M: the attacker's own ERC20.
    - 58.69M: an honest token.
  - All paths are within 1.5% of each other. The 32-level tree insert dominates the cost.
  - 256 roots cost 14.82e9 sierra gas in total.
  - The per-transaction cap is 1.0-1.11e9 (versioned constants 0.14.1-0.14.3). That is 17-19 roots per transaction, so 14-16 transactions.
  - The block sierra capacity of 5e9 gives 3-4 blocks, which is 5-7 s at the recorded 1.70 s per block.
  - The recorded PROOF2 round trip is 128-160 s, so 19-31 flushes fit in one round trip.
  - Cost at Sepolia prices is about 296-356 STRK per flush. Keeping the pool closed costs about 8.0-9.6k STRK per hour. Mainnet prices are unknown.
- **Evidence (executed-poc):**
  - `g25_real_spend_survives_255_roots` and `g25_real_spend_forced_unknown_root` use the real S1 statement with PROOF2 facts. After 255 junk roots the spend settles; after 256 it gets `UNKNOWN_ROOT`, and both nullifiers stay unspent.
  - Output is in `swarm/G25-forced-revert-linkage/g25-snforge-final.txt`, with arithmetic in `h1_numbers.txt`.
  - Five lanes reproduced this independently: L02, L07, L08, L09, L15.
- **Severity settled: medium.** Lane claims ranged from low to medium. Every verifier vote was medium or low with a "confirmed" verdict. G25 measured batching for the first time and showed the flush fits many times inside one wrap latency.
- **Fix:**
  - Preferred: bound root validity by block height, not by insert count. Store `root_history: key -> recording block` and accept a root while `current - recorded <= W`, with W well above PROOF2 latency (for example 600-4096 blocks). Junk inserts then cannot age a root, and every statement gets a deterministic expiry (this also bounds F07).
  - Alternatives:
    - Advance the ring at most once per block.
    - Never evict. This is sound, because the tree is append-only and nullifiers are global, but it lengthens F07.
  - The server should check `root_is_known` right before PROOF2, and the wallet should re-simulate right before submitting.

#### F03 (medium): A statement that leaves the wallet ties its nullifiers to what it reveals; re-plans and forced reverts leak asset and recipient

- **Mechanism:**
  - The nullifier is `H(NF, nk || cm || pos)` (`client-port/src/payment.rs:268-270`). It depends only on the note, never on the plan.
  - A failed or reverted spend leaves both nullifiers unmarked, because `verify_spend` in `pool_v2.cairo:521-546` is atomic and the root check comes before marking.
  - `docs/sdk-spec.md:434-436` lets re-plans of a live record "change outputs, amounts or recipients".
  - `docs/sdk-spec.md:421-424` (SDK-P16) and the account's lack of a signature let anyone holding a client proof re-wrap and settle it.
- **Variant A, re-plan seen by a server (L13.2).**
  1. The user sends hidden transfer T to server X, and X stalls.
  2. The user re-plans the same note as exit E to address R.
  3. Whoever saw both (X, another server, the RPC provider that simulated them, or everyone if T reverted) learns T's asset and that the owner of R sent T.
  4. X can still settle T before E, so an executed "hidden" transfer then has a known asset and sender.
  - The bench's real Sepolia statements S2 (hidden NFT gift, token_out 0) and S4 (NFT withdrawal to 0xb0b) share nf0 and the root. Both reached the gateway and RPC simulation.
- **Variant B, forced revert of an exit (G25.2).**
  1. A flush (F02) lands between the pre_confirmed simulation and inclusion. Alternatively, a party that sees the signed transaction delays it or orders a tipped flush ahead of it; the SDK uses `tip: 0`, `docs/sdk-spec.md:462`.
  2. The exit is published REVERTED, with nf_real, asset A and recipient R.
  3. Any later statement of that note carries the same nullifiers. With the sticky companion that is both nullifiers; with the bench wallet it is the real one.
  4. A re-planned hidden transfer, its outputs and any later mix are therefore tagged with asset A and linked to R.
- **Evidence (executed-poc):**
  - `swarm/verify/L13_2-reproduce/pool/src/tests/test_pool_v2.cairo`: a third-party caller settles the stale hidden plan after 20 unrelated deposits, then the exit fails with `NULLIFIER_USED`.
  - `swarm/G25-forced-revert-linkage/poc/tests/forced_revert_linkage.rs`: two real proved statements with circuit hash `e3 9a 2b f6...`, equal to the deployed pin. They show 2/2 shared nullifiers when an exit is re-planned as hidden under the sticky companion.
  - snforge `g25_real_spend_forced_unknown_root`: the reverted S1 leaves `get_nullifier_spent == false`.
  - That reverted transactions are included and published is code-reading of sequencer 625929a (F33).
  - The fraction of spends a blind third-party flusher can push to an on-chain revert (about 5-10%) is reasoning.
- **Severity: medium** (linkability of spends to notes and owners, conditional). Both variants were confirmed by 4 verifier votes, all at medium.
- **Fix:**
  - Spec (`hidden-asset-spec` §6/§7, `sdk-spec` §9.1):
    - Once a statement has left the wallet, re-plans of that record must keep the same exit profile (same asset path and same recipient) until the record is dead.
    - Never re-plan exit to hidden or hidden to exit.
    - After a published revert, treat the note as tagged and never mix it.
    - State that simulation cannot prevent a published revert.
  - Pool: F02's block-height window removes the cheap third-party trigger.
  - Only a private submission channel stops the privileged parties (RPC, relayer, server, sequencer).
  - Wallets should use a nonzero tip.

#### F04 (medium): Notes funded with an all-zero rho are credited but can never be spent

- **Where:**
  - `bench/m31-pool/hidden_asset.py:65-72` (`find_notes`) and `bench/m31-pool/policy_wallet.py:129-134` (`parse_m301` does no validation).
  - The normative receiving rule, `docs/hidden-asset-spec.md:381-384`, only recomputes cm.
  - `pool_v2.cairo:178-181`: the proofless append paths accept any nonzero inner.
  - The spend relation requires a nonzero rho: `payment4.rs:420-421`, and `:138` in the native statement check.
- **Attack:**
  1. Alice deposits X USDC with `inner = H(INNER, receiver_Bob || 0^9)` and a correctly sealed M301 for Bob.
  2. Bob's wallet recomputes cm, finds a match, and shows X USDC.
  3. No prover can ever spend the note.
  4. A merchant who ships on wallet confirmation loses the goods. Alice pays the same as an honest purchase and burns her own funds.
  - An NFT sent through the hook the same way locks that token id permanently.
- **Evidence (executed-poc):**
  - snforge `l16_zero_rho_deposit_accepted`: the leaf equals the pool's commitment.
  - `swarm/L16-note-encryption/poc_zero_rho_e2e.py`: the note is credited `[[0,500,[0...0]]]`, and `wallet prove4` exits with rc=101 "invalid spend: input encoding".
  - The verifier's `swarm/verify/L16_1-reproduce/poc/tests/zero_rho.rs` shows the circuit's `nonzero_vector` (`payment.rs:523-535`) rejects every witness, so a custom prover cannot spend it either.
- **Fix:** Put the SDK-M1 receive checks (`docs/sdk-spec.md` §6 rule 4) into hidden-asset-spec §6 and into both bench `find_notes` functions, before any hashing:
  - exact M301 layout with zero padding;
  - rho and receiver words below p;
  - rho not all zero;
  - 0 < amount < 2^128 and 0 < asset < 2^251.
  - The SDK implementation was not checked.

### 2.3 Low

**F05: Bench wallet uses a fresh dummy per proof; spec §6 contradicts itself** (L13.1, L12.2, L14.4, L16.4)
- **Where:** `client-port/examples/wallet.rs:189-195` draws the dummy sk, rho, position and siblings from OsRng on every `prove4` (doc comment at :23-25). `bench/m31-pool/hidden_asset.py` and `bench/m31-sepolia/hidden_asset_flow.py` store no companion. `docs/hidden-asset-spec.md:367-369` says "never reused, including when a spend is re-proved", while the amendment at :369-376 (SDK-M10/M17) makes the dummy sticky.
- **Impact:** re-proving one single-input spend publishes the same nf0 next to a new nf1. Anyone who sees both statements learns the real nullifier and that the spend had one input, which the V4 uniform shape is meant to hide.
- **Evidence (executed-poc):**
  - `swarm/L13-privacy-metadata/py/retry_dummy.py`: 3 `prove4` runs give one nf0 and three different nf1. Reproduced independently.
  - The real Sepolia S2/S4 share nf0 and differ in nf1.
- **Severity:** low, because it affects the bench wallet only. It would be medium in any production wallet that follows the §6 base sentence. The SDK is specified to be sticky but was not checked.
- **Fix:**
  - Implement per-note companions in the bench wallet, or mark it non-conforming.
  - Rewrite the §6 base sentence and mark the HA-M6 resolution as superseded.
  - Test that two `prove4` runs of one note publish the same nf1.

**F06: Verified invoke spends are bearer authorizations; third parties can settle and sandwich them down to `minimum`** (L07.2)
- **Where:**
  - `pool_v2.cairo:211-282`: no caller check.
  - `open_note.cairo:81-116`: the intent has no submitter.
  - `adapter.cairo:48-75`: never reads the sender.
- **Attack and evidence:**
  - A contract runs buy, `apply_spend_with_invoke(victim spend)`, then sell, in one transaction.
  - This was executed with a real client proof and the real account message, with facts simulated: the victim received 371 instead of the fair 384 (its minimum was 370), and the attacker went from 180 to 193 (`swarm/L07-bridge-binding/pool/src/tests/l07_sandwich.cairo`, re-run by two verifiers).
- **Who can do it:**
  - Anyone who holds the statement and facts before settlement: the relayer, RPC provider, server, sequencer and p2p peers, and everyone after a published revert.
  - In sequencer checkout 625929a, `crates/apollo_transaction_converter/src/transaction_converter.rs:398-410` skips PROOF2 verification when the facts hash is already stored. There, a later transaction with the same facts needs no valid proof. I read this code; it was not run, and the live PROOF2 gateway may differ.
- **Severity settled: low.** The loss is bounded by the user's own `minimum`, and only invoke spends are affected. Verifier votes were medium and low. See the disputed items (section 3).
- **Fix:**
  - Wallets should use a tight destination minimum and a short expiry.
  - Document that a reverted execution stays settleable by anyone until expiry or proof age.
  - Optionally add a `submitter` field to `hash_intent_of`.

**F07: Plain V4 spends have no expiry; a withholding server chooses when they settle** (L15.4, G25.3)
- **Where:** `adapter.cairo:64-67` bounds only the PROOF2 base block. `spend4.cairo:31-50` has no validity field.
- **Impact:** a server that keeps a client proof can re-wrap it with a fresh base block at any time while the root is in the ring, which is indefinitely on a quiet pool. It can settle next to the user's next action (timing correlation), or ahead of the user's re-plan so that the re-plan reverts publicly.
- **Evidence (executed-poc):** `g25_stale_proof_reverts_in_execute`: a stale base block gives `PROOF_AGE`, and the same statement re-faked with a fresh base block settles.
- **Fix:** the F02 block-height window gives every statement a deterministic expiry. Alternatively, bind a fixed-offset `valid_until` into the statement.

**F08: FRI soundness is 96 bits conjectured, about 56 bits proven** (G24.1, L05.4, L06.4, G24.3)
- **Where:**
  - `client-port/src/prove.rs:31-32` (`BRIDGE_FRI`: pow 26, blowup 2, 35 queries, fold 4).
  - Vendored `circuit_air/src/multiverifier_consts.cairo:17-24`.
  - `verifier_core/src/verifier.cairo:65-69` (`security_bits >= 96`, computed as pow + blowup x queries).
  - The DEEP coefficient and the fold alphas are drawn with no grinding (stwo `prover/pcs/mod.rs:302-305`).
- **Numbers (reasoning, lane script `swarm/G24-cairo-gate-forgery-and-soundne/soundness.py`):**
  - 96 bits under the ethSTARK conjecture.
  - About 56.3 bits proven in the Johnson regime; about 49.7 in unique decoding.
  - The best known attack costs about 96 bits of work.
  - Upstream (26 + 1 x 70) sits on the same line.
  - Because the DEEP coefficient and fold alphas are not ground, the commit phase caps the proven bound at 97.7 bits (unique decoding) or 64 bits (Johnson), however many queries are used.
  - The theorem constants were recalled without network access (plus or minus 2 bits).
- **Cost (executed):**
  - 35 queries: 1.98M bridge steps and 29.3k felts.
  - 76 queries: 3.85M steps. 110 queries: 5.26M steps.
  - Each extra query adds about 45k-41k steps and about 650 felts.
  - More than 42 queries overflows the 2^12 eq table under the blinding budget and forces a re-pin (G24.3).
- **Fix:**
  - State "conjectured 96, proven about 56" in `prove.rs`, the consts and the spec.
  - If 100 proven bits are required: add a 3-bit or larger grind before the DEEP and fold challenges (a Rust and Cairo protocol change), use about 112 queries, re-pin, and budget about 2.7x the bridge steps.

**F09: Inflation-critical circuit constraints are not killed by any committed test** (L01.1, L14.2, L14.5, G23.2)
- **What:** mutation testing on copies of client-port. Each of the following mutants passes all suites (payment_r0, payment_r4 12/12, payment_r4_malicious 7/7, policy_p1 7/7, policy_p1_malicious 11/11):
  - carry quartic removed (`payment.rs:602-605`);
  - amount-bit booleanity removed (`merkle.rs:16-19` via `payment.rs:552`);
  - limb decomposition replaced by a free guess;
  - input-1 limbs unranged (`payment4.rs:430`);
  - output limbs unranged (`:443`);
  - position-bit booleanity removed;
  - `(1-x)*intent` removed (`:541`);
  - input sk/rho nonzero removed (`:418-421`);
  - identity-flag booleanity removed (`:547`);
  - withdrawn limbs unranged (`:528`).
- **Regression-model PoCs (executed), each gate-valid once its constraint is removed and rejected today:**
  - in = 5 to out = 5 + p;
  - a negative limb (+32,575);
  - a dummy mint of 327,675 units;
  - a free-carry mint of p.
  - Files: `swarm/L01-circuit-value/poc/tests/l01.rs`, `swarm/L14-spec-conformance/mutpoc/tests/regression_mint.rs`, `swarm/G23-p1-shared-pool-drain/poc/tests/g23_loadbearing.rs`.
- **Why it matters:** the pinned circuit hash offers no protection, because `build_bridge_arith.py` re-pins from whatever the proving run produced.
- **Mitigations already in place:**
  - Some mutants have a later backstop: the bridge exit rule catches the `m10` mutant, and the bridge 'amount limb range' check catches the withdrawn-limb one.
  - Deleting only the quartic `eq` while leaving the `eval!` product trips the unused-variable lint in `payment_r0::circuit_finalizes_with_lint`, so the regression needs a clean deletion.
- **Fix:**
  - Add raw-value tamper hooks for carries, limbs and bits.
  - Commit the lane cases: carry outside {-2..1}, a non-boolean amount bit, input-1 limbs (p-5, 5, 0...) on a dummy, an output limb of 2^16 or more, a non-boolean position bit with sibling = node, a zero-budget invoke with x forced to 0, and an identity flag of 2.
  - Add a pinned-hash CI test (F38).

**F10: Cairo absent-sum and LogUp-sum checks block inflation on their own, and committed tests pass without them** (L06.1, G24.2)
- **Where:** vendored `circuit_air/src/lib.cairo:185-188` (`absent_components_claim_zero`) and `:189-193` (`lookup_sum(...).is_zero()`).
- **Evidence (executed-poc):**
  - A real proof of the pinned circuit with the withdrawal raised by 1 and the imbalance moved to the absent `triple_xor` sum:
    - The real bridge rejects it: "absent component claims a nonzero sum".
    - A copy with only that assert removed accepts it and emits the binding.
    - The existing `*-absent-claimed-sum` cases fail on both builds (with "Invalid OODS eval" on the copy), so the 60-case suite cannot tell them apart. (`swarm/L06-stark-cairo/poc/tests/l06.rs`, `bridge-noabsent/`)
  - The G24_2 verifier disabled the LogUp-sum assert (`swarm/verify/G24_2-code-path/bridge-nosum`):
    - The unbalanced eq forgeries (withdrawal +1 and +2^16, and the +p carry-quartic case) were ACCEPTED.
    - The committed `validate_bridge_r4.py` still passed 60/60 (`validate-nosum.out`).
  - A Cairo-only change to qm31_ops constraint weighting fails closed: honest proofs are rejected (`runs-mut.out`).
  - So the risk is a rebase or vendor refresh that removes a whole check. `build_bridge_arith.py` re-copies circuit_air from the fork on every build.
- **Fix:** add these to the `validate_bridge_r4.py` FORGERIES with required reason substrings:
  - the 17 G24 gate-invalid proofs (`swarm/G24-cairo-gate-forgery-and-soundne/poc/tests/g24.rs`);
  - the L06 forge-amount-absent proof;
  - require the reason on the existing absent cases.

**F11: Bridge-only statement rules have no real-proof negative tests** (L14.7, G23.1)
- **Which rules:** the circuit admits the statements and only the bridge rejects them.
  - R4: amount without recipient (`cairo-r4/bridge/src/lib.cairo:136`), zero pool (`:123`), pool of 2^251 or more (`:126`), 28-bit limb range (`:55`).
  - P1 (`cairo-p1/bridge/src/lib.cairo`): limb range `:58`, canonical felt `:61`, address range and withdrawal pairing `:143-151`.
- **Evidence (executed-poc):**
  - Real forged proofs are rejected with the named reasons (`swarm/L14-spec-conformance/poc/tests/extra_forgeries.rs`, `swarm/G23-p1-shared-pool-drain/poc/tests/g23_bridge.rs`).
  - The G23_1 verifier removed the P1 limb-range and withdrawal asserts: 5 forged proofs were then accepted, and the committed validator did not notice (`swarm/verify/G23_1-code-path/run_mut.py`).
- **Impact if a check regressed:** creator/acceptor address confusion of the PI-2 class. It is not inflation.
- **Fix:** commit these real-proof negatives, plus a raw-limb builder for the limb-range case.

**F12: Lane packing relies on an M31 pin applied by convention** (L04.1, L02.4)
- **Where:**
  - `membership.rs:116-120` (`pack` = `from_partial_evals`), `:148-210`.
  - The only guard is the finalize pin `pointwise_mul(var, one) = var` at `target/proving-arith/crates/circuits/src/context.rs:221-223`.
- **Evidence (executed-poc):**
  - A lane-shift forgery of a digest word is rejected only by the projection gate, and accepted when the two projection gates are removed (`swarm/L04-poseidon2/poc/tests/l04.rs`).
  - A non-base sibling is valid before finalize and invalid after.
  - An analyzer shows that all 2,067 pack products in production have lanes forced into the base field, and that there are 0 coordinate-mixing products in the relation.
  - The G24 `c-pin-recipient` forgery shows the pin is the only barrier against shifting amount limbs inside packed output 25, and that Cairo enforces it.
- **Fix:**
  - Use `M31Wrapper` types, or debug-assert on `pack`, `sponge_lanes` and `compress_lanes`.
  - Commit the analyzer test and the lane-shift negative.

**F13: `verify_circuit_proof` takes root, config, outputs and salt from the proof** (L05.1)
- **Where:** `circuit_prover/src/verify.rs:22-64`. The root comes from `stark.commitments[0]` at `:29`, and the config from the proof at `:31/:41`.
- **Evidence (executed-poc):** each of the following returns Ok, while `native_verify` rejects the first three (`swarm/L05-stark-rust/poc/tests/l05.rs` t07-t11):
  - a weak config (1 query, 0 PoW bits);
  - a proof of another circuit with the same layout;
  - trace lifting +2;
  - salt 12345.
- **Current callers:** `prove.rs:89-97` `native_verify` and the Cairo bridge both pin everything.
- **Fix:** have the function take the trusted root, PcsConfig and outputs, or rename it to `..._unpinned`.

**F14: Client prover panics on an inconsistent witness** (L05.2)
- **Where:** `prove.rs:176-204` never calls `is_circuit_valid`. The fork's `prover.rs:230` `assert_eq!(lookup_sum, 0)` then panics. That assert is also present upstream.
- **Impact:** with `panic = "abort"`, a wasm module aborts. This contradicts the module doc at `prove.rs:1-3`.
- **Evidence (executed-poc):** withdrawal +1 panics (t16).
- **Fix:** check `is_circuit_valid()` first and return Err.

**F15: Rust `bridge_checks` mirror accepts non-canonical felts** (L03.1)
- **Where:** `payment4.rs:202-233` and `payment.rs:157-163`. The Cairo bridge rejects these values at `lib.cairo:48-59`.
- **Evidence (executed-poc):** three real proofs (intent = p, delivery = p, delivery = 2^252-1) pass `bridge_checks` and are rejected by the bridge with 'non-canonical felt'.
- **Impact:** wasted proving and wrapping only.
- **Fix:** add canonicity checks to `bridge_checks`, and make `felt_limbs` reject values at or above p.

**F16: Compress node format undocumented; math-review NO-GO never closed on record** (L04.2, L14.3)
- **Where:**
  - Production pins Tree::Compress (`prove.rs:39`; bridge tag R0C4).
  - `payment.rs:14-17` still says "experimental ... pending its own review".
  - `reviews/math-review.md:16-18` says NO-GO.
  - `results/stwo-client-r0-compress/README.md` says "not an adopted format".
  - `docs/hidden-asset-spec.md` §2 does not define the node layout or the level word.
- **Where each math-review precondition stands:**
  1. The M1 layout fix is done (`payment.rs:245-256`, fixed words at 18..23).
  2. The algebraic/CICO bound check was answered by G22 (reasoning, with executed degree measurements). It finds no attack below the generic bounds at RP = 22.
  3. The literature check was done from memory only and must be repeated online.
  4. The constants KAT was closed by execution: L04 regenerated all 214 Grain constants, and the L14_3 verifier's `grain_kat.py` and `matrix_kat.py` agree.
- **Current state:** Rust, Python, Cairo and pinned Plonky3 all agree on the layout (151/151 oracle checks).
- **Fix:**
  - Write the node definition into spec §2.
  - Record the precondition results and update the math-review verdict and the `payment.rs` doc.
  - Do the online literature check (G22 names the 2025 "Skipping Class" result).

**F17: Fee-on-top ERC20 makes an asset insolvent** (L09.1)
- **Where:** `pool_v2.cairo:189-192` checks only the receiver-side delta. The ERC20 `pay_out` at `:566-568` checks only the bool. The header comment at `:10-11` overclaims.
- **Evidence (executed-poc):** after two deposits of 1000, held = 1000 and balance = 990, and the last holder's withdrawal gets `INSUFFICIENT_FUNDS` (`swarm/L09-pool-assets/pool/src/tests/test_l09_assets.cairo`).
- **Scope:** only notes of that asset are affected.
- **Fix:** at deposit, also require that the caller's balance fell by exactly `amount`. Optionally check the payout delta.

**F18: INVOKE can target an allowlisted shadow class** (L10.2)
- **Where:** `pool_v2.cairo:221-227` applies the class allowlist to COMPUTE only, and `:253` calls `privacy_invoke` with user calldata.
- **Evidence (executed-poc):** a hypothetical allowlisted class with two entry points is driven to act for a victim's commitment with no proven handle.
- **Current exposure:** not exploitable with the upstream anonymizer, which exposes only `privacy_invoke_with_computation`.
- **Fix:** in the INVOKE branch, assert that the target's class is not allowlisted, or document the obligation in open-note-spec.

**F19: `set_verifier` emits no event; no owner view** (L08.3, L15.3)
- **Where:** `pool_v2.cairo:381-385`. Compare `:391-396` (`PolicyVerifierSet`) and `:402-407` (`ShadowClassSet`).
- **Evidence (executed-poc):** `spy_events` shows 0 events.
- **Visibility:** a swap is still visible in state diffs and in the transaction itself.
- **Fix:** emit `VerifierSet` (also in the constructor) and add `get_owner`.

**F20: One hostile ciphertext aborts the reference V4 note scan** (L16.2)
- **Where:** `bench/m31-pool/hidden_asset.py:68-71` passes an unchecked asset to `wallet commitment`. `felt_limbs` panics on values of 2^252 or more (`payment.rs:160`), and `policy_note.py:18-20` has `check=True`.
- **Evidence (executed-poc):** a poisoned M301 before a real note makes the whole scan raise, and the honest note is not credited (`swarm/L16-note-encryption/poc_receive.py` case D; independent reproduction `swarm/verify/L16_2-reproduce/repro.py`).
- **Severity settled: low.** It affects the bench reference helper only, funds stay spendable with a fixed wallet, and the fix is trivial. Votes were medium and low. It would be medium in a production wallet that lacks SDK-M2 (not checked).
- **Fix:** validate every field before any tool call, wrap each candidate in try/except, and mirror `policy_wallet.recover` (PI-3).

**F21: Non-canonical rho words (r+p) are credited but unspendable** (L16.3)
- **Where:** `policy_wallet.py:59-60` decodes without a range check. `wallet inner` reduces mod p, so the recomputed cm matches, but `payment4.rs:138` rejects the stored rho.
- **Evidence (executed-poc):** the note is credited, the spend fails with 'input encoding', and it works after reduction.
- **Fix:** reject words at or above p when parsing (SDK-M1 rule 4). Do not normalize silently.

**F22: No private fee path for hidden-asset spends** (L13.3)
- **Why:** any withdrawal forces x = 1 and publishes the asset (`payment4.rs:538-546`; bridge `lib.cairo:139-141`; pool `pool_v2.cairo:527-530`). A fee note uses one of the two outputs, which leaves no change.
- **Consequence:** in practice the user pays gas from a public account. On Sepolia this is about 3.4 STRK and 138.3M L2 gas per hidden transfer, and the bench flow uses one ACCOUNT for everything.
- **Evidence:** code-reading, plus the existing tests re-run by two verifiers.
- **Severity settled: low.** The finder claimed medium; both verifiers said low. The SDK already reports `linkable: true`, so this is a documented limitation and a design constraint for a future relayer.
- **Fix:** before shipping a relayer, specify a fee mechanism that does not reveal the asset. State in §7 that hidden-asset privacy needs an unlinkable submitter.

**F23: ERC721 exits reveal that both outputs are zero-value and nf0 is real** (L13.4)
- **Why:** one ERC721 id backs at most one amount-1 note (`pool_v2.cairo:427-428`), and input 0 is nonzero (`payment4.rs:429`). So a withdrawal of amount 1, or any exit that brings `held[a]` to 0, implies both output leaves are zero-value and nf0 is the real input.
- **Evidence:** reasoning, consistent with Sepolia S4.
- **Fix:** document it in spec §7.

**F24 (ZK): O4, no valid simulator route for T3 and FRI values** (L11.1, G21.2, G21.4)
- **What is wrong in the draft:**
  - `reviews/hiding-argument.md:122-131` (§4.2) derives the T3 openings from local trace values.
  - The prover commits the composition halves L and R separately (`stwo prover/mod.rs:64-70`, `cpu/circle.rs:266-271`), and the verifier checks only `L + pi^{t-1}(z).x * R` (`core/proof.rs:50-55`).
  - Any functional that returns R(P) depends on about 2^18 points, so no local simulator exists.
- **Further results:**
  - G21's `h5_cross` shows that every T3 coordinate and every FRI value has cross terms between every pair of blinding variables, and that conditioning on T2 fixes all blinding. So the proposed conditional-affine simulator cannot work.
  - G21.4 shows there are 16 M31 coordinate-wise composition relations, not 4. They are statement-determined and harmless, but any simulator must satisfy them.
- **Evidence:**
  - reasoning, plus the executed cross-term test `swarm/G21-zk-o4-nonlinear-production/poc/src/bin/h5_cross.rs`;
  - null probes of degree 2 and below (`swarm/L11-zk-theory/poc/tests/quadratic.rs`).
  - No distinguisher was found.
- **Severity settled: low.** The finder claimed medium; both verifiers said low. This is a gap in a document marked DRAFT, not a leak.
- **Fix:** either
  - (a) add a ZK-FRI masking column: an unconstrained random QM31 column of full degree in the DEEP batch;
  - (b) randomize the split pieces, which needs degree slack; or
  - (c) state O4 as conjectural, backed by the G21 dominance evidence.

**F25 (ZK): Hiding argument §4.1 assumes independent rows (O2); now closed by G32** (L11.2, L12.1, G32.3)
- **What is wrong in the draft:** `hiding-argument.md:108-121` factors over "independent rows". In fact:
  - x is shared by rows A and D;
  - y is shared by rows B and D;
  - e is shared by qm31_ops row E and the eq row (`finalize.rs:91-120`);
  - multiplicities are 2/2/1/0/3.
- **Resolution:** G32.1 redoes the argument per iteration and gets the 2^-62 bound. G32.3 shows that the F_{p^4} Weil step is not the load-bearing one: the non-degeneracy condition (alpha not in F_{p^2}) is.
- **Evidence (executed-test):** `swarm/L11-zk-theory/poc/tests/rows.rs`; `swarm/G32-zk-additive-bound-and-characte/poc/src/model.rs`.
- **Fix:** replace §4.1/O2 with the G32 argument, including the group size of 44 forced by the eq row.

**F26 (ZK): Public claimed sums are masked only by the eq blinding rows** (L11.3)
- **Why:** per iteration, the qm31_ops LogUp terms for x, y and z cancel. Only e crosses components: -2/d(e) in qm31_ops and +2/d(e) in eq. So `claimed_eq = W_eq + sum_i 2/d(e_i)`.
- **Evidence (executed-test):**
  - With the eq rows removed, both claimed sums become the same across seeds and change with the witness (`swarm/L11-zk-theory/poc/tests/claims.rs`).
  - In production they vary with the seed.
- **Fix:** state this as a lemma, and add a regression test that the claimed sums vary with the seed.

**F27 (ZK): Hiding safeguards are not dimension-aware; no committed V4 hiding regression test** (G21.1, G21.3, L11.4, G32.6, L14.8)
- **The tests:**
  - On a small circuit at the production FRI config, the full-transcript linear test is clean at k = 200 blinding iterations, while the transcript variety still depends on the private value (Jacobian rank 3,200 against dim V_pub 5,620).
  - The degree-2 and degree-3 subset probes stay silent even at k = 2 on the real circuit.
  - Only the Jacobian dimension test separates these cases. Production has dim V_pub = 7,720, a threshold of k >= 483, and a budget of 2,390 (4.95x).
- **The runtime guard:** `prove.rs:200-203` compares QM31 FRI values plus a per-column constant against the number of iterations. It does not count M31 dimensions. It still forces k >= 1,747 today, but it would pass a blinding change that cuts the randomness per iteration.
- **The repo's hiding examples:** they ran only on V3 `payment::build`. The L14_8 verifier retargeted `hiding_rank` (all 8 shapes), `hiding_invariants` and `hiding_points` (Single, Transfer) to `payment4`. All were clean: rank 336/336, 0 invariants, points full rank 468 and 6,768 (`swarm/verify/L14_8-code-path/out/run-log.txt`). This is now executed evidence, but it is not committed.
- **Evidence:** executed-poc (`swarm/G21-zk-o4-nonlinear-production/poc/src/bin/{h2_sweep.rs,h2_gap.rs,h2_quad.rs}`).
- **Severity settled: low.** The finder claimed medium; both verifiers said low. Production passes with margin.
- **Fix:**
  - Make the Jacobian dimension test the hiding regression test.
  - Check `16*k >= dim V_pub` in M31 units in `prove()`.
  - Port `h12_model`'s structural checks (dim V_i = 36, d = 1128, kernel = claim sum, at least 12 disjoint spanning groups).
  - Commit V4 versions of the hiding examples.
  - Mark Lemma C as necessary but not sufficient.

**F28: Pool V2 branches and the real account path are not covered by committed tests** (L14.6, L02.5, L10.5, L07.7)
- **What is missing:** no committed V2 test reaches any of the following:
  - UNKNOWN_ROOT, ZERO_NULLIFIER, WRONG_CHAIN/WRONG_POOL, PROOF_REJECTED;
  - INTENT_NEEDS_INVOKE, ASSET_RANGE, EXECUTION_*, IDENTITY_*;
  - a duplicate nullifier within one spend;
  - high tree indices, TREE_FULL or root-ring eviction;
  - the real statement account running against the pool.
- **Evidence (executed-test):** the lanes wrote tests for all of these, and they pass:
  - `swarm/L14-spec-conformance/pool/src/tests/test_l14_gaps.cairo` (24 tests);
  - `swarm/L02-circuit-membership/pool/src/tests/test_l02.cairo` (15);
  - `swarm/L10-pool-invoke-policy/pool/src/tests/test_l10.cairo` (14);
  - `swarm/L07-bridge-binding/pool/src/tests/l07_*.cairo` (24).
- **Fix:** commit them.

### 2.4 Info (observations, doc drift, positive results)

| ID | Title | Original ids |
|---|---|---|
| F29 | When the tree is nearly full every note freezes, withdrawals included; filling it is infeasible (about 2.5e17 L2 gas) | L02.2, L08.5, L15.7 |
| F30 | The pool tree format is a free constructor argument, not tied to the R0C4 pin; the binding domain does not include the format | L02.3, L14.10 |
| F31 | Adapter header documents only the V3/P1 tags; the real Sepolia facts match the V4 tuple | L07.4, L15.6 |
| F32 | Adapter does not pin facts[5..6] (block hash, config hash); it relies on the sequencer | L07.5, L15.5 |
| F33 | Sequencer mechanics: reverted PROOF2 transactions are included with public calldata; proofs are archived before execution; ordering is by tip; client-proof ZK must hold against the operator's archive | G25.4, L07.6 |
| F34 | Proof encoding malleability: `channel_salt` not pinned (salt+P accepted); extra empty tree-0 sample columns accepted | L05.6, L06.2 |
| F35 | Native verifier panics on malformed proofs | L05.3 |
| F36 | Rust verifier lacks the relation-uses < P check (Cairo has it) | L05.5 |
| F37 | Upstream test helper `stwo_verify` discards the PoW result | L05.7 |
| F38 | Vendored circuit-hash KAT is stale (fails); no committed test ties the pin to current code (executed: all 8 shapes match today) | L06.3, L14.9 |
| F39 | Spec §4.2 names `guess_bits` and `payment.rs:632`; code uses `payment4.rs` `bit()` | L01.2, L03.4 |
| F40 | Identity handle proves key ownership, not one handle per user and application (scope is a free witness) | L03.2 |
| F41 | Delivery digests, recipient and intent (when x = 1) are free prover inputs; their meaning is checked by bridge and pool | L03.3 |
| F42 | Poseidon2 margin and compression-mode analysis: (8,22) against minimum (6,20); antisymmetric-pair round skipping (executed, 2 rounds; about 8 by counting); generic bounds collision 2^139.5, inversion 2^186 | L04.3, G22.1, G22.2 |
| F43 | Cairo lazy-reduction permutation has a wide overflow margin | L04.4 |
| F44 | `held` caps payouts at the whole pool's holding of an asset, not per user | L08.4 |
| F45 | Sepolia pool deployed with the owner account as placeholder verifier (fails closed) | L08.6 |
| F46 | Unowned ERC1155/ERC721 surplus can be credited by the token's own hook call | L09.3 |
| F47 | Token issuer and recipient trust on payout (ERC721 `transfer_from`, ALREADY_HELD after clawback, pause/blacklist) | L09.4 |
| F48 | Collect-only and COMPUTE need an ERC20 input-0 note; each COMPUTE publishes (handle, asset) | L10.3 |
| F49 | COMPUTE class check is per class, and runs before the budget transfer | L10.4 |
| F50 | H3 refinement: at most about 2^-160 on the additive part; the 2^-16 cap applies only through O4; draft Lemma D vs §5 inconsistent | L11.6, G32.2 |
| F51 | O3 leaf-entropy claim false as stated; settled: T1/T2 siblings keep full rank (16 and 12 M31), l3/l4 fully determined | L11.5, G32.5 |
| F52 | Lemma A/C gaps on eq closed by lanes; "eq is the tight case" misplaced | L11.7, L11.8 |
| F53 | The topology check in `prove()` cannot detect a branch on private data; none exists (32 builds identical) | L11.9 |
| F54 | PoW nonce layout depends on the grinder implementation; SIMD is deterministic across thread counts | L12.3 |
| F55 | Bench flows use a fixed output-slot convention | L13.5 |
| F56 | `wallet prove4` publishes the root of whatever leaf prefix it is given | L13.6 |
| F57 | Older bench sync paths query `get_nullifier_spent` per note | L13.7 |
| F58 | Residual open items from prior reviews (L3, N3, HA-IC1, HA-IC3(c), bounded-pcs M2) | L14.11 |
| F59 | NFT hooks are not a cheaper flush path; the ERC1155 hook needs no real token | G25.5 |
| F60 | Positive: the additive transcript part is within 2^-62 of witness-independent (O2 closed) | G32.1 |
| F61 | Positive: character-sum distinguishers find nothing; the positive controls are detected | G32.4 |
| F62 | Lifted Merkle commitment does not bind small columns as lifts; argued safe for eq by LogUp averaging (not executed) | G24.4 |
| F63 | Fixture key derivations have no chain/pool context | L16.5 |
| F64 | `find_notes` trusts its input: no digest check, no leaf authentication, no dedup | L16.6 |
| F65 | Receiver matched only against the decrypting index; nonzero M301 padding accepted | L16.7 |
| F66 | Viewing keys disclose more than ADR-0020 states (no internal change key) | L16.8 |
| F67 | Sealed boxes are not key-committing; the cm check makes this harmless | L16.9 |
| F68 | Delivery is X25519 only: no forward secrecy, not post-quantum (documented) | L16.10 |
| F69 | Spec wording errors: M301 token described as nine words (it is a 32-byte felt); P1 spec lists 28-bit felt limbs as a circuit rule | L16.11, G23.3 |

---

## 3. Disputed items and severity settlements

Settled by the synthesis lead (rationale above):
- **F01 owner drain: settled high.** The rubric names owner drain as high. Threat-model votes (medium x3, low x1) rightly note it is documented and owner-only. The finding L08.1's claim that the "only acknowledgments" are pool-v2-spec and m1-invariant-review is wrong: `README.md:219`, the docs guide `privacy.mdx:72` and spec §5.7 also disclose it.
- **F02 root flush: settled medium.** Lane claims ranged from low to medium; G25 measured batching.
- **Settled low:**
  - F20 (claimed medium): bench helper only.
  - F22 (claimed medium): documented limitation.
  - F24 (claimed medium): draft argument gap, no leak.
  - F27 (claimed medium): production margin 4.95x.

Still open (with the exact question):
1. **F06 severity (low vs medium).** Does the live, PROOF2-accepting Starknet gateway skip PROOF2 re-verification for a facts hash it has already stored, as `transaction_converter.rs:398-410` does in checkout 625929a? If yes, any on-chain observer can re-settle a reverted invoke with a dummy proof blob, and the attacker set is "everyone". If no, only parties that saw the proof can. The local checkout does not know PROOF2, and the 0.14.4+ constants are absent.
2. **F03 third-party reach.** Can any public party observe pending transactions before inclusion? What fraction of spends can a blind flusher force to revert on chain? The estimate of about 5-10% is reasoning only.
3. **F08 proven bound.** The 56/50-bit figures use BCIKS20/ethSTARK constants recalled without network access (plus or minus 2 bits), and they do not include 2024-2025 proximity-gap results. Whether a conjectured 96 bits is acceptable is a policy decision.
4. **F16 / F42 compression-mode literature.** Does any 2024-2026 result (the "Skipping Class" paper on Poseidon2 modes, the EF CICO bounty techniques) reduce full-round t = 24, RP = 22 Poseidon2-M31 below 2^128 in a mode with 6 fixed input words? This was checked from memory only.
5. **O4 statistical ZK (F24).** Is the distribution of T3 and FRI l0-l2 values, conditional on the additive part, statistically close to a witness-independent one? Algebraic dominance is shown, but no equidistribution bound exists.

---

## 4. Refuted attack hypotheses (do not re-raise)

Each line gives the blocking check and whether the refutation was executed.
- **Inflation by p, 2^128 or k·p through carries:** blocked by the quartic (`payment.rs:602-605`) and the forced zero top carry (`:597-598`). Executed: exhaustive, and 16,384 builds per witness.
- **Negative limb through a non-boolean amount bit:** blocked by `guess_bits` booleanity (`merkle.rs:16-19`). Executed.
- **Dummy input carrying value or squatting a victim's nullifier:** blocked by `sum1*(1-e1)=0` (`payment4.rs:430-433`) and nk derived in-circuit (`:449`). Executed.
- **Same note in both input slots:** blocked by the bridge 'duplicate nullifier' check (`lib.cairo:104-106`) and pool `NULLIFIER_USED` (`pool_v2.cairo:537-545`). Executed.
- **Position aliasing for a double spend:** needs two separately funded copies, each with its own nullifier (L02 t05). Executed.
- **Cross-asset spend (spend A, withdraw B):** blocked by a single token witness (`payment4.rs:410-412, 461-467`), the binding, and `HELD_UNDERFLOW`. Executed with real facts.
- **Absent-component claimed-sum forgery (math-review M2):** blocked by `circuit_air/src/lib.cairo:185-188` and Rust `circuit_claim.rs:75-101`. Executed.
- **Output forgery balanced on a present component:** blocked by the OODS check (`verifier_core/src/verifier.cairo:105-109`). Executed.
- **Gate-invalid witness with a consistent transcript (add, sub, mul, M31 pin, eq, carry quartic; 17 cases):** blocked by 'Invalid OODS eval' or 'Logup sum is not zero' (`lib.cairo:189-193`). Executed.
- **Non-canonical output encoding (value + p):** blocked by M31 `BoundedInt<0, P-1>` (`fields/m31.cairo:23-28`), giving INVALID_PROOF_ENCODING. Executed.
- **Weaker FRI config, foreign circuit, or a different blinding count:** blocked by the pinned FRI config (`circuit_air lib.cairo:122`) and the circuit-hash pin (bridge `lib.cairo:86-89`). Executed.
- **Lane-shift or non-base-lane hash forgery:** blocked by the finalize M31 pin (`context.rs:221-223`) and the pointwise constraint. Executed.
- **Non-canonical nullifier or root words:** blocked by `read_digest` DIGEST_WORD (`hash.cairo:126-133`). Executed.
- **Relayer or front-runner rewriting any Spend or ExecutionIntent field:** blocked by PROOF_BINDING, BAD_BINDING or EXECUTION_INTENT (`adapter.cairo:69-73`; `spend4.cairo:31-51`; `pool_v2.cairo:214-218`). Executed, about 40 mutations.
- **Ciphertext swap or alteration by the server or relayer:** blocked because the delivery digests are in the binding (bridge `lib.cairo:161-185`; `spend4.cairo:39-44`). Executed with real facts.
- **Replays across accounts, classes, tags and relations:**
  - a statement wrapped by another account or class;
  - a V3 statement on the V4 pool;
  - P1 as R0, or R0 as P1;
  - one PROOF2 used for two spends.
  All blocked by PROOF_BINDING. The binding domains differ (`spend4.cairo:36`, `spend.cairo:106`, `policy.cairo:88`), and `n_messages == 1`. Executed.
- **Facade token minting notes of a real NFT:** blocked because the asset id binds the caller (`pool_v2.cairo:421-423, 440-445`; `assets.cairo:31-33`). Executed.
- **Reentrancy through tokens, adapters or hooks:** blocked by the `start()` lock (`pool_v2.cairo:481-484`). Executed.
- **ERC721 double backing:** blocked by `held == 0` plus `owner_of` (`pool_v2.cairo:426-428`). Executed.
- **ERC20/NFT standard confusion:** blocked by `contract_standard`, ASSET_REGISTERED and ASSET_COLLISION (`pool_v2.cairo:184-185, 492-513`). Executed.
- **P1 overdraw, split inflation, refund abuse or hostile controller:** blocked by `policy.rs:526-572`, conservation, and a controller that runs after the checks and cannot change amounts (`pool_v2.cairo:307-345`). Executed (G23).
- **NFT hooks as a cheaper flush path:** not cheaper (all paths within 1.5%). Executed.
- **Extra grinding power from `channel_salt`:** none beyond re-seeding the blinding (G24 reasoning).
- **Lifted eq copies disagreeing usefully:** blocked by LogUp averaging and relation-uses < P. Reasoning only (G24.4).
- **Sponge/compress domain confusion (math-review M1):** fixed (`payment.rs:245-256`). Executed with a Plonky3 oracle.
- **H2-class linear leak in qm31_ops blinding:** blocked by the mul row (`finalize.rs:105`). Executed; the positive control detects the pre-fix build.
- **H4-class unmasked LogUp batch:** absent in the arithmetic profile (no lookup components). Executed.
- **Linear linkability of two spends by one key; shape or asset leaking through proof size or structure; dummy ciphertexts distinguishable:** none found (L12, L13). Executed.
- **Two-key sealed-box ambiguity:** harmless because every credit path checks cm (reasoning).
- **Relayer turning an execution revert into a free validate-time rejection:** not possible; `call_contract` is forbidden in validate mode (blockifier `hint_processor.rs:529-537`). Code-reading.
- **Lane premise "round 1 of compress cannot be linearised":** wrong, but the margin is unaffected (G22.1). Executed.
- **Lane premise "blinding-row multiplicities are 0":** wrong; they are 2/2/1/0/3 (L11.3). Executed.

---

## 5. Assurances

### 5.1 Established by execution

**Circuit (payment4 and gadgets)**
- **Conservation is an integer identity.** Every per-limb equation is equivalent to its integer form (5,242,816 triples). The quartic has exactly the roots {0, 1, p-2, p-1}, checked over all of M31. 16,384 carry vectors fail on each of five inflation witnesses. (`swarm/L01-circuit-value/poc/tests/l01.rs`; `payment.rs:597-610`)
- **Amount and value rules.** Amount limbs lie in [0, 2^16), and the published withdrawal is the conserved variable. ERC721 notes cannot merge or split upward. Extreme amounts (2^128-1) prove and self-verify. (L01)
- **Membership.**
  - Position bits are boolean and shared between the climb and the nullifier.
  - Compress node layout: circuit = native = Cairo = Plonky3.
  - An enabled input 1 must reach the same root.
  - The pool tree equals the client tree for 24 mixed appends and for indices up to 2^32-1, in both storage modes. (L02, L04, L08)
- **Statement layout.**
  - The 128 output limbs match `statement_limbs` for all 8 shapes.
  - Exactly the documented free limbs (deliveries, recipient, intent when x = 1) are unconstrained.
  - Differential fuzzing: 400 mutations, 0 cases where the circuit accepts and the reference rejects. (L03)
- **Constant pinning.** The Poseidon2 constants are reproduced by an independent Grain LFSR and match pinned Plonky3 byte for byte. The linear layers are invertible, M4 is MDS, and the M_I^k characteristic polynomials are irreducible for k up to 48. (L04; L14_3 verifier KAT)
- **Topology independence.** The finalized topology does not depend on witness or shape (8 shapes x several witnesses). The pinned circuit hash equals the current code at fork HEAD for R4 (all 8 shapes) and for P1 (all 5 kinds). (L05, L06, L11, L12, L14, G23)

**Proof system and Cairo verifier**
- **Rejections.** The absent-sum forgery, output forgeries balanced on eq or qm31_ops, gate-invalid witnesses (including lifting +2), extra or missing outputs, and every post-proof transcript mutation are all rejected. Bounded PCS mode gives byte-identical proofs. (`swarm/L05-stark-rust/poc/tests/l05.rs`)
- **Mutation and forgery sweeps.**
  - 1,854 proof mutations on 7 real proofs: all rejected, apart from 3 encodings that re-encode the same statement (F34).
  - 17 gate-invalid forgeries rejected by the pinned bridge; the honest control is accepted.
  - The FRI config pin rejects 16 variants per proof.
  - The fork's batched inversions equal upstream's `fold_line`/`fold_circle` on fold steps 1-4.
  - (`swarm/L06-stark-cairo/`, `swarm/G24-cairo-gate-forgery-and-soundne/`)
- **Vendored code is current.** The vendored Cairo verifier matches fork HEAD on 110/110 files; only the generated sections differ. (L06, L14)

**Bridge, account, adapter, pool**
- **Binding.** The bridge binding equals `spend4::compute_binding` for 6 shapes on real proofs.
- **End-to-end settlement.** Real account code, then the real Proof2Adapter, then pool V2, settles 5 shapes with real client proofs. (`swarm/L07-bridge-binding/pool/src/tests/l07_custody.cairo`)
- **Every Spend and intent field is bound.** 20 Spend mutations and 16 intent mutations are rejected with exact reasons. The adapter's facts matrix rejects every alternative layout. (L07, L10)
- **Pool behaviour.**
  - Reentrancy lock on all state-changing entries.
  - Tree correctness and `insert_two` equal to two `insert_leaf` calls at deep merges.
  - Exact 256-root eviction.
  - Canonical digests, and nullifiers marked in sequence and atomically.
  - `held` equals holdings after a real-proof flow.
  - Pool entry points reject standard confusion, facade tokens, re-entering tokens and ERC721 double backing.
  - (L08, L09, L10, L15, G23)
- **P1.** Conservation, split, selector and refund rules hold. P1 and V4 share nullifiers correctly. Real P1 proofs settle with `held = balance`. (G23)
- **Metadata uniformity.** A real Sepolia ERC20 hidden transfer and an ERC721 hidden transfer have identical gas, events and storage structure. Proof structure is shape-independent (248 proofs). Dummy and real ciphertexts are indistinguishable (20k samples). (L13)

**Zero knowledge**
- **Inventory.** An exact inventory of what a proof reveals: 8,512 revealed M31 against 38,240 independent blinding M31. (L11 E1)
- **Linear tests.** At production size (35 queries, 2,390 iterations, 8,429 functionals, 8,728 proofs), no witness-dependent linear functional exists. The pre-H2 control is detected. (G21 H1; L12 E1 at 5 queries)
- **Algebraic dominance.** Jacobian rank equals hull - 16 on T3, OODS, claims and deep FRI subsets (up to 1,740 coordinates) for two witnesses. The k = 2 control is detected. (G21)
- **Additive-part model.** Exact (0/1,132 mismatches). Structure: dim V_i = 36, d = 1128, 54 disjoint spanning groups at 21 challenge sets. (G32)
- **Character-sum tests.** 68,400 production and 158,432 pinned tests: 0 rejections. The controls give p = 1e-87, 1e-110 and 1e-147. (G32)
- **Hiding examples retargeted to V4.** `hiding_rank` on 8 shapes, and invariants and points on Single and Transfer: all clean. (L14_8 verifier)
- **P1 rank audit.** 0 unblinded combinations. (G23)

### 5.2 Established by reading or reasoning only

- **Token limbs.** They are not range-checked in the circuit but stay canonical, because of leaf invariant I and bridge `felt_from_limbs` (`payment4.rs:409-412`; `hash.cairo:93-101`; bridge `lib.cairo:48-59`).
- **Gate-to-AIR reduction.** qm31_ops mul limbs and pointwise flags are correct, and relation uses stay below p (L05, L06, reading).
- **Transcript order.** The Cairo `verify_circuit` order matches the Rust prover and verifier (L06, reading; honest proofs verify).
- **Sequencer pre-validation.** The sequencer checks the program-hash allowlist, the base-block hash and the config hash (blockifier `account_transaction.rs:238-352`, reading).
- **Compression-mode Poseidon2.** No algebraic attack beats the generic bounds at RP = 22 (G22 reasoning). The degree tables and the 2-round bypass were executed.
- **Additive-part bound.** The 2^-62 figure itself (G32, reasoning over the executed structure).
- **Lifted eq columns.** Their soundness rests on LogUp averaging (G24.4).
- **Cross-relation nullifiers.** No dummy nullifier can hit a P1 nullifier (domain separation of NK and PNK).
- **Viewing keys.** They cannot spend, because ak, nk and ivk are never witnesses (L16).

---

## 6. Coverage gaps and recommended next tests

**Not covered**
1. **G31 (OODS lie and FRI adversarial) did not run.** No cheating prover committed non-low-degree DEEP quotients against the Cairo FRI verifier. No acceptance-rate curve at low query counts exists. No verifier-side transcript-order reading was done for `core/pcs/verifier.rs`, `core/fri.rs` or Cairo `fri.cairo`/`pcs`. The fork-modified `fold_line`/`fold_circle` were not tested with adversarial data. **This is the largest soundness gap. Re-run it.**
2. **O4 statistical ZK proof.** The full-vector production Jacobian (about 7,700 directions, 6-10 h) was not run. The Jacobian was not run on shapes other than Single, or on witness pairs other than A/B.
3. **H3 fix** (rejection-sample limbs below p) is still open.
4. **Online literature check** for Poseidon2 compression mode and for proximity-gap constants.
5. **Excluded: PROOF2, the virtual OS, the live sequencer and the gateway.** Behaviour on 0.14.4+ is unknown. Mainnet gas prices and block capacities are unknown.
6. **Excluded: SDK and server.** In particular, whether the SDK implements sticky companions (F05), the receive rules SDK-M1/M2 (F04, F20, F21), and the re-plan rules (F03).
7. **Invoke and COMPUTE with real facts.** No real R0 V4 invoke or COMPUTE proof facts exist; invoke paths were tested with mock or pinned verifiers.
8. **Cross-relation end to end.** A V4 spend of a P1 output was not run through bridge-r4; it was checked at circuit and root level only.
9. **Upstream stwo core.** No white-box review of lifted PCS, DEEP or FRI; it was exercised black-box only.
10. **Network-layer metadata** (IP, relay timing) was not covered.

**Recommended next tests** (all have working lane code to port)
- **Circuit.** Add the F09 regression tests. Port `swarm/L01-circuit-value/poc/tests/l01.rs` and `swarm/L14-spec-conformance/mutpoc/tests/regression_mint.rs` into `tests/payment_r4_malicious.rs`, and add raw tamper hooks.
- **Bridge validator.** Add to `validate_bridge_r4.py` and `validate_bridge_p1.py`, with required reasons:
  - the 17 G24 gate-invalid proofs;
  - the L06 absent-sum forgery;
  - the L14/G23 bridge-only negatives;
  - also run the validator against the `bridge-noabsent` and `bridge-nosum` mutants as a meta-test.
- **Pins.** Add a witness-free circuit-hash pin test (`swarm/L14-spec-conformance/poc/tests/circuit_hash.rs`) and replace the stale vendored KAT.
- **Lane packing.** Add the analyzer test and the lane-shift negative (`swarm/L04-poseidon2/poc/tests/l04.rs`).
- **Hiding.** Add the Jacobian-dimension hiding regression and the `h12_model` structural check (G21, G32), slow-flagged, and commit the V4 hiding examples.
- **Pool.** Commit `test_l14_gaps.cairo`, `test_l02.cairo`, `test_l10.cairo` and the `l07_*` real-account harness.
- **Root window.** After the F02 fix, re-run `g25_real_spend_forced_unknown_root` to show that junk deposits no longer age a root.

---

## Appendix: merge map

| Merged | Original ids |
|---|---|
| F01 | L07.1, L08.1, L10.1, L14.1, L15.2 |
| F02 | G25.1, L15.1, L08.2, L02.1, L07.3, L09.2 |
| F03 | L13.2, G25.2 |
| F04 | L16.1 |
| F05 | L13.1, L12.2, L14.4, L16.4 |
| F06 | L07.2 |
| F07 | L15.4, G25.3 |
| F08 | G24.1, L05.4, L06.4, G24.3 |
| F09 | L01.1, L14.2, L14.5, G23.2 |
| F10 | L06.1, G24.2 |
| F11 | L14.7, G23.1 |
| F12 | L04.1, L02.4 |
| F13-F15 | L05.1, L05.2, L03.1 |
| F16 | L04.2, L14.3 |
| F17-F23 | L09.1, L10.2, L08.3+L15.3, L16.2, L16.3, L13.3, L13.4 |
| F24 | L11.1, G21.2, G21.4 |
| F25 | L11.2, L12.1, G32.3 |
| F26 | L11.3 |
| F27 | G21.1, G21.3, L11.4, G32.6, L14.8 |
| F28 | L14.6, L02.5, L10.5, L07.7 |
| F29-F69 | see section 2.4 |

## Cost of this review

One workflow run (wf_79e3771d-227), 102 subagents plus the orchestrating session, 6.6 hours wall clock,
3,059 tool calls. Every call ran on Claude Opus 5.5 at standard speed. The costs below are API-equivalent at
first-party list prices per million tokens: input $4, output $20 (thinking is billed as output), cache read
$0.20, cache write $5 (5-minute TTL) or $8 (1-hour TTL). They are not necessarily what was billed: a
subscription session is priced differently. Computed from the per-call usage records in the transcripts
(`swarm/token_usage.py`).

| Stage | Model calls | Output (incl. thinking) | Uncached input + cache writes | Cache reads | API cost |
|---|---:|---:|---:|---:|---:|
| Attack | 1,196 | 1.84M | 6.55M | 248.94M | $119.34 |
| Verify | 1,152 | 0.99M | 4.72M | 84.24M | $60.17 |
| Gaps | 553 | 1.32M | 10.45M | 127.12M | $104.06 |
| Synthesize | 10 | 0.08M | 0.36M | 2.82M | $3.96 |
| Orchestrator (main session) | 62 | 0.09M | 0.76M | 11.30M | $10.15 |
| **Total** (102 subagents) | 2,973 | 4.31M | 22.85M | 474.42M | $297.68 |

Cost by token type: input $0.02, output $86.29, write_5m $110.39, write_1h $6.10, read $94.88
Fast-mode calls: 0; calls on other models: 0

Notes on the record:
- Lane G31 did no attack work. Its report says the session was stopped by a safety intervention while it read
  prover-side PCS code, before any forgery tooling existed. Its gap (section 6, item 1) is still open.
- The synthesis agent was not allowed to write files. This report is its blocked write, recovered from its
  transcript by the orchestrator with two corrections: the lane count (23, not 26) and the raw finding count
  (120, from the workflow journal). `swarm/findings.json` holds the 120 raw findings with every verification vote and
  each lane's assurances and uncovered items; the merge into F01-F69 is in the appendix above.

