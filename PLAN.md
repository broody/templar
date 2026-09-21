# Templar — Trustless Private Pool: Plan

> **Current priorities:** use [TODO.md](TODO.md) to track implementation work.
> This document retains the historical plan and engineering analysis.
>
> **Current direction (2026-09-21):** [ADR-0018](docs/adr/0018-stwo-private-proving.md)
> selects local S-two/native PROOF1 proving. [ADR-0021](docs/adr/0021-push-only-payments.md)
> selects ordinary push payments to reusable addresses, encrypted public delivery,
> optional viewing, and seed-plus-history recovery.
> [ADR-0022](docs/adr/0022-controlled-push-payments.md) adds optional controlled notes.
> [ADR-0023](docs/adr/0023-return-notes-and-adapter-compatibility.md) adds return notes
> with upstream-compatible atomic external funding.
> The initial product excludes
> invoices and delivery channels. Use the [current specification](docs/push-payment-spec.md)
> and [Vocs guide](docs/guide/README.md) for this architecture. The roadmap and
> analysis below retain earlier assumptions and do not override these decisions.
> Production integration, cryptographic review, scalable private sync, and desktop
> qualification remain outstanding.
> **Active focus:** reduce native proving memory while preserving a future
> browser/WASM implementation path. Browser proving is a strategic target, not
> a current release requirement. See the [memory review](docs/prover-memory-review.md)
> for measured progress, device budgets, and remaining work.

A plan to turn `starkware-libs/starknet-privacy` into a privacy pool with **no trusted
parties other than Starknet itself** — Tornado-Cash-style trustlessness, while keeping
the upstream design's flexibility (arbitrary amounts, encrypted notes, private DeFi
invokes, selective disclosure).

> **Development guide**: current work and its priority live in [TODO.md](TODO.md);
> the *why* lives in the ADRs — [docs/adr/README.md](docs/adr/README.md). Section references
> below (ADR-000X) map to the decision behind each phase.

---

## 1. What upstream has, and what must go

Upstream architecture (all references relative to `~/development/starknet-privacy`):

1. **Client phase** — the pool (a Starknet account contract) receives
   `(user_addr, user_private_key, client_actions)` in calldata and compiles them into
   `ServerAction`s (`packages/privacy/src/privacy.cairo:195-245`).
2. **Prover** — an *operator-side proving service* executes that compilation inside a
   "virtual Starknet block" and returns a STARK proof + proof facts
   (`README.md:7`, `sdk/src/internal/proof-invocation-factory.ts:121-195`).
3. **Server phase** — the wallet submits `apply_actions` with the proof attached; the
   sequencer verifies the proof; the contract validates only the *proof facts*
   (`privacy.cairo:808-843`). Critically, **the contract cannot tell who ran the
   prover** — this is the architectural seam Templar exploits.

Trust holes to remove, in order of severity:

| # | Hole | Location upstream | Fix |
|---|------|-------------------|-----|
| H1 | **Auditor**: user's private viewing key ECDH-encrypted to `auditor_public_key` at registration, stored + emitted; auditor reconstructs the entire transaction graph retroactively | `privacy.cairo:319-356`, `utils.cairo:220-229`, `events.cairo:13` | Delete (see §3.1) |
| H2 | **Prover sees all secrets**: `user_private_key` and every action in plaintext per proof request; single centralized operator; can link deposits↔withdrawals | `interface.cairo:371-374`, `sdk/src/internal/proof-invocation-factory.ts` | User-generated proofs (see §5) |
| H3 | **Screener**: on-chain-enforced deposit screening attestations (Elliptic AML), fail-open prover config | `privacy.cairo:921-943`, `proof-interceptor/` | Delete; optional ZK compliance (see §6) |
| H4 | **Public deposit attribution**: `Deposit.user_addr` is a plaintext indexed event field; `Withdrawal.to_addr`+amount public; `OpenNoteDeposited.depositor` public | `events.cairo:16-40, 66-78` | Commitment-based deposit (see §4) |
| H5 | **Withdraw ciphertext reuse**: no freshness check on withdraw `random` → identical `enc_user_addr` publicly links a user's withdrawals | `actions.cairo:191-201` | Replaced by H1 removal + nonce |
| H6 | **No Merkle tree**: note existence proven by prover's storage reads; only works while the prover is trusted with secrets | `privacy.cairo:100` | Commitment tree (see §4) |
| H7 | **Per-recipient channel counts** leaked via `get_num_of_channels` | `privacy.cairo:1078-1080` | Drop view or obfuscate |

Non-goals: hiding the withdrawal *recipient* (inherent — the funds go there), hiding
deposit amounts at the ERC20 layer (inherent), defending against global network-level
traffic analysis (out of scope, as in Tornado).

---

## 2. Threat model (Templar target)

Trusted: Starknet sequencer (proof verification), the Cairo compiler/prover code being
correct (auditable, open source), the user's own device.

**Not trusted** (each must learn nothing linking deposits to withdrawals):

- *Chain observers* — see only commitments, nullifiers, ciphertexts, transfer events.
- *Relayers / paymasters* — see the tx they submit; a user must not reuse one for both
  deposit and withdrawal (upstream already supports paymaster submission).
- *Discovery services* — upstream already supports self-hosting + OHTTP
  (`crates/discovery-service/specs/05-security-considerations.md:68-79`); Templar adds
  the option of trusting nobody by syncing from your own node.
- *Auditors / screeners* — no global keys exist. Selective disclosure only.
- *Anyone else* — including other users.

---

## 3. Phase 1 — Contract v2: strip the backdoors

A new contract (new class, fresh deploy — no storage migration needed if we go
commitment-tree-native, see §4). Concrete diff list against upstream
`packages/privacy/src/`:

### 3.1 Remove the auditor (H1, H5, part of H7)

- Delete `auditor_public_key` storage/constructor/admin fn/event
  (`privacy.cairo:109-110, 156-163, 1151-1204`).
- Delete `EncPrivateKey`, `EncUserAddr`, `EncOutgoingChannelInfo` types, the
  `encrypt_private_key` / `encrypt_user_addr` / `encrypt_outgoing_channel_info`
  helpers (`utils.cairo:202-258`), and every call site: `set_viewing_key`
  (`privacy.cairo:319-357`), `withdraw` (`privacy.cairo:518-529`),
  `create_open_note` (`privacy.cairo:701-712`).
- `SetViewingKey` keeps only `(user_addr, public_key)` — the *voluntary* viewing-key
  disclosure mechanism is preserved: anyone who wants an auditor/counterparty to see
  their activity hands them the private scalar out-of-band. Selective disclosure
  without a global key.
- Delete `get_num_of_channels` (H7) or return only an encrypted count.

### 3.2 Remove the screener (H3)

- Delete `screener_public_key`, `_verify_screening`, `open_note_depositor_screening_policies`,
  the `ScreeningAttestation` calldata suffix, `snip12.cairo`'s `DepositorValidation`
  (`privacy.cairo:104, 112, 921-943`; `sdk/src/internal/screening-calldata.ts`).
- `apply_actions` loses the `Option<ScreeningAttestation>` tail; the SDK loses the
  interceptor error mapping (`sdk/src/internal/errors.ts`).
- `proof-interceptor/` and `elliptic-proxy/` are not carried over at all.

### 3.3 Fix the public leaks (H4)

- `Deposit` event: drop `user_addr`; emit `(note_commitment, token, amount)` where
  `note_commitment` hides the owner (see §4). Amount stays visible (it must match the
  ERC20 `transferFrom` anyway); unlinkability comes from the spend step, as in Tornado.
- `Withdrawal` event: keep `to_addr`, `token`, `amount` (inherent); drop `enc_user_addr`.
- `OpenNoteDeposited`: depositor visibility is inherent to open notes (someone must
  `transferFrom` them) — document as a *deliberately public* flow; private users use
  encrypted notes instead. Templar's open notes are for donation/VASP-style on-ramps.
- Mint-to-note deposits: replaced by the standalone proofless `deposit()` entry
  point (ADR-0011) — the two-part leaf lets the contract recompute the
  commitment from public fields, and the depositor is always the caller, which
  kills the allowance-pull class by construction.

---

## 4. Phase 2 — State model: commitment tree (H6)

Upstream stores notes in `Map<note_id, Note>` and ownership is established by storage
reads inside the trusted prover's virtual block. For user-generated proofs, existence
must be provable without seeing all storage:

- **Commitment** (V3, ADR-0011/0012): `note_secret = H(salt, owner_private_key)`
  derived recipient-side; `inner = H(note_secret)` is the hiding inner
  commitment; the leaf `cm = H(token, amount, controller, policy_commitment,
  inner)` is computable on-chain from public fields (enabling the proofless
  `deposit`) while remaining unopenable without `note_secret`. Exact preimage
  order and tags: spec §3.1.
- **Sparse Merkle tree** (`Map<index, cm>` + root in storage, root emitted in every
  spend event): Starknet storage-as-map gives us the sparse tree for free; leaf
  inclusion is proven inside the ZK statement via a sibling path (~log2(N) Poseidons,
  ≈ 40 × 3 hashes for 10^12 leaves — cheap).
- **Nullifier set**: unchanged from upstream (`nullifiers: Map<felt252, bool>`,
  `WriteOnce`, `privacy.cairo:102`) — upstream's nullifier design is already sound and
  reused verbatim (`hashes.cairo:229-236`).
- **Channel/subchannel machinery**: cut (ADR-0012). Its upstream job was
  ECDH delivery of sender-generated note secrets to recipients; notes are
  recipient-authored (invoice flow), so there is nothing to deliver. Discovery
  is local matching of `NoteCommitted` events against self-issued invoices.
- **Root registry**: `root_history: Map<felt252, bool>` (bounded ring) so proofs can
  reference a recent root without race conditions on the current root.

Client consequence: the SDK must maintain the tree locally (fetch leaves from
discovery/node, recompute root). The discovery service gains a "get leaves[i..j]"
endpoint; it remains zero-trust since leaves are commitments, not secrets.

---

## 5. Phase 3 — Proving architecture (H2)

Goal: no party that sees `user_private_key`, note selection, or recipients.

### 5.1 The statement to prove (per spend)

For each input note and output note, the user proves:

1. I know preimages of k nullifiers `nf_i` and their commitments are leaves in the
   tree with root R (Merkle path verification).
2. None of `nf_i` is in the nullifier set (enforced on-chain, not in the proof).
3. Value conservation: Σ in-amounts = Σ out-amounts (+ change).
4. Output commitments are correctly derived from fresh secrets.
5. (Optional) association-set membership for compliance (§6).

This is a small, fixed-circuit statement — no Cairo VM, no OS execution.

### 5.2 Resolved design — single-phase (ADR-0010)

The earlier A/B/C staging (client-side Stwo end state / inner proof inside an
operator-proved outer block / clean-room Tornado) is **superseded by ADR-0010**.
With private invokes cut, the outer virtual block had no remaining
justification: **users generate a Groth16/BN254 proof of the §5.1 statement
locally, and the pool verifies it on-chain** via a Garaga-class verifier
contract behind the `IVerifier` seam. There is no operator role, no client
phase, no proof-facts gating, and no L1 message path; the pool is trustless at
M2. The historical options analysis and Stwo end-state rationale remain in
ADR-0005 (superseded).

Trade accepted: **private invokes are permanently cut.** Curated DeFi
integrations ship as app-specific controllers (§6b) — withdrawal leg to the app
contract, batched public execution, proceeds re-enter as notes — which need no
outer block.

### 5.3 Interface sketch

```
// TemplarPool (Cairo)
fn apply_spend(
    root: felt252,
    nullifiers: Span<felt252>,
    out_commitments: Span<felt252>,
    encrypted_notes: Span<EncNote>,      // ECDH to recipients as upstream
    ext: Option<ExternalCall>,           // withdraw or invoke, follows outputs
    proof: Proof,                        // inner ZK proof over the statement above
)
```

Verification is on-chain: a Garaga-style Groth16 verifier contract behind the
`IVerifier` seam. Its gas lands on every spend — measure on a production
sequencer and price into the fee model (review §E).

---

## 6. Phase 4 — Compliance without backdoors

Replace identity screening with **opt-in, zero-knowledge association sets**
(Privacy-Pools/0xbow pattern):

- A user who wants a compliance attestation proves in ZK: "my deposit's source set ⊆
  association set AS_k" — no identity, no address, no linkage.
- Relying parties (exchanges, funds) verify the attestation off-chain or a hash of it
  on-chain; non-users are unaffected. The pool never enforces screening (that's H3).
- The viewing-key mechanism (§3.1) covers *audit me personally* cases.

---

## 6b. Controlled notes (PR broody/starknet-privacy#2) — adopted, with one redesign

Upstream PR #2 adds contract-governed private value: a `ControlledNote`
(`{hiding commitment, controller}`) whose creation debits private balance and whose
every spend requires authorization from the bound application contract, validated
inside the proven execution via `privacy_validate_controlled_transition` and applied
on-chain via `privacy_apply_controlled_transition` (≤16-felt public receipt, one
controller per tx, no open-note outputs in controlled txs).

**Evaluation: feasible and structurally aligned — it is the one upstream note type
that already follows the Tornado disclosure pattern.** Public events are
commitment-only (`ControlledNoteCreated {note_id, controller, commitment}`,
`ControlledNoteUsed {nullifier, controller}`); create↔spend is unlinkable
(`nullifier = H(note_id, blinding(spend_key))`, blinding secret; `note_id` hides
`sender_addr` behind a spend-key nonce); spend is bearer-keyed, so no dependency on
the auditor path (H1) and none on the screener (H3 — the PR's screening hunk is
dropped). Because `note_id` is *public at creation*, spends can check the opening
against stored public storage — controlled notes need **no Merkle membership** and
slot into Phase 2 without the tree.

Integration changes for Templar:

1. **Controller moves out of the proving trust set (the one real redesign).**
   Upstream runs the controller's validation *inside* the proven execution, which
   would force the outer prover to expose the transition (openings, recipients,
   spend keys) to the prover→controller path. Templar instead has the controller
   validate off-chain and return a **signature over the transition commitment**
   `H(ControlledTransition)`; the inner circuit (M2) proves opening correctness
   (`commitment` preimage), nullifier derivation, value conservation, and binds
   the transition commitment; the controller signature itself is verified
   on-chain in Cairo (spec §6.3). Capability-equivalent (the controller still
   sees the transition — from the user, before signing), stateful policies still
   work (controller checks its own storage pre-signature), and no prover or
   operator ever enters the trust set (single-phase, ADR-0010).
   Replay/partial-replay is already prevented by the WriteOnce nullifier plus
   commitment binding; keep the PR's epoch/nonce-in-receipt guidance for staleness.
2. **Data minimization in `ControlledTransition`.** Upstream feeds the controller
   *every* action in the tx, including ordinary `UseNote` nullifiers/amounts and
   `CreateEncNote` recipients — mixing an unrelated private transfer into a
   controlled tx would leak it to the controller. Templar: controlled txs carry only
   controlled openings + deposits + withdrawals (or per-item consent with SDK
   warnings).
3. **Prover trust gap in the PR is resolved for free**: "the proving endpoint
   receives note openings" (PR's own remaining-work list) stops being true —
   there is no proving endpoint at all; proofs are user-generated and verified
   on-chain (ADR-0010).
4. **Keep**: the note-id/commitment/nullifier derivations (`hashes.cairo` additions
   are sound and domain-separated), one-controller-per-tx invariant, the
   void-return apply ABI with pool-caller authentication, bearer spend semantics.
   **Document**: the escrow deadlock property (a dead controller locks value; a
   policy-encoded deadline is the partial mitigation).

Cost impact: ~2–3 Poseidon per note create, ~2 per spend — negligible against the
M0 benchmark (~75 Poseidon + 6 EC-muls per transfer); the sig-based variant also
keeps the controller's Cairo policy code entirely out of the verified path.

> **Revision (ADR-0009)**: the evaluation above led to full **note-type
> unification** — a single note format with `authorization = NONE | Controller`,
> both types as tree leaves, bearer `spend_key` replaced by owner-keyed notes, and
> open notes cut from v2. It also surfaced a flaw in the draft spec's
> controlled-note map design (spend-linkable under a blind prover) — corrected in
> ADR-0009 and the current spec.

---

## 7. Milestones

| Milestone | Deliverable | Depends on |
|-----------|-------------|------------|
| M0 ✅ | Feasibility benchmark (`bench/`, `bench-results.md`) — ~2.4k steps / 6 EC-muls / 75 Poseidon per transfer; Stwo prove ≈ 4–5 s flat (fixed AIR frame dominates, ~2.7 GB — memory, not compute, is the mobile blocker) | — |
| M0b ✅ | Controlled notes (PR #2) evaluated — adopted with controller-out-of-prover redesign (§6b) | — |
| M1 | TemplarPool contract v2: auditor/screener-free, single unified note format (ADR-0009), commitment tree + nullifier ring; snforge tests incl. adversarial (replay, forgery, root-reuse, controller-sig malleability, creator-spend attempts) | §3, §4, ADR-0009 |
| M2 | Inner-statement circuit (gnark, Groth16/BN254 — ADR-0008; 4/4/2 padded shape — ADR-0014) + Garaga on-chain verifier contract + tests: soundness against crafted nullifiers/roots/counts/tc; single circuit covers ordinary and controlled spends; deposits need no circuit (ADR-0011) | §7, ADR-0009/0011/0012/0014 |
| M3 | Mainnet readiness (ADR-0010): governance (upstream Roles/AccessControl/Replaceability), Groth16 ceremony, Stark-ECDSA sig verifier (replaces mock), audit, fee re-measurement on a production sequencer | M1, M2 |
| M4 | Desktop proving: target 16 GB host, ≤4 GiB preferred / 6 GiB maximum client working set; ≤30 s preferred / 60 s maximum preparation; no swap dependence (2026-09-20 user direction, ADR-0017) | M2 |
| M5 | Association-set attestations (opt-in) | M2 |

## 8. Risks / open questions

- **Groth16 on-chain verification cost**: verifier gas lands on every spend;
  benchmark the Garaga verifier on a production sequencer and price it into the
  fee model (review §E) once M2 lands.
- **Trusted setup** for Groth16 — resolved (ADR-0008): one public per-circuit
  ceremony with a published transcript; PLONK with an inherited public SRS is
  the documented zero-new-ceremony fallback.
- **Encrypted-note delivery**: moot (ADR-0012) — notes are recipient-authored
  (invoice flow), so there is nothing to deliver and no address→key registry.
  Push-style UX (receive boards) is an SDK-layer pattern, not protocol surface.
- **Amount correlation**: deposit amounts visible at ERC20 layer; withdrawals with
  the same amount are correlatable like Tornado's. Mitigate at the UX layer
  (split/change notes), not in the protocol.
- **Controlled-note lockup**: bearer spend + controller veto means a dead/paused
  controller permanently locks value (holder cannot spend, controller cannot take).
  Inherent to escrow; surface in SDK, consider policy-encoded deadlines
  (§6b, upstream already suggests nonce/deadline receipts).
- **Controller identity is public** at note creation (`ControlledNoteCreated`
  emits `controller`) — by design, but applications wanting anonymous-controlled
  notes would need controller-side stealth deployment (fresh contract per pool).

---

## 9. Immediate next steps

**2026-09-20 desktop update:** the user target is normal desktops, not phones.
The internal-only tree insertion fix and invoice-output circuit correction are
implemented. [Desktop pathfinding](bench/desktop/README.md) demonstrates an
ordinary native-BN254 2/2/1 payment and withdrawal through the real Garaga
verifier. This experiment does not migrate the production pool. ADR-0017 records
the proposed next path; controller destination binding, governance/trust posture,
token semantics, production integration, and audit remain outstanding.


1. ✅ M0 benchmark — see `bench/` and `bench-results.md`.
2. **M1 (code complete)**: spec frozen —
   [`docs/pool-v2-spec.md`](docs/pool-v2-spec.md) (Accepted, 2026-09-19).
   Done: hash module (golden vectors), tree + root ring (naive-reference
   cross-checked, ring eviction), nullifier set, `apply_spend` with §7.4 gating
   + load-bearing 1:1 action zip, 55 tests incl. the full adversarial battery
   and the proofless-deposit suite (ADR-0011),
   apply_spend+deposit gas snapshot (spec §9.4 / review §E), and the M1 invariant
   review — [`docs/m1-invariant-review.md`](docs/m1-invariant-review.md):
   13 enforced+tested invariants, §5 phase machinery mapped to its post-ADR-0010
   disposition, accepted risks documented (allowance pull now resolved by
   ADR-0011; discovery spam reduced by ADR-0012).
   **Governance fix landed (review §B): the three trust anchors (verifier,
   sig_verifier, fee) are owner-gated with tests; single-owner is interim —
   upstream Roles/AccessControl still required before production (M3).**
   **M1 code complete — next: M2 inner-statement circuit + on-chain verifier.**
3. ✅ ADR-0008 resolved (Groth16/BN254, `bench/adr8/`); **ADR-0010 resolved the
   deployment shape: single-phase, on-chain verification, operator removed,
   private invokes permanently cut** (supersedes ADR-0001/0005).
4. Write the inner-statement spec formally (Lean stays an option — upstream
   has formal verification in `lean/`).
