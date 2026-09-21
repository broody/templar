# M1 invariant review — spec §5/§6/§7.4 vs `packages/pool`

Status: **Reviewed 2026-09-19**, against `packages/pool` at commit
"apply_spend + adversarial battery (32 tests)". Scope: every invariant the
frozen spec (and upstream's two-phase design) implies for the server phase,
mapped to where M1 enforces it, where a milestone seam defers it, and where a
risk is accepted rather than enforced. Feeds PLAN §9.2.

> **Update 2026-09-20 (ADR-0011/0012):** accepted risk §D.1 (allowance pull) is
> now **resolved by construction** — deposits moved to the standalone proofless
> `deposit()` entry point where the depositor is always the caller — and §D.2
> (discovery spam) is structurally reduced by recipient-authored notes. The §A
> table gained A13; §E was re-measured after the change.

## Follow-up correction (2026-09-20)

The original review missed that embedding the full tree interface exposed
`insert_leaf` publicly. An isolated test confirmed an unauthorized, unfunded
leaf could become part of an accepted root. This has now been corrected by
moving mutation to the component's internal trait, leaving only tree reads in
the pool ABI. `direct_tree_insert_is_not_an_entrypoint` guards the production
interface; a separate writer exists only in the test mock. A tree-capacity
check also rejects insertion once the depth-32 space is full.

The revised pool suite passes 57 tests. This closes that specific critical
issue; it does not make the old review exhaustive or the deployment ready.
Controller-signed withdrawal destinations and governance remain open blockers.

## A. Enforced in M1 (with the test that pins it)

| # | Invariant | Source | Enforcement | Test |
|---|---|---|---|---|
| A1 | Nullifier set is WriteOnce; replay reverts | §4, §7.4 | `pool.cairo` `_apply_actions` | `replay_nullifier_reverts` |
| A2 | `tree_root` ∈ acceptable ring (incl. evicted roots rejected) | §7.4 | `_validate_statement` + tree ring | `stale_root_reverts`, `root_history_ring_evicts_oldest` |
| A3 | Statement binding ties public inputs to exact actions | §7.3.6 | recomputed in `_validate_statement` (circuit re-asserts in M2) | `tampered_binding_reverts` |
| A4 | 1:1 ordered zip: actions ↔ public inputs, exact counts both ways | §7.4 (added) | `_apply_actions` per-kind indices | `forged_extra_nullifier_reverts`, `missing_nullifier_action_reverts`, `leaf_commitment_mismatch_reverts` |
| A5 | Context pinning: `PROTOCOL_VERSION`, `pool_address`, `chain_id` | §7.2/§7.4 | `_validate_statement` | `wrong_pool_address_reverts`, `wrong_chain_id_reverts`, `wrong_protocol_version_reverts` |
| A6 | No state change without inner-proof authorization | §5, ADR-0001 | `IVerifier` gate (M1: mock seam) | `rejected_proof_reverts` |
| A7 | Controlled spend ⇔ exactly one matching `ControllerApply` (controller, transition_commitment, deadline, sig) | §6 | `_apply_actions` + tail consistency | `controlled_spend_without_apply_reverts`, `controller_mismatch_reverts`, `expired_deadline_reverts`, `rejected_controller_signature_reverts`, `apply_on_ordinary_spend_reverts`, `double_controller_apply_reverts`, `controlled_spend_happy_path` |
| A8 | Zero-value guards (nullifier/leaf/token/recipient) — keeps padded (circuit) and non-padded (Cairo binding) encodings unambiguous | §7.4 | guards + tree `ZERO_LEAF` | `zero_nullifier_reverts`, tree tests |
| A9 | Atomicity: events, state writes, fee, ERC20 moves all revert together | Cairo semantics | structural (single tx frame) | implicit in every revert test |
| A10 | Reentrancy | upstream shape | bool guard around `apply_spend` | structural (not adversarially tested — a malicious-token callback test would need a callback ERC20; deferred) |
| A11 | Fee collected (token configurable, STRK default) before actions | §4 | `_collect_fee` | `fee_is_collected_from_caller` |
| A12 | Empty root known from genesis (first spend bundle spendable) | §7.4 | constructor seeds zero chain | `empty_root_known_from_genesis` |
| A13 | Deposit amount binding + caller attribution (two-part leaf, ADR-0011) | §3.1/§5.1 | `deposit()` recomputes the commitment on-chain from public fields; pulls `msg.sender` only | `deposit_zero_amount/token/inner_reverts`, `deposit_pulls_only_from_caller`, `controlled_deposit_then_spend`, happy-path event assertions |

Front-running a submitted bundle is **dead by construction** once the real
verifier lands: the proof covers `statement_binding`, which covers
`H(server_actions)` — any action edit reverts with `BAD_BINDING` without the
front-runner being able to re-prove. With the M1 mock verifier this is
obviously not true; nothing in M1 is deployable to production anyway (see B).

## B. Governance fix — LANDED in M1 (2026-09-19), full components remain M3

**Fixed:** the three trust anchors are now owner-gated (`owner` set at deploy,
`transfer_ownership`, `NOT_OWNER` reverts; tests
`non_owner_cannot_*`, `owner_can_replace_verifier`,
`bundle_after_verifier_swap_reverts`, `ownership_transfer_moves_owner`,
`old_owner_loses_fee_control_after_transfer`):

1. `verifier` address — a malicious verifier is total compromise (the M1 mock
   accepts everything). Replaced in M2 by the real on-chain inner-proof verifier
   (Garaga-class; ADR-0010 single-phase — there is no later proof-facts
   migration). Now `set_verifier` (owner-only).
2. `sig_verifier` address — same class; becomes on-chain cairo-ec verification
   (§6.3, ADR-0006). Now `set_sig_verifier` (owner-only).
3. Fee config — was unguarded; now `set_fee` (owner-only).

**Still open (tracked — M3, mainnet readiness per ADR-0010):** single-owner is an
interim guard, not governance — upstream `Roles/AccessControl/Replaceability`
components (spec §4) replace it, and deployment to production stays blocked until
that lands. The M1 owner can
*keep the contract safe* (pause-by-verifier-swap is effectively an emergency
brake: swap in a rejecting verifier and no bundle can pass), but must not be
confused with decentralized control.

## C. Post-ADR-0010 disposition — removed or deferred, mapping not gaps

| Upstream mechanism | M1 status | Disposition |
|---|---|---|
| §5 phase ordering (`SetViewingKey → … → Withdraw`) | absent — M1 `apply_spend` is a self-contained, fully-proven bundle per call; there is no client phase to order | **removed** (ADR-0010): no client phase exists, so there is nothing to order; the 1:1 action zip + statement binding carry the integrity |
| Invoke / one-invoke-per-tx | n/a — invokes are cut; multiple `apply_spend` calls per tx are safe (each bundle independently proven + zipped) | **removed** (ADR-0010): private invokes permanently cut; curated DeFi via app controllers (spec §6) |
| `proof_validity_blocks` recency window | removed from storage (ADR-0010) | **removed** — there is no outer proof whose recency needs gating |
| Channel/viewing-key storage (§4) | not implemented — delivery machinery, not spend integrity | lands with the SDK as ordinary contract calls; derivations already frozen in §3.1 |

## D. Accepted risks / notes

1. ~~**Allowance pull (economic).**~~ **Resolved (ADR-0011).** Deposits moved to
   the standalone proofless `deposit()` entry point, which always pulls from
   `get_caller_address()` — no bundle can touch a third party's allowance, and
   the two-part leaf binds the deposited amount on-chain by construction.
2. **Discovery metadata spam (reduced, ADR-0012).** `note_id` is unproven
   (`NoteCommitted`) — garbage events are possible at the same trust level as
   upstream's channel data. But recipients now match on commitments they
   authored themselves, so garbage `note_id`s can at worst waste a lookup, never
   hide or redirect a payment. Spam costs senders fees and buys nothing.
3. **Conservation is not an M1 check.** Σ in/out per token is a §7.3.5 circuit
   property (M2). The pool intentionally cannot verify it (no openings); the
   zip (A4) bounds what unproven legs can touch.
4. **Tree capacity** is 2^32 (ADR-0013) — a finite, documented bound: ~4.3 B
   leaves sustains 1 M new notes/day for ~12 years. Worst case is a
   redeploy-and-migrate event (notes port via spend-into-successor), not a
   protocol failure.

## E. Fee-model snapshot (feeds §9.2)

Measured with snforge 0.63 (`src/tests/bench_pool.cairo`); l2 gas net of the
identical ~21.8 M deploy prefix (the constructor's zero-chain init halved with
ADR-0013's depth 32). Measured 2026-09-20 after ADR-0011/0012/0013.
Caveats: snforge's gas model is not the production sequencer's — re-measure
before finalizing fees; withdrawal-leg benches pre-fund the pool via the mock's
faucet, which adds one ERC20 storage write to those measurements.

| Bundle shape | l2 gas (net) | l1 data |
|---|---|---|
| fixed apply overhead (no-op bundle) | ~0.9 M | ~0 |
| per nullifier write | ~0.6 M | ~100 |
| leaf insert, steady-state marginal | ~6.5 M | ~0 (deduped within tx) |
| first leaf insert per tx | ~20.5 M | +3.4 K |
| `deposit()` (token pull + first insert + events) | ~21.3 M | +3.6 K |
| controlled small (1 nullifier + 1 leaf + apply) | ~21.3 M | +3.6 K |
| 2×2 bundle + 1 withdrawal | ~29.8 M | +4.1 K |
| max bundle (4+4+2wd+controlled, ADR-0014) | ~44.6 M | +4.9 K |

Cross-validation: the steady-state marginal (6.66 M, from the 1→16 leaf
delta) dropped from 11.31 M at depth 64 — slightly more than half remains
because per-insert fixed costs (count/ring writes) don't scale with depth.
The first-insert premium (~13.8 M over marginal) is intrinsic to the tree's
first insert under snforge's model — not `apply_spend` overhead.

Fee-model guidance: `base + 0.6 M × nullifiers + 6.7 M × leaves (+ first-insert
premium) + ERC20 legs`, verified end-to-end by the max-bundle (4/4/2) number.
