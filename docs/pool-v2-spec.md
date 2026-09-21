# TemplarPool v2 — Contract & Statement Specification

Status: **Preserved specification for the existing V3 package format** (frozen
2026-09-19). The current product architecture is the
[push-payment specification](push-payment-spec.md), adopted by
[ADR-0021](adr/0021-push-only-payments.md). This document still describes
`packages/pool/` until production integration; it is not the specification for
new push notes. Existing leaves must retain their original nullifier semantics.

Revision notes: this draft was rewritten after ADR-0009 — single note format with
optional controller authorization, both types as tree leaves, open notes cut. The
prior controlled-note map design (and its spend-linkability flaw under a blind
prover) is documented in ADR-0009. Revised after **ADR-0010** — the architecture
is single-phase (on-chain inner-proof verification; no client phase, no outer
virtual block, no operator) and private invokes are permanently cut. Revised
again after **ADR-0011/0012** — two-part commitment leaf with a standalone
proofless `deposit` (deposits leave the spend statement), and recipient-authored
notes (invoice flow): the channel machinery is cut.

Governing ADRs: 0002 (no auditor), 0003 (no screening), 0004 (tree + nullifier
ring), 0006 (controller authorization redesign), 0007 (event minimization), 0009
(note-type unification), 0010 (single-phase architecture; invokes cut), 0011
(two-part leaf + proofless deposit), 0012 (recipient-authored notes). ADR-0001
and ADR-0005 are superseded by ADR-0010. Out of scope here: proof-system
internals (ADR-0008), discovery protocol details, SDK UX.

---

## 1. Hash functions and field caveat

- All hashing is **Starknet Poseidon** (`poseidon_hash_span`, felt252 field),
  matching upstream `packages/privacy/src/hashes.cairo`. Domain separation via
  felt252 tags (`'NAME:V3'`) as the first preimage element.
- **Cross-field caveat (measured — ADR-0008 resolved)**: the inner SNARK runs over
  BN254 and implements felt252-Poseidon via non-native arithmetic. Measured
  (gnark, `bench/adr8/`): 47.5k constraints/permutation with general emulated
  arithmetic (~222/mul), ~6–8k is an unimplemented custom limb-folding target, not an audited or
  measured implementation. Note H(a,b) = the
  contract's `poseidon_hash_span` 2-element sponge = **2 permutations** in the
  circuit. Accepted for v2 to keep a single hash world (contract and circuit
  agree byte-for-byte). Rejected alternative: SNARK-native tree hashing —
  creates two incompatible hash domains across the state model.
- ECDSA for controller authorization is Stark-curve, verified **on-chain in
  Cairo** (not in-circuit) — see §6.

## 2. Design constants (freeze)

| Constant | Value | Notes |
|---|---|---|
| `TREE_DEPTH` | 32 | sparse tree over storage; 2^32 leaves (ADR-0013) |
| `ROOT_HISTORY_SIZE` | 256 | ring of acceptable roots |
| `MAX_INPUT_NOTES` | 4 | per spend bundle (ADR-0014) |
| `MAX_OUTPUT_NOTES` | 4 | per spend bundle (ADR-0014) |
| `MAX_WITHDRAWALS` | 2 | public outs per bundle (ADR-0014) |
| `NO_CONTROLLER` | 0 | sentinel: ordinary note (no authorization gate) |
| `PROTOCOL_VERSION` | 'TEMPLAR_V2' | in statement binding |

## 3. Note format (single, unified — ADR-0009; derivations V3 — ADR-0011/0012)

### 3.1 Derivations

```
note_secret = H(NOTE_SECRET_TAG, salt, owner_private_key)   // recipient-side (ADR-0012)
inner       = H(NOTE_INNER_TAG, note_secret)                // hiding inner commitment (ADR-0011)
note_id     = H(NOTE_ID_TAG, note_secret)                   // recipient-authored discovery key
commitment  = H(COMMITMENT_TAG, token, amount, controller, policy_commitment, inner)
nullifier   = H(NULLIFIER_TAG, note_secret)
```

- `owner_private_key` is the recipient's viewing/spend scalar. It is what makes
  the nullifier **receiver-only** (ADR-0009): a sender who paid an invoice knows
  `token`, `amount`, `inner`, and `note_id` but not `note_secret` (hidden behind
  `inner`'s preimage resistance), so they can never spend a note they funded.
- `salt` (u128, fresh random per note) is chosen by the recipient. Hiding does
  not depend on salt secrecy — only on `note_secret` secrecy.
- `inner` is the only secret-bearing leaf input, yet is public at creation
  (deposit calldata, or the invoice). Every other leaf field is public at
  creation too, so the commitment is computable by the contract (`deposit`,
  ADR-0011) and by senders (invoice outputs) — while remaining unopenable
  without `note_secret`.
- `note_id` is public at creation as the **discovery/matching key** (opaque to
  observers). It is **not** revealed at spend.
- `controller` and `policy_commitment` are `0` for ordinary notes. Binding them
  into the commitment makes the authorization requirement immutable: a note
  created as controlled can never be spent as ordinary (enforced in-circuit).
- One secret (`note_secret`) anchors the family: `inner`, `commitment`, and
  `nullifier` all descend from it — a single preimage chain per input note in
  the circuit.

Literal domain-separation tag values (pinned at freeze; the note family is V3
after ADR-0011/0012, the binding family stays V2):

| Symbol | Literal |
|---|---|
| `NOTE_SECRET_TAG` | `'NOTE_SECRET_TAG:V3'` |
| `NOTE_INNER_TAG` | `'NOTE_INNER_TAG:V3'` |
| `NOTE_ID_TAG` | `'NOTE_ID_TAG:V3'` |
| `COMMITMENT_TAG` | `'COMMITMENT_TAG:V3'` |
| `NULLIFIER_TAG` | `'NULLIFIER_TAG:V3'` |
| `TRANSITION_COMMIT_TAG` | `'TRANSITION_COMMIT_TAG:V2'` |
| `TX_BIND_TAG` | `'TX_BIND_TAG:V2'` |

### 3.2 Authorization

`authorization = NONE | Controller(transition_commitment)`.

- **NONE** (`controller = 0`): the plain private-transfer path. No application,
  no signature — Tornado semantics with flexible amounts.
- **Controller**: every spend of the note requires the bound controller's
  authorization (§6). Creating a controlled note debits private balance (a
  spend-bundle output with `controller ≠ 0`) or funds it directly through
  `deposit(controller ≠ 0)` (ADR-0011); the funded value stays in the pool until
  the controller authorizes a transition.

There is no separate note type — controlled notes are ordinary notes with a
non-zero `controller`. Transferring a controlled note to another party = spend +
create under the same controller in one transition.

### 3.3 Note creation and discovery (invoice protocol — ADR-0012)

Only a note's recipient can author it: `note_secret` requires their
`owner_private_key`. To be paid, the recipient picks a fresh `salt`, derives
`note_secret` / `inner` / `note_id` locally, and sends an **invoice**
`{token, amount, inner, note_id}` (optionally `controller`, `policy_commitment`)
to the sender off-chain. The sender's spend bundle inserts the corresponding
`commitment` as an output — computable from the invoice's public fields plus
`inner`, never openable by the sender.

Discovery is local: the recipient watches `NoteCommitted` events and matches
`note_id` / `commitment` against invoices they issued (a discovery service can
pre-filter events without learning anything). Invoices pin the amount — a
sender cannot underpay an invoice, only pay it or not. Push-style payments are
an SDK-layer concern (receive boards of pre-published single-use invoices).
Voluntary disclosure (ADR-0002) is out-of-band: hand over the
`owner_private_key` or per-invoice openings.

Upstream's channel/subchannel machinery (channel keys, ECDH channel info,
recipient/outgoing channel storage, the viewing-key registry) is **cut** — its
job was delivering sender-generated secrets, and recipients now generate their
own.

### 3.4 Open notes — cut (ADR-0009)

Upstream's open notes and the external-callback funding flow
(`deposit_to_open_note`, anonymizer callbacks, open-note screening policies) are
**not in v2**. Re-add paths when needed: app-specific controllers (the
anonymizer becomes the note's controller) or withdraw-and-redeposit.

## 4. Storage layout (complete — the M1 freeze)

| Member | Type | Notes |
|---|---|---|
| `tree` | `Map<u64, felt252>` | leaf commitments at `leaf_index` |
| `tree_count` | `u64` | next insertion index |
| `tree_root` | `felt252` | current root |
| `root_history` | `Map<felt252, bool>` | acceptable roots (ring) |
| `ring_slots` | `Map<u64, felt252>` | ring cursor slot → root, to locate the evicted oldest root (§9.3 decision) |
| `root_ring_index` | `u64` | ring cursor |
| `nullifiers` | `Map<felt252, bool>` | single domain, WriteOnce |
| `fee_token` | `ContractAddress` | canonical STRK at deploy; configurable only so tests can plug a mock |
| `fee_amount` / `fee_collector` | | tx fee in STRK, outside private accounting |
| governance | `owner` + Roles/AccessControl/Replaceability | M1: single owner guards fee/verifier config (interim, review §B); full upstream components before production (M3 — mainnet readiness, ADR-0010) |

**Deliberately absent** (vs upstream + PR #2): `auditor_public_key`,
`enc_private_key`, `screener_public_key`,
`open_note_depositor_screening_policies`, `notes` map, `controlled_notes` map,
open-note storage/counters, `get_num_of_channels`, the channel/subchannel maps
(`recipient_channels`, `outgoing_channels`, `channel_exists`, `subchannel_*`),
and the `public_key` viewing-key registry (ADR-0012).

## 5. Transaction lifecycle

Templar v2 is **single-phase** (ADR-0010): there is no client phase, no outer
virtual block, no operator, and no proof-facts gating. A spend is one
transaction, built and proven by the user:

1. **Off-chain**: the SDK builds the spend bundle (select inputs, compute
   outputs, collect controller authorization if any) and generates the inner ZK
   proof (ADR-0008) over the statement of §7. It also builds the server actions
   — nullifier writes, leaf insertions, withdrawals, controller apply.
2. **On-chain (`apply_spend`)**: the contract recomputes the statement binding
   over the public inputs and actions (§7.3.6), verifies the inner proof
   on-chain via the verifier contract (`IVerifier` seam), verifies the
   controller signature on-chain if `controller ≠ 0` (§6), then applies the
   actions atomically under the reentrancy guard, the fee, and the state checks
   of §7.4 — including the load-bearing 1:1 zip of actions against proven public
   inputs, which is what makes SDK-built actions safe without a proven client
   phase. The contract performs **no** secret-dependent logic — it never sees
   openings.

Deposits are not part of the bundle (ADR-0011): they enter through the
standalone proofless `deposit` entry point (§5.1), where the depositor is
always the caller. Upstream's remaining action set is reduced accordingly:
`UseNote` / `CreateEncNote` / `Withdraw` survive as bundle legs;
`CreateOpenNote` and `Invoke` are **cut** (ADR-0009, ADR-0010 — curated DeFi
integrations ship as app-specific controllers instead, §6), and the
channel/viewing-key actions are **cut** with the delivery machinery
(ADR-0012). Controlled creation/spend are the *same* legs as ordinary
create/spend with a non-zero `controller` field — no separate action kinds.

### 5.1 Public entry points

```cairo
fn apply_spend(
    public_inputs: SpendPublicInputs,   // §7.2
    proof: Span<felt252>,               // inner ZK proof, verified on-chain (IVerifier)
    server_actions: Span<ServerAction>, // SDK-built; zip-checked 1:1 against §7.2 (§7.4)
)

/// Proofless deposit (ADR-0011): the commitment is recomputed on-chain from
/// the public fields + `inner`, so the amount is bound by construction and no
/// proof is needed. The depositor is always the caller.
fn deposit(
    token: ContractAddress,
    amount: u128,
    controller: ContractAddress,
    policy_commitment: felt252,
    inner: felt252,
    note_id: felt252,
)
```

## 6. Controller authorization (ADR-0006 redesign, retained)

1. The SDK sends the canonical `ControlledTransition` (§6.1) to the controller
   **off-chain**. The controller runs its policy (may read its own storage),
   returns `(nonce, deadline)` and a **Stark-curve ECDSA signature** over
   `transition_commitment`.
2. `transition_commitment = H(TRANSITION_COMMIT_TAG, PROTOCOL_VERSION, chain_id,
   pool_address, padded-legs, deadline, nonce)` — where padded-legs is the
   ADR-0014 fixed-size encoding of exactly this bundle's legs:
   `n_in, nullifiers[4], in_amounts[4], n_out, commitments[4], out_amounts[4],
   n_wd, withdrawals[2] as (token, low, high), controller`. The circuit
   recomputes it from witnesses (§7.3.4), so the controller's signature binds
   the real legs — amounts included. It cannot reference `statement_binding`
   (circular: the binding embeds the commitment).
3. The signature is verified **on-chain in Cairo** (cairo-ec/Garaga-class
   verification — steps, not constraints). The inner circuit binds the spend to
   `transition_commitment` via the transition openings (§7) and asserts the
   note's commitment-preimage `controller` equals the transition's controller.
4. On-chain staleness: `apply_spend` reverts if `block_number > deadline`; the
   controller's `nonce` namespace is its own (monotonic counters or otherwise).
5. The canonical `ControlledTransition` serialization of the draft is replaced
   by the **padded-legs preimage** (ADR-0014) the circuit recomputes — fixed
   field order, one array per list, counts inline, zero padding to MAX_*,
   controller/deadline/nonce last:

```
TRANSITION_COMMIT_TAG, protocol_version, chain_id, pool_address,
n_in,  (nullifier, in_amount)[4] zero-padded,
n_out, (commitment, out_amount)[4] zero-padded,
n_wd,  (token, amount_low, amount_high)[2] zero-padded,
controller, deadline, nonce
```

   The controller learns the legs off-chain (nullifiers, amounts, commitments,
   withdrawals) and signs only the hash. It never learns ordinary-note
   recipients (ADR-0006 data-minimization), and ordinary notes never appear in
   a transition at all (ADR-0009: a controlled tx's legs are controlled notes
   only — enforced in-circuit by §7.3.4 controller consistency).

## 7. The spend statement (M2 freeze)

### 7.1 Private witnesses

Per input note: `merkle_path[TREE_DEPTH]`, the `note_secret` preimage
(`salt`, `owner_private_key`), `token`, `amount`, `controller`,
`policy_commitment`. Per output note: the recipient invoice (`inner`, `token`, `amount`,
`controller`, `policy_commitment`), with no recipient salt or private key. If any input or output is
controlled: all controlled transition openings (§6.1).

### 7.2 Public inputs (`SpendPublicInputs`)

```
protocol_version, chain_id, pool_address
tree_root
input_nullifiers[MAX_INPUT_NOTES]
output_commitments[MAX_OUTPUT_NOTES]
withdrawals[MAX_WITHDRAWALS]:    (token, amount)      // to_addr applied on-chain, not proven
controller: ContractAddress | 0                       // single-controller-per-tx invariant
deadline: u64                                         // 0 for ordinary bundles (ADR-0014)
transition_commitment: felt252 | 0
statement_binding: felt252                            // §7.3.6
```

The **Groth16 public-input vector is the fixed scalar subset** (ADR-0014):
`[protocol_version, chain_id, pool_address, tree_root, controller, deadline,
transition_commitment, statement_binding]`. The array fields enter the proof
via `statement_binding`, which the pool recomputes from calldata.

### 7.3 Statement (what the inner proof asserts)

1. For every input note: recomputed `note_secret = H(NOTE_SECRET_TAG, salt,
   owner_private_key)`, `inner = H(NOTE_INNER_TAG, note_secret)`, and
   `commitment = H(COMMITMENT_TAG, token, amount, controller,
   policy_commitment, inner)` equals a leaf on `merkle_path` ascending to
   `tree_root`.
2. For every input note: `H(NULLIFIER_TAG, note_secret)` equals the
   corresponding public `input_nullifiers[i]`.
3. For every output note: recompute `H(COMMITMENT_TAG, token, amount, controller,
   policy_commitment, inner)` from invoice fields and assert it equals the
   corresponding public `output_commitments[j]`. Knowledge of the recipient
   secret is required only when that note is later spent.
4. **Authorization consistency**: the controller derived from every input/output
   commitment preimage equals the public `controller` field; if `controller ≠ 0`,
   the `transition_commitment` recomputed over the padded-legs preimage (§6.2)
   covers exactly the legs of this bundle — nullifiers and amounts in,
   commitments and amounts out, withdrawals, deadline, nonce.
5. **Conservation**: single-token bundles (ADR-0014) — `Σ in = Σ out +
   Σ withdrawals`, with all amounts range-checked to u128 so sums cannot wrap
   (withdrawals verifiable on-chain against ERC20 transfers; deposits are not a
   bundle leg — ADR-0011).
6. **Binding**: `statement_binding = H(TX_BIND_TAG, §7.2 fields, H(server_actions))`
   over the **padded encoding** (ADR-0014): counts inline, arrays zero-padded to
   MAX_*, withdrawals as `(token, low, high)`, then `controller, deadline,
   transition_commitment, actions_hash` — the proof is single-use: it commits
   to exactly one transaction's actions and public inputs.

### 7.4 On-chain checks (`apply_spend` + `deposit`)

- `tree_root` ∈ `root_history`; nullifiers unused (WriteOnce); `tree_count` ≤
  capacity; output commitments inserted at `tree_count..`; `block_number ≤
  deadline` (controlled txs); controller signature verified on-chain (§6);
  inner proof verified on-chain via `IVerifier` (ADR-0010); fee handling as
  upstream.
- **Action zip (load-bearing)**: server actions are re-checked 1:1 against the
  public inputs in order — every `NullifierWrite[i] == input_nullifiers[i]`,
  `LeafInsert[i].commitment == output_commitments[i]`, and withdrawal
  `(token, amount)` entries match, with exact counts in both directions; a
  `ControllerApply`'s `deadline` must equal the public-input `deadline`
  (ADR-0014). The statement binding ties the actions into the proven statement
  (§7.3.6), but only the on-chain zip prevents an SDK from *adding* unproven
  writes (e.g. a forged extra nullifier would let anyone DoS an arbitrary
  note). `note_id`/`to_addr` are on-chain-only and unproven by design (§7.2,
  §8). Zero nullifiers/commitments/tokens are rejected in real slots; the
  binding's padding slots are zero on both sides by construction.

## 8. Events (ADR-0007 policy applied)

| Event | Fields | Notes |
|---|---|---|
| `NoteCommitted` | `note_id`, `leaf_index`, `commitment`, `controller` | `controller = 0` for ordinary; discovery artifact retained |
| `NullifierSpent` | `nullifier`, `controller` | create↔spend unlinkable; controller public (accepted, ADR-0006) |
| `Deposited` | `token`, `amount` | **no depositor**; attribution only at ERC20 layer |
| `Withdrawal` | `to_addr`, `token`, `amount` | inherent; unlinkability lives in the spend |
| `ControllerAuthorized` | `transition_commitment`, `controller` | replaces upstream's in-proof validate receipt |
| `OwnershipTransferred` | `from`, `to` | governance |

Open-note events (`OpenNoteCreated`, `OpenNoteDeposited`) are gone with the
feature (ADR-0009); upstream's `ExternalContractInvoked` and the invoke action
are gone with invokes (ADR-0010); `ViewingKeySet` and `packed_value` are gone
with the channel machinery (ADR-0012). `get_num_of_channels` is removed.

## 9. Open items (do not block freeze)

**Desktop pathfinding update (2026-09-20):** tree mutation is internal-only;
`insert_leaf` is absent from the production ABI. The corrected output witness
uses invoice fields, matching ADR-0012. The native BN254 benchmark in
`bench/desktop` is a separate experimental format, not an amendment to the
production hash/statement encoding. Controller signatures still omit withdrawal
destinations, and owner-controlled verifier replacement remains a trust assumption;
both remain production blockers. Desktop resource requirements and the proposed
hash decision are recorded in ADR-0017.


1. ✅ ADR-0008 resolved — Groth16/BN254 (§1, `bench/adr8/`). Remaining: on-chain
   verifier gas (Garaga) measured on a production sequencer → fee model (review §E).
2. ✅ Root-update cost measured (M1, `packages/pool`; depth 32 per ADR-0013):
   per-insert ≈ **6.7 M l2 gas** steady-state (32 sibling reads + 32 node
   writes + 32 Poseidon); first insert in a tx ≈ **20.5 M** (cold storage). The
   zero-chain init (32 steps) is paid once by the deployer in the constructor.
   Measured via the bench suite (`bench_apply_1_leaf` / `bench_apply_16_leaves_only`)
   in snforge.
3. ✅ `root_history` ring eviction: **evict oldest**, implemented via `ring_slots`
   (`ring_index % ROOT_HISTORY_SIZE` → evicted root), storage table updated.
4. ✅ `apply_spend` + `deposit` gas snapshot (M1, `packages/pool/src/tests/bench_pool.cairo`,
   snforge 0.63 — re-measure on a production sequencer before finalizing fees).
   Full table + fee-model guidance: [`docs/m1-invariant-review.md`](m1-invariant-review.md) §E.
5. ~~Stealth viewing-key publication~~ — moot: the viewing-key registry is cut
   with the channels (ADR-0012); voluntary disclosure is out-of-band.
6. ✅ `deposit` emits both `Deposited` and `NoteCommitted` (ADR-0011) — the
   deposit-time commitment is computed on-chain, so both events carry identical
   public information.
7. Anonymizer re-integration pattern for DeFi returns (app-controller template vs
   withdraw-and-redeposit) — future ADR when the first integration lands.
8. Receive-board pattern for push-style payments (ADR-0012) — SDK/discovery
   layer, spec needed when the SDK lands.
