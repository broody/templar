# Policy notes — bounded policy-controlled private assets

Status: **design reviewed (GO); implemented experimentally, implementation review pending**
(ADR-0025, Proposed). Revision 3, after the design reviews and re-reviews in
`bench/m31-pool/reviews/policy-note-design-{math,protocol}-review.md` (finding IDs `PN-*`, `P-*` and
`N-*` are cited where they changed the text). Implementation: `client-port/src/policy.rs` and
`cairo-p1`, `bench/m31-pool` (`policy.cairo`, `policy_escrow.cairo`, `policy_note.py`,
`policy_wallet.py`, `policy_e2e.py`). It targets the compact client-proof path (ADR-0024): a fixed
arithmetic relation proved on the client with S-two (stwo-circuits, arithmetic-only fork), wrapped
by the server as PROOF2, settled by the M31 pool (`bench/m31-pool`).

## 1. Purpose and scope

A **policy note** is a private note whose value can only move into one of a small set of
outcomes committed when the note was created. It is spent with a per-note **capability**, not a
wallet key. An on-chain **controller** contract decides which outcome is currently allowed. After a
committed **deadline**, the pool alone allows the refund outcome.

Intended scenario (first milestone): a depositor funds an escrow note, gives a separate executor
that note's opening, and goes offline. The arbiter approves the settlement on the controller; the
executor proves it; the controller applies its state change atomically with the pool operation; the
beneficiary receives an ordinary note and spends it normally. If settlement never happens, anyone
holding the opening can refund the depositor after the deadline, and the depositor can do so from
the wallet seed alone. No approval signer exists anywhere.

**Bounded, not general.** The relation checks a committed outcome menu. It cannot run
application-defined private logic (upstream PR #2's `privacy_validate_controlled_transition`
executes controller Cairo inside the proof; the compact relation cannot). Consequently:

- outcomes are fixed at creation, except one public split amount chosen at settlement;
- no policy can decide an outcome from private data (sealed-bid comparison, private predicates);
- a controller cannot verify a note's existence, amount or terms before settlement, so
  applications that need collateral assurance at commitment time (auctions) are **not** supported
  by this tier (P-4);
- one policy input per settlement; no ordinary inputs beside it; one token;
- no replacement policy note with a privately computed remainder (streaming vesting, partial
  release). A *fixed* outcome may pay into another policy note (§4.5).

General controllers would need per-application circuits (a later tier, not designed here).

## 2. Baseline

Unchanged and reused:

- **Hash.** `H(kind, payload)` is the framed rate-15 sponge over `[TAG, 1, kind, 0] ++ payload`
  (level word 0) with the width-24 Poseidon2-M31 permutation, truncated to nine words
  (`client-port/src/payment.rs`, `h`). Existing kinds: `AUTH 1, NK 2, OWNER 3, INNER 4, NOTE 5,
  NODE 6, NF 7, NODE1 8, IDENTITY 9`.
- **Ordinary note.** `receiver = H(OWNER, H(AUTH, sk) ‖ H(NK, sk))`,
  `inner = H(INNER, receiver ‖ rho)`,
  `cm = H(NOTE, chain₉ ‖ pool₉ ‖ token₉ ‖ amount₈ ‖ inner)`,
  `nf = H(NF, nk ‖ cm ‖ pos_lo ‖ pos_hi)`. Felts are nine 28-bit limbs; u128 amounts eight 16-bit
  limbs; u64 block numbers four 16-bit limbs. One depth-32 tree, one nullifier set.
- **R0 V3** (ordinary spends, open notes, shadow accounts): 2 inputs, ≤ 2 outputs, one optional
  withdrawal, intent, identity handle. **Not modified by this design.**
- **Delivery.** Every new note carries a 304-byte sealed-box ciphertext of a 256-byte plaintext,
  published as ten words; `delivery = Poseidon('CTRL_DELIVERY_V1', 304, words)`
  (`docs/push-payment-spec.md`, `spend.cairo` `delivery_digest`).
- **Pool deposit.** `deposit(token, amount, inner, ciphertext)` computes `cm` on chain from the
  caller-supplied `inner`.
- **PROOF2 binding.** A statement account emits `message_hash = Poseidon(statement, 0, 5,
  statement_class, ACCOUNT_TAG, chain, pool, binding)`; a verifier adapter checks the transaction's
  proof facts against it and the pool recomputes `binding` from calldata.

## 3. Keys and note format

New hash kinds (all at level 0): `PNK 10`, `PRECV 11`, `POLICY 12`, `OUTCOME 13`, `OREST 14`,
`POLICY_ID 15`.

A policy note has a nine-word secret **capability** `cap` (nonzero, canonical M31 words):

```
pnk      = H(PNK, cap)                                  // nullifier / tracking key
recv_p   = H(PRECV, pnk ‖ policy)                       // the note's "receiver"
inner    = H(INNER, recv_p ‖ rho)                       // unchanged construction
cm       = H(NOTE, chain₉ ‖ pool₉ ‖ token₉ ‖ amount₈ ‖ inner)   // unchanged construction
nf       = H(NF, pnk ‖ cm ‖ pos_lo ‖ pos_hi)            // unchanged construction
```

`policy` is the nine-word policy digest (§4). A policy note is an ordinary-format leaf whose
receiver is a policy receiver instead of an owner receiver:

- **Creation needs no new code path.** An R0 V3 output with `receiver = recv_p`, or a pool
  `deposit` with `inner = H(INNER, recv_p ‖ rho)`, creates a policy note, with a standard-format
  ciphertext (§9). On chain and in the statement it is indistinguishable from an ordinary note.
- **No cross-spending.** The ordinary relation spends a leaf only if its receiver equals
  `H(OWNER, …)` for a known `sk`; the policy relation (§5) only if it equals `H(PRECV, …)` for a
  known `cap`. A leaf spendable by both would require an `OWNER`/`PRECV` output collision.
- **One nullifier per note.** `nf` depends only on `cap` (through `pnk`), `cm` and position, so
  every holder of the capability derives the same nullifier. The nullifier set is shared with R0.
- **Capability separation.** `cap` authorizes spending. `pnk` with the opening minus `cap` lets a
  watcher recognize the note and its nullifier without being able to spend.

## 4. Policy digest and outcomes

### 4.1 Policy

```
orest   = H(OREST, o₁ ‖ o₂ ‖ o₃)
policy  = H(POLICY, version₁ ‖ kind₁ ‖ controller₉ ‖ controller_class₉ ‖ handle₉ ‖ deadline₄
                    ‖ salt₉ ‖ o₀ ‖ orest)
policy_id = H(POLICY_ID, chain₉ ‖ pool₉ ‖ token₉ ‖ amount₈ ‖ policy)
```

- `version = 1`, `kind = 1` (outcome menu): **circuit constants** in P1, not witnesses (PN-3).
  Other kinds belong to later tiers and are never spendable by P1.
- `controller`: the controller contract address. `controller_class`: its class hash, pinned.
- `handle`: an application-defined felt. **It is unauthenticated creator input**: anyone can create
  a note naming any handle (PN-1/P-1). Controllers must authorize on `policy_id` (§7.1), and may
  use the handle only for data the creator is entitled to choose (the reference escrow uses it as
  the arbiter's address).
- `deadline`: a block number.
- `o₀`: the **refund** outcome digest (§4.4). `o₁ … o₃`: other outcome digests. An unused slot is
  nine zero words; it can never be selected (no preimage hashes to zero).
- `salt`: nine random words (seed-derived, §9.1), so a policy whose outcomes carry no secret
  randomness (withdrawals only) still has an unguessable digest (N-6).
- `policy_id` is published at settlement and is what controllers register and approve. It commits
  to the chain, pool, token and **note amount** as well as the policy, so a copy of the same
  policy funded in another token, pool or amount has a different `policy_id` (N-1: without the
  token, a holder could settle a junk-token copy and consume the arbiter's approval). It reveals
  nothing about the note without the salt.

### 4.2 Outcome

```
o = H(OUTCOME, type₁ ‖ not_before₄ ‖ out₀ ‖ out₁ ‖ w_recipient₉ ‖ w_amount₈)
out_j = active₁ ‖ receiver₉ ‖ rho₉ ‖ amount₈ ‖ delivery₉
```

- `type ∈ {1, 2}`.
- `type = 1` **fixed**: every field is committed. For each `j`: if `active = 1`, `receiver`,
  `rho` and `delivery` are nonzero, `amount ≠ 0`, and the output's commitment is
  `H(NOTE, context ‖ amount ‖ H(INNER, receiver ‖ rho))`; if `active = 0`, all of `out_j` is zero.
  `w_recipient` and `w_amount` are both zero or both nonzero. At least one output or the
  withdrawal is present.
- `type = 2` **split**: `out₀` and `out₁` are both `active = 1` with committed `receiver`, `rho`
  and `delivery`, and `amount = 0` in the preimage. The withdrawal fields are zero. At settlement a
  public `x` with `1 ≤ x ≤ note amount` gives `out₀` amount `x` and `out₁` amount
  `note amount − x`; if `x = note amount`, `out₁` is inactive (zero commitment and delivery).
- `not_before`: a block number; the outcome may settle only at or after it.
- `delivery`: the delivery digest of that output's ciphertext, fixed at creation (§9).
- Every output `rho` in a policy is distinct and fresh (derived as in §9); reusing a `rho` across
  outcomes or notes would give identical commitments and link them (PN-8).

### 4.3 Conservation

Fixed: `out₀.amount + out₁.amount + w_amount = note amount` as integers. Split: by construction.

### 4.4 Refund

`o₀` must be fixed with `not_before = 0`, an active `out₀` and no withdrawal (enforced by P1,
§5), so a refund always creates a private note and can never be stuck on a withdrawal the pool
rejects (N-5 math, P-12). The **standard refund**, which
wallets create and which seed recovery assumes, pays the whole amount to one ordinary output at the
depositor's own receiver, with no withdrawal and a deterministic delivery (§9). Before the deadline
the refund is controller-gated like any other outcome; after it the pool allows it without the
controller (§6).

### 4.5 Chaining

A fixed outcome's receiver may itself be a policy receiver: the outcome then creates a new policy
note (e.g. the next vesting tranche). Its amount is fixed at creation; there is no private
remainder arithmetic.

## 5. Policy settlement relation (P1)

A **new, separate** client relation, with statement tags `P1V1` / `P1C1` for the two tree formats
(distinct from R0's `R0V3` / `R0C3`). It shares R0's hash, tree and range-check gadgets.

**Private witness:** `cap`, `rho`, `amount`, `position`, `siblings[32]`; the policy header
(`controller`, `controller_class`, `handle`, `deadline`, `salt`); the selected outcome's full preimage;
the digests needed to recompute `policy` (`o₀` or `orest`, and the two unselected `o₁…o₃`).

**Public statement** (in output order):

| Field | Limbs |
|---|---|
| tag | 2 |
| chain, pool, token | 27 |
| root | 9 |
| nullifier | 9 |
| commitments[2] | 18 |
| deliveries[2] | 18 |
| withdrawal recipient, amount | 17 |
| controller, controller_class, handle | 27 |
| policy_id | 9 |
| deadline, not_before | 8 |
| outcome index, outcome type | 2 |
| x (split amount, 0 for fixed) | 8 |
| data (a felt carried verbatim) | 9 |

163 limbs, padded to 164 (41 QM31 outputs).

**Constraints:**

1. **Encodings and ranges (PN-2).** Every digest word and `cap`, `rho` word is canonical
   (`< 2³¹ − 1`); `cap` and `rho` are nonzero; felt limbs are 28-bit; **every amount limb in the
   witness and the selected outcome preimage, `x`, and the split remainder is range-checked to 16
   bits**; block-number limbs are 16-bit; `amount ≠ 0`. The same limb variables feed the outcome
   hash, the output commitments, the public fields and conservation; no value is re-encoded
   between them.
2. **Note.** `pnk`, `recv_p`, `inner`, `cm` as §3, with `policy` recomputed per step 3 from the
   header, the constants `version = kind = 1`, and the outcome digests.
3. **Selection (PN-3).** The public outcome index is `Σ k·b_k` over four boolean selector bits
   with `Σ b_k = 1`. The selected slot's digest is recomputed from the selected preimage; every
   other slot's digest is a witness. Concretely `o₀ = b₀·ô + (1 − b₀)·w₀` and
   `o_k = b_k·ô + (1 − b_k)·w_k` for `k = 1..3`, where `ô` is the recomputed digest, word by word;
   `orest = b₀·w_rest + (1 − b₀)·H(OREST, o₁ ‖ o₂ ‖ o₃)` (a refund needs only `orest`, which seed
   recovery provides, §9.2); then `policy` as §4.1.
4. **Membership and nullifier.** `cm` climbs `siblings` at `position` to `root`;
   `nullifier = H(NF, pnk ‖ cm ‖ pos_lo ‖ pos_hi)`.
5. **Public header.** The public controller, class, handle, deadline and `policy_id` equal the
   private/recomputed ones (`policy_id` from the public context and the private `amount`); the public outcome type and `not_before` equal the selected preimage's.
6. **Type.** `type ∈ {1, 2}` (boolean-decomposed). `b₀ = 1` requires `type = 1`,
   `not_before = 0`, `active₀ = 1`, and `w_recipient = w_amount = 0`.
7. **Fixed** (`type = 1`): `x = 0`; `active_j ∈ {0, 1}`; active outputs are well formed
   (including a nonzero delivery, so no outcome, and in particular no refund, can be unsettleable
   for a missing ciphertext; F-3 math) and
   inactive ones all zero (§4.2); each public commitment and delivery equals the outcome's (zero
   when inactive); the public withdrawal equals the outcome's; conservation (§4.3) holds as
   integers with R0's carry gadget.
8. **Split** (`type = 2`): `active₀ = active₁ = 1`, preimage amounts zero, withdrawal zero;
   `r = amount − x` computed limb by limb with boolean borrow bits, the final borrow zero (so
   `x ≤ amount`); `x ≠ 0` and `r`'s zero test by the same gadget: with `σ(v)` the sum of `v`'s
   eight 16-bit limbs (below 2¹⁹, so no wraparound), a witness `z ∈ {0,1}` and inverse `t` satisfy
   `σ·t = z` and `σ·(1 − z) = 0`, so `z = 1` exactly when the value is nonzero (N-6 math); `x`
   requires `z = 1`; `r`'s bit is named `nz_r`. The preimage flag `active₁` stays `1` (it is
   hashed as committed); `nz_r` only gates what is published for the second output (F-1/F-2).
   commitment₀ = `H(NOTE, context ‖ x ‖ H(INNER, receiver₀ ‖ rho₀))`; commitment₁ =
   `nz_r · H(NOTE, context ‖ r ‖ H(INNER, receiver₁ ‖ rho₁))` and delivery₁ = `nz_r ·` the
   outcome's, word by word; delivery₀ = the outcome's.
9. `data` is unconstrained (bound by the statement and the pool's binding).

`x` for a split and `data` are the only values chosen at settlement, and **every capability holder**
can choose them (PN-6): controllers must pin them (§7.1).

## 6. Pool settlement

New entry point `apply_policy_spend(spend: PolicySpend, data: Span<felt252>,
ciphertexts: Span<Span<felt252>>, proof: Span<felt252>)`, under the pool lock:

1. **Statement (PN-9/P-9).** Context (chain, pool, token). Proof facts through a **separate** P1
   verifier adapter in its own pool storage slot (`policy_verifier`, owner-set like `verifier`),
   pinned to the P1 statement-account class and account tag `TMPZP1_POLICY_V1`. The P1 bridge
   (Cairo, inside the virtual OS) checks the client proof against the pinned P1 circuit, the
   statement tag (`P1V1` or `P1C1` for its configured tree format), the output count (41 QM31) and
   zero padding, decodes felts with canonical `felt_from_limbs` (rejecting limbs ≥ 2²⁸ and values
   ≥ p) and amounts/blocks from 16-bit limbs, and passes the decoded statement to the account,
   which emits the message (N-5). As defense in depth it also re-checks what the circuit already
   enforces: outcome index `< 4`, type `∈ {1, 2}`, type `1` exactly when `x = 0`, each delivery
   nonzero exactly when its commitment is, withdrawal recipient and amount both zero or both
   nonzero, a nonzero nullifier, and addresses below 2²⁵¹. The binding is
   `Poseidon('TMP1_BIND_V1', chain, pool, token, root₉, nullifier₉, commitment₀₉, commitment₁₉,
   delivery₀, delivery₁, w_recipient, w_amount, controller, controller_class, handle,
   policy_id₉, deadline, not_before, outcome index, outcome type, x, data)`: digests as their nine
   M31 words, every other field as one felt (its decoded value) (PN-9). Known root; fresh nullifier in the
   shared nullifier map (marked spent). R0 and P1 proofs cannot be exchanged: the adapters pin
   different statement classes, account tags and binding tags, and the bridges pin different
   circuits and statement tags.
2. `Poseidon(data) == spend.data`. Each supplied ciphertext is ten words and its delivery digest
   equals the public delivery; an inactive slot has no ciphertext.
3. With `b` the current block: `b ≥ not_before`.
4. **Controller window** (`b ≤ deadline`):
   - `controller ≠ 0`, `controller ≠ pool`, and `get_class_hash_at(controller) ==
     controller_class` (a nonzero class; an undeployed address fails).
   - Call `controller.templar_apply_policy(authorization, data)` via `call_contract_syscall`
     with `unwrap_syscall`, so any controller failure reverts the whole transaction (P-10); the
     call must return exactly `['TEMPLAR_POLICY_OK']` (PN-7). The selector is Templar-specific,
     **not** PR #2's `privacy_apply_controlled_transition` (P-5): an upstream-style controller
     trusts that call's arguments as its own privately validated receipt, which these are not.
   - ```
     authorization = ['TEMPLAR_POLICY_V1', chain, pool, token, policy_id, handle,
                      outcome index, outcome type, x, key(nullifier), not_before, deadline,
                      key(commitment₀), key(commitment₁), withdrawal recipient, withdrawal amount]
     ```
     (`key(0) = 0` for an inactive output.)
5. **Refund window** (`b > deadline`): outcome index must be `0`; the controller is not called and
   its class is not checked.
   In both windows the pool also asserts that outcome index `0` has type `1` (defense in depth over
   §5 step 6, N-5).
6. Withdrawal recipient ≠ pool. Append new notes with their ciphertexts; pay the withdrawal; emit
   `NotePublished` for each and
   `PolicySettled { key(nullifier), controller, handle, policy_id, outcome, x, first_index }`
   (`x` and the note indices let split receivers learn their amounts, P-3).

The pool lock is held throughout; the controller cannot re-enter the pool. Relayer fees are out of
scope, as for R0 (P-14).

## 7. Properties and controller obligations

### 7.1 Controller obligations

A controller is security-critical application code. It must:

- authenticate `caller == pool` for the one pool it serves and check `authorization[0..4]`
  (tag, chain, pool, token);
- **authorize on `policy_id`**, never on `handle` alone: `handle`, the outcome index and every
  outcome are chosen by whoever creates a note, so a note naming another case's handle is an
  attacker's note (PN-1/P-1: a decoy note on the victim's handle could otherwise consume the case's
  approval and leave the real note only its refund);
- pin every value chosen at settlement: the outcome index and, for a split, `x`;
- allow at most one outcome per `policy_id` at a time, and record consumption;
- treat the deadline as final: after it, the note may already have been refunded without a
  callback (P-13; the `PolicySettled` event reports it).

### 7.2 Properties

- **Binding.** The proof fixes the note, `policy_id`, the outcome, the output commitments,
  deliveries, withdrawal, `x` and `data`; the relayer can change none of them. Chain, pool and
  token are in both the commitment and the statement.
- **Replay / double claim.** The nullifier is unique per note and shared by all capability holders.
- **Authorization freshness.** The controller decides at apply time from its current state; there
  is no stored receipt to replay.
- **Settle/refund race.** Before the deadline both go through the controller, which allows at most
  one; after it only the refund exists; one nullifier makes outcomes exclusive in any case.
- **Deadline boundary (P-7/PN-5).** An approval that is not *settled* by the deadline block is
  lost: after it, the depositor (or any holder) can refund. Proving, PROOF2 wrapping (minutes) and
  the adapter's maximum proof age consume that margin. Wallets must refuse to prepare a
  controller-window settlement too close to the deadline, and applications should choose deadlines
  with ample margin. A beneficiary who does not hold the capability depends on someone who does to
  settle in time; the beneficiary should hold it.
- **Controller pinning (P-6/PN-11).** The class hash fixes the controller's *code*, not its state
  or configuration. A proxy's class is the proxy; an admin setter, a replaceable owner or an
  upgrade to another class and back all escape it. Reference controllers are non-proxy, immutable
  and without admin setters. An upgraded controller blocks controller-gated outcomes until the
  deadline; the refund then works without it. A controller cannot freeze value past the deadline;
  an application that wants indefinite authority sets a far deadline, which is public at settlement.
- **Bearer semantics (reverses ADR-0009 §3).** The depositor keeps the capability. That is
  acceptable because no unconstrained spend exists: any holder can only cause committed outcomes,
  gated by the controller on `policy_id` with pinned `x` before the deadline, and limited to the
  refund after it.
- **Creation is unauthorized and private.** A policy note can only restrict its creator's funds,
  so the controller does not authorize creation (PR #2 does). Controllers register the
  `policy_id`s they accept through their own calls; they cannot verify a note's existence or amount
  before settlement.

## 8. Privacy

- **Creation:** indistinguishable from an ordinary note (deposit or R0 V3 output, standard-size
  ciphertext).
- **Settlement publishes:** that it is a policy spend (the P1 statement tag and entry point),
  controller, class, handle, `policy_id`, deadline, outcome index and type, `not_before`, `x`,
  `data`, the withdrawal, the output commitments, and the root (whose age bounds the note's
  creation time, PN-8). Fixed-outcome output amounts and receivers stay hidden. A split reveals
  `x`; it reveals the note amount only when `x` equals it (the second output is then visibly
  inactive) (PN-8/P-3).
- **Linkage:** settlement is linked to its application case (`handle`, `policy_id`) by design, not
  to the funding transaction or the depositor's other notes. A controller registration of
  `policy_id` links registration and settlement.
- **Holders:** the depositor and executor learn the full opening, including every outcome's
  receiver, `rho` and amount, so they can recognize the beneficiary's resulting note commitment
  (not spend it or see it spent).
- The P1 proof must be zero-knowledge on the same terms as R0 (blinding per the H2 fix); the
  hiding argument for the compact proofs is still open and gates real value.

## 9. Delivery, recovery and transport

### 9.1 Seed-derived values (PN-4/P-2)

For each policy note the wallet draws a fresh random 16-byte nonce `ν` (not a counter, so retries
and several devices cannot reuse one, N-3). With the wallet's policy seed `s_pol` (derived from the
wallet seed under its own label) and `ctx = chain ‖ pool ‖ ν`:

- `HKDF` is HKDF-SHA256 with an empty salt, input key `s_pol` and info `label ‖ ctx`, where the
  label is its ASCII bytes, `chain` and `pool` are 32-byte big-endian and `ν` its 16 raw bytes.
- `M31⁹(·)` expands 72 bytes and maps each 8-byte big-endian chunk to `u64 mod (2³¹ − 1)` (bias
  below 2⁻³²); an all-zero result is rejected by drawing a new `ν`.
- The X25519 scalar is 32 expanded bytes, clamped per RFC 7748.
- Test vectors pin all of this during implementation (F-1 math, F-4 protocol).

```
cap          = M31⁹(HKDF(s_pol, 'TEMPLAR_POLICY_CAP' ‖ ctx))
rho          = M31⁹(HKDF(s_pol, 'TEMPLAR_POLICY_RHO' ‖ ctx))
salt         = M31⁹(HKDF(s_pol, 'TEMPLAR_POLICY_SALT' ‖ ctx))
rho_refund   = M31⁹(HKDF(s_pol, 'TEMPLAR_POLICY_REFUND_RHO' ‖ ctx))
esk_refund   = X25519 scalar from HKDF(s_pol, 'TEMPLAR_POLICY_REFUND_EPH' ‖ ctx)
```

Other outcome `rho` values are fresh random (the executor receives them). The refund ciphertext is
a sealed box whose ephemeral key is `esk_refund` instead of a random one; the libsodium sealed-box
format (`epk ‖ box(m, nonce = BLAKE2b(epk ‖ pk))`) is unchanged, so the result is an ordinary,
indistinguishable ciphertext that the wallet can regenerate byte for byte. Each `esk_refund` is
used for exactly one message.

### 9.2 Creation ciphertext (the depositor's backup)

**M31 note plaintext.** The compact path has so far used a synthetic payload, and the reference
plaintext in `push-payment-spec.md` has 32-byte fields, which cannot hold a nine-word M31 digest.
This design therefore defines the compact path's plaintext (256 bytes, all big-endian): M31 words
take 4 bytes each, so a digest takes 36; felts take 32; amounts 16; block numbers 8. The ordinary
M31 note plaintext is:

| Field | Bytes |
|---|---|
| version `'M301'` | 4 |
| token | 32 |
| receiver (nine words) | 36 |
| `rho` (nine words) | 36 |
| amount | 16 |
| zero padding | 132 |

Chain and pool are the scanned pool's own context and are not repeated (F-1 math).

The creation output's ciphertext is a standard 304-byte sealed box to the depositor's own incoming
key. Its 256-byte plaintext uses version `'PB01'` instead of `'M301'`:

| Field | Bytes |
|---|---|
| version `'PB01'` | 4 |
| token | 32 |
| amount | 16 |
| controller | 32 |
| controller_class | 32 |
| handle | 32 |
| deadline | 8 |
| `orest` (nine words) | 36 |
| policy nonce `ν` | 16 |
| refund receiver index | 4 |
| zero padding | 44 |

With the seed, this recovers `cap`, `rho`, `salt`, the standard refund outcome (own receiver at
the index, `rho_refund`, whole amount, deterministic delivery) and therefore `o₀`, `policy` and
`cm`. The wallet verifies the recomputed `cm` against the leaf before trusting the backup. That is
enough to refund after the deadline from the seed alone. Chain and pool are the scanned pool's own
context.

The standard refund's plaintext is pinned byte for byte (N-4 and F-1 math): the `'M301'` plaintext
with the token, the refund receiver, `rho_refund` and the note amount, sealed with `esk_refund` to
the depositor's incoming key at that receiver index.

### 9.3 Executor and beneficiaries

- **Executor:** receives the full opening (every outcome preimage, `rho`s and output ciphertexts)
  out of band; the transport is application-owned.
- **Fixed-outcome beneficiary:** receives an ordinary note whose standard ciphertext the creator
  produced; recovered like any push payment.
- **Split receivers (P-3):** the creator cannot know the amount, so a split output's plaintext uses
  version `'PS01'`: the `'M301'` fields with a one-byte side flag taken from the padding. The `x` side's amount
  field is zero (it learns `x` from `PolicySettled` and nothing more, N-4); the remainder side's
  carries the note amount, from which it subtracts `x`. The wallet recomputes the commitment and
  checks it against the leaf at the reported index.
- **Acceptance checklist (PN-5)** for a beneficiary or executor given an opening: recompute `cm`
  and find it in the tree at a root; check the controller class and that it is a non-proxy
  reference controller; check the deadline margin; decrypt and check its own output's ciphertext
  against the committed delivery; then hand the verified `policy_id` to the controller's approver
  (§10), or for a registering controller confirm that it registered this `policy_id` (F-5). A
  depositor's wallet creates only the standard refund (§4.4); the relation guarantees a refund
  creates a private note with a delivery, but a counterparty relying on the refund still checks
  that its receiver and ciphertext are the depositor's (P-12).

## 10. Reference controller: escrow

`EscrowController(pool)`, immutable, no admin. The `handle` is the **arbiter's address**; cases
are keyed by `(policy_id, arbiter)`, so there is no registration race (P-8) and nothing to open:

- `approve(policy_id, outcome)` by the arbiter (caller), once per `policy_id`: records the only
  outcome (`1` release to the seller, `0` cancel) that may settle, **stored as `outcome + 1`** so
  that an unset entry (zero) never matches outcome `0` (N-2). Write-once, so there is no
  release/cancel race.
- `templar_apply_policy`: checks the caller, the context (tag, chain, pool; the token is already
  bound by `policy_id`), `type = 1`, and
  that `approved[(policy_id, handle)] == outcome + 1` and not consumed; marks it consumed; returns
  `'TEMPLAR_POLICY_OK'`.

A decoy note naming the same arbiter, or a copy of the policy funded in another token, pool or
amount, has a different `policy_id`, which the arbiter never approved.

**Which `policy_id` the arbiter approves (N-7 math).** The seller (beneficiary) receives the
opening, runs the acceptance checklist (§9.3), and gives the arbiter the verified `policy_id`; or
the arbiter receives the opening and verifies it itself. The arbiter approves only a `policy_id`
that the party it protects has verified.
The deadline refund needs nothing from the controller.

**Tests.** Acceptance: the §1 scenario end to end with real proofs, including an executor that
holds only the opening, and a seed-only refund after the deadline. Rejection: wrong destination,
amount, policy, `policy_id` or controller; missing or wrong capability; ordinary spend of a policy
note and vice versa; settlement before `not_before`, controller-window settlement after the
deadline, non-refund outcome after it; unapproved or already consumed `policy_id`, including
outcome `0` for a never-approved `policy_id`; decoy note on the same handle; junk-token or
other-amount copy of an approved policy; replay and double claim; cross-chain or cross-pool reuse; manipulated commitments,
deliveries, `x` or `data`; P1 proof to R0's entry point and vice versa; direct controller
invocation; settle/refund race at the boundary block; controller class change; controller revert
or wrong return rolling back everything; split bounds (`x = 0`, `x > amount`, `x = amount`);
out-of-range limbs and wrapped conservation (PN-2); index/selector mismatch (PN-3). Plus unchanged
R0 V3 behaviour.

## 11. Limits and deferred

One policy input and no ordinary inputs per settlement; menu of four outcomes; two outputs; one
withdrawal; one token; fixed amounts except one split. Deferred: private controller logic
(per-application circuits), creation attestations (collateral assurance for auctions), replacement
notes with private remainders, open notes funding policy notes (possible without relation changes,
via a destination `inner`), multi-token settlement.
