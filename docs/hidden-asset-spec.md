# Hidden-asset spends and ERC721/ERC1155 notes

Status: **design reviewed (GO); implemented experimentally (M31 pool V2, R0 V4); implementation reviewed (GO).** Revision 3, with §3.3 and §5.2 wording corrected after the implementation review. Revision 1 was reviewed in
`bench/m31-pool/reviews/hidden-asset-design-{math,protocol}-review.md` (both CONDITIONAL GO);
revision 2 was re-reviewed there (both GO), and revision 3 adds those re-reviews' Low and Info
items. Finding IDs `HA-M*` and `HA-P*` are cited where they changed the text. Targets
the compact client-proof path: the R0 relation (`bench/m31-private-wrapper/client-port/src/payment.rs`),
its bridge and statement account (`client-port/cairo-r0`), and the M31 pool (`bench/m31-pool`).

## 1. Purpose and scope

Today every R0 spend publishes its token, including in-pool transfers with no withdrawal. Every
leaf's token is therefore publicly known: deposits and funded open notes publish it, and a spend's
outputs inherit the spend's public token. The tree is partitioned by token, and a spend's
anonymity set is the notes of its token only.

This design does three things in one new relation version, **R0 V4**, deployed in a **new pool**
(§5.6):

1. **Hidden token.** The token becomes a private witness value. A spend publishes it only when
   value leaves the pool (a withdrawal or an open-note execution). An in-pool transfer publishes
   no asset. Upstream Starknet Privacy already hides the token of private transfers (encrypted
   notes store `token = 0`; per-token balances are checked inside the proven execution).
2. **Uniform shape.** Every V4 spend publishes exactly two nullifiers and two output commitments
   with ciphertexts. A single-input spend uses a zero-value **dummy input**; a spend with fewer
   than two real outputs uses zero-value **dummy outputs**. Observers cannot tell one input from
   two, or one output from two.
3. **ERC721 and ERC1155 assets.** A note's token field becomes an **asset identifier**. ERC20
   keeps the contract address; ERC1155 and ERC721 use a hash of the standard, contract and token
   id. ERC721 notes always hold amount 1, which needs the single-input spend from point 2.

Out of scope for this milestone:

- spends that move several assets at once (atomic private swaps, NFT-for-token trades);
- NFT budgets or NFT destinations in open-note executions (`OpenNoteDeposit` has no token id,
  and upstream adapters expect ERC20);
- hiding the token in policy-note settlement (P1 is unchanged; its settlement is already a
  public, application-linked event);
- hiding which NFT is deposited or withdrawn: edges stay public;
- hiding the asset of a collect-only invoke (`intent ≠ 0`, zero budget), which V4 reveals (HA-M7e).

## 2. Baseline (unchanged)

- **Hash.** `H(kind, payload)`: the framed rate-15 Poseidon2-M31 sponge truncated to nine words
  (`payment.rs`, `h`). Kinds `AUTH 1, NK 2, OWNER 3, INNER 4, NOTE 5, NODE 6, NF 7, NODE1 8,
  IDENTITY 9` and the policy kinds `10–15`. **This design adds no hash kind.**
- **Note.** `receiver = H(OWNER, H(AUTH, sk) ‖ H(NK, sk))`, `inner = H(INNER, receiver ‖ rho)`,
  `cm = H(NOTE, chain₉ ‖ pool₉ ‖ token₉ ‖ amount₈ ‖ inner)`, `nf = H(NF, nk ‖ cm ‖ pos_lo ‖ pos_hi)`.
  Felts are nine 28-bit limbs; amounts eight 16-bit limbs. The commitment format is unchanged.
- **Delivery.** 304-byte sealed box of a 256-byte plaintext, ten words;
  `delivery = Poseidon('CTRL_DELIVERY_V1', 304, words)`. The `M301` plaintext already carries the
  token (nine M31 words), so a recipient learns a note's asset by decrypting.
- **Binding and wrapping.** The bridge decodes the statement limbs, checks them and computes the
  binding; the statement account emits `[class, tag, chain, pool, binding]`; the pool recomputes
  the binding from calldata and checks the proof facts through its verifier adapter.
- **P1** (policy settlement) is not modified.

## 3. Assets

### 3.1 Identifiers

A note's `token₉` field holds a felt **asset identifier** `a`:

| Standard | `a` | Note amount |
| --- | --- | --- |
| ERC20 | the token contract address (as today) | u128, nonzero |
| ERC1155 | `Poseidon('TEMPLAR_ASSET_V1', 1155, contract, id.low, id.high)` | u128, nonzero |
| ERC721 | `Poseidon('TEMPLAR_ASSET_V1', 721, contract, id.low, id.high)` | exactly 1 |

`Poseidon` is Starknet's felt252 `poseidon_hash_span`, computed by the pool and the wallet, never
in the circuit. The relation treats `a` as an opaque felt.

Every identifier is **below 2^251** (HA-M3, HA-P4). An NFT registration whose hash is at or above
2^251 is rejected (probability about 2^-55 for an honest id); that (contract, id) pair cannot be
deposited. Identifiers therefore fit `ContractAddress` fields, the unchanged P1 bridge's range
check, and the wallet's backup check. V4's own fields are typed `asset: felt252`.

ERC20 addresses and NFT identifiers are disjoint in practice: a confusion needs a deployed address
equal to a `TEMPLAR_ASSET_V1` hash, a second preimage (about 2^251) to target another's asset, or
a birthday collision (about 2^125) between two assets the attacker owns. Two cheap guards
(HA-P10): the ERC20 `deposit` rejects an identifier present in the registry, and NFT
registration requires that no contract is deployed at `a` (`get_class_hash_at_syscall(a) == 0`,
to be confirmed for undeployed addresses during implementation).

### 3.2 Registry and contract standards

- `assets: Map<felt252, AssetInfo { standard, contract, id: u256 }>`: written once, on the first
  deposit of an ERC721 or ERC1155 asset, in the same transaction as its first note. Emits
  `AssetRegistered { asset, standard, contract, id }`. Views: `get_asset(a)` and
  `asset_id(standard, contract, id)`.
- `contract_standard: Map<ContractAddress, u8>` (ERC20, ERC721 or ERC1155) (HA-P1): written on a
  contract's first deposit through **any** path, including the ERC20 `deposit` and open-note
  destination funding. A deposit or destination that uses a different standard for a recorded
  contract is rejected. This prevents one contract (an ERC-404-style hybrid, or a shared
  721/1155 ledger) from backing notes under two standards, where one standard's movements could
  unback the other's notes.
- For a genuine hybrid contract, whichever standard deposits first is fixed for good; the other
  standard's deposits are then rejected. This affects availability only, not solvency; supporting
  hybrids is a listing decision (HA-P13).
- NFT registration also requires the contract to answer SRC5 `supports_interface` true for the
  matching token interface (`IERC721_ID` or `IERC1155_ID`). This screens accidents only.
- Payout routes by the registry alone: an identifier absent from it is an ERC20 address.

### 3.3 Invariants

**Leaf invariant I** (HA-M2). Every leaf the pool appends is
`H(NOTE, chain₉ ‖ pool₉ ‖ felt_limbs(a) ‖ amount₈ ‖ inner)` with `0 < a < 2^251`, canonical 28-bit
limbs, and `a` either registered or an ERC20 address recorded in `contract_standard`. The append
paths are:

1. `deposit` (ERC20), `on_erc721_received`, `on_erc1155_received` (§5.1): the pool computes `cm`;
2. open-note destination funding: the pool computes `cm` from `dest.token`;
3. P1 settlement outputs: P1 proves them under its public token;
4. V4 outputs: they reuse the private asset of input 0, a proven member (by induction).

Every future path that appends leaves must preserve I.

**Solvency** is per contract ledger (HA-P1). For every asset `a`, the sum of unspent note amounts
of `a` equals the pool's internal holding `held[a]` (§5.1). The contract's own view is checked
per operation, not assumed between them (HA-P14, HA-IC7): each deposit requires the reported
holding to cover `held[a]` (ERC1155 `≥`, ERC721 ownership, ERC20 the exact delta), and each payout
requires its own delta (ERC20 by the transfer's result, ERC1155 the balance drop, ERC721 the new
owner). Each spend conserves a single asset. A malicious contract can
affect only notes of its own identifiers. Distinct contracts at different addresses that share a
ledger (facades) cannot be detected on chain; that is a listing decision for a production pool.

## 4. Relation R0 V4

### 4.1 Public statement

```text
tag₂, chain₉, pool₉, token_out₉, root₉, nf₀₉, nf₁₉, cm₀₉, d₀₉, cm₁₉, d₁₉,
recipient₉, w_amount₈, intent₉, identity₉
```

The V3 layout with `token` replaced by `token_out`: 127 limbs, padded to 128, emitted as 32 QM31
outputs. Statement tags: `R0V4` for the sponge tree and `R0C4` for the compress tree (V3 used
`R0V3`/`R0C3`, `payment.rs:55-58`).

### 4.2 Witness variables

All in `build` (`payment.rs:632`), each created once and shared by every rule that names it
(HA-M1d):

- `pub_ctx`: `chain₉ ‖ pool₉`, guessed words, published.
- `token`: nine guessed words, **private**; the single asset witness.
- `context = pub_ctx ‖ token`, used by all four NOTE hashes.
- Inputs `i ∈ {0, 1}`: `skᵢ`, `rhoᵢ` (`guess_words`, each `nonzero_vector`), `bitsᵢ` (32 position
  bits, `guess_bits`), and amount limbs `amtᵢ`.
- `e₁`: the input-1 enable bit, `guess_bits(…, 1)` (boolean: `e₁·(e₁ − 1) = 0`).
- `x`: the exit bit, `guess_bits(…, 1)`.
- Outputs `j ∈ {0, 1}`: `recvⱼ`, `rhoⱼ` (`guess_words`, each `nonzero_vector`) and amount limbs
  `outⱼ`. There is no output `active` flag.
- `recipient₉`, `withdrawn₈` (`amount_unchecked`), `intent₉`, identity flag and `scope` as V3.

### 4.3 Constraints (normative)

1. **Asset.** `token` is nonzero: `nonzero_vector(token)` (Q2; defense in depth over invariant I).
   Its limbs are not range-checked in the circuit; invariant I and the bridge's check on
   `token_out` at exit cover canonicity.
2. **Input 0 is real.** `amt₀ = amount(amount₀)`, which range-checks the eight limbs and asserts
   the amount nonzero (`payment.rs:538`). Its membership climb produces `cur₀`, which is the
   **published root**.
3. **Input 1 may be a dummy.** `(amt₁, sum₁) = amount_unchecked(amount₁)` (`payment.rs:547`).
   `sum₁ · (1 − e₁) = 0` on that same `sum₁`; the eight limbs are below 2^16, so the sum is below
   2^19 and is zero only if every limb is (HA-M1a). The climb of input 1 produces `cur₁`, and for
   every word `ℓ`: `e₁ · (cur₁,ℓ − cur₀,ℓ) = 0` (HA-M1c). The V3 unconditional equality
   `cur[0] = cur[1]` (`payment.rs:727-729`) is removed. The **same** `amt₁` limbs enter `cm₁`'s
   NOTE hash and `conservation`, and the **same** `e₁` enters both products (HA-M1d).
4. **Nullifiers.** Both are computed as V3 (`H(NF, nkᵢ ‖ cmᵢ ‖ lo ‖ hi)`) and published. A
   dummy's `sk`, `rho` and position are arbitrary.
5. **Outputs.** For both slots: `(outⱼ, _) = amount_unchecked(amountⱼ)` (zero allowed), `recvⱼ` and
   `rhoⱼ` nonzero, `cmⱼ = H(NOTE, context ‖ outⱼ ‖ H(INNER, recvⱼ ‖ rhoⱼ))` published unmasked. The
   V3 `active` machinery (`word·a`, the delivery zeroing and `nonzero_*_if`, `payment.rs:657-666,
   749-756`) is removed (HA-M1e). Delivery limbs are carried as V3.
6. **Conservation.** `conservation([amt₀, amt₁], [out₀, out₁, withdrawn])`, unchanged
   (`payment.rs:571-614`).
7. **Exit reveal.** For each limb `ℓ`: `token_outₗ = x · tokenₗ`. For each amount limb `k`:
   `(1 − x) · withdrawnₖ = 0`. For each intent limb `ℓ`: `(1 − x) · intentₗ = 0`. So a withdrawal
   or an intent forces `x = 1` and `token_out = token`. A voluntary reveal (`x = 1` with neither)
   is rejected by the bridge (§4.5).
8. **Identity.** As V3: `H(IDENTITY, sk₀ ‖ scope)` masked by the identity flag; `sk₀` is the real
   input's key.

The published limbs are `[tag, pub_ctx, token_out, cur₀, nf₀, nf₁, cm₀, d₀, cm₁, d₁, recipient,
withdrawn, intent, identity]`, padded to 128.

### 4.4 Malicious-witness tests (required)

Each must fail to produce a proof, or produce a statement the bridge rejects (HA-M1):

- `e₁ = 0` with `amount₁ ≠ 0`;
- `e₁ = 1` with an input 1 that is not a member under `cur₀`;
- `e₁ = 2`, and `x = 2` with no exit;
- `x = 0` with `w_amount ≠ 0`; `x = 0` with `intent ≠ 0`;
- `amount₀ = 0`;
- input 1 committed under a different asset than input 0 (it cannot share `token`);
- `token = 0`;
- an output under a different asset than the inputs;
- conservation off by one in either direction;
- a voluntary reveal (`x = 1` with no withdrawal and no intent): the bridge rejects it;
- the same leaf used as both inputs: the bridge and the pool reject the duplicate nullifier.

Positive tests, to catch an over-strict implementation (HA-M10): a dummy input 1 on a random
path; a pure transfer that passes the bridge with `token_out = 0`; a single-input spend of an
ERC721 note (amount 1) to one real and one dummy output; an exit of an asset identifier just
below 2^251.

### 4.5 Bridge and account (HA-M4, HA-P3)

The R0 V4 bridge decodes the statement, range-checks every limb as V3 (28-bit felt limbs,
16-bit amount limbs, canonical felts via `felt_from_limbs`), then checks:

- tag is `R0V4` or `R0C4` for the bridge's tree format; the padding limb is zero;
- chain and pool nonzero, and `pool < 2^251` as V3 (the V3 `token ≠ 0` context check is **not**
  carried over);
- **exit rule:** `token_out ≠ 0 ⇔ (w_amount ≠ 0 ∨ intent ≠ 0)`, and `token_out < 2^251`;
- both commitments nonzero, both deliveries nonzero (V3's "delivery ⇔ active" and "some output
  or withdrawal" are not carried over);
- both nullifiers nonzero and distinct;
- `recipient ≠ 0 ⇔ w_amount ≠ 0`, and `recipient < 2^251`;
- identity nonzero ⇒ intent nonzero.

The binding:

```text
binding = Poseidon('TMR0_BIND_V4', chain, pool, token_out, root₉, nf₀₉, nf₁₉, cm₀₉, d₀, cm₁₉, d₁,
                   recipient, w_amount, intent, identity₉)
```

The account's message tag is `'TMPZR0_PAYMENT_V4'`. The bridge, account and verifier adapter are
new classes. The pool repeats the checks it can see as defense in depth.

## 5. Pool

A new reference pool, **M31 pool V2**, with only V4 spend entry points (§5.6).

### 5.1 Deposits

Every deposit requires `amount ≠ 0` (ERC721: exactly 1) and a nonzero `inner`, checks the
contract standard (§3.2) and maintains `held: Map<felt252, u256>` with checked arithmetic.
Hook `data` is exactly 19 words: `inner` parsed with `read_digest` (nine canonical M31 words) and
the ciphertext's ten words passed to `delivery_digest` (HA-M9).

- **ERC20** `deposit(token, amount, inner, ciphertext)`: as today, plus: rejects a registered
  identifier, records `contract_standard[token] = ERC20` on first use, and checks the pool's
  `balance_of` rose by exactly `amount` (HA-P12, aligning with the other paths).
- **ERC1155, push** (HA-P5). The user calls
  `C.safe_transfer_from(user, pool, id, amount, data = inner₉ ‖ ciphertext₁₀)`. No approval to the
  pool is needed. The pool's `on_erc1155_received(operator, from, id, value, data)`:
  - requires the pool is not locked, then takes the lock;
  - takes `C = caller`, computes `a = H(1155, C, id)`, applies the standard and registration rules
    (§3.1–3.2) and the 2^251 bound;
  - requires `0 < value < 2^128` (note amounts are u128; HA-M9) and well-formed `data` with
    nonzero `inner`;
  - requires `balance_of(pool, id) ≥ held[a] + value` (OZ credits before the hook, so the balance
    already includes `value`), then sets `held[a] += value`;
  - appends `cm = commitment(chain, pool, a, value, inner)` with the ciphertext's digest;
  - releases the lock and returns `IERC1155_RECEIVER_ID`.

  `on_erc1155_batch_received` always reverts.
- **ERC721, push.** The user calls `C.safe_transfer_from(user, pool, id, data = inner₉ ‖
  ciphertext₁₀)`. The pool's `on_erc721_received(operator, from, id, data)` mirrors the ERC1155
  hook with `a = H(721, C, id)`, amount 1, and the check `owner_of(id) == pool ∧ held[a] == 0`,
  then `held[a] = 1`; it returns `IERC721_RECEIVER_ID`.
- **SRC5.** The pool answers `supports_interface` true for `ISRC5_ID`, `IERC1155_RECEIVER_ID` and
  `IERC721_RECEIVER_ID`, and false for `ISRC6_ID`.
- **Unsolicited transfers** (HA-P11). A safe transfer with malformed `data` reverts. A plain
  `transfer_from` of an ERC721, or a hook-less ERC1155 mint, cannot be prevented: the token is
  held without a note, `held[a]` is unchanged, and for ERC721 the id can no longer be deposited.
  It is lost; there is no rescue path (a rescue would give the owner power over pool holdings).

### 5.2 V4 spends

`apply_spend(spend, proof)` and `apply_spend_with_invoke(spend, intent, proof)` take the V4
`Spend` (`asset: felt252` in place of `token`). Under the lock, the pool checks:

- chain, pool, the binding (`TMR0_BIND_V4`) and the verifier verdict;
- the root is in the pool's `root_history`;
- both nullifiers nonzero, distinct and absent from the pool's single `nullifiers` map, then
  marks both (dummies included) (HA-M8);
- both commitments nonzero; both ciphertexts present and matching their delivery digests; both
  outputs appended (dummies included);
- the exit rule `asset ≠ 0 ⇔ (w_amount ≠ 0 ∨ intent ≠ 0)`;
- `apply_spend` requires `intent = 0` and no identity; `apply_spend_with_invoke` as V3, plus
  `asset` must be an ERC20 (not registered) and every destination token an ERC20 recorded (or
  recordable) as such. `hash_intent` binds `asset` in the token position. Each funded
  destination adds its measured amount to `held[dest.token]`.

Effects order: for `apply_spend`, nullifiers, appends, then `pay_out`; for
`apply_spend_with_invoke`, as V3, nullifiers, the destination checks, the budget's `pay_out`, the
adapter call, the pulls, then all appends together (HA-IC7).

### 5.3 Payout by standard

`pay_out(asset, recipient, amount)` is the single payout path for V4 withdrawals, open-note
budgets and P1 settlements. It requires `recipient ≠ 0` and `recipient ≠ pool` for every caller
(HA-P6), and decrements `held[asset]` with a checked subtraction **before** the external call
(HA-P14).

- ERC20 (not registered): `transfer(recipient, amount)`.
- ERC1155: reads the pool's balance, calls `safe_transfer_from(pool, recipient, id, amount, [])`,
  requires the balance fell by exactly `amount`. The recipient's receiver check applies: a
  recipient without SRC5 support for `IERC1155_RECEIVER_ID` or `ISRC6_ID` makes the payout revert
  (HA-P7). The recipient's hook runs under the pool's lock.
- ERC721: requires `amount == 1`; `transfer_from(pool, recipient, id)` (no recipient hook);
  requires `owner_of(id) == recipient`.

`Withdrawn { asset, recipient, amount }` carries the identifier; standard, contract and id come
from `AssetRegistered`.

### 5.4 Policy notes with NFTs

P1 is unchanged, so its token stays public at settlement. A policy note may hold an ERC721 or
ERC1155 asset: its deposit hook `data` carries the policy `inner`. Its withdrawal is paid by
`pay_out`.

- For an ERC721 note (amount 1), P1's `1 ≤ x ≤ amount` forces `x = 1`, so a split degenerates to
  "all to out₀". No pool rule is needed; wallets must refuse to create split outcomes for ERC721
  notes.
- An ERC1155 outcome paying a withdrawal inherits the recipient's liveness (HA-P7): if the fixed
  recipient cannot receive ERC1155, that outcome never settles, and only the refund remains. The
  policy acceptance checklist (`policy-note-spec.md` §9.3) gains this check.

### 5.5 Supported token interfaces

The pool calls snake_case `transfer`, `transfer_from`, `balance_of`, `owner_of`,
`safe_transfer_from` and `supports_interface`, with the interface ids of OpenZeppelin Cairo ≥ 0.20
(verified identical in 0.20.0 and `openzeppelin_interfaces` 2.2.0). CamelCase-only (Cairo 0 era)
collections revert at deposit. The pool exposes no camelCase receiver hooks (HA-P12).

The push hooks assume, of a token contract (HA-P15): it credits the pool before calling the hook
(as OpenZeppelin does); its views (`balance_of`, `owner_of`) may be read from inside the hook,
mid-transfer; a mint to the pool with acceptance check (`from = 0`) creates a note like any other
safe transfer; and it registers its SRC5 token interface id. A contract that departs from any of
these fails safe: the deposit reverts, or the tokens are held without a note.

### 5.6 Deployment and migration (HA-P2)

Commitments bind the pool address, and the reference pool has no upgrade path. Adding one would
let its owner replace the code holding all funds. So:

- V4 ships as a **fresh deployment** (M31 pool V2) whose only spend entry points are V4. V3 is
  never live in the same pool, so there is no coexistence window, no contract-standard backfill,
  and one nullifier set and root history by construction.
- Notes in the existing reference pool stay there and remain spendable under V3; users move by a
  public withdrawal and a new deposit. The existing pools hold only Sepolia test tokens.
- A production pool that wants in-place upgrades must specify its upgrade authority explicitly;
  this design does not add one.

### 5.7 Entry points of M31 pool V2 (HA-P16)

- `deposit` (ERC20), `on_erc1155_received`, `on_erc1155_batch_received` (always reverts),
  `on_erc721_received`, `supports_interface`;
- `apply_spend`, `apply_spend_with_invoke` (V4 only);
- `apply_policy_spend` (P1, unchanged relation), with its own P1 verifier adapter deployed for
  the new pool address; payouts through `pay_out`;
- owner: `set_verifier`, `set_policy_verifier`, `set_shadow_class`;
- views: `get_nullifier_spent`, `get_delivery_digest`, `get_verifier`, `get_policy_verifier`,
  `is_shadow_class`, `get_asset`, `asset_id`, `get_contract_standard`, `get_held`, and the tree's
  views.

**M31 pool V3** (`bench/m31-pool/cairo/src/pool_v3.cairo`; `docs/account-bound-note-spec.md` §8)
settles R0 V5 and P1. Against V2:

- `apply_spend` and `apply_spend_with_invoke` take R0 V5 spends: the V4 fields plus a public
  `valid_until` in the binding (`TMR0_BIND_V5`). A bound spend's account is checked inside the
  statement account's proven execution and never reaches the chain. A spend is accepted while
  `block ≤ valid_until`, `valid_until` is a nonzero multiple of `Q`, and `valid_until ≤ block + E
  + Q`;
- roots by supersession: the current root is always accepted, and a replaced root for `W` blocks
  after it was replaced (`get_root_superseded_at`), with `W ≥ E + Q` checked by the constructor;
- the owner levers are timelocked: `propose(key, value)`, `apply(key)` within `[eta, eta + T]`
  (then the proposal lapses), and `cancel(key)`, where the key is `'R0'` or `'P1'` (a verifier)
  or a shadow class hash (allowed or not); `initialize(r0, p1, shadow_classes)` runs once, before
  any deposit; ownership moves in two steps (`transfer_ownership`, `accept_ownership`);
- views: `get_verifier(kind)`, `get_proposal(key)`, `get_parameters` (`E`, `Q`, `W`, `T`),
  `get_owner`, `get_pending_owner`, `is_shadow_class`, `get_nullifier_spent`,
  `get_delivery_digest`, `get_asset`, `get_contract_standard`, `get_held`, and the tree's views;
  no `asset_id` view;
- no fees and no gating: anyone may call every entry point but the owner's, and the service is
  paid off chain (account-bound spec §7.2).

## 6. Wallet (normative)

- **Dummy values** are nine words each sampled uniformly in `[0, p)` (canonical M31, nonzero
  vector), like real secrets (HA-M10).
- **Dummy inputs** (HA-M6). Input 1's `sk`, `rho` and position are drawn fresh from a CSPRNG for
  every proof, independent of seed-derived counters, and never reused, including when a spend is
  re-proved after a failed submission. The wallet stores nothing for them. **Amendment
  (`docs/sdk-spec.md` §3.3, SDK-M10, SDK-M17):** a note's dummy input is sticky. The first time a
  statement naming the note as a single real input leaves the wallet (to a prover server or the
  chain), its dummy witness becomes the note's companion and is reused by every later
  single-input statement naming that note until the note is spent, since the real nullifier may
  then be seen again and a fresh dummy beside it would single it out. A companion is never used
  with another note.
- **Dummy outputs** (HA-P9, HA-M7d). A zero-value note to a fresh CSPRNG receiver and `rho`. Its
  ciphertext MUST be produced by the same libsodium `crypto_box_seal` call as real outputs, with a
  freshly generated X25519 key pair and a CSPRNG 256-byte plaintext. 304 random bytes are
  distinguishable (the ephemeral key's top bit is clear). A wallet test checks this layout for
  real and dummy outputs.
- **Receiving** (HA-M5). Accept a note only after recomputing
  `cm = H(NOTE, chain ‖ pool ‖ a ‖ amount ‖ inner)` from the decrypted fields and matching the leaf
  at its published index. For a registered `a`, also recompute its identifier from the
  `AssetRegistered` event read from the pool's address.
- **Assets and metadata** (HA-P8.3, HA-P10). Sync `AssetRegistered` in bulk or from a snapshot,
  never per asset. Read token metadata (`name`, decimals, `token_uri`) and display balances
  through bulk or cached queries, not per-note lookups, since each targeted query reveals
  interest to the RPC provider. `AssetRegistered` can grow through spam registrations (one real
  deposit each); wallets sync it lazily.
- **ERC1155 recipients** (HA-P7). Before building a withdrawal or accepting a policy opening that
  pays ERC1155, check that the recipient supports SRC5 and `IERC1155_RECEIVER_ID` or `ISRC6_ID`.
  Relayers and executors simulate before submitting; a recipient hook can revert or burn gas.
- **Simulate every exit** (HA-M11). A reverted withdrawal or invoke still publishes its calldata,
  including the asset. Wallets and relayers simulate every exit before submitting.
- **ERC721 receipts.** A received ERC721 note has amount 1; spending it uses a dummy input 1.

## 7. Privacy analysis

**An in-pool V4 transfer publishes:** the root, two nullifiers, two output commitments with their
ciphertexts and digests, and zeros for `asset`, the withdrawal, the intent and the identity.
Plus transaction metadata: sender, fee payer and resource bounds, timing, and the base block of
the proof facts.

**Hidden from observers and from the wrapping server:** the asset, whether there were one or two
real inputs, and how many real outputs there were. These are hidden only as far as the compact
client proof is zero-knowledge; that argument is still being qualified (HA-M7a). V4 adds three
private facts to it (`token`, `e₁`, `x`) and no public ones.

**The anonymity set** of a transfer's input is every leaf at or before the spend's root, weighted
by what is publicly known about each leaf (HA-P8.1, HA-M7c):

- deposits, open-note destinations and P1 outputs have public assets; only V4 transfer outputs
  hide theirs. Asset privacy improves as V4 outputs accumulate;
- dummy outputs count as leaves but are never spent;
- the root's age bounds input 0's age and can fingerprint a wallet's sync policy;
- anyone holding a note's `nk` (for example a full viewer) can tell that note's nullifier from a
  dummy, and so learn whether the spend had one real input or two (HA-M7b).

**Still public:**

- deposits (asset, amount, depositor) and withdrawals (asset, amount, recipient);
- open-note executions (asset, budget, adapter, calldata, destinations), including collect-only
  invokes;
- policy settlements, as today, including the token;
- the set of NFTs the pool holds at every block (`owner_of`, `balance_of`), and so each NFT's
  time in the pool; for ERC721, a deposit and a later withdrawal of the same id are linked by
  definition;
- RPC activity: nullifier-spent and delivery-digest polling, and any targeted metadata reads;
- a reverted exit's calldata, including its asset (HA-M11).

**Wallet fingerprints** (HA-P8.5). Any implementation-dependent choice partitions the set by
wallet: how dummies are built, root selection, fee settings. §6 fixes the dummy construction;
wallets should converge on root selection and fee policy.

**Analytics.** Public per asset: the pool's holdings (its `balance_of` / `owner_of`, and `held[a]`),
and each flow: deposits, withdrawals, open-note budgets and fundings, P1 payouts. Holdings are not
simply deposits minus withdrawals, because the other flows and unsolicited transfers also move
them (HA-P8.4). Total in-pool transfer count remains public. Lost: the per-asset count of in-pool
transfers (per-asset volume was already hidden).

**Costs.** Uniform shape adds, for spends with fewer than two real outputs, one or two extra
leaves and ciphertexts, and for single-input spends one extra nullifier write. To be measured.

## 8. Review resolutions

| Finding | Resolution |
| --- | --- |
| HA-M1 | §4.2–4.4: variables, gadgets and shared witnesses pinned; malicious-witness tests listed |
| HA-M2 | §3.3 invariant I with its append paths; `token ≠ 0` constrained (§4.3.1) |
| HA-M3, HA-P4 | §3.1: identifiers below 2^251; V4 fields typed `asset: felt252` |
| HA-M4, HA-P3 | §4.5: V4 bridge checks, exit rule in the bridge, tags named |
| HA-M5 | §6 receiving rule |
| HA-M6, HA-P9 | §6 dummy construction |
| HA-M7, HA-P8 | §7 rewritten |
| HA-M8 | §5.2 single nullifier set and root history; §5.6 fresh pool |
| HA-P1 | §3.2 contract-standard map and SRC5 screening; §3.3 solvency per contract ledger |
| HA-P2 | §5.6 fresh deployment, V3 never coexists |
| HA-P5 | §5.1 push deposits for ERC1155 and ERC721, no approvals; hook rules specified |
| HA-P6 | §5.3 `recipient ≠ pool` for every payout |
| HA-P7 | §5.3, §5.4, §6 ERC1155 recipient liveness |
| HA-P10 | §3.1 guards, §3.2 views, §6 registry sync |
| HA-P11 | §5.1 unsolicited transfers are lost; no rescue path |
| HA-P12 | §5.1 ERC20 balance delta; §5.5 supported ABI |
| Q1 | ERC20 keeps the raw address (§3.1) |
| Q2 | `token ≠ 0` constrained (§4.3.1) |
| Q3 | No pool rule; wallets refuse ERC721 splits (§5.4) |
| Q8 | Fresh deployment (§5.6) |
| HA-M9 | §5.1 `value < 2^128`, `data` parsing, checked `held` |
| HA-M10 | §4.4 added tests; §4.5 `pool < 2^251`; §6 dummy sampling |
| HA-M11 | §6 simulate every exit; §7 reverted exits |
| HA-P13 | §3.2 hybrids: first standard wins, a listing decision |
| HA-P14 | §3.3 restated claim; §5.1 u256 `held`; §5.3 checked decrement before the call |
| HA-P15 | §5.5 hook assumptions |
| HA-P16 | §5.7 entry points, including P1 |
| HA-IC1–IC7 | Implementation review (`hidden-asset-impl-contract-review.md`): added tests, wallet registry resolution and dummy sampling, a size gate, destination checks before external effects, a nonzero verifier at deployment; §3.3 and §5.2 wording |
