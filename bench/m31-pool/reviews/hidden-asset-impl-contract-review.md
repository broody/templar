# Hidden-asset spends and NFT notes: implementation protocol and contract review

Independent reviewer; I did not write the implementation. I also wrote the design reviews
(`hidden-asset-design-protocol-review.md`, including the revision-2 re-review).

Date 2026-09-24, branch `feat/hidden-assets` at `daf4cfe`. The review is against
`docs/hidden-asset-spec.md` revision 3, §3–§7. I modified no code or docs, only this file.

**Evidence labels:**
- **D**: demonstrated by a test I ran.
- **R**: reasoned from the code.
- **V**: verified against third-party source, here the OpenZeppelin Cairo 3.0.0 components the
  test tokens embed.

## Scope

**Pool** (`bench/m31-pool/cairo/src`):
- `pool_v2.cairo`, all 612 lines;
- `assets.cairo`, `spend4.cairo`;
- the `hash_intent_of` refactor in `open_note.cairo:75-116` (the V3 `hash_intent` now delegates to
  it with byte-identical input);
- `test_nft.cairo`, `tests/test_pool_v2.cairo`, `tests/test_hidden_asset_e2e.cairo`,
  `tests/hidden_asset_vectors.cairo`.

**Bridge and account:**
- `client-port/cairo-r4/{bridge,account}/src/lib.cairo`;
- the `tmpzr4` entry in `build_bridge_arith.py`;
- `validate_bridge_r4.py` (`binding`, `args`);
- `capture_os.py` R4 mode;
- the evidence in `results/r4-bridge/`. The template hashes in `bridge-build-record.json` match the
  current `cairo-r4` sources byte for byte.
  - The circuit source `payment4.rs` changed after that evidence, in `32e622b`.
  - That diff touches only the native reference (`statement` versus `bridge_checks`) and tests,
    not `build`. The e2e driver also re-asserts that the proof's circuit hash equals the bridge
    pin (`hidden_asset_e2e.py:44-45`).

**Wallet side:**
- `hidden_asset.py`, `hidden_asset_e2e.py`;
- `examples/wallet.rs` `prove4`, `fresh_digest` and `root`;
- `payment4.rs` `statement_limbs` and `bridge_checks`, for the encodings only.

**Evidence:** `bench/m31-pool/results/hidden-asset-e2e.json`.

**What I ran** (read-only; the Rust build output went to `~/.local/share/templar/runs/ha-impl-review`):
- `snforge test` in `bench/m31-pool/cairo` (scarb 2.18.0 / snforge 0.63.0): **218 passed, 0
  failed**. That covers 30 `test_pool_v2` tests and 6 real-proof `test_hidden_asset_e2e` tests.
  **D**
- `scarb build`: **CASM bytecode of `M31PoolV2` is 76,793 felts** (V3 `M31Pool` is 69,932), and its
  Sierra program is 37,480 felts. **D** The account's 61,395 CASM felts are taken from
  `bridge-build-record.json`, whose sources hash-match. I did not rebuild the bridge.
- `cargo test --release --features tamper --test payment_r4 --test payment_r4_malicious`
  (nightly-2026-01-15): result under "Rust tests" at the end of this file.

I did not run the large-proof end to end.

## Verdict

**GO.** The pool, bridge, account and wallet helpers implement §3–§7 as specified. Every design
finding HA-P1 to HA-P16 is carried into code or documentation (table below). I found no
soundness, solvency or privacy defect.

**Encodings.** They match across all layers:
- the Rust statement limbs;
- the Cairo bridge decoding;
- the bridge `binding`, the pool `spend4::compute_binding` and the Python
  `hidden_asset.binding`/`validate_bridge_r4.binding`, all in the same field order;
- `encode_spend`, which matches `Spend` Serde.

The real-proof test settles all four statements against the adapter's message hash and ends at
the wallets' root (**D**).

**Findings.** Seven, all Low or Info. They are test coverage for paths the code implements but no
test executes, wallet conformance to §6, and evidence hygiene. They should be closed before the
code is treated as reference, but none blocks it.

## Conformance to the design findings

| ID | Status | Where in code |
|---|---|---|
| HA-P1 contract standards | Done | `record_standard` (`pool_v2.cairo:488-495`) on ERC20 `deposit` (:184), open-note destinations (:262) and both hooks through `register` (:499). SRC5 screening on first registration (:508-509). Tests: `nft_contract_as_erc20_rejected`, `erc20_contract_as_nft_rejected`, `one_contract_two_nft_standards_rejected` (**D**). |
| HA-P2 fresh deployment | Done | New contract `M31PoolV2`; no V3 entry point and no upgrade path (grep). |
| HA-P3 bridge checks | Done | `cairo-r4/bridge/src/lib.cairo:120-143` implements every §4.5 rule. Tag `R0V4`/`R0C4` is pinned from the manifest, and the account tag is `'TMPZR0_PAYMENT_V4'` (`account:37`). 57/57 validation cases, including 5 real proofs the circuit admits but the bridge must reject. |
| HA-P4 range and types | Done | `below_bound` at registration (:504) and at spends (:527); `Spend.asset: felt252`; `Withdrawn.asset`. |
| HA-P5 push deposits | Done | Details under "Checks found sound". |
| HA-P6 `recipient ≠ pool` | Done | `pay_out` (:557), for every caller. **D** `withdrawal_to_the_pool_rejected`. |
| HA-P7 recipient liveness | Done (pool) | **D** `erc1155_payout_to_recipient_without_src5_reverts`. The wallet-side SRC5 pre-check has no code in `hidden_asset.py` (HA-IC3). |
| HA-P8 privacy text | Done (spec) | Nothing to implement. |
| HA-P9 dummy ciphertexts | Code done, test missing | `hidden_asset.dummy_output` (:34-39) uses a real `SealedBox`. The required layout test is absent (HA-IC3). |
| HA-P10 guards and views | Done | `ASSET_REGISTERED` (:183, :261); `ASSET_COLLISION` (:507); `get_asset`, `asset_id`, `get_contract_standard`, `get_held`. |
| HA-P11 unsolicited | Done | **D** `erc721_unsolicited_plain_transfer_is_lost`, `erc1155_hookless_mint_does_not_block_deposits`. |
| HA-P12 ERC20 delta, ABI | Done | `DEPOSIT_AMOUNT` (:190), but untested (HA-IC2). |
| HA-P13 hybrids | Done (spec) | Nothing to implement. |
| HA-P14 `held` | Done, test partial | `Map<felt252, u256>`, checked add and subtract, decrement before the external call (:558-560). The cross-path invariant test is missing (HA-IC1). |
| HA-P15 hook assumptions | Done | Comments at :420 and :442-444; spec §5.5. |
| HA-P16 entry points | Done | `IM31PoolV2`, `IAssetReceiver` and the tree views match §5.7 exactly. |

## Findings

### HA-IC1: Low. The V4 open-note execution path and the cross-path `held` invariant have no success-path test

**Location:** `pool_v2.cairo:210-278`; `tests/test_pool_v2.cairo:426-441` (the only invoke test).
The design finding was HA-P14 item 4.

**Problem.** `apply_spend_with_invoke` is the only V2 path that does all of the following, and no
test drives it to success (unit or real-proof):
- pays a budget through `pay_out`;
- records a new ERC20 standard for an adapter-returned token;
- credits `held[dest.token]` from a measured balance delta;
- emits `OpenNoteFunded` at `first + created + i` with `created = 2` (always, in V4).

The single invoke test, `execution_with_nft_asset_rejected`, stops at `EXECUTION_ASSET`. The
bridge's `invoke` and `shadow` shapes are validated only standalone.

The invariant `held[a] = Σ unspent note amounts of a`, which the spec now makes the solvency
statement (§3.3), is asserted only after individual steps: ERC20 deposit plus withdrawal, one
ERC1155 payout, and the e2e end state. It is never asserted after the invoke path, P1 splits or a
mixed sequence.

**Failure scenario (R).** A later edit reorders the budget `pay_out` after `append_notes`, drops
`held.write` at :267, or changes `created`. Every existing test still passes, and the pool either
under-credits `held` (later withdrawals fail with `HELD_UNDERFLOW`) or over-credits it (the
backstop against an unbacked ERC20 withdrawal is lost). `OpenNoteFunded.index` could also point
at the wrong leaf, and wallets locate funded notes by it.

**Required change.** Add a `test_pool_v2` success test with `MockSwapAdapter`:
- ERC20 budget to the adapter, and a destination in a second, not-yet-recorded ERC20;
- assert `get_contract_standard(dest) == ERC20`, `held` on both tokens, and the `OpenNoteFunded`
  index against `get_leaf_count`.

Add one test that runs deposit (all three standards), a transfer, an invoke, a P1 settlement and
a withdrawal on one pool, and checks `held[a]` against the ledger after each step.

### HA-IC2: Low. Implemented rejection branches that no test reaches

**Location:** `pool_v2.cairo`.

The following checks exist in code, but nothing in the suite reaches them. Each is a single
assert that a refactor could drop silently.

| Branch | Line | What would show it |
|---|---|---|
| ERC721 `NOT_RECEIVED` (direct hook call without a transfer) | :422 | Mirror `erc1155_hook_without_transfer_rejected` with `on_erc721_received` from the NFT contract's address. |
| `ALREADY_HELD` | :423 | A direct `on_erc721_received` for a deposited id, with the caller cheated to the NFT contract. |
| `DEPOSIT_AMOUNT` (fee-on-transfer ERC20) | :190 | A fee-taking test ERC20. |
| `ASSET_COLLISION` | :507 | Use `deploy_at` to place a contract at `asset_id(721, nft, id)`, then push that id. |
| `ASSET_RANGE` / `below_bound` | :504, :527 | A unit test of `below_bound(2^251 − 1)` and `below_bound(2^251)`; a spend with `asset = 2^251`. |
| Open-note destination `ASSET_REGISTERED` / `STANDARD_MISMATCH` | :261-262 | An adapter returning an NFT contract or identifier. |
| ERC20 `deposit` of a not-yet-recorded OZ ERC721 | :187-189 | Rejected only because ERC721 `transfer_from` returns unit and `IERC20Dispatcher`'s bool deserialization panics (**R**, **V**). |

Also, `both_outputs_required` and `both_ciphertexts_required` (`test_pool_v2.cairo:168-184`) call
`spend4::compute_binding` directly and never reach the pool. The pool does call the same
function (:528), so the rule holds, but the tests do not show the pool rejecting.

**Required change.** Add the tests above. For the last two, submit through `apply_spend`.

### HA-IC3: Low. Wallet helpers fall short of §6 in three places

**Location:** `hidden_asset.py:34-61`; `policy_note.py:23-24`.

- **(a) No layout test (HA-P9).** The spec makes the test normative ("a wallet test checks this
  layout for real and dummy outputs"). No such test exists (grep over `bench/m31-pool`). The code
  is right: `dummy_output` uses `SealedBox(PublicKey).encrypt`. Only the regression guard is
  missing.
- **(b) The receiving rule is incomplete (HA-M5).** `find_notes` recomputes `cm` from the
  decrypted asset, which is the part that matters for soundness. It does not do the second half:
  for a registered `a`, "recompute its identifier from the `AssetRegistered` event". A note of an
  unregistered and unrecorded `a` cannot exist (invariant I). So this is a display and UX gap,
  not a loss. The same gap applies to the HA-P7 recipient SRC5 pre-check and to "simulate every
  exit" (HA-M11), neither of which has helper code.
- **(c) Dummy distribution differs from HA-M10.** `pn.random_digest` draws each word in `[1, p)`,
  while §6 (HA-M10) says `[0, p)` with a nonzero vector. The Rust `fresh_digest`
  (`wallet.rs:206-213`) conforms. The Python helper supplies dummy-output receivers and `rho` and
  real-output `rho`. These values are private: they enter commitments only, so the difference is
  not observable on chain. It is a conformance gap only.

**Required change.**
- Add the layout test. Check that bit 255 of the 32-byte ephemeral key is clear in real and dummy
  boxes, plus a statistical check that a 304-random-byte blob fails it.
- Add an asset-resolution step to `find_notes`, or document that it belongs to the production
  wallet.
- Make `random_digest` match HA-M10, or amend the spec to `[1, p)`. Either is fine, but the two
  must agree.

### HA-IC4: Info. The committed e2e evidence is not what the committed driver writes

**Location:** `results/hidden-asset-e2e.json`; `hidden_asset_e2e.py:54, 61-62, 187`.

The driver writes the following:
- `bridge: {passed, steps}`;
- `os: {steps, seconds, exact_message}`;
- `settlement` as a list of `[PASS]` and `GAS` log lines.

The JSON instead has these:
- `bridge: {cases, passed, steps}`;
- `os` without `seconds`;
- a `settlement_gas` dictionary.

So the file was post-processed or produced by an uncommitted variant of the driver.

Separately, the two pure transfers cost 55.19M and 53.66M L2 gas. The difference comes from the
tree position (leaf count 3 versus 5 at `insert_two`), not from the asset. The pool's transfer
path has no asset-dependent branch (**R**). The file does not say so, and a reader could take it
as an asset-dependent gas leak.

**Required change.**
- Commit the driver that produced the file, or regenerate the file.
- Add a one-line note that gas differences between transfers reflect tree position only. Better,
  add a test that settles an ERC20 and an NFT transfer at the same leaf parity and asserts equal
  gas, within syscall noise.

### HA-IC5: Info. Pool V2 is at 93.7% of the CASM limit

**Location:** `M31PoolV2` class.

- CASM bytecode is 76,793 felts against the 81,920-felt limit, leaving 5,127 felts (6.3%) of
  headroom. **D**
- The V3 pool is 69,932. V2 adds about 6.9k felts for the hooks, registry, `pay_out` and SRC5.
- The account is 61,395 (75%).

Any further fix or feature risks crossing the limit, and the failure appears only at declaration.
`compact_perm` halves the permutation's share if needed.

Small savings in the hot path:
- `delivery_digest` is computed twice per output, once in `spend4::compute_binding`
  (`spend4.cairo:117`) and again in `outputs()` (`pool_v2.cairo:548`). Passing the digests through
  saves two 12-felt Poseidon calls per spend.
- The `BAD_RECIPIENT` assert at :240 is redundant with `verify_spend`'s `BAD_WITHDRAWAL` (:523).

**Required change.** Add a size check that fails the build when CASM exceeds, for example,
80,000. Optionally, deduplicate the digest.

### HA-IC6: Info. Deployment assumptions to confirm on Sepolia

**Location:** `pool_v2.cairo:164-169, 507`.

1. **`get_class_hash_at_syscall` on an undeployed address.** Registration relies on it returning
   0 (`ASSET_COLLISION`). The spec asked for confirmation, but it is confirmed only under snforge's
   blockifier (every NFT registration in the suite passes). Confirm it on the target network at
   the first NFT deposit.
2. **The constructor accepts a zero `verifier`.** It is inherited from V3, and `set_verifier`
   rejects zero. A misdeploy fails closed, since the call to address 0 reverts, but with a
   confusing error. Consider `ZERO_VERIFIER` in the constructor.
3. **Nothing on chain ties the `verifier` adapter to the V4 account tag and class.** Only the
   deployment configuration does. A misconfigured adapter still cannot accept a V3 message,
   because the binding tags `TMR0_BIND_V3` and `TMR0_BIND_V4` differ. Record the expected tuple
   `(statement class, 'TMPZR0_PAYMENT_V4')` in the deployment checklist.

### HA-IC7: Info. Spec wording to align with the code

**Location:** spec §5.2 last line and §3.3; `pool_v2.cairo:236-278`.

- §5.2 says the effects order is "nullifiers, appends, then `pay_out`". That holds for
  `apply_spend` and P1. `apply_spend_with_invoke` pays the budget *before* the adapter call and
  the appends, as V3 does, because the adapter needs the budget. Everything stays under the lock,
  and `held` is decremented first, so this is sound. State the exception.
- §3.3 says `held[a] ≤ what the contract reports` "is checked at every deposit and payout". The
  ERC20 payout path checks only `transfer`'s return value, not the balance, and the ERC1155
  payout checks the delta, not `held ≤ balance` afterwards. Say "each deposit checks it, each
  payout checks its own delta or ownership".

## Checks found sound

- **Lock and hooks (R, D).**
  - Both hooks call `start()` first and clear the lock last (`:416`, `:427`, `:435`, `:451`).
  - Every pool-initiated external call runs under the lock, so any hook reached from a payout,
    adapter, controller or ERC20 pull reverts with `REENTRANCY`. **D** for a payout hook
    re-entering `deposit`.
  - A panic anywhere reverts the whole transaction.
  - The batch hook always panics. **D** for a length-2 batch; OZ routes length 1 to the single
    hook (**V**).
- **Caller trust and receipt checks (R, D).**
  - The identifier binds `get_caller_address()`.
  - The ERC1155 check is cumulative: `balance ≥ held + value`, written as the new `held`.
  - The ERC721 check is `owner_of == pool ∧ held == 0`.
  - So a direct hook call without a transfer fails (**D**, ERC1155), and a hook-less surplus is
    never credited while not blocking the id (**D**).
  - A double hook call by a buggy contract needs a real surplus.
  - OZ credits before the hook (**V**: `erc1155.cairo:607-619`, `erc721.cairo:154-166`).
- **Registration (R, D).**
  - The standard is recorded before the identifier.
  - The registry is written once, with `AssetRegistered`.
  - The following all run only on first registration: the `2^251` bound, the class hash at the
    identifier, and SRC5 on the claimed token interface.
  - The Python `asset_id` equals the Cairo one: the real-proof test finds `NFT_ASSET` and
    `MULTI_ASSET` registered at the driver's values.
- **Solvency and `held` (R, D).**
  - Every append path preserves invariant I:
    - ERC20 `deposit` records the standard and checks the exact delta;
    - the hooks register and check receipt;
    - open-note funding records ERC20 and checks the delta;
    - P1 and V4 outputs inherit the asset of a proven member.
  - `held` moves only at deposits, funded destinations (+) and `pay_out` (−), all with checked
    arithmetic.
  - `pay_out` for an identifier that is neither registered nor recorded hits `HELD_UNDERFLOW`
    before any call. So `held` is also a backstop against paying out an asset the pool never
    received.
  - **D** `withdrawal_beyond_holdings_rejected`, `erc721_amount_two_rejected`, and the e2e end
    state (`held` of ERC20 1000, NFT 0, ERC1155 0).
- **`pay_out` (R, D).**
  - The recipient must be neither 0 nor the pool.
  - `held` is decremented before the call.
  - Routing is by the registry.
  - ERC1155 uses a safe transfer with an exact before/after delta.
  - ERC721 requires amount 1, uses `transfer_from`, then checks `owner_of == recipient`.
  - `Withdrawn` carries the identifier.
  - It is the only payout call site: :205, :238 and :339.
  - **D**: ERC1155 to an account-like recipient; the NFT escrow release through P1; the real
    ERC1155 P1 release and the real NFT withdrawal.
- **Exit rule and uniform shape at pool and bridge (R, D).**
  - Pool (:523-527), bridge (:136-141) and `bridge_checks` in Rust are identical rules.
  - Both outputs are required nonzero, with ciphertexts (`compute_binding`, `append_notes`
    `ZERO_DELIVERY`), and both nullifiers are marked spent, dummies included (**D**).
  - The in-pool transfer path has no asset-dependent branch.
  - `Spend.asset` is bound (**D** `asset_is_bound`, `hidden_asset_real_revealed_transfer_rejected`).
  - Redirecting a real NFT withdrawal fails `BAD_BINDING` (**D**).
- **Encodings (R, D).** One binding field order across the bridge `binding`, `spend4`,
  `hidden_asset.binding` and `validate_bridge_r4.binding`:

  ```text
  TMR0_BIND_V4, chain, pool, token_out, root₉, nf₀₉, nf₁₉, cm₀₉, d₀, cm₁₉, d₁,
  recipient, amount, intent, identity₉
  ```

  - `encode_spend` matches the Serde of `Spend` (`Withdrawal {recipient, amount}` and spans with
    length prefixes).
  - The adapter's message is `Poseidon(statement, 0, 5, class, 'TMPZR0_PAYMENT_V4', chain, pool,
    binding)`, and the driver asserts that `facts[8]` equals it for each real proof before
    settling.
- **Dummy input (R).** `prove4` draws the dummy's `sk`, `rho`, position and siblings fresh from
  `OsRng` for every proof, never from the seed (`wallet.rs:206-254`), and the native
  `bridge_checks` runs before proving.
- **P1 unchanged (R, D).**
  - `apply_policy_spend` matches the V3 logic except that it pays through `pay_out`.
  - NFT identifiers fit its `ContractAddress` token field (`< 2^251`).
  - The V3 pool's tests all still pass after the `hash_intent_of` refactor.

## Rust tests

`cargo test --release --features tamper --test payment_r4 --test payment_r4_malicious` with `RUSTUP_TOOLCHAIN=nightly-2026-01-15` and `CARGO_TARGET_DIR` under `~/.local/share/templar/runs/ha-impl-review`: **`payment_r4` 12 passed, `payment_r4_malicious` 7 passed, 0 failed** (**D**).

`payment_r4_malicious` requires the `tamper` feature; without it, cargo refuses to build that target.

`payment_r4` includes `bridge_only_rules`, which shows the circuit admits each statement the bridge must reject. It also includes `asset_just_below_2_251` and `v4_spends_v3_notes`, which cover the encodings the pool and bridge depend on.
