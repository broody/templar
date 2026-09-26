# Account-bound SDK key code (P4): math review

- Reviewer: independent Math Reviewer (did not write the code)
- Date: 2026-09-26
- Under review: the uncommitted changes on `feat/account-bound`:
  - `sdk/core/src/{keys,snip12,spend,store}.rs`;
  - the WASM changes;
  - `sdk/core/tests/{spend_v5,spend_bound,vectors_keys}.rs`;
  - `sdk/vectors/{keys.json,check_keys.py}`;
  - the bench wallet's `keys5`.
- Against: `docs/account-bound-note-spec.md` §3, §4.1, §5.2, §5.3, §6 (with `kstoreid_w`) and
  §8.2; baseline `docs/sdk-spec.md` §3.

## 1. Verdict

**CONDITIONAL GO.**

The key derivations, the SNIP-12 V5 message, the V5 binding and the V5 statement checks are
correct and match the spec, the Cairo bridge and starknet.js. Nothing lets a bound wallet produce
an ordinary receiver, reuse a Templar key, or prove a statement the bridge rejects.

**Condition (AB-SM1):** before bound wallets are exposed beyond the core (WASM or TS), the core
must tie each pool to its relation. It must refuse bound keys and addresses for a pool without
bound mode, and derive `Version` from the pool. Today a bound address can be made for pool V2,
and value sent to it can never be spent.

## 2. What is correct (checked by reading, tests and the independent reference)

- **Seed and origin rule (§6.1).**
  - `BoundSeed` is 28 bytes with a 21-word BIP-39 backup (224 bits plus a 7-bit checksum).
  - `BoundSeed::from_mnemonic` accepts 21 words only, and `Seed::from_mnemonic` accepts 24 only.
    Both directions are tested.
  - `wallet(A)` requires `0 < A < 2^251`, and `Account::bound` rejects a zero account.
- **Keys (§6.2).**
  - `PRK_w = HKDF-Extract("TEMPLAR_BOUND_WALLET_V1", S_w)`.
  - `info = label ‖ actx [‖ u32₄(i) big-endian]`, with `actx = felt₃₂(chain) ‖ felt₃₂(pool) ‖
    felt₃₂(A)`.
  - SPEND gives `wide9` of 144 bytes; INCOMING gives `clamp` of 32 bytes; STORE and STORE_ID
    give 32 bytes each, over `actx`.
  - `ak = H(WAUTH, felt_limbs(A) ‖ sk)` and the receiver are taken from `payment5::{ak_of,
    receiver_of}`, the relation's own functions.
  - The labels are prefix-distinct from each other and from the ordinary labels, and the salts
    differ. The same 28 bytes used as a Templar seed prefix give unrelated keys (tested).
  - `A` in every context separates `sk`, `nk`, `ivk` and the store keys across accounts (tested).
  - `python3 sdk/vectors/check_keys.py` gives 9 ordinary and 18 bound accounts matching: an
    independent HKDF, `wide9`, `clamp`, X25519, BIP-39 and address encoding. The WAUTH receiver
    comes from the bench wallet's `payment5`, which is independent of the SDK but not of the
    relation.
- **No ordinary receiver from `S_w`.** `H(AUTH, sk)` appears only in the ordinary
  `Account::new`, reached from `Seed`. In `plan()`:
  - inputs must be leaves under `account.receiver`, so the bound receiver for a bound wallet
    ("not_ours" otherwise);
  - change and consolidation go to `account.receiver`, sealed to `account.pk`;
  - dummies are CSPRNG.
- **Key sources.** A `Seed` is never bound, and a `BoundWallet` is always bound to `A`:
  - `plan()` refuses V4 for a bound wallet;
  - `witness()` refuses a plan whose `bound_account` differs from the key source's, a V4 plan
    that is bound or has an expiry, and a V5 plan with `valid_until ∉ [1, 2^56)`;
  - the tests cover the cross-wallet refusals in both directions.
- **Companion (§6.2, AB-M14).** `Companion::nullifier(…, account)` builds the dummy under
  `payment5::receiver_of(felt_limbs(account), sk)`. `plan()` checks spentness with the key
  source's account, and the test confirms that the published nullifier is the bound one and not
  the ordinary one. Companions are random and never seed-derived.
- **Statement checks match the bridge.** `witness()` runs `payment5::statement` and then
  `payment5::bridge_checks`, the mirror I matched to the Cairo bridge in P2 and P3. The
  decoder-only rules (limb ranges, padding, M31 range) hold by construction for a natively
  computed statement. So the SDK never proves a statement the bridge rejects. The coordinator's
  real-bridge runs confirm this (SDK proofs accepted, bridge binding equal to the SDK's, a changed
  account rejected).
- **Binding (§5.2).** `binding5` uses the V4 field order, then `valid_until` as one felt; it
  never includes the account. It equals starknet.js for the four KAT statements.
- **Spend message (§5.3).**
  - Domain `('Templar', 'V5', chain, 1)` with the revision-1 type hash.
  - Struct `(pool, Poseidon(binding, salt), token_out, recipient, u128 amount, intent)`.
  - `hash = Poseidon('StarkNet Message', domain, account, struct)`, where the account is the
    statement's, as the signer.
  - The hashes and the typed data (u128 as a decimal string, revision `"1"`, chain as text)
    equal starknet.js for all KAT spends.
  - `SpendMessage::of` refuses an ordinary statement and a salt that is zero or ≥ 2^251.
- **Salt.** `random_salt` masks the top byte to 3 bits (value < 2^251) and rejects zero, so it is
  uniform on [1, 2^251).
- **`valid_until` (§8.2).** `ceil((latest + E)/Q)·Q` with checked arithmetic, `0 < Q < 2^32`,
  `E < 2^32`, and a result in `[1, 2^56)`. It lies on the grid, in `[latest + E, latest + E +
  Q − 1]`. The edges are tested.
- **Store.** `StoreKeys` separates the bound store and record ids from the Templar wallet's
  (tested).

## 3. Findings

### AB-SM1 (medium): a bound wallet can make addresses for a pool whose relation has no bound mode, and funds sent there are frozen

- **Where:** `keys.rs` `BoundWallet::keys` and `Address::of` accept any `(chain, pool)`;
  `spend.rs` `PlanInput.version` is chosen by the caller; neither the core nor the TS layer maps a
  pool to its relation.
- **Failure scenario.**
  1. An app or configuration bug derives a bound wallet's address for pool V2, or for any pool
     that runs R0 V4.
  2. Payers or deposits send notes to it; pool V2 accepts any `inner`.
  3. R0 V4 has no WAUTH key, so no V4 statement can ever spend a bound note, and those funds are
     lost for good. No escape path exists (ADR-0026).

  For an ordinary wallet, a version/pool mismatch only makes the proof fail at the pool, a
  liveness issue.
- **Fix.**
  - Put the pool-to-relation map in the core's network constants.
  - `BoundWallet::keys` and every bound address or deposit path refuse pools without R0 V5.
  - `plan()` derives `Version` from the pool, instead of taking it from the caller.
  - Add tests: a bound address for a V4 pool is refused; a V4 plan against a V5 pool is refused.
- **Timing:** before bound wallets are reachable through WASM or TS.

### AB-SM2 (low): `SpendMessage::of` takes the binding as a parameter

- **Where:** `snip12.rs` `SpendMessage::of(statement, binding, salt)`.
- **Failure scenario.** A caller passes the binding of another plan that has the same displayed
  fields, for example an earlier re-plan of the same withdrawal with other outputs, change,
  `valid_until` or root. The user's signature then authorizes that other statement, not the one
  shown. Both are the user's own plans, so this is not theft. But the signature should be derived
  from exactly the statement displayed.
- **Fix.** Compute `binding5(statement)` inside `of`, and take `(statement, salt)`. Optionally
  run `bridge_checks` there too.

### AB-SM3 (info): the WASM and TS layers are not yet bound-aware

- The WASM `companion_nullifier` hardcodes account zero. Once bound wallets go through WASM, it
  must take the key source's account, or the pre-proof "companion not spent" check will test a
  nullifier that is never published.
- `version` defaults to `v4`.
- `Statement` serializes `withdrawal_amount` (u128) and `valid_until` as JSON numbers. JS must not
  parse them numerically, as the P3 README also notes. The typed data already uses a decimal
  string.

### AB-SM4 (info): stale plans

- `witness()` checks that `valid_until` is in range, but not the pool's grid or freshness.
- A stored plan proved late yields a statement the pool rejects, which costs liveness only. The
  signature then covers the stale expiry.
- Consider having `prove_plan` take the current `Expiry` and refuse a plan whose `valid_until` has
  passed or is off-grid, in line with AB-PV6's re-plan rule.

## 4. What I ran

- **Copy.** `sdk/` copied to `~/.local/share/templar/runs/review-p4-math/sdk`, with the path
  dependencies made absolute and `kat.json` placed at the `include_str!` path.
- **Core tests.** `cargo +nightly-2026-01-15 test --release -p templar-core` passes: unit 19,
  determinism 1, sepolia_s1 1, spend_bound 1, spend_flow 2, spend_v5 3. `vectors_keys` needs
  `--features test-rng` and passes with it.
- **Independent reference.** `python3 sdk/vectors/check_keys.py` (read-only, using the existing
  bench wallet binary, which postdates the `wallet.rs` change): "9 accounts, 18 bound accounts,
  all vectors match".
- **Nothing** under `/home/broody/development/templar` was modified.

**Not run.** The real-bridge acceptance of SDK proofs; I relied on the coordinator's
`r5-p3b` and `p4-m1` runs. The TS layer, which has no bound support yet.

## Resolution (implementer, 2026-09-26)

| Finding | Change |
| --- | --- |
| AB-SM1 | New `sdk/core/src/pool.rs`. `PoolRef { chain, pool, version }` carries each pool's relation, and `KNOWN_V4_POOLS` refuses R0 V5 for the Sepolia pool V2 whatever the caller says. `BoundWallet::keys` takes a `PoolRef` and refuses any pool that does not settle R0 V5 (`wrong_relation`), so no bound key, address or deposit exists for such a pool. `KeySource::account` takes the `PoolRef`, and `plan()` and `witness()` build it from the plan. Tests: `pool::tests`, `bound_keys_are_scoped_by_the_account`, `spend_bound`. The bound key vectors move to a V5 pool (`bound_pool`), and `check_keys.py` follows |
| AB-SM2 | `SpendMessage::of(statement, salt)` computes `binding5(statement)` itself and runs `payment5::bridge_checks` first. Tests: the message's binding equals the proof's, and a statement the bridge rejects has no message |
| AB-SM3 | Deferred to P4 M5, where WASM and TS become bound-aware: the companion's account, the version from the pool, and exact-digit JSON |
| AB-SM4 | `prove_plan(keys, plan, now, rng)`: a V5 plan needs `now` (the latest block and the pool's `E`, `Q`), and `check_fresh` refuses a plan off the grid, at or behind the latest block, or beyond `E + Q` (`stale_plan`). Test: `ordinary_v5_transfer_and_withdrawal` |

## Re-check (AB-SM1, AB-SM2, AB-SM4)

**GO.** AB-SM3 is deferred to M5.

### What I ran

In a refreshed copy:
- the core suite passes: unit 20 (with `pool::tests`), determinism 1, sepolia_s1 1, spend_bound 1,
  spend_flow 2, spend_v5 3;
- `vectors_keys` with `test-rng` passes;
- `check_keys.py` matches 9 ordinary and 18 bound accounts, now on `bound_pool`.

### Status of each finding

- **AB-SM1: resolved for every pool the SDK knows.**
  - `BoundWallet::keys(&PoolRef, i)` calls `check_bound()`, which requires V5.
  - `PoolRef::new` refuses V5 for the known Sepolia pool V2, and `plan()` and `witness()` build
    it that way.
  - `Address::of` needs an `Account`, so there is no bound address or deposit for a V4 pool.
  - The TS network constants list only pool V2, which is exactly the refused pool.
  - Tests: `wrong_relation` for a V4 `PoolRef`, and a refusal of V5 on the known pool.
- **AB-SM2: resolved.** `SpendMessage::of(statement, salt)` runs `bridge_checks` and computes
  `binding5` itself. Tests: the message binding equals the proof's, and a bridge-rejected
  statement is refused.
- **AB-SM4: resolved.**
  - `check_fresh` requires `valid_until % Q = 0`, `valid_until > latest` and
    `valid_until ≤ latest + E + Q`, which matches §8.2 (stricter by one block on the lower
    bound).
  - `prove_plan` requires `now` for V5.
  - Test: `stale_plan`.

### Non-blocking notes

1. The AB-SM1 guard is a denylist plus the version the caller declares.
   - When pool V3 is added (P6), record each pool's relation in the network constants. Preferably
     also keep an allowlist of R0 V5 pools in the core.
   - Make `PoolRef`'s fields private, since a struct literal bypasses `new`.
   - The `pool.rs` doc says "only for a pool known to take R0 V5", which the code does not yet
     check.
   - A bound wallet's recovery over past pools must skip V4 pools rather than abort (M5).
2. `check_fresh` adds `now.window + now.quantum` unchecked. Validate `E` and `Q` below 2^32, as
   `valid_until()` does.
3. `SpendMessage`'s fields are still public, which the KAT test uses. Document `of` as the only
   production constructor.

**Re-check notes applied (implementer):**
- `PoolRef`'s fields are private, so it is built only by `PoolRef::new`.
- The `pool.rs` doc now says what the code checks: the declared relation plus the known-V4 denylist. An allowlist of V5 pools comes with P6's network constants.
- `check_fresh` validates `E` and `Q` below 2^32 before adding.
- `SpendMessage::of` is documented as the only production constructor.
- Bound-wallet recovery that skips V4 pools is noted for M5.
