# Client SDK: math review (implementation)

- **Role:** independent Math Reviewer. I did not write the implementation.
- **Date:** 2026-09-24
- **Commit reviewed:** `9fbdd6a` (`feat/sdk`; `client-port: lock file after the fork drops
  stwo_cairo_prover`). The uncommitted working-tree edits (docs, `sdk/README.md`) are out of scope.
  Fork commit `250cc9c1e` in `target/proving-arith`.
- **Against:** `docs/sdk-spec.md` revision 3, `docs/reviews/sdk-design-{math,protocol}-review.md`,
  `client-port/src/{payment,payment4}.rs`, `bench/m31-pool/{hidden_asset,policy_wallet}.py`,
  `cairo/src/{spend,spend4}.cairo`, `server/prover/src/pipeline.rs`, `docs/hidden-asset-spec.md` §6.
- **Changes made:** none, apart from this file. I used a throwaway probe crate in my scratch
  directory, not the repository, to exercise edge cases.

## Verdict: CONDITIONAL GO

The cryptography matches the spec and the deployed formats. I found no Critical issue. Before
anything reaches a user, fix these:

- **SDK-IM1:** the core can panic on its input.
- **SDK-IM2:** a deposit can go to another pool's address and strand the funds.
- **SDK-IM3:** the normative negative tests are missing.

The Low and Info items can follow.

**What I verified:**

- **Tests.** `cargo test --release -p templar-core`: 16 of 16 pass. `python3
  sdk/vectors/check_keys.py`: all vectors match (9 accounts, 2 sealed boxes).
- **Keys.** HKDF labels and context, `wide9`, clamping, the BIP-39 entropy with a 24-word check,
  and the gap limit. Domain separation holds: the labels differ before the context starts.
- **Addresses and viewing keys.** F4Jumble, Bech32m, the fingerprint, and the payload and type
  bytes. The probe confirmed each §4.1 rejection: wrong type, wrong version, nonzero padding,
  HRP and chain mismatch, zero pool, a receiver word equal to `p`, `pk` bit 255, 151 bytes, and a
  Bech32 (not Bech32m) checksum. The viewing-key import checks are in place.
- **Sealed boxes.** The libsodium layout: the BLAKE2b-24 nonce, HSalsa20 then
  XSalsa20-Poly1305, and `epk ‖ tag ‖ ct`. The seven blocked u-values are right: five are listed,
  and `p` and `p + 1` are excluded by the range check. Both directions reject a non-contributory
  shared secret. The ten-word split, and the delivery digest against `spend.cairo`.
- **Scanning.** The rule order in `scan.rs`. The probe confirmed PS01: side 0 → `x`, side 1 →
  `amount − x`, and a wrong index, `x > amount`, a missing settlement or side 2 each reject. A
  digest mismatch is reported. The TS layer detects conflicting duplicates (`wallet.ts:296`).
- **Spends.**
  - Selection, a random order for the outputs and for two real inputs, and fresh dummies (a real
    sealed box to a fresh key).
  - The sticky companion. Its nullifier matches the relation's dummy input: the same context,
    amount 0, and `receiver_of(sk)`.
  - The binding and calldata against `hidden_asset.py`, `spend4.cairo`, and the Sepolia S1
    vector (all 90 felts).
- **Result checks.** The nine facts and the message hash
  `Poseidon(statement, 0, 5, class, short_string(tag), chain, pool, binding)` are identical to
  the server's (`pipeline.rs:154,178`). The window is computed locally.
- **Store.** AEAD with length-prefixed associated data.
- **Tree.** Append and truncate against `payment::tree_paths`.
- **Library prover (`prove.rs`).**
  - FRI 2/35/26, checked against the fork's file.
  - `blinding_budget` is algebraically equal to the bench `support` version.
  - The topology check, the mandatory hiding-budget check and self-verification are all present.
  - Dropping `validate_circuit` is covered by native verification.
- **Fork `250cc9c1e`.** I compared the moved items mechanically. `G_STATE_INDICES`,
  `PackedTripleXor32`, `PackedBlakeRoundSigma`, `AtomicMultiplicityColumn` and `Enabler` are
  token-identical to `crates/prover/src/witness/{fast_deduction/blake.rs,utils.rs}`, apart from
  doc comments. Nothing else in `circuit_prover` references `stwo_cairo_prover`.
- **WASM boundary.** No export returns `sk`, `ak`, `nk`, `ivk` or `kstore`, except
  `viewing_key_export`. Plans expose only the dummy companion, and scans expose `rho` and
  nullifiers, both by design. The seeded exports are `#[cfg(feature = "test-rng")]`, and
  `build-wasm.sh` fails if the release artifact exports `test_*`.

## Findings

### SDK-IM1: Medium: a plan with 64-digit felt strings panics inside the relation

**Where:** `sdk/core/src/spend.rs:288-356` (`witness`), `felt.rs:127`, `payment.rs:160`.

**Problem.** `felt::parse` accepts up to 64 hex digits, so leading zeros are allowed. `witness`
parses `plan.chain`, `plan.asset` and `plan.withdrawal_recipient`, but then passes the **original
strings** to `payment4::statement` and `bridge_checks`, and also `Private.token =
plan.asset.clone()`. Those functions call `felt_limbs`, which asserts at most 63 nibbles. The
probe hit `felt exceeds 252 bits` for each of the three fields.

The panic is reachable through `prove_spend` and any other caller of `witness` or `prove_plan`.
That breaks §2: no input may panic in the core's own code. The worker only contains the crash;
it does not excuse it. Non-canonical strings, such as uppercase hex, also flow unchanged into the
statement JSON sent to the server.

**Required change.** In `witness`, rebuild every felt string from the parsed value
(`felt::to_hex(&parse(x)?)`) before building `Private` and the statement. Add a regression test
for 64-digit and uppercase inputs.

### SDK-IM2: High: deposits do not check the address's chain and pool

**Where:** `sdk/wasm/src/lib.rs:113-131` (`note_for`), `sdk/ts/src/wallet.ts:480-488`.

**Problem.** §4.1 requires the payer to reject an address whose `chain` and `pool` differ from
the pool it pays into. §10.1 specifies `note_for(address, asset, amount, chain, pool)`. The
export takes no chain or pool, and `deposit` passes any decoded address. The address may belong
to another pool, a past one, or a mainnet address on Sepolia.

Such a deposit publishes a note whose receiver and key come from another pool. The recipient's
wallet scans this pool only with this pool's keys, so it never finds the note. The returned
`commitment` also uses the address's pool, so it disagrees with the leaf this pool publishes.
That is noticed only after the funds are in. Transfers already enforce the rule
(`spend.rs:233`); deposits bypass it.

**Required change.** `note_for` takes `chain` and `pool`, and returns `wrong_pool` unless both
equal the address's. Add a test.

### SDK-IM3: Medium: the normative negative tests are missing

**Where:** `sdk/core/src/address.rs:233-265`, `scan.rs` (no tests), `sealbox.rs:443-456`,
`sdk/ts/test/wallet.test.ts:200-207`.

**Problem.** §12.3 and §2 require several tests that do not exist:

- every §4 decoding rejection (in-tree: only the checksum and the cross-type cases);
- every §6 scan rule: PS01 side 0 and side 1, `x > amount`, a wrong `PolicySettled` index, side
  greater than 1, a digest mismatch, a commitment mismatch and a receiver mismatch;
- opening a box whose `epk` is a blocked point;
- a malformed-input sweep of every WASM export.

The probe shows the implementation behaves correctly on each case except IM1. That is exactly
what the missing sweep would have caught. The TS test "errors carry their core code" also passes
when no error is thrown, because it has no `expect.assertions` and no `toThrow`.

**Required change.** Add these tests to the tree. The probe's cases can be lifted as they are.

### SDK-IM4: Low: the core does not check that inputs and the companion are unspent

**Where:** `spend.rs:182-285`.

**Problem.** §7.2 says the core checks that each input is "unspent". §3.3 says "before proving,
the core checks that the companion's nullifier is not spent". Both checks exist only in TS
(`wallet.ts:470` and `wallet.ts:550-553`). The pool rejects a spent nullifier, so no funds are at
risk. But the rule is not enforced where the spec places it, and the core API accepts spent
notes.

**Required change.** Pass the spent nullifiers into `plan` and check the inputs and the
companion there, or amend §3.3 and §7.2 to assign these checks to TS.

### SDK-IM5: Low: the client's circuit hash is never compared to the pin

**Where:** `spend.rs:428-443`, `sdk/ts/src/prove.ts`, `wallet.ts`.

**Problem.** §8 says the client's own circuit hash must equal the pin. `Proved.circuit_hash` is
returned, but nothing compares it with `network.circuitHash`. A mis-built WASM would be caught
only by the bridge, after the statement has left the wallet. Under §9.1 that locks the notes
until the root is evicted (512 or more leaves).

**Required change.** Compare the hash before the statement leaves the wallet: in `prove_plan`
(pass the pin in) or in TS before `leaving`.

### SDK-IM6: Low: consolidation can fail although a valid pair exists

**Where:** `spend.rs:199-206`.

**Problem.** The code picks the globally smallest note, then looks for a second note in that
note's account. If the smallest note is alone in its account, consolidation fails even when
another account holds two notes. The probe confirmed this.

**Required change.** Choose the smallest two notes within the same account, over all accounts.

### SDK-IM7: Low: amount rules differ between the plan and re-plan paths

**Where:** `spend.rs:100-102`, `spend.rs:191-212`.

**Problem.** On the `required_inputs` path, `want == 0` is not rejected. A zero-amount re-plan
transfer produces a real `M301` of amount 0 to the payee, which the payee's scan discards (probe
result: outputs `["0", "5"]`). A zero withdrawal is caught only by `bridge_checks`. Separately,
`u128::from_str` accepts `"+5"` and leading zeros, so non-canonical decimals pass.

**Required change.** Reject a zero amount for Transfer and Withdraw on every path. Accept only
canonical decimals (`0` or `[1-9][0-9]*`).

### SDK-IM8: Low: `prove_plan` trusts that each ciphertext encodes its output

**Where:** `spend.rs:321-333`.

**Problem.** `witness` checks the words, the range and the digest, but not that ciphertext `i`
decrypts to `(asset, receiver_i, rho_i, amount_i)`. Plans are stored and proved again later
(§9.1), so a corrupted or tampered plan could strand the change or the payment while the
relation and the pool accept it.

**Required change.** For outputs to the account's own receiver, open the box with `ivk` and
compare the fields. For the payee, keep each output's ephemeral secret in the plan and
re-derive the box. This adds no new secret, since the plan already holds `rho` and the amount.

### SDK-IM9: Info: zeroization is partial

**Where:** `keys.rs:274-281,260`, `scan.rs:190-197`, `spend.rs:307`.

**Problem.** Several secrets are not zeroized:

- the HKDF PRK;
- `ScanKey` (`ivk`, `nk`);
- `payment4::Private` (`sk`);
- the `Seed::mnemonic` `String`;
- `bip39::Mnemonic`.

This is hygiene only, since the seed lives in JavaScript (SDK-M14).

**Required change.** Use `Zeroizing` wrappers, `ZeroizeOnDrop` on `ScanKey`, and bip39's
`zeroize` feature.

### SDK-IM10: Info: an uppercase full viewing key fails to import

**Where:** `address.rs:198`.

**Problem.** The type is chosen by a case-sensitive `starts_with("templarfvk")`. An uppercase
full viewing key is therefore rejected as "wrong prefix". Uppercase addresses and incoming keys
decode (probe).

**Required change.** Lowercase the string before routing.

### SDK-IM11: Info: one store key serves two primitives, and record ids are not injective

**Where:** `store.rs:145-152`.

**Problem.** `kstore` is both the XChaCha20-Poly1305 key and the HMAC key for record ids. Also,
`type ‖ 0x00 ‖ key` is not injective if a type contains NUL. Types are constants, so neither is
exploitable today.

**Required change.** In the next store version, derive separate subkeys and use the
length-prefixed encoding of `ad()`.

### SDK-IM12: Info: minor items

**Where:** `sealbox.rs:311`, `result.rs:92`,
`client-port/examples/support/mod.rs:31-46,64-72`.

- `seal_with`, which takes a caller-chosen ephemeral key, is public core API. Gate it behind
  `cfg(test)` or `test-rng`.
- `base_block + SUBMIT_DELAY` and `base_block + max_proof_age` are unchecked. They wrap in
  release and panic in debug. Use `checked_add`.
- In the bench only: `support::native_verify` and `negatives` still honour `TEMPLAR_FRI`, while
  the library prover ignores it. `wallet` with `TEMPLAR_FRI` set now fails in the negatives
  step. Drop the override from `support`, or document it.

## Re-review (5bd6ac6)

- **Date:** 2026-09-24. **Commit:** `5bd6ac6` (`Client SDK: implementation review fixes`),
  reviewed as `git diff 9fbdd6a 5bd6ac6 -- sdk bench docs/sdk-spec.md`.
- **Checks run:**
  - `cargo test --release -p templar-core --features test-rng`: 20 of 20 pass. New:
    `address_rejections`, `scan_rules`, `blocked_ephemeral_key_does_not_open` and `spend_rules`.
  - `python3 sdk/vectors/check_keys.py`: all vectors match.
  - `vitest -t "every WASM export"`: passes.
  - A stricter sweep of my own, in scratch, over the built release `.wasm`: 100 malformed or
    hostile calls, including a non-canonical companion, `inner` equal to `p`, a `u64::MAX` proof
    age and a hostile scan request. Every call threw a JSON string error; none trapped.

### Verdict: GO

Every finding is resolved. SDK-IM8 and SDK-IM9 are resolved only in part; the residue is Info
and accepted. I found no new issue above Low.

### Status of SDK-IM1 to SDK-IM12

| Finding | Status | Evidence |
| --- | --- | --- |
| IM1 | Resolved | `witness` rebuilds chain, pool, asset, recipient and deliveries with `to_hex` before `Private`, `statement` and `bridge_checks`, so every string reaching the relation is canonical. The 64-digit case in `spend_rules` passes. |
| IM2 | Resolved | `note_for` takes chain and pool and returns `wrong_pool` on a mismatch (`wasm/lib.rs:113-119`). `deposit` passes them (`wallet.ts:553`), and a TS test covers it. |
| IM3 | Resolved | New tests cover every §4.1 rejection (all seven blocked `pk` classes via 0, 1, `p − 1` and `≥ p`), the uppercase full viewing key, an unclamped `ivk`, and every §6 rule including all PS01 cases and a forged registration. Also new: opening with a blocked `epk`, and the TS export sweep. See N1 for the sweep's weak assertion. |
| IM4 | Resolved | `plan` takes `spent`. It refuses a spent input (its nullifier recomputed after the ownership check) and a spent reused companion (`companion_spent`). TS passes every synced nullifier. `prove` rechecks the companion. |
| IM5 | Resolved | `Spend.prove` compares `circuit_hash` with the pin before the record is marked `left` (`wallet.ts:840-841`), and a test covers it. |
| IM6 | Resolved | Consolidation takes the smallest same-account pair over all accounts, with overflow checked. |
| IM7 | Resolved | `u128_of` accepts canonical decimals only, used in the core and in WASM. The zero check now runs after selection on every path, re-plans included. |
| IM8 | Resolved in part | An output to the spending account must open under its `ivk` and match asset, receiver, `rho` and amount exactly. It must also be `M301`; a PS01 plaintext is refused. A payee's output is still unchecked. The plan sits in the AEAD store and JS already holds the seed, so this is accepted (Info). |
| IM9 | Resolved in part | `ScanKey` is `ZeroizeOnDrop`. The HKDF PRK, `payment4::Private` and the mnemonic string are not; this is hygiene only (SDK-M14), accepted. |
| IM10 | Resolved | The prefix is routed on the lowercased string; a test covers it. |
| IM11 | Resolved | A separate `kid` under `TEMPLAR_STORE_ID_V1` with a length-prefixed HMAC input. The HKDF `info` strings stay distinct by length (80, 83, 84 and 87 bytes for store, id, spend and incoming). Spec §10.3 is updated. |
| IM12 | Resolved | `seal_with` is behind `cfg(any(test, feature = "test-rng"))`, and `vectors_keys` requires that feature. The window additions use `checked_add`. The bench `TEMPLAR_FRI` note was advisory and is unchanged. |

I also checked that the new exports are sound. `pool_commitment` equals the pool's `H(NOTE, …)`
on a range-checked `inner`, with fallible limbs. `test_expected_facts` is test-only under
`test-rng`, which the release build check covers.

### New items

#### N1: Low: the WASM sweep does not detect a trap

**Where:** `sdk/ts/test/wallet.test.ts:376-385`.

**Problem.** The sweep accepts any thrown value whose `String(...)` is truthy. A `panic = "abort"`
trap throws `RuntimeError: unreachable`, which passes that check, so the test cannot tell a trap
from an error.

My stricter scratch sweep found no traps today.

**Required change.** Assert `typeof threw === 'string'` and a parsable `{code}`. Add at least one
hostile but well-formed input per JSON export: the IM1 plan with 64-digit felts through
`prove_spend`, and non-canonical digests.

#### N2: Info: record ids changed without a schema bump

**Where:** `store.rs:53-62`, `SCHEMA = 1`.

**Problem.** Stores written before `5bd6ac6` become unreachable under the new names. A lost live
record or companion would re-open its notes for selection. That is harmless before any release,
since nothing has shipped.

**Required change.** None before the first release. After it, any change to naming or encoding
must bump `SCHEMA` and migrate.
