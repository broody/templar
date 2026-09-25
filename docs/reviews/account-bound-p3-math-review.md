# R0 V5 Cairo bridge (P3): math implementation review

- Reviewer: independent Math Reviewer (did not write the code)
- Date: 2026-09-26
- Scope: the bridge only. The statement account belongs to the protocol reviewer.
- Under review (uncommitted, under `bench/m31-private-wrapper/client-port/`):
  - `cairo-r5/bridge/src/{lib,snip12,snip12_kat}.cairo`;
  - `cairo-r5/kat/{gen_kat,v5}.cjs` and `kat.json`;
  - the r5 entry in `build_bridge_arith.py`;
  - `validate_bridge_r5.py`;
  - `results/r5-bridge/`.
- Against:
  - `docs/account-bound-note-spec.md` revision 4, §5.1–§5.3;
  - the Rust mirror `src/payment5.rs` (`decode_statement`, `bridge_checks`), reviewed in P2;
  - the R4 bridge `cairo-r4/bridge/src/lib.cairo` as the baseline.

## 1. Verdict

**GO.**

- The bridge enforces every §5.1 rule, and each matches the Rust mirror.
- No V4 check was lost.
- The binding has §5.2's field order, with `valid_until` as one felt and without the account.
- The SNIP-12 constants and hash match §5.3 and starknet.js.

Two low findings should be closed before the P3 record is final: one Cairo rule has no test, and
the non-forgery validation cases do not assert why they are rejected. Neither changes soundness.

## 2. Conformance

### 2.1 Decoding and checks (§5.1) against the mirror

| Rule | Cairo (`verify_payment`) | Mirror (`decode_statement`, `bridge_checks`) |
| --- | --- | --- |
| 35 outputs, 140 limbs | `outputs.len() == 35` | length 140 |
| Limb < p | by type: `M31InnerT = BoundedInt<0, 0x7ffffffe>`, and corelib deserializes `BoundedInt` through a checked `TryInto` | explicit `M31 range` |
| Tag `R0C5` | pinned from the trusted manifest | same |
| `nf₀ ≠ nf₁` | yes | yes |
| Felt fields at 2, 11, 20, 65, 83, 92, 109, 127: limbs < 2^28, value < p | `felt_from_limbs` on each | same |
| Amount limbs 101–108 < 2^16 | yes | yes |
| `valid_until` limbs 136–137 < 2^28, value ≠ 0 | `valid_until_from_limbs` | same |
| Padding 138–139 zero | yes | yes |
| V4: zero context, pool/asset/recipient < 2^251, nonzero nullifiers, commitments and deliveries, recipient ⇔ amount, exit rule, identity ⇒ intent | all present, line for line R4's | same |
| `account < 2^251` | yes (`account = 0` allowed) | same |
| Circuit hash pinned; `verify_circuit` last | pin equals `trusted-config.json` (R5) | — |

- Only the order of checks differs from the mirror, which changes the error message and nothing
  else.
- The decoder layout matches `statement_limbs` exactly.
- `main` also compares the account and `valid_until` with the caller's values.

### 2.2 Binding (§5.2)

- `Poseidon('TMR0_BIND_V5', chain, pool, token_out, root₉, nf₀₉, nf₁₉, cm₀₉, d₀, cm₁₉, d₁,
  recipient, w_amount, intent, identity₉, valid_until)` has a fixed length of 64 felts.
  `w_amount` enters as a u128 felt and `valid_until` as one u64 felt. The account is not included.
- Three references agree:
  - the Cairo code;
  - `validate_bridge_r5.py`'s Python `binding` over `bench/adr8/ref_poseidon.py`, for all 16
    honest proofs;
  - the JS `binding` in `gen_kat.cjs`, for four KAT statements that include extremes
    (`w_amount = 2^128 − 1`, `valid_until = 2^56 − 1`, `pool = 2^251 − 1`) and an invoke with an
    identity.
- Each KAT also asserts that the same fields with a nonzero account bind identically.
- This closes AB-IM4.

### 2.3 Spend message (§5.3)

- **Domain:** `'Templar'`, `'V5'` (a non-numeric short string), `chainId` = the statement's
  chain, revision encoded as 1.
- **Struct fields:** `pool, binding_commitment, token_out, withdrawal_recipient,
  withdrawal_amount (u128), intent`, which is revision 4's struct with `valid_until` removed.
- **Hashes:**
  - `binding_commitment = Poseidon(binding, salt)`;
  - `hash = Poseidon('StarkNet Message', domain_hash, account, struct_hash)`.
- **References.**
  - The type hashes and the three spend vectors (Sepolia and mainnet; account `2^251 − 1`; salt
    1; u128 maximum) come from starknet.js 10.8's own `getTypeHash`, `getStructHash` and
    `getMessageHash`. That is an independent SNIP-12 implementation.
  - `real-wallets.json` shows Ready X and Braavos signing this exact struct and domain, which is
    §15 P3's requirement.

## 3. What I executed

- **Build.** `build_bridge_arith.py results/stwo-client-r5/trusted-config.json
  …/review-p3-math/base`:
  - 13/13 bridge tests pass (5 unit tests and 8 KATs);
  - the account builds;
  - the executable's sha256 (`5fcc53a0…`) equals the one `validation.json` records and the one in
    `r5-p3/final`, so the build is reproducible.
- **Targeted mutants.** Each ran in its own copy of that build: rebuilt, run through the bridge's
  Cairo tests, and run on 8 real-proof cases:
  - three honest proofs (bound partial, ordinary transfer, bound shadow) with the Python binding;
  - a padding-limb tamper;
  - the `account-range`, `valid-until-zero`, `valid-until-limb-range` and `duplicate-nullifier`
    forgeries.

  The driver is `…/review-p3-math/mutate_p3.py`, with results in `mutants-p3.json`.

  | Mutant | Result |
  | --- | --- |
  | none (control) | all pass |
  | `account < 2^251` deleted | killed: `forge-account-range` accepted |
  | `valid_until ≠ 0` deleted | killed: unit test and `forge-valid-until-zero` |
  | `nf₀ ≠ nf₁` deleted | killed: `forge-duplicate-nullifier` |
  | binding: `valid_until` before identity | killed: KATs and all three honest bindings |
  | binding: account appended | killed: KATs ("binds identically") and the honest bindings |
  | SNIP-12 domain version `'V4'` | killed: KATs |
  | SNIP-12 struct fields reordered | killed: KATs |
  | **`valid_until` hi-limb bound deleted** | **survives: nothing tests limb 137 (AB-IM6)** |
  | **padding check deleted** | killed only by my reason-checking case. `validate_bridge_r5.py` would still pass, because the tamper is then rejected by proof verification (AB-IM7) |

## 4. Findings

### AB-IM6 (low): the `valid_until` hi-limb bound and the account's canonicity boundary have no Cairo test

- **Where:** `lib.cairo` `valid_until_from_limbs`, `felt_from_limbs` on the account;
  `validate_bridge_r5.py` forgeries.
- **What is wrong.**
  - The unit test and the forgery both put the out-of-range value in the lo limb (136). Deleting
    `hi < 2^28` survives everything.
  - The account's "value < p with 28-bit limbs" rule is tested in Cairo only through the shared
    `felt_from_limbs` unit test at `2^252 − 1`. There is no real proof with `account = p`, although
    the P2 mirror tests it and the circuit admits it without any tamper hook.
- **Impact.** Neither is exploitable:
  - with the lo limb checked, `lo + hi·2^28` stays injective, and the pool's
    `valid_until ≤ block + E + Q` rejects a far value;
  - the canonicity check is the shared, unit-tested function.

  But the Cairo rule set is the one P3 must pin, per F11.
- **Required.**
  - A Cairo unit test with the hi limb at 2^28.
  - Real-proof forgeries `valid-until-hi-limb-range` (tamper `[0, 1 << 28]`) and
    `account-noncanonical` (account = p, no tamper), rejected with `limb range` and
    `non-canonical felt`.

### AB-IM7 (low): the non-forgery negatives do not assert which check rejects them

- **Where:** `validate_bridge_r5.py`: only forgeries pass a `reason_substring`.
- **What is wrong.** The 88 altered-statement cases pass on any nonzero exit. So a check that
  fires before proof verification (the tag, padding and exit rule on the tampered outputs) can be
  deleted, and the suite still passes, because proof verification rejects the tamper later. The
  README's "each is rejected by that check" is true only of the forgeries.
- **Impact.** The padding and tag checks are redundant with the pinned circuit, which publishes
  constant zeros and a constant tag. So nothing is exploitable, but the suite does not demonstrate
  those checks.
- **Required.** Assert the reason on the output-tamper cases where a decode check fires first:
  - tag → `statement tag`;
  - padding → `statement padding`;
  - the transfer `token-out` tamper → `exit rule`.

  Or state in the README that these cases only show the proof binds the outputs.

### AB-IM8 (info): assumptions the bridge relies on

- **Limbs below p.** Cairo decodes limbs from `M31` values, whose type is `BoundedInt<0, P−1>`,
  deserialized with a checked `TryInto`. I verified this in a local corelib checkout
  (`~/development/cairo/corelib`, `into_felt252_based::SerdeImpl`); that it equals scarb 2.18's
  corelib is inferred. The mirror's explicit `M31 range` check matches this.
- **Padding and tag checks.** They are defence in depth: the pinned circuit fixes both.
- **The KATs' binding vectors** come from a JS re-implementation by the author, not from an outside
  library. The independent cross-checks are the Python `ref_poseidon` binding on 16 real proofs,
  and my binding-order mutants, which both fail.

## 5. What I checked and what I could not check

**Read.**
- The three bridge sources and the KAT generator and helper.
- The build script's r5 entry, and the pinned circuit hash and tag in the built bridge.
- `validate_bridge_r5.py`, all 116 rows of `validation.json` (116/116, with each rejection
  reason), the README and the build record.
- The R4 bridge and the P2 mirror.
- The vendored `verifier_core` M31 type and the corelib Serde.

**Ran.**
- One fresh build, whose executable matches the recorded one.
- 10 targeted mutants: bridge tests plus 8 real-proof cases each.

Nothing under `client-port` was modified. My copies and results are under
`~/.local/share/templar/runs/review-p3-math/`; the mutant copies have been deleted.

**Not run.**
- The full 8-minute validation; I relied on the recorded `validation.json` plus my targeted cases.
- The statement-account tests and real-wallet runs (protocol scope).
- A new forged proof, which would need a prover build.
