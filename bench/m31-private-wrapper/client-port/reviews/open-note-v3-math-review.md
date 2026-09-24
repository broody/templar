# Math review: R0 V3 (execution intent and identity handle)

2026-09-24. Independent Math Reviewer. I did not write this change and received no
implementer reasoning.

## Scope

- Commits `05084b4` (V3 statement) and `e6227f8` (zero budget allowed under an intent), diffed
  against V2.
- `src/payment.rs` (all of it), `tests/payment_r0.rs`, `cairo-r0/bridge/src/lib.cairo`,
  `cairo-r0/account/src/lib.cairo`, `validate_bridge_r0.py` (V3 diff).
- Consumers used as context: `bench/m31-pool/cairo/src/spend.cairo` (`binding_of`),
  `pool.cairo` (`apply_spend`, `apply_spend_with_invoke`, `pay_withdrawal`), `open_note.cairo`
  (`hash_intent`, `partial_commitment`, `identity_commitment`), the upstream
  `starknet-privacy/packages/shadow_account_anonymizer`.
- Specs: `docs/open-note-spec.md` §"Compact client-proof path (R0 V3)", ADR-0023 amendment.
- I ran `cargo test --release --test payment_r0`: 7/7 pass. I did not run the Cairo bridge,
  PROOF2 or any prover, and I did not re-review V2 parts that V3 leaves unchanged.

## Findings

| ID | Sev | Location | Issue | Concrete scenario | Suggested fix |
|---|---|---|---|---|---|
| V3-1 | Medium (hiding) | `pool.cairo:155`, `open_note.cairo:97-106`, `spend.cairo:41` | The handle is public calldata (`spend.identity`), and `partial = Poseidon('TEMPLAR_IDENTITY_V1', handle)` is a public function of it. Anyone can therefore compute `commitment_from_partial(partial, n)` for every nonce. Upstream documents the commitment preimage as "off-chain only and unrecoverable from on-chain data" (`shadow_account_anonymizer.cairo`, `privacy_invoke_with_computation` doc) and uses the nonce to give one identity several distinct shadow accounts. In Templar, all nonces under one `(sk₀, scope)` form one publicly linkable set. The spec's statement "only the owner of sk₀ can produce a handle" is true for authorization but says nothing about unlinkability. | A user opens shadow position A with nonce 0 and position B with nonce 1 at the same dapp. An observer reads `spend.identity` from either transaction, calls `get_shadow_accounts(partial, 0, 1024, false)` and gets both shadow-account addresses. A and B, and every COMPUTE spend that touched them, are linked. | Choose one: (a) put the nonce inside the proven value, `H(IDENTITY, sk₀ ‖ scope ‖ nonce)`, with the nonce bound through the intent, and derive the identity commitment directly from that value instead of going through `commitment_from_partial`; or (b) document that the nonce gives no unlinkability on this path, and have wallets use a fresh `scope` for each shadow account that must stay unlinkable, always with nonce 0. |
| V3-2 | Low (hiding, wallet) | `payment.rs:117-123, 764-766`; spec l.27 | `scope` is a free private witness. The circuit and the pool never tie it to the adapter or dapp, the chain or the pool (upstream's partial includes `dapp_name`). Separation between applications and deployments rests entirely on how the wallet derives `scope`. `sk` itself carries no chain or pool context, so a reused scope gives the same handle on every deployment. | A wallet uses a constant scope. The same 9-word handle then appears in COMPUTE spends to two different adapters, or on Sepolia and mainnet, and links them. | Specify the wallet derivation, for example `scope = H(wallet secret, chain, pool, adapter/dapp_name, account index)`. Alternatively, add public chain/pool/adapter words to the handle preimage; the adapter would then need to be a statement field. |
| V3-3 | Low (tests) | `validate_bridge_r0.py:69`, `tests/payment_r0.rs:172-199` | Missing negative coverage. There is no `wrong-identity` bridge case (only `wrong-intent` was added). No proof exercises a nonzero identity with a zero intent, which the circuit permits and only the bridge rejects (`lib.cairo:140`). No proof exercises intent limbs ≥ 2²⁸, which the circuit permits and `felt_from_limbs` rejects. No test checks that swapping the inputs changes the handle. | A regression that dropped `s.identity == identity` in `main`, or the `identity intent` assert, would pass all current tests. | Add `wrong-identity` and `identity-without-intent` bridge cases. For a malicious-witness proof, a test-only `build` variant can emit raw intent limbs. Add a relation test with inputs swapped and one with the flag off but a nonzero scope. |
| V3-4 | Info | `tests/payment_r0.rs:1,173`; `bridge lib.cairo` module doc | Stale docs. The test file header still says "V2", and the `v3_intent_and_identity` doc still says "an intent needs a budget", which `e6227f8` reversed. | — | Update the comments. |
| V3-5 | Info (design) | `payment.rs:766` | The handle depends only on input 0's key. Any COMPUTE action therefore needs an unspent, nonzero note under exactly that `sk` in slot 0, plus a second nonzero input (V2 still requires two real inputs). A wallet with per-note or diversified keys cannot reach its shadow accounts, and rotating the key loses them. A prover that knows two keys can pick either one's handle by ordering the inputs. That is expected, since it knows both keys. | — | Document that shadow-account identity requires a stable `sk`. |
| V3-6 | Info (hiding, background) | `payment.rs:763-767` | The handle hash runs even when the flag is off, so the trace carries rows that depend on `sk₀` and `scope` in every proof. With the H2 blinding fix (fork `4de7408a6`) this is covered by ZK. Without the fix, it would add more sk-dependent rows to the leaked `D` polynomial. **Not verified:** that the V3 bridge proofs (18/18) were produced with the fixed fork. | — | Confirm the prover used for V3 artifacts includes the H2 fix. |

No Critical or High findings.

## Checked and found sound

**Q1. Identity output soundness**
- The flag comes from `guess_bits(…, 1)`, which constrains `b·(b−1)=0` (`merkle.rs:13-23`), so it is boolean.
- The output is `handle_i · flag` (`payment.rs:767`): exactly zero when the flag is 0, and exactly the in-circuit hash when it is 1. A scaled or forged handle is impossible.
- `sk[0]` in the IDENTITY request (`:766`) is the same `Vec<Var>` that feeds the AUTH/NK derivation (`:663`), and through it the receiver, `cm₀`, the membership path and `nf₀`. The handle key is therefore the key proven to own input 0.
- Different keys on the two inputs are fine. Only `sk₀` enters the handle, and the prover must know both keys to spend.
- Forging another user's handle needs a preimage `(sk', scope')` of a target 9-word output under the IDENTITY frame. That is a generic second-preimage or preimage attack on a width-24, capacity-9 (≈279-bit) sponge, costing ≈2^139 or more. Knowing `scope` alone does not help.
- A zero handle with the flag set has probability about 2⁻²⁷⁹.

**Q2. Intent**
- The intent is guessed as 9 M31 limbs and output verbatim (`:763`). Like the V2 recipient and deliveries, it is bound to the proof as a public output.
- The circuit does not range-check the limbs. `felt_from_limbs` checks each limb is below 2²⁸ and that the 252-bit value is below p (`lib.cairo:45-56`). Every accepted intent therefore has exactly one limb encoding, with no malleability between circuit and bridge.
- `binding` appends the decoded felt. The pool recomputes the intent via `hash_intent`, which covers chain, pool, token, kind, adapter, nonce, budget recipient and amount, expiry, selector, calldata and destinations. It then compares the result against `binding_of` (`spend.cairo:101-117`).
- The field order is identical in the bridge (`lib.cairo:158-183`), the pool and `validate_bridge_r0.py`.
- Identity words are canonical M31 (QM31 coordinates) on the bridge side, and felt equality in Poseidon forces the pool's words to match.

**Q3. V2 guarantees**
- Conservation, inactive-slot rules, the withdrawal range and nullifier checks are unchanged.
- The topology is the same for all five shapes, both trees: the identity hash and the intent guesses run unconditionally, and the test asserts this.
- Tags were bumped for both tree formats (`R0V3`, `R0C3`), as were the binding tag (`TMR0_BIND_V3`) and the account message tag (`TMPZR0_PAYMENT_V3`). No V2 statement or fact can be read as V3.
- Output offsets: tag 0-1, chain 2, pool 11, token 20, root 29, nf 38/47, cm₀ 56, d₀ 65, cm₁ 74, d₁ 83, recipient 92, amount 101-108, intent 109-117, identity 118-126, padding 127. These match the `build` concatenation (`payment.rs:769`), `statement_limbs`, and the bridge slices.
- The padding limb is a circuit constant zero (fixed by the pinned circuit hash) and is checked again at `lib.cairo:117`.

**Zero-budget intent (`e6227f8`)**
- The bridge still enforces that the recipient and amount are both zero or both nonzero, and that some output exists.
- `pay_withdrawal` with a zero amount requires a zero recipient.
- `hash_intent` commits to the (zero) budget and recipient.
- No value can be created or redirected this way.

**Q4. Hiding with the flag off**
- The statement carries nine zeros whatever `sk₀` or `scope` is. Only the flag's value is public, and the pool requires it anyway: COMPUTE needs an identity and INVOKE forbids one.
- The intent itself is public by design.

**Q5. Domain separation**
- Every hash is framed `[TAG, 1, kind, level]`. IDENTITY=9 differs from AUTH 1, NK 2, OWNER 3, INNER 4, NOTE 5, NODE 6, NF 7 and NODE1 8.
- The 18-word payload has the same length as OWNER, INNER and NODE, but the kind word separates them.
- Compress-mode nodes place `NODE1` in capacity positions, while IDENTITY sits in rate position 2 of a sponge with zero capacity at the start. They cannot collide.
- Nine-word truncation gives about 139-bit collision resistance, which is adequate.

**Q6. Bridge and pool rules**
- The "identity needs intent" rule is checked in the bridge (`lib.cairo:140`) and in native `statement`.
- The pool also rejects any identity on `apply_spend`, requires an identity for COMPUTE and forbids one for INVOKE.
- The account passes intent and identity only through `binding`.

## Verdict

**CONDITIONAL GO for research use.** The V3 relation and bridge are sound: no forgery, no
malleability, and no regression of V2 guarantees. Conditions:
- Resolve or explicitly document V3-1: nonce-level shadow accounts are publicly linkable, contrary to upstream's stated property.
- Specify the scope derivation (V3-2).
- Add the missing negative tests (V3-3) before the implementation is called qualified, per the ADR-0023 amendment's own condition.
