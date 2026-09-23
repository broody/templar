# R0 payment route: binding and boundary review

Date: 2026-09-23. Reviewer: an independent agent. It did not modify committed code.
Branch `pathfinding/client-zk` (HEAD `b0a8d9f`). Built instance reviewed:
`target/bridge-r0c`, which pins the `Tree::Compress` circuit, hash word 0 `2423306541`. Its
`bridge/src` and `account/src` equal `cairo-r0/` apart from the generated `pinned.cairo`. Its
vendor tree equals the fork (`target/proving-arith@8acdbe55`) apart from the two generated files
`multiverifier_consts.cairo` and `preprocessed_columns.cairo` (checked with `diff -rq`).

## Verdict

**CONDITIONAL GO for continued research use.**

The bridge and account correctly do what they claim:
- They pin one circuit.
- They decode the 92-limb statement canonically and injectively.
- They emit a message that commits to every limb through an injective fixed-length Poseidon
  binding.

I found no way for a proof from another circuit, or a changed or non-canonical statement, to
pass `verify_payment`. I found no way for the server to change the emitted facts.

The condition is that this route has **no settlement security of its own yet**. Root freshness,
nullifier uniqueness, the delivery digests, the token, the pool identity and the
class/sender/OS identity are all deferred to a pool that does not exist yet. The pool must meet
the checklist in §7 before any claim of end-to-end payment security. The results are not safe
to describe as "R0 payment verified on-chain".

## Findings by severity

No Critical or High findings in the reviewed code.

### M1 (Medium, design dependency): the emitted message relies entirely on an unimplemented pool

`account/src/lib.cairo:36-39` emits `[class_hash, 'TMPZR0_PAYMENT_V1', chain, pool, binding]`.
The account checks only `chain == tx.chain_id` (`:33`). It does not check `pool`. The reference
`StatementAccount` stores its pool and asserts it (`controlled-push-e2e/cairo/src/statement_account.cairo:34`).

The reference also does more in the circuit: it checks nonzero and range for chain, pool and
token (`statement.cairo:139`) and nonzero commitments and deliveries (`:171`). R0 moves all of
this, and all spend semantics, into the future pool's `binding` recomputation.

- **Failure scenario.** Suppose a pool recomputes `binding` from delivery digests the caller
  supplies, instead of `delivery_digest(ciphertext)`. It would publish notes whose ciphertexts
  do not match what the prover committed to. Similarly, a pool that does not pin `from_address`
  and the class would accept a message from any account that emits the same 5-felt shape.
- **Fix.** Implement §7 exactly. Optionally, restore defence in depth in the account: store and
  assert the pool, as the reference does, and assert `token != 0` and address range.

### M2 (Medium, evidence): the 15 bridge checks mostly exercise the standalone harness, not the account path

`validate_bridge_r0.py:55-61`: 7 of the 14 negatives (wrong chain, pool, token, root,
nullifier, swapped outputs, delivery) fail on the comparisons in the `#[executable] main`
harness (`bridge/src/lib.cairo:127-135`). The account path has no such comparisons. There, those
properties hold only if the pool recomputes the binding.

Other gaps:
- There is no negative OS capture: wrong tx chain, a proof for another circuit, or a changed
  proof through the account.
- There is no test of circuit identity against real foreign proofs.
- There is no pool-side test.
- The two output-mutation cases (`:47-50`) are rejected at the interaction PoW. So they exercise
  Fiat–Shamir, not the LogUp binding of outputs.

- **Fix.** Add the cases in §6 (13 run here) to the committed validator. Add at least one
  negative OS capture (wrong `chain_id` expecting panic `chain`, and a membership proof
  expecting `not the client circuit`). When the pool exists, add pool-level replay and
  wrong-binding tests. Optionally, re-grind the 20-bit interaction PoW after an output
  mutation, so that the rejection comes from `InvalidLogupSum` or OODS.

### L1 (Low): the relation identifier does not separate formats

The Sponge and Compress circuits emit the same statement tag (`payment.rs:44`, `TMPZ`,`R0V1`),
the same binding domain (`lib.cairo:94`, `'TMR0_BIND_V1'`) and the same message tag
(`account:37`). The circuit identity rests entirely on the class hash, which transitively
carries the circuit pin.

`privacy-contract.md` §2 item 1 asks for a hash-suite and relation identifier in `x`.

There is no double spend across formats: commitments and nullifiers do not depend on the
format. But a pool that accepts both classes against one tree would only have the weaker tree
format's membership soundness.

- **Fix.** Use a distinct tag and binding domain per format and version. The pool should pin
  exactly one class per tree.

### L2 (Low): semantic context checks are weaker than the reference and the context-binding precedent

The bridge checks canonical felts (`lib.cairo:35-46`). It does not check:
- a nonzero chain, pool or token;
- `pool` and `token < 2^251`, which the reference enforces with `addr()`
  (`statement.cairo:124,139`);
- nonzero delivery digests, which the reference checks in-circuit (`statement.cairo:171`) and
  in `publish` (`pool.cairo:158`).

On the client side, `felt_limbs` (`payment.rs:108-114`) does no canonical or field-range check.
A value at or above the field prime just produces a proof the bridge rejects (liveness only).

- **Impact.** Liveness only, provided the pool compares against its own address, a
  `ContractAddress` token and a computed digest.
- **Fix.** Add these checks to the pool, and optionally to the bridge.

### L3 (Low, provenance): `fork_vendor` in the build record is always empty

`build_bridge_arith.py:65` filters out any path with a `target` component. The fork lives
under `…/templar/target/proving-arith`, so every file is dropped.
`target/bridge-r0c/build-record.json` records `"fork_vendor": {}`. The vendored verifier is
identified only by `fork_commit` plus the clean-tree check (`:39-40`).

- **Fix.** Filter on `p.relative_to(UPSTREAM / c).parts`.

### I1 (Info): the proof bytes are malleable

`channel_salt` is reduced mod P before mixing (`circuit_air/src/lib.cairo:231`). The same proof
with `salt + P` is accepted with the identical binding (case `channel-salt-plus-P`, §6).

- **Rule.** The pool and server must never use a hash of the proof or the tx as a replay key.
  The nullifiers are the replay key.

### I2 (Info): a bearer proof with no expiry, relayer or fee

The statement has no fee, relayer, deadline or submitter. Anyone who holds the client proof,
including the server, can wrap and submit it. It cannot be redirected, because every output is
fixed. It stays valid while its root is in the pool's accepted-root history.

- **Rule.** If fees ever come out of shielded value, they must enter the statement. Public fees
  charged to the caller, as in `pool.cairo:112-116`, need no binding.

### I3 (Info): digests are 279 bits

Roots, nullifiers and commitments are 9 × M31 words (279 bits). They cannot be packed into one
felt252 injectively.

- **Rule.** The pool must key nullifiers, roots and leaves by the exact 9 words, or by a
  collision-resistant hash of them. Never reduce them mod p. `privacy-contract.md` §2 says the
  same.

### I4 (Info): how the pin is produced

`prove_payment_r0.rs:286-295` computes the root and circuit hash from the `NoValue` topology.
It asserts the topology equals the witnessed circuit with its blinding (`:288`).

All 13 fresh-witness runs in `scratchpad/r0c/*/trusted-config.json` give the same circuit hash
and preprocessed root.

- **Recommendation.** Add a witness-free pin tool and check it in CI, so that the manifest is
  not a by-product of a proving run.

### I5 (Info): the harness checks lengths late

`main` checks lengths (`lib.cairo:131`) after slicing (`:130`). This is harmless: slicing panics
first. The account does not use `main`.

## Answers

### 1. Circuit identity

A proof for another circuit cannot pass, short of a Blake2s collision.

- **What the hash covers.** `verify_payment` computes
  `compute_circuit_hash(proof.config.log_blowup_factor, proof.commitments[0])`
  (`lib.cairo:52-61`, `circuit_hash.cairo:19-49`). That is Blake2s over the blowup, the
  **compiled** `COMPONENT_LOG_SIZES` and the proof's preprocessed root. The bridge asserts it
  equals the pin (`:62`).
- **What the preprocessed root commits to.** It commits to every wiring column: the eq and
  qm31_ops addresses, the op flags and the multiplicities. The multiplicities include the uses
  by the 23 public outputs, which sit at variables 3..25 (`claims.cairo:68-98`). Topology,
  profile and the placement of outputs are therefore all pinned.
- **Where the rest is fixed.** Verification then uses the compiled constants:
  - `PREPROCESSED_COLUMN_LOG_SIZES`;
  - `N_OUTPUTS = 23`, asserted in both the bridge (`:64`) and the verifier (`lib.cairo:219`);
  - `circuit_fri_config()` = PoW 26, blowup 2, 35 queries, fold 4, last layer 0, asserted
    exactly (`lib.cairo:223-224`).
- **Consistency.** The same `circuit_hash` is mixed into the channel (`:271`). The proof carries
  no circuit hash field of its own that could be used instead.
- **Blowup.** A changed blowup changes the hash (tested). The FRI config pin also rejects it.
- **Absent components.** The generator sets the absent components' column indices to
  `INVALID_COLUMN_IDX = 10^9`. The fork's `CircuitAir` skips components with log size 0
  (`circuit_air.cairo:150-260`), so those indices are never dereferenced. A nonzero claimed sum
  on an absent component is rejected (`claims.cairo:134-147`; tested).
- **N_OUTPUTS substitution.** The substitution is a single exact text replacement, asserted
  (`build_bridge_arith.py:48-49`).
- **Executed here (§6), all rejected with `not the client circuit`:**
  - a real arithmetic membership proof (8 outputs);
  - a real **Sponge-tree R0** proof (same 23-output layout, different circuit);
  - one flipped preprocessed-root word;
  - blowup 1.
- **Also executed:** PoW 20 and 34 queries are rejected by the FRI pin; 22 outputs by `output count`.

### 2. Statement decoding

- **Canonical output coordinates.** The coordinates come from `QM31Serde` into `M31`, whose
  inner type is `BoundedInt<0, P-1>` and is deserialized with a range check. Values `P` and
  `v + P` fail as `INVALID_PROOF_ENCODING` (tested). So every digest word is a canonical M31,
  and the 9-word spans are injective.
- **In-circuit constraints.** M31 guesses are constrained into the base field by a pointwise
  multiply with one at finalization (fork `circuits/src/context.rs:219-222`). Outputs are
  `from_partial_evals` of four M31 variables (`payment.rs:550`), so the coordinates are exactly
  the limbs.
- **Felt fields.** `felt_from_limbs` requires 9 limbs, each `< 2^28`. It rebuilds the value and
  requires it to be `< p`, so the result is canonical and injective. Review unit tests pass:
  a limb of `2^28` is rejected, `p-1` is accepted and `p` is rejected.
- **Context limbs in the circuit.** They are not range-checked in the circuit. That is fine:
  the same variables feed every note commitment (`payment.rs:436,479-485`). So the commitments
  bind exactly the limbs the bridge validates.
- **Layout.** The tag is at 0..2 and checked. The layout matches `statement_limbs`, `build` and
  the bridge slices:
  - chain 2, pool 11, token 20;
  - root 29, nf₀ 38, nf₁ 47;
  - cm₀ 56, d₀ 65, cm₁ 74, d₁ 83.

  All 92 limbs are used, with no padding. **Every limb is checked or bound in the binding.**
- **Pairs.** The (cm_j, d_j) pairs keep their position in both the statement and the binding.
  Swapping the pairs, or crossing the deliveries, changes the binding (computed in Python and by
  a Cairo unit test).
- **Duplicate nullifiers.** The check compares all 9 words (`lib.cairo:77`). The circuit itself
  does not enforce it.

### 3. Binding

- **Construction.** `binding` is `poseidon_hash_span` over exactly 51 felts in fixed order:
  - the domain `'TMR0_BIND_V1'`;
  - chain, pool, token;
  - 9 root words, 9 + 9 nullifier words;
  - 9 cm₀ words, d₀, 9 cm₁ words, d₁.
- **Injectivity.** Every field has a fixed width and every element is canonical. So the encoding
  is injective, and a collision is a Poseidon collision.
- **What the account emits.** It emits the message shown in M1. The OS commits to it:
  PROOF2 output-preimage fact 7 equals `Poseidon(from_address, 0, 5, payload…)`, recomputed here
  and matching `results/stwo-client-r0-compress/proof2/output-preimage.json`.
- **Chain.** Checked against the virtual tx (`account:33`) and emitted.
- **Pool.** Emitted and bound, but not checked by the account.
- **Token.** Bound only inside the binding.
- **Replay across chains.** Blocked by the account check plus the pool's `chain == own chain`
  check.
- **Replay across pools.** Blocked only by the pool checking `payload.pool == self`. The binding
  also covers the pool, and every note commitment binds the pool, chain and token
  (`payment.rs:186-189`), so a proof's inputs cannot exist under another pool's tree.
- **Replay across tokens.** Tokens are separated by the commitment context.
- **Replay across classes.** The class value in the payload is self-reported by the running
  code. It is meaningful only together with a pinned `from_address`, as in the reference
  (`proof_adapter.cairo:291`).
- **Same-pool replay.** Blocked only by nullifiers.
- **Compared with the reference `compute_binding`** (`spend.cairo:54-80`). R0 drops the
  following, which are acceptable for the fixed R0 shape:
  - version, as a separate field: it is folded into the domain and message tag;
  - counts and padding;
  - controller, deadline, nonce and transition;
  - withdrawals.
- **What must stay equivalent.** The reference computes delivery digests **from the
  ciphertext** inside the binding, and R0's pool must do the same.

### 4. Account and OS boundary

- **`__validate__`** (`account:19-26`). It enforces zero tip and zero max prices (prove-only).
  It has no signature check, which is intended because anyone may drive it. It ignores nonce,
  paymaster data and deployment data, none of which reach the payload.
- **`__execute__`.** It requires caller 0.

The payload depends only on the following, so the server cannot choose or change any fact the
client proved:
- the client proof, which fixes chain, pool and binding;
- the tx `chain_id`, which is forced equal to the proved chain;
- the account's own class.

What the server does control:
- which deployed instance (address) it uses;
- the base block (proof age);
- extra transactions in the virtual block;
- whether to submit at all (it can censor or delay).

The pool must pin the address, class, message count, OS program and output version, and check
proof age, as `proof_adapter.cairo:278-293` does.

### 5. Test coverage

The committed 15 cases are listed in M2. Missing before this review:
- foreign-circuit proofs;
- blowup, FRI and output-count variants;
- non-canonical M31 coordinates;
- limb-range and `p` boundary unit tests;
- pair crossing;
- proof malleability;
- any negative OS capture;
- pool tests.

§6 covers all of these except the OS and pool tests.

## 6. Extra cases run (copies only)

The copy is at `scratchpad/review-binding/bridge` and the script is
`scratchpad/review-binding/extra_cases.py`. The results are in
`scratchpad/review-binding/extra/report.json`, and every case behaved as expected. The proof is
`r0c/t4-16-1` unless stated otherwise.

| Case | Expected | Result |
| --- | --- | --- |
| valid, second fresh proof (`t4-16-2`) | accept | accepted |
| arithmetic **membership** proof (8 outputs) | reject | `not the client circuit` |
| **Sponge-tree R0** proof (`r0l`, 23 outputs) | reject | `not the client circuit` |
| preprocessed root word ^1 | reject | `not the client circuit` |
| `log_blowup_factor` 2→1 | reject | `not the client circuit` |
| `pow_bits` 26→20 | reject | `unexpected proof fri config` |
| `n_queries` 35→34 | reject | `unexpected proof fri config` |
| 22 outputs (length fixed up) | reject | `output count` |
| nf₀ word 0 = P | reject | `INVALID_PROOF_ENCODING` |
| nf₀ word 0 = v+P | reject | `INVALID_PROOF_ENCODING` |
| channel_salt + P | accept (malleability) | accepted, same binding `0x7c76…e66f` |
| proof 2 with statement 1 | reject | `context` |
| both (cm, delivery) pairs swapped in args | reject | `commitments` |

The Cairo unit tests added in the copy all pass (6/6):
- a limb of `2^28` is rejected;
- `p-1` is accepted;
- `p` is rejected;
- binding differs under delivery swap and nullifier swap.

The binding in Python changes when the pairs are swapped and when the deliveries are crossed.

## 7. Pool obligations checklist (for parity with the reference)

The future pool **must** do all of the following, atomically in one call.

**Proof facts**

1. It authenticates the PROOF2 facts from `tx_info.proof_facts`, as `proof_adapter.cairo:278-293`
   does:
   - `PROOF…` version, `VIRTUAL_SNOS` variant, pinned OS program hash, output version;
   - base block `< current` and `current - base ≤ max_age`;
   - message count `== 1`;
   - `facts[last] == Poseidon(pinned_account_address, 0, 5, pinned_class, 'TMPZR0_PAYMENT_V1', chain, pool, binding)`.
2. It pins exactly **one** account class per tree. The class transitively pins the circuit hash,
   the FRI config, `N_OUTPUTS` and the verifier code. It rejects a proof in the calldata
   (`PROOF_IN_TX_ONLY`) and accepts calls only from its own flow.

**Context**

3. `chain == get_tx_info().chain_id`, `pool == get_contract_address()`, `token != 0`, and
   `token` is a valid `ContractAddress` the pool supports.

**Binding**

4. It recomputes `binding` from its own values: the domain, chain, pool, token, the 9-word
   root, nf₀ and nf₁ **in statement order**, and cm₀ with d₀ and cm₁ with d₁ **in position
   order**. Each dⱼ must be `delivery_digest(ciphertextⱼ)`, computed by the pool with the
   pinned canonical encoding. Never accept a caller-supplied digest.

**State checks**

5. The root is one of the pool's own **M31** tree roots (`root_is_known`), keyed injectively
   (I3).
6. nf₀ ≠ nf₁ (already in the bridge), each nullifier is unspent, and both are then marked spent.
   Keys are exact or hashed 9-word values, never reduced.

**Outputs**

7. It publishes cm₀ and then cm₁ into the M31 tree with authenticated appends, from the
   **current** root and count (`privacy-contract.md` §5). It stores dⱼ at each index and
   rejects dⱼ = 0.
8. Deposits create M31 commitments with the same formula (context limbs, eight 16-bit amount
   limbs, inner) and u128 amounts. Otherwise the notes cannot be spent, or the value is not
   backed.

**Other**

9. Public fees, if any, are charged outside the statement. Shielded fees need a new statement
   field.
10. It uses a reentrancy lock, as `pool.cairo:154-156` does. Replay protection comes only from
    nullifiers, never from a proof or tx hash (I1).

## Limits

- **Synthetic local runs only.** One synthetic local fixture. No network. No pool exists.
- **What I did not review:** the soundness of the Poseidon2-M31 parameters, the experimental
  truncated-permutation node format, the stwo and FRI soundness at 96 bits, the privacy and
  zero-knowledge properties, or the virtual OS or PROOF2 internals beyond the message-hash fact.
- **Evidence I relied on:**
  - the committed OS capture and PROOF2 reports; I did not rerun them;
  - the committed native-negative and topology tests in `tests/payment_r0.rs`; I did not rerun
    them.
- **Output-mutation rejections** stop at the interaction PoW. I did not attempt a PoW re-grind.
