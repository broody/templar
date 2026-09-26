# Pool V3 with R0 V6: one wallet model

Status: **design, revision 3** (phase A of [ADR-0027](adr/0027-one-wallet-model.md)).
- **Revision 2's re-check** is in the same review record.
  - The Math Reviewer gave CONDITIONAL GO: phase C may start on this design. Its conditions are
    applied here: the full wiring test, the kept binding vectors, the mutation-table rules, and route
    admission per kind.
  - The Protocol Reviewer gave CONDITIONAL GO. Its conditions for coding the routing adapter are
    applied here: the precondition table, the cap and lapse rules, both kinds everywhere, pinned
    generation states, the own route by statement, refunds, and the bucket-check fault rule.
- **Revision 1's design review** (`docs/reviews/pool-v3-spec-design-review.md`): Math Reviewer
  CONDITIONAL GO, Protocol Reviewer CONDITIONAL GO, adversarial review CONDITIONAL GO. It found no
  blockers and confirmed 24 findings, all applied here. The reviewers' answers to revision 1's open
  questions are in §17.
- It replaces [account-bound-note-spec.md](account-bound-note-spec.md), which describes the
  deployed R0 V5 and stays as the record of it until the cutover (§11).
- Nothing here is implemented. Phase B (removing bound mode off chain) is cleared. Phase C may start
  once revision 3's final check is recorded and the §14 amendments are applied. The Math Reviewer
  signed off the relation design, and the routing adapter is coded to §6.3's precondition table.

Targets:
- the compact client-proof path: a new relation `client-port/src/payment6.rs`, a new bridge and
  statement account (`client-port/cairo-r6`), and a new **routing adapter** class
  (`bench/m31-pool`);
- the deployed **M31 pool V3**, unchanged;
- the prover server (`server/`), the relayer, and the SDK (`sdk/`).

Finding IDs from earlier reviews (`AB-*`, `F*`, `PS-*`, `KC-*`, `C*`) are kept where a rule carries
over. This design review's IDs are `MR-V6-*`, `PV3-*` and `PV3-A*`.

## 1. Purpose and scope

One wallet model (ADR-0027 decision 1). Every user holds ordinary Templar notes, spent with the
Templar key inside the client proof. External wallets connect for login, deposits, withdrawals and
paying for the service, and never authorize spends.

This spec defines:
1. **R0 V6**, which is R0 V5 with the mode fixed to ordinary: no mode bit, no `WAUTH`, no published
   account (§3, §4).
2. **The V6 bridge and statement account**, with no signature path (§5).
3. **A routing adapter class** used for both of pool V3's verifier kinds, R0 and P1. It holds
   timelocked routes, so a new statement (an OS rotation, a device route) is added without swapping
   the pool's verifier (§6).
4. **Submission, connected accounts and payment** (§7), and the **prover server** and **SDK**
   changes (§9, §10).
5. **The cutover on Sepolia** from today's adapters to routing adapters (§11). Mainnet deploys V6
   and routing adapters from the start.

Out of scope:
- the vault's specification (ADR-0027 decision 4; phase F);
- the extension (ADR-0027 decision 5);
- the Templar Pass, ticket issuance and relayer operations beyond §7 (P7);
- device-side proving (ADR-0027 decision 6; `bench/m31-device-proof1/PLAN.md`);
- identity-scope rules (F40).

## 2. Baseline (unchanged)

Everything in [hidden-asset-spec.md](hidden-asset-spec.md) (R0 V4, pool V2) not changed below:
- the hash `H(kind, level, payload)`: a framed rate-15 Poseidon2-M31 sponge with nine-word digests;
- felt limbs (nine 28-bit little-endian limbs) and amount limbs (eight 16-bit limbs);
- the note format `cm = H(NOTE, chain₉ ‖ pool₉ ‖ asset₉ ‖ amount₈ ‖ inner)`, with
  `inner = H(INNER, receiver ‖ rho)`;
- nullifiers `nf = H(NF, nk ‖ cm ‖ pos_lo ‖ pos_hi)`;
- the private asset and exit bit, dummy input 1, delivery digests, two outputs and the
  conservation gadget;
- assets and their registry, deposits and payouts.

Receivers are the ordinary ones: `receiver = H(OWNER, H(AUTH, sk) ‖ H(NK, sk))`.

## 3. What changes from R0 V5

| | R0 V5 | R0 V6 |
| --- | --- | --- |
| Mode | `m ∈ {0, 1}`, `m = 1 ⇔ account ≠ 0` | none (ordinary only) |
| Authorization key | `ak = H(AUTH, sk)`, or `H(WAUTH, account ‖ sk)` when bound | `ak = H(AUTH, sk)` |
| Published `account` | nine limbs (127–135) | removed |
| Statement | 138 limbs, padded to 140, 35 outputs | 129 limbs, padded to 132, 33 outputs |
| Tags | `R0V5`, `R0C5` | `R0V6` (`0x52305636`), `R0C6` (`0x52304336`) |
| Binding | `TMR0_BIND_V5` | `TMR0_BIND_V5`, unchanged (§5.2) |
| Message tag | `'TMPZR0_PAYMENT_V5'` | `'TMPZR0_PAYMENT_V6'` |
| Statement account calldata | `(proof_data, salt, signature)` | `(proof_data)` |

**The limb map φ.** V6's statement is V5's with limbs 127–135 (the account) deleted, and
`valid_until` moved from V5's limbs 136–137 to V6's limbs 127–128. V6's tag and three zero padding
limbs complete it.

**Equivalence (normative).** R0 V6 is defined by its own constraints (§4.3). Its accepted set is
exactly the accepted set of V5 with `m = 0` and `account = 0` substituted, mapped by φ. That holds
in both directions:
- every V5-ordinary witness is a V6 witness with the same values;
- every V6 witness is a V5-ordinary witness.

Receivers, commitments, nullifiers, delivery digests, the identity handle and the binding are
equal. The Math review of revision 1 walked `payment5.rs` constraint by constraint. The only
bound-only parts are the account guess, the `m` booleanity check and mode rules, the two `WAUTH`
requests, the per-word selects, and the published account limbs.

**The hash kind `WAUTH = 16` is reserved permanently.** Bound receivers already in pool V3's tree
contain it (§11.5), and no later hash may reuse the kind.

## 4. Relation R0 V6

### 4.1 Public statement

```text
tag₂, chain₉, pool₉, token_out₉, root₉, nf₀₉, nf₁₉, cm₀₉, d₀₉, cm₁₉, d₁₉,
recipient₉, w_amount₈, intent₉, identity₉, valid_until₂
```

- These are 129 limbs: 2 + 13·9 + 8 = 127, plus two for `valid_until`. They are padded with three
  zero limbs to 132 and emitted as **33 QM31 outputs**. The last output is
  `[valid_until_hi, 0, 0, 0]`.
- `valid_until` is a block number below 2^56, as two 28-bit little-endian limbs.
- Tags: `R0V6` (sponge tree) and `R0C6` (compress tree; pool V3 uses the compress tree, F30).
- V3, V4 and V5 keep their modules and output counts; V6 defines its own.

### 4.2 Witness variables

As V4 (hidden-asset-spec §4.2), plus `valid_until`: two guessed words, published. The outputs are
V4's two slots.

### 4.3 Constraints (normative)

V4's constraints 1–8 hold, with these changes:

1. **Keys.** For both inputs, `akᵢ` is the output of the circuit's own `H(AUTH, skᵢ)` evaluation,
   where `skᵢ` is the guessed key whose `H(NK, skᵢ)` enters `OWNERᵢ` and `nfᵢ`. Then
   `receiverᵢ = H(OWNER, akᵢ ‖ nkᵢ)` feeds `cmᵢ`.
2. **Identity (load-bearing).** `handle = H(IDENTITY, ak₀ ‖ scope)`, masked by the identity flag.
   - **The first nine payload words of `IDENTITY` are the output variables of the `H(AUTH, sk₀)`
     evaluation:** the same variables that enter `OWNER₀`, with no second guessed or copied variable
     between them. The digest lanes are themselves tied by `unpack` (§4.4).
   - **The attack this stops.** Suppose `ak₀` were a guessed copy, shared by `OWNER₀` and
     `IDENTITY`. Anyone who knows a victim's `ak_v`, for example a full-viewing-key holder, could:
     1. deposit a note to `H(OWNER, ak_v ‖ H(NK, sk_att))`;
     2. spend it with the guessed `ak₀ = ak_v` and their own `sk_att`;
     3. publish `H(IDENTITY, ak_v ‖ scope)`, the victim's handle, and act through the victim's
        shadow accounts.

     Deriving `ak₀` from `sk₀` inside the circuit rules this out.
   - This is V5's ordinary handle; ADR-0027 amends ADR-0023's `H(IDENTITY, sk₀ ‖ scope)`. No V5
     shadow account exists on Sepolia, since pool V3's allowlist is empty.
3. **Published limbs.** `[tag, pub_ctx, token_out, cur₀, nf₀, nf₁, cm₀, d₀, cm₁, d₁, recipient,
   withdrawn, intent, identity, valid_until]`, then three zero limbs. The circuit does not
   range-check `valid_until`; the bridge does.

**Outputs and conservation are V4's, unchanged:** two output slots, and
`conservation([amt₀, amt₁], [out₀, out₁, withdrawn])` with carries in {−2, …, 1}.

**Invariant B′ (binding coverage).** Every published limb except the tag and the padding enters
the binding (§5.2). Two accepted statements with equal bindings therefore agree on every published
field, up to a Poseidon collision. V5's Invariant B (the binding determines the account) is moot.

### 4.4 Tests (required)

**Ported from V5 (normative).** Every test in `payment_r5.rs` and `payment_r5_malicious.rs` that
does not involve `m` or `account` moves to `payment6` on ordinary fixtures, over all shapes and
both trees. That includes:
- topology shape-independence;
- the F38 pinned-hash test, for R6;
- the ordinary part of `identity_handles_follow_the_selected_key`.

**The mutation table (re-check F7).** The P2 mutant script is not in the repository.
- **Re-run.** The documented table (`docs/reviews/account-bound-p2-math-review.md`, the F09 and
  AB-IM1 tables) is re-run against `payment6.rs`, dropping only the mode and account rows. The
  padding and `valid_until` mirror rows move to V6's offsets.
- **New V6 rows:**
  - a guessed `ak` copy;
  - a guessed `nk` copy into `OWNERᵢ` or `NFᵢ`;
  - `AUTHᵢ` and `NKᵢ` computed over different `sk` guesses;
  - the `R0C6` tag check deleted in the mirror;
  - one row per fan-out wire of the wiring test.
- **Counting kills.** The F38 pinned-hash test, and any comparison with recorded proofs, do not
  count. Each mutant records the test that killed it, or "equivalent".
- **Kept.** The mutant script and its results are committed (for example
  `results/stwo-client-r6/mutants.json`), so the Math implementation review can re-run them.

**New malicious and boundary tests,** each failing to prove or rejected by the bridge:
- each of the three padding limbs, nonzero, one at a time;
- `valid_until = 0`, and each `valid_until` limb at 2^28 (AB-M14);
- with kills for the nonzero and range checks on `valid_until`.

**The wiring test (MR-V6-1; re-check F1, F2),** normative and in AB-M6 style through
`debug_info`.

*What is recorded.* Each wire is recorded where it is produced, under the tamper feature:
- every `hash_batch` return (`AUTH`, `NK`, `OWNER`, `INNER`, `NOTE`, `NF`, `IDENTITY`), keyed by
  batch and request index, since hash kinds repeat across batches;
- every membership level's input node and output (`NODE` in the sponge tree, `NODE1` in the
  compress tree), per path, keyed by level (MR-V6C-1);
- the outputs of the `x` gate on `token` (`token_out`) and of the identity mask;
- every guess site: `token`, `pub_ctx`, the position and amount bits, `e1`, `x`, the identity flag;
- every `amount_from_bits` and `pack` return;
- every consumer slot.

*What is asserted.* Variable-id equality on every fan-out edge and every hash-output-to-consumer
edge, single-use ones included:
- `identity.ak[k] == owner₀.ak[k] == auth₀.out[k]`;
- `ownerᵢ.ak == authᵢ.out`, and `ownerᵢ.nk == nfᵢ.nk == nkᵢ.out`;
- `authᵢ.in == nkᵢ.in ==` the `skᵢ` guess;
- `nfᵢ.cm == pathᵢ.leaf == noteᵢ.out`, and `NFᵢ`'s lo and hi inputs are the `pack` outputs over the
  same bit variables as the path;
- `innerᵢ.recv == ownerᵢ.out`, and `noteᵢ.inner == innerᵢ.out`;
- the `NOTE` amounts are the conservation amounts;
- `withdrawn` is the same variable in conservation, the `x` gate and the published limbs;
- `token` is the same variable in all four `NOTE` contexts and in `token_out`;
- `pub_ctx` is the same variable in `NOTE` and in the published limbs;
- the published root is `cur₀`, and the published `nf`, `cm`, `token_out` and `identity` are the
  gate outputs;
- every membership hop: level 0 reads `noteᵢ.out`, level `l + 1` reads level `l`'s output, and
  `pathᵢ.root` is the last level's output;
- the enabled-input gap compares `path₀.root` with `path₁.root`, and the idle rule reads the
  `sum₁` that input 1's amount limbs make.

Every hash digest word is itself a guessed M31 lane, tied to the permutation by `unpack`'s repack
check. So the test compares variable ids with the lanes `hash_batch` returns. Optionally, it also
checks that each slot variable is an `unpack` lane tied by its repack check to that permutation's
output.

*Mutation kills.* A guessed copy of any recorded wire, on the path to any of its consumers, fails
the wiring test. `check_vars_used` is not relied on for hash-output wires. If it is kept as an
extra guard, `c.set_outputs(&outputs)` runs first, or `finalize(true)` does.

**The plant test** (a regression, not a mutation kill; re-check F8). The planted note is built with
`payment_r5_malicious.rs:98-114`'s `plant(tree, public, p, |_| ak_v)`. The honest V6 circuit is then
run with `sk_att`, and must fail, or publish neither that root nor `H(IDENTITY, ak_v ‖ scope)`
(compare `payment_r5.rs:303-326` and `:161-194`). The mutation table credits the guessed-`ak` mutant
only to the wiring test.

**Cross-version tests (MR-V6-6).**
- **V5-ordinary against V6 equality,** over all shapes and both trees, as in
  `payment_r5.rs:164-196`. It includes an identity-active shape and a single input with its stored
  companion, compares limbs under φ, and is mirrored in part in the SDK core's vectors.
- **A `TMR0_BIND_V5` known-answer test (re-check F3).**
  - **The anchor:** the starknet.js vectors in `cairo-r5/kat` (`kat.json` "bindings", and the binding
    part of `gen_kat.cjs`), moved to `cairo-r6/kat` or `sdk/vectors`.
  - **The check, at the statement level:** these all equal the anchor's values, at `valid_until` 1
    and 2^56 − 1 and with a nonzero identity:
    - the V6 bridge's `binding()`;
    - `spend5.cairo`'s `compute_binding`, over a `Spend` whose ciphertexts give the same `d_j`;
    - the Rust binding and the SDK binding.
  - **The Cairo decode offsets** (`valid_until` at 127–128, padding at 129–131, the `R0C6` tag) are
    exercised by a `validate_bridge_r6` run on real proofs. It accepts every shape, recomputes each
    binding independently, and rejects V4's forged statements, `valid_until = 0`, each `valid_until`
    limb at 2^28, and each nonzero padding limb.
- **Positive cases:** every V4 shape; `valid_until = 1`; `valid_until = 2^56 − 1`.

**The hiding regression** (F27, ADR-0024 gate 4) is run for V6's circuit.

### 4.5 Budget

- R0 V5 proves at trace 2^18. V6 drops two `WAUTH` hashes (four permutations), the mode gadget,
  the selects and nine published limbs, so it stays at 2^18.
- The WebAssembly proof time is measured again (phase C). The target is at or below V5's median of
  6.2 s in Chrome.

## 5. Bridge and statement account (`cairo-r6`)

### 5.1 Bridge checks

The bridge decodes and range-checks every limb as V4 does, and checks everything V4's bridge
checks (hidden-asset-spec §4.5). It also checks:
- **Offsets under φ** (§3). `valid_until` is at limbs 127–128, and the padding at 129–131.
- **`valid_until`:** both limbs are below 2^28, and `valid_until ≠ 0`.
- **Padding:** all three padding limbs are zero.
- **Tag:** the tag is `R0C6` (pool V3's compress tree).

The Rust mirror `bridge_checks` matches the bridge exactly (F15).

### 5.2 Binding

```text
binding = Poseidon('TMR0_BIND_V5', chain, pool, token_out, root₉, nf₀₉, nf₁₉, cm₀₉, d₀, cm₁₉, d₁,
                   recipient, w_amount, intent, identity₉, valid_until)
```

- It is byte-identical to `spend5.cairo`'s `compute_binding`, which pool V3 recomputes from the
  `Spend`. The tag stays `TMR0_BIND_V5`, because pool V3 hardcodes it (`spend5.cairo:37`).
- Relation versions are told apart by where the message comes from. The routing adapter pins, per
  route, the statement account, its class and its account tag inside the message hash (§6), and the
  OS enforces the message's `from_address`.
- This is safe only because every route satisfies the route relation invariants of §6.5: notes,
  nullifiers, the identity slot and the binding mean the same thing under every route.

### 5.3 Statement account

`__validate__(proof_data)` checks zero tip and zero prices only (`PROVE_ONLY`, as V5).

`__execute__(proof_data: Span<felt252>)`:
1. The caller is 0 (`OS_ONLY`). This caller-0 guard blocks re-entry, and stays in `__execute__`: a
   direct call to `__execute__` skips `__validate__`.
2. `statement = verify_payment(proof_data)`, and `statement.chain` equals the transaction's chain
   id. This duplicates the adapter's chain check, and is kept as defense in depth.
3. Emit exactly one message, `[class_hash, 'TMPZR0_PAYMENT_V6', chain, pool, binding]`, to
   `to_address` 0.

There is no salt, no signature, no constructor argument, no storage read and no external call. The class has no `replace_class`, no
`library_call` into mutable code, and no `is_valid_signature`. So it satisfies the route admission
checklist of §6.5. Class size is expected below V5's 63,483 CASM felts.

## 6. The routing adapter (new class)

Pool V3 has one verifier slot per kind (`R0`, `P1`). A routing adapter fills one slot and holds
routes, so a new statement account (an OS rotation, a device route) is added as a route under the
pool's timelock, without a verifier swap. Both kinds use the class: two instances, one per kind
(§11).

### 6.1 Routes and the constructor

**A route pins eight fields:**
- `statement`: the statement account's address;
- `statement_class`: its class hash;
- `account_tag`: the message tag it emits;
- `os_program`: `facts[2]`;
- `proof_version`: `facts[0]`, `'PROOF2'` for the large path;
- `proof_variant`: `facts[1]`, `'VIRTUAL_SNOS'` today;
- `output_version`: `facts[3]`, `'VIRTUAL_SNOS0'` today;
- `max_proof_age`: in blocks.

The class fixes only the nine-felt facts length and the one-message rule, `facts[7] == 1`.

**Routes are keyed by `statement`, and every route has its own statement account.** An OS rotation
or a device route deploys a new instance of a reviewed statement class at a new address (a new
salt) and adds it as a new route. So routes never replace each other in place, and a proof matches
at most one route, since the message hash covers the OS-enforced `from_address`. **A removed key is
retired** (ADV-V6-3): once its removal applies, `propose_route(key, Some(_))` is refused
(`ROUTE_RETIRED`), with the same fields or others. Restoring a route removed by mistake takes a new
statement-account instance.

**The constructor** takes the pool, the adapter's `kind` and the initial routes.
- It requires a nonzero pool, `kind ∈ {'R0', 'P1'}`, between 1 and `MAX_ROUTES = 4` initial routes,
  and distinct keys.
- Each initial route passes `propose_route`'s per-route checks (§6.3): every field nonzero,
  `0 < max_proof_age ≤ E + Q`, `statement` neither the pool nor this adapter, and
  `get_class_hash_at(statement) == statement_class`. Each emits `RouteSet(statement, Some(route))`.
- The adapter is bound to exactly one pool.

**The adapter class is immutable:** no `replace_class`, no `library_call` and no owner storage. The
SDK, server and relayer pin `get_class_hash_at(adapter)`. Phase C fixes the Serde order of the
`Route` struct, with known-answer vectors shared by the Cairo code, the SDK and the server
(`sdk/vectors/routing.json`, generated by `bench/m31-pool/gen_routing_vectors.py`): a route, `Some`
and `None`, a two-route `get_routes()` and a `get_route_proposals()` with an addition and a removal.

### 6.2 Verification

`verify(proof, public_inputs)` keeps `Proof2Adapter`'s checks, generalized:
- **Caller and inputs:**
  - `proof` is empty (`PROOF_IN_TX_ONLY`), and the caller is the pool (`ONLY_POOL`);
  - `public_inputs` is `[chain, pool, binding]`, with `chain` equal to the transaction's chain id
    and `pool` equal to the pool;
  - the facts have nine felts, and `facts[7] == 1`.
- **A route matches.** There is an active route whose `proof_version`, `proof_variant`, `os_program`
  and `output_version` equal `facts[0]`, `facts[1]`, `facts[2]` and `facts[3]`, and whose message
  hash `Poseidon(statement, 0, 5, statement_class, account_tag, chain, pool, binding)` equals
  `facts[8]`.
- **That route's age bound:** `base < current` and `current − base ≤ max_proof_age`, where
  `base = facts[4]`.
- **That route's class, re-read** (PV6-C3): `get_class_hash_at(statement) == statement_class`
  (`ROUTE_CLASS`). This is defence in depth only. It catches a class change still in place at
  submission. It cannot see the class at the proof's base block, so a class swapped away and back
  before submission passes. Immutability after apply is an admission rule (§6.5).
  It is checked before the age bound, so a proof failing both reverts with `ROUTE_CLASS`.

A proof that matches no active route is rejected (`NO_ROUTE`).

### 6.3 Route changes (timelocked like the pool)

The adapter has **no owner of its own.** It reads the pool's owner (`get_owner`) and its timelock
constant (`get_parameters().timelock`) at both propose and apply. So one multisig and one `T` govern
every lever.
- Transferring the pool's ownership also transfers route governance. Pool V3's ownership transfer is
  two-step but not timelocked, and routes inherit that as every pool lever does. The SDK surfaces
  `OwnershipTransferStarted` and `OwnershipTransferred`.
- The owner call is a view on the pool that takes no lock, so it raises no reentrancy concern.

**Proposing and applying are allowed only while this adapter is the pool's verifier for its kind**
(`pool.get_verifier(kind) == this`). Before activation, routes come only from the constructor,
which the pins cover (§10.2). Cancelling is allowed at any time.

**The calls:**
| Call | Preconditions | Effect |
| --- | --- | --- |
| `propose_route(statement, Some(route))` | owner; active; `statement` is not an active key and is not retired; every field nonzero; `0 < max_proof_age ≤ E + Q`; `statement` is neither the pool nor this adapter; `get_class_hash_at(statement) == statement_class`; active routes + 1 ≤ `MAX_ROUTES`; pending proposals (lapsed ones included) below `MAX_PENDING = 2`, unless this replaces a same-key proposal | records the proposal with `eta = block_timestamp + T`; a replaced same-key proposal emits `RouteCancelled`; emits `RouteProposed` |
| `propose_route(statement, None)` | owner; active; `statement` is an active key; the same pending cap | as above, for a removal |
| `apply_route(statement)` | owner; active; `block_timestamp ∈ [eta, eta + T]`. For an addition, re-checks that the key is not retired, the class hash and active routes + 1 ≤ `MAX_ROUTES`. For a removal, at least one route must remain | applies the change; a removal retires the key; emits `RouteSet(statement, Option<Route>)`; clears the proposal |
| `cancel_route(statement)` | owner; a proposal exists, lapsed or not; allowed while inactive | clears it; emits `RouteCancelled` |

- **Replacing a route in place is not possible.** A changed route is a new statement account,
  added, and the old one is removed later (§6.4).
- **Lapsed proposals** stay listed, and count toward `MAX_PENDING`, until they are cancelled or
  replaced, as the pool's own proposals do.
- **Replacing a sole route found unsound:** propose the fixed route and the removal together (two
  pending proposals), then apply the addition first.
- **Events** carry the full route, with `statement` as a key: `RouteProposed`, `RouteCancelled` and
  `RouteSet`. Phase C tests every row and edge case of the table.

**Views:**
- `get_pool()` and `get_kind()`;
- `get_routes()`: the full active set, compared by clients as a set;
- `get_route(statement) -> Option<Route>`;
- **`get_route_proposals()`:** every pending proposal, as `(statement, Option<Route>, eta)`. This is
  the normative source of pending route changes. An event scan is an optional cross-check.

### 6.4 Values, size and OS rotation

- **`max_proof_age = 1,024`** for today's routes, well above PROOF2 latency.
- The class is small, so declaring it costs a few STRK. It adds an owner lever, which the governance
  review and the guide's governance page cover.
- **OS rotation,** in order:
  1. deploy a new statement-account instance of the same reviewed class;
  2. `propose_route` it with the new `os_program`, and `apply_route` it before the gateway switches
     programs;
  3. at the switch, the server moves its OS runner and its route pin to the new route;
  4. remove the old route no sooner than `max_proof_age` blocks after the switch.

  The server's "own route" is the route keyed by the statement address in its relation's
  configuration (§9.5). So a new route under a new key never triggers the server's own-route
  refusal. P1 rotates the same way, since it too has a routing adapter.
- **Anonymity partition.** The proof facts show each spend's route: the proof version, the OS
  program, and the statement, which can be derived from the message hash. So concurrent routes
  partition the anonymity set. Overlaps are kept short, and every route proposal's review, and the
  device-route ADR, state the expected size of that set.

### 6.5 Route admission (normative)

**A routed statement class** must satisfy:
- no constructor arguments, no storage reads and no external calls, so its class hash fixes its
  relation (re-check F6);
- no `replace_class`, and no `library_call` into mutable code. The adapter cannot enforce this
  after apply (§6.2's class re-check sees only the class at submission), so it is enforced by this
  admission review;
- exactly one message, emitted only from `__execute__` behind the caller-0 guard, with payload
  `[runtime class, tag, chain, pool, binding]`, where `binding` is `spend5.cairo`'s
  `compute_binding` for R0 (`policy_binding` for P1);
- `__validate__` is `PROVE_ONLY`;
- no `is_valid_signature`.

**Route relation invariants, per kind (MR-V6-2; re-check F5, PR2-4).**
- **Accepted-set inclusion.** For every R0 route `R`, any accepting `R` transcript whose statement
  passes `R`'s bridge yields, efficiently, a V6 witness for the same decoded statement. For every P1
  route, the same holds against the P1 relation and `policy_binding`.
- **R0 domain:**
  - `OWNER` receivers;
  - `nf = H(NF, H(NK, sk) ‖ cm ‖ pos_lo ‖ pos_hi)`;
  - the first nine words of the `IDENTITY` payload are input 0's in-circuit `H(AUTH, sk₀)`, never a
    raw or guessed key;
  - `TMR0_BIND_V5` semantics.
- **P1 domain:**
  - `PRECV` receivers;
  - `nf = H(NF, pnk ‖ cm ‖ pos_lo ‖ pos_hi)`;
  - `TMP1_BIND_V1` semantics, with no identity slot.
- **Consequences, stated normatively:**
  - each note (a `cm` at a leaf position in the pool's compress tree) has exactly one nullifier any
    route can publish for it, equal to its kind's formula;
  - every published nullifier, a disabled input's included, is computed over values the prover
    knows, never a free word.
- **Cross-kind rules:**
  - every route spends only leaves of its own kind's receiver domain;
  - no route spends `WAUTH` receivers;
  - the distinct binding tags `TMR0_BIND_V5` and `TMP1_BIND_V1` keep a route placed in the wrong
    kind's adapter harmless;
  - a relation in a new domain uses a distinct receiver hash kind, conserves value per asset across
    all domains, and derives any identity handle over `H(AUTH, sk₀)` or a separate kind.

§3 is the instance for V5 and V6. The P1 relation was already reviewed, so admitting the existing
P1 statement account needs only the class checklist and these invariants.

**Review (re-check F6):**
- **Math review is skipped only** when `statement_class` equals a class hash already signed off (a
  recompile is a new class) and the change is a new OS program or proof version. Any other new
  relation needs a Math review.
- **A new `os_program`** must equal the hash embedded in the pinned StarkWare virtual-OS release, the
  value the server's startup check compares against its runner.
- **Each route proposal states** which facts the sequencer, not the adapter, is trusted to check
  (`facts[5]` and `facts[6]`), and the expected size of its anonymity set (§6.4).
- A relation with new public fields needs a new pool.

## 7. Submission, connected accounts and payment

### 7.1 Outputs

A spend has V4's two outputs (payment and change, or dummies), in uniformly random order
(sdk-spec §7.2). No output pays the relayer or the pool.

### 7.2 Who submits

- **Plain spends (`apply_spend`).** The service's relayer submits every spend the server proves.
  Spend results go from the vault (ADR-0027 decision 4) straight to the prover server and the
  relayer, never through the application.
- **Invokes and P1 settlements** (`apply_spend_with_invoke`, including `COMPUTE`, and
  `apply_policy_spend`) are not relayed until the SDK's tight minimums exist (F06). Until then the
  vault's submitter account submits them, after the user consents (below).
  - **Relaying invokes is a launch requirement for the web application.**
  - SDK submission of invokes and P1 settlements from the vault is an explicit deliverable of phases
    C and F.
- **Every linkable submission asks first (PV3-7, PV3-A4).** Before any submission that links an
  account to the spend (from the vault submitter, or an override), the SDK asks the user. It names
  the account and says how the account was funded. It offers the alternatives:
  - wait and retry the relayer until `send_deadline − FALLBACK_MARGIN`;
  - a second relayer, once one exists;
  - let the record die and plan again.

  A relayer refusal never triggers a linkable submission by itself.
- **Refunds when the service fails to settle (PR2-7).** A relay item can end with no landed or pending
  transaction for a cause that is not the client's:
  - a relayer refusal, or the relayer not taking the item in time;
  - a deadline or root margin that the server admitted;
  - a verifier or route change after admission.

  In those cases the server returns blind refunds on the job's stored refund requests, and the SDK
  plans again with them. So letting a record die costs only liveness. A nullifier spent elsewhere,
  or any other client cause, keeps the tickets spent.
- **Fallback for plain spends,** in order: a second, independently operated relayer, once P7
  defines its job intake; then the vault's submitter account, with consent. The timing rule of
  account-bound spec §7.4 (P4b) is unchanged: at once after a refusal, otherwise only from
  `send_deadline − FALLBACK_MARGIN` (40 blocks), and never while the relayer's transaction is
  pending or after it landed.
- **The vault's submitter account** is never funded from the connected account; that is a
  constraint on phase F. Any funding is public, and its amount and timing can correlate. One reused
  submitter account links all its submissions to each other.
- **The connected account** submits only through an explicit, linkable override. That override
  needs a wallet API that signs and sends a proof-carrying transaction. None is known today; until
  one exists and is tested on Ready, Braavos and Controller, the override is unavailable.
- A standard paymaster does not replace the relayer: the paying account would be the transaction's
  account.

### 7.3 Relayer

**Acceptance** is account-bound spec §7.3's. Before submitting, the relayer:
1. requires `send_deadline ≥ latest + margin`, a root the pool accepts (account-bound spec §8.3)
   and unspent nullifiers;
2. checks that `get_verifier('R0')` is the pinned adapter with its pinned class, and that `get_route(statement)` equals
   the pinned route in all eight fields (PV3-A8). A mismatch is answered "retry later", never
   "refused";
3. simulates with validation, and keeps a deduplication set of nullifiers until each deadline;
4. for invokes, relays only with tight minimums (F06).

The handoff, answers and margins of account-bound spec §7.4 (P4b) are unchanged.

**What changes for the relayer:**
- its pins become a set of generations per kind: adapter, its class, route set, circuit hash and
  relation version;
- **dual-version (PV3-5).** During the cutover it serves both generations, with the relation carried
  on each relay item and the verifier and route checked per item. The server relays both `r5` and
  `r6` until apply;
- it does not permanently deny notes whose revert reason is a verifier or route rejection.

### 7.4 Connected accounts (normative)

- **Identity separation:**
  - no login session, cookie or wallet credential reaches the prover server, the relayer or the
    ticket redeemer;
  - job requests carry no session;
  - OHTTP is recommended for job submission.
- **RPC separation:**
  - The vault owns the spend provider, and refuses one that shares a node with the application's
    provider.
  - Spend-specific reads cover fee estimates, simulation, nullifier, root and recipient checks, and
    status polling. They go through the relayer, or through a provider that has not seen the
    connected account, over OHTTP where available.
- **The pass.** Buying it on chain with the connected wallet would publicly link the pass to the
  depositing account. So the pass is bought from an unlinked account, or paid off chain so the mint
  does not name the payer. P7 decides which (AB-P32).

### 7.5 Templar Pass, tickets and free withdrawals

Account-bound spec §7.2 carries over (a summary; P7 specifies it), with these changes:
- **No account.** Claim timing and issuer-key periods remain the only links between a pass and
  spends. The cost table is unchanged.
- **Free full withdrawals** keep their check: `intent = 0`, a priced `token_out` at or above its
  minimum, and the openings of both outputs as zero-value notes. The per-account daily cap goes.
- **Deposit cycling (PV3-A6).** An attacker can repeat "deposit, then free full withdrawal", paying
  only a deposit's gas per cycle while the service pays for a PROOF2 and the relayer's gas. A
  per-note limit cannot stop it: the server cannot recognize a note across spends without learning
  it. A per-asset limit adds nothing beyond the global bucket. So:
  - **every free job, over OHTTP or not, carries a proof-of-work stamp** (PS-13) priced near the
    service's cost of one job, with difficulty rising as the free queue fills;
  - the global bucket is sized to the relayer's gas budget, and the 25% prover-time share stays;
  - **free exits are best-effort** and can be exhausted by one party. Paid exits and self-hosting
    are unaffected, and the product says so.

## 8. M31 pool V3 (deployed, unchanged)

Pool V3 is account-bound spec §8, deployed on Sepolia (`bench/account-bound-p6`). Its code, `Spend`
format, binding, expiry (`E` 1,500, `Q` 100), root window (`W` 4,096), timelock (`T` 7,200 s on
Sepolia; at least 7 days on mainnet), fixes and "no fees, no gating" rule all stay. Changes are in
its configuration only:
- its R0 verifier becomes a routing adapter with the V6 route (§6, §11);
- its P1 verifier becomes a routing adapter with one route: pool V2's P1 statement account, whose
  circuit carries the H2 fix, checked against §6.5 before the swap;
- its shadow-class allowlist stays empty until a class is reviewed and proposed.

The owner levers of account-bound spec §8.4 stand. Routes add one lever, governed the same way
(§6.3). On mainnet, pool V3 is deployed and initialized with routing adapters directly.

## 9. Prover server

### 9.1 Job body

```text
{ relation: "r6", proof, statement,
  pool_call: { entry_point: "apply_spend" | "apply_spend_with_invoke", calldata },
  payment?: { tickets, refund_requests } | { free_full_withdrawal: { openings: [inner₀, inner₁], stamp } } }
```

There is no salt and no signature. The pool call is parsed strictly and matched field by field to
the bridge-checked statement, as in P4.

### 9.2 Admission

In order, cheapest first:
1. size and encoding;
2. configuration match;
3. payment:
   - tickets, reserved;
   - or the free-withdrawal check, with its proof-of-work stamp, which routes the job to the free
     queue;
4. work deduplication;
5. expiry;
6. chain state: root known, nullifiers unspent, and the root still accepted at `send_deadline`;
7. the bridge, and the calldata match.

The checks mirrored from the pool (account-bound spec §9, "Checks mirrored from the pool") carry
over, including an invoke's state (AB-SP7). At admission and again at job start, the server also
requires:
- `get_verifier(kind)` for the relation's kind is a pinned adapter, with its pinned class, and
  `get_routes()` is a pinned state of its route set (§10.2);
- the relation's route is active and equal to its pin in all eight fields;
- no verifier change for that kind, and no change to its own route, is due (§9.5).

V5's step 8, the signature check, is gone. The ticket states follow P4 by cause, without the
signature-failure case, plus the refunds of §7.2 (relay failures) and §9.3 (bucket failures that
are the server's fault).

### 9.3 Job start and bounds

- **Job start** repeats the expiry, chain, verifier and route checks at the chosen base block. The
  virtual transaction's calldata is `(proof_data)`.
- **Resource bounds:** caps on virtual-OS steps, named builtins and Blake compressions, measured
  again from a V6 virtual-OS run on live Sepolia state (phase C). If the OS result does not report
  Blake, the prover binary checks it. `os_l2_gas` (default 450M, sized from the bound
  `__execute__`) is measured again.
- **The bucket check (§17, answer 4).** Before proving, the server asserts that the job's component
  sizes fit the pinned PROOF2 leaf bucket, so that every spend has the same public PROOF2 header.
  This replaces the class allowlist and the padding.
  - **Fault (PR2-12).** A failure is the client's fault only when `proof_data` deviates from the
    pinned proof structure for the statement's shape; its tickets then stay spent. Otherwise it is the
    server's fault, and the tickets are refunded.
  - **In practice** the bridge pre-check already fixes `proof_data`'s structure, so a miss at the
    bucket stage is always the server's fault.
  - **Checks.** The server runs a reference job against the bucket at startup and refuses to start if
    it misses; a route switch is a new release, so the restart that deploys it checks again. Phase C
    measures the margin across every V4 shape and both trees.

### 9.4 Data and RPC

- Bound-mode data rules go: no tmpfs requirement, no memory-only retention for bound jobs, no
  operator-controlled node. Jobs follow prover-server-spec's ordinary retention.
- The pre-checks still send the statement's root and nullifiers to the server's node. A self-hoster
  should use their own node for privacy (prover-server-spec §2), but it is no longer required.
- Removed settings and outputs:
  - `operator_node`, `bound_account_classes`, `bound_data_dir`, `bound_retention_secs`;
  - the bound fields in `/v1/info`, the per-account free cap, and the 403 reasons `account_class`
    and `signature`.

  `prover.example.toml` is updated.

### 9.5 Info, pins, pending changes and dual-version operation

- **`/v1/info`** gains an `r6` section: the pool parameters (`E`, `Q`, `W`, `T`), the adapter, the
  server's route and the circuit hash. It has no spend-message hashes.
- **Per-route proof ages (§17, answer 2).** `max_proof_age` moves from the network section to each
  relation's route. The startup check compares each route. `pending_margin_secs` defaults to the
  largest age served times 6 seconds.
- **Pending changes.** The server refuses a relation's jobs from `pending_margin_secs` before `eta`
  until `eta + T`, unless the change is applied, cancelled or lapsed, when either of these is due:
  - an R0 verifier change;
  - a change to the server's own route: the route keyed by the statement in the relation's
    configuration.

  A pending route addition under a new key does not stop the server. The same rules apply to `p1`,
  keyed on `'P1'` (PR2-1).
- **Results name their route (PR2-3).** Each job result and relay item carries the route key
  `statement` (the statement account's address, §6.1), distinct from the job body's public
  statement. The SDK
  and the relayer check `facts[0..3]`, the age and the message hash against that route.
- **The config hash** (`facts[6]`) stays pinned. If an OS rotation changes it, it moves into that
  route's pin.
- **Dual-version operation, for the cutover only.**
  - The server starts with both `r5` and `r6` configured, and treats whichever is not the pool's
    current R0 verifier as dormant, not fatal. It switches on `get_verifier('R0')`, without a
    restart, when the swap applies.
  - For `p1`, no new relation version is needed, only an adapter switch. The old P1 adapter and the
    P1 routing adapter are both configured, and `get_verifier('P1')` selects one. The one not selected
    is dormant, not fatal at startup.
  - The release after apply removes the `r5` pins and the old P1 adapter.

## 10. SDK

### 10.1 Removed

- Bound wallets: `boundWallet`, `boundSetupCheck`, `BoundSigner`, `authorize`,
  `BOUND_ACCOUNT_CLASSES`, and the `prover_account_class` error code.
- The core's bound keys and `snip12`.
- The `spend_message` check on servers.
- `sdk/vectors/keys.json`'s `bound_seeds`, regenerated with `check_keys.py` and `vectors_keys.rs`.
- **Not removed in phase B: the SNIP-12 vectors and tests.** They test code that stays: `cairo-r5`
  is the deployed V5 source, and its bridge's `snip12_kat.cairo` is generated from `cairo-r5/kat`'s
  SNIP-12 part; `bench/wallet-sig-spike/snip12` is a spike that `wallet-sig-spike/e2e` builds on. No
  live path uses them after phase B. The starknet.js `TMR0_BIND_V5` vectors in `cairo-r5/kat`
  (`kat.json` "bindings" and the binding part of `gen_kat.cjs`) are **kept**, and phase C copies
  them to `cairo-r6/kat`, where they anchor §4.4's binding test (re-check F3).

### 10.2 Changed

- **Versions.** The relation version `v6` is separated from the pool's ABI generation (pool V2,
  pool V3) in the network, chain and prover modules and in core `pool.rs`.
- **Generations (PV3-5, PR2-2).** For each kind, a pool entry holds a list of generations. A
  generation is an adapter, its class, and every pinned state of its route set.
  - A release pins every state a planned change passes through: before and after each addition and
    each removal. It also pins each planned removal as a proposal.
  - The SDK accepts `get_routes()` equal to any pinned state of the current adapter. It checks a
    result against the route in that state whose message hash matches `facts[8]`.
  - The SDK plans with the R0 generation whose adapter is `get_verifier('R0')`. Records planned under
    V5 before apply finish or expire.
- **Pins and checks (PV3-2, PV3-A2, PR2-1).** For **both kinds**, wherever the SDK checks a verifier,
  it also requires:
  - `get_verifier(kind)` equals a pinned adapter, and `get_class_hash_at(adapter)` its pinned class;
  - `get_pool()` equals the pool;
  - `get_routes()` equals a pinned state of that adapter's route set: the count, and all eight
    fields of each route;
  - `get_class_hash_at(route.statement) == route.statement_class` for each active route;
  - `get_route_proposals()` holds nothing but pinned planned changes, or removals of pinned routes
    that leave a usable route (§10.3).

  Any mismatch is treated as `verifier_changed`. These views replace the storage-slot reads in
  sdk-spec §8, in the prover-server spec, and in §11.1's read-back.
- **Connected-account rules** (§7.4): spend reads through the relayer or an unseen provider, and
  submission per §7.2, with consent for any linkable submission. The owner-submit refusal
  generalizes: a connected account never submits by default.
- **Backup check.** Addresses are gated on the seed's word check.
- **The vault split** (ADR-0027 decision 4) is specified in phase F.

### 10.3 Pending changes

The SDK shows every pending proposal with its `eta` and lapse time (account-bound spec §8.4), and
surfaces ownership-transfer events. For **both kinds** (PR2-1), it reads `get_route_proposals()` on
the current adapter, and on any adapter that is the value of a pending verifier proposal. An unpinned
change on either kind refuses deposits, even though the SDK does not plan P1 spends yet.
- **A pending change that equals one pinned in the running SDK release (PV3-8)** shows a notice and
  does not block deposits. The change is the full value, either:
  - a verifier proposal whose adapter has exactly the pinned route set and no pending route
    proposals, re-checked on every poll until apply;
  - or a route proposal equal to a pinned planned route, or a pending removal of a pinned route,
    unless it would remove every route the SDK can use (PR2-2).
- **Any other pending verifier or route change** refuses deposits and offers an exit: a route is as
  strong as a verifier.
- A pending shadow-class change is unchanged: a warning, and routes that would break are not built.

For the Sepolia cutover, the owner may keep the stricter rule (deposits refused even for the pinned
change) as a drill.

## 11. Cutover on Sepolia

Every on-chain action is approved by the owner. Mainnet needs no cutover: it deploys V6 and routing
adapters from the start.

### 11.1 Before `propose` (phase D)

1. Declare and deploy the V6 statement account. Declare the routing adapter class. Deploy two
   instances:
   - `R0`, with the V6 route;
   - `P1`, with the P1 route, after checking the P1 statement account against §6.5.
2. Read back, for both adapters, through the views (§10.2): `get_pool`, `get_kind`, `get_routes` and
   `get_route_proposals` (empty). Also read back each adapter's class and each route's class on
   chain.
3. Release the SDK, server and relayer with those pins, in dual-version mode (§7.3, §9.5, §10.2).
4. Announce the cutover.

### 11.2 The swap (phase E)

1. `propose('R0', r0_adapter)` and `propose('P1', p1_adapter)` on pool V3, in the same window.
2. Deposits are refused from `propose` (or allowed with a notice, per §10.3). The server refuses
   `r5` jobs, and `p1` jobs likewise, from `eta − pending_margin`: with `T` = 7,200 s and a margin of
   6,144 s, that is about 18 minutes after `propose`.
3. `apply('R0')` and `apply('P1')` within `[eta, eta + T]`. If the window passes, the proposals
   lapse and are proposed again.
4. At apply, the server and relayer switch to `r6`.

### 11.3 After apply

1. V5 records die at `valid_until` plus the record depth, and the wallet plans them again under V6.
2. The relayer's denial state for V5 spends is cleared, and the next release removes the `r5` pins.
3. **A Sepolia end to end up to the gateway:** P6's ordinary deposit (1,000 token A) is spent under
   V6 through the SDK, the `r6` server and the relayer's simulation. The gateway still refuses
   PROOF2.

### 11.4 Governance drill (PV3-14, PR2-11)

1. Simulate a V5 proof against the routing adapter, and expect `NO_ROUTE`.
2. **Propose an unpinned dummy route, then cancel it.** The SDK blocks deposits with the alarm; the
   server keeps serving `r6`, since the change is not its own route.
3. **Add a planned route.** Deploy a second instance of the reviewed V6 class (a new salt), pinned
   as a planned route in the release, then propose and apply it. The SDK accepts the new pinned
   state, and the server keeps serving. Remove the route no sooner than `max_proof_age` later.
4. **Read back** `get_routes()` and `get_route_proposals()` on both adapters, P1 included.

Simulating the activation gate and the last-route refusal is optional, since phase C tests cover
them.

### 11.5 Stranding

After apply, a bound receiver `H(OWNER, H(WAUTH, A ‖ sk) ‖ nk)` could be spent under V6 only with a
second preimage of the receiver (account-bound spec S1). Every bound receiver in pool V3's tree is
therefore unspendable forever.
- Today that is P6's one bound deposit of 1,000 test token A.
- Wallets never create bound receivers again; any bound address anyone still holds is a burn
  address.
- The V5 statement account stays deployed and could still emit messages, but no route accepts them
  (§11.4, step 1). The V5 adapter is retired.

The outage runs from `propose + (T − pending_margin)` until apply and reconfiguration. It is
acceptable on Sepolia, where the gateway refuses large proofs anyway.

## 12. Threat model and privacy

| Party | Learns or can do | Cannot |
| --- | --- | --- |
| Pool owner (multisig) | apply routes, R0 and P1 swaps and shadow-class changes after `T`; delay the service by leaving a proposal due | act without `T` of public notice. The user's defense is the SDK's watch on pending changes (§10.3) and an exit |
| Prover server | the statement and the full pool calldata, early; the client's network metadata unless OHTTP is used | learn the spender (absent timing and network correlation), move funds or change outputs. It can delay a spend until it expires, or refuse it |
| Relayer (same operator) | job ↔ submission; submission metadata. It chooses when to settle, up to `send_deadline`. A refusal forces the user to choose between a linkable fallback and a delay | force a linkable submission (the SDK asks first), or make the user pay again for a withheld spend: tickets are refunded (§7.2) |
| Ticket issuer | which pass claimed how many tickets, and when | link a redeemed ticket to a pass, except by claim timing and the issuer-key period |
| Server, free full withdrawal | that both outputs are empty, so the inputs held exactly `w_amount` | — |
| Vault and application front end (operator-served) | the vault holds the seed; the front end knows the connected account | a compromised deploy of either could correlate or steal. Trusted afresh on every load (ADR-0027 decision 4) |
| Browser extensions with host access to the vault | everything the vault page sees, including the seed | outside what a web vault can defend (ADR-0027 decision 4) |
| Vault submitter account, and whoever funded it | publicly linked to each invoke, P1 settlement or fallback it submits; one reused account links its submissions to each other | — |
| Server's RPC node | root and nullifiers of each statement | learn the spender |
| StarkWare gateway / sequencer operator | the PROOF2 object | see the witness, once PROOF2 hiding (ADR-0024 gate) holds |
| On-chain observer | V4's public data plus `valid_until`, and each spend's route (proof version, OS program, the statement from the message hash) and base block. Concurrent routes partition the anonymity set (§6.4) | — |

Rows for the second relayer and the OHTTP relay are added when P7 specifies them.
- **PROOF2.** It no longer differs by mode, so the padding work is moot. Once ADR-0024 gate 4
  establishes the client proof's hiding, PROOF2's witness holds only that proof and public data.
- **Gates.** Real value stays gated on ADR-0024's hiding (gate 4) and review (gate 5) gates.
- **A leaked Templar seed is theft** of the pool notes and the shadow-account positions (ADR-0027,
  consequences).

## 13. Liveness

All spends stop while:
- Templar's service refuses and nobody self-hosts. The pool is free, and anyone may run the prover
  (about 29 GiB) and submit;
- the gateway rejects PROOF2 (today on Sepolia);
- no route accepts the current OS program: a new program arrives before its route applies (§6.4);
- the server's refusal window for a due verifier change of the relation's kind, or an own-route
  change, is open (§9.5). This is why
  OS rotations use new route keys. The owner's runbook applies or cancels promptly at `eta`.

A spend is delayed, not lost, while:
- the relayer is down: the SDK waits, retries, or asks to fall back (§7.2);
- the vault's submitter account has no funds: the linkable fallback is unavailable, so the spend
  waits for a relayer or its record dies and is planned again.

One asset's exits also stop if its token starts charging the sender or rebases (account-bound spec
§8.5, AB-PV5).

The block-denominated constants (`E`, `Q`, `W`, `max_proof_age`) shrink with a faster block time.
Changing `max_proof_age` is a route change; the others need a new pool.

## 14. Amendments to other specs

Applied in phase A, after the design sign-off and before any code:
- **sdk-spec.md:**
  - remove §3.4 (bound seeds) and the bound parts of §9.2, §10.2, §11 and §14;
  - add R0 generations (§10.2), the route-set pins and views, the pending-change rules (§10.3), the
    connected-account and consent rules (§7.2, §7.4), and version `v6`;
  - replace §8's storage-slot reads with the views.
- **prover-server-spec.md:**
  - §2 (no account in any mode), the admission order and checks of §9.2, the bucket check (§9.3);
  - the `(proof_data)` calldata, per-route ages and pending rules (§9.5);
  - `/v1/info`'s `r6` section, dual-version operation, and the removed settings (§9.4).
- **hidden-asset-spec.md:** §5.7 names pool V3's verifiers as routing adapters.
- **open-note-spec.md:** the identity handle (its `sk₀` text becomes `ak₀ = H(AUTH, sk₀)`), and the
  owner lever (`set_shadow_class` becomes the timelocked `propose` and `apply`).
- **ADR-0023:** its handle text, per ADR-0027.
- **The guide's governance page:** routes.

## 15. Phases and acceptance

ADR-0027 decision 7:
- **A. Design:** this spec, its re-check, and the §14 amendments, with Math and protocol sign-off.
- **B. Off-chain removal of bound mode** (implemented 2026-09-26).
  - First, move the shared tests to ordinary fixtures; then add the rules that need no vault.
  - Until the swap, r5 admission refuses statements with `account ≠ 0` at parse, before payment
    is looked at, like any malformed body (no work, no ticket taken). A statement naming account 0
    over a proof that binds an account fails the bridge pre-check, a client fault that consumes
    tickets. The SDK cannot plan them: its core has no bound keys and always states account 0.
  - The connected-account rules of §10.2 need the vault, so they land with phase F. Phase B
    removes the bound-only rules (owner-submit, the spend provider) without replacing them.
- **C. V6:**
  - the relation, bridge, statement account and routing adapter;
  - SDK core and WebAssembly `v6`, server `r6`, and relayer support;
  - SDK submission of invokes and P1 from the vault (§7.2).

  Tests:
  - §4.4, including the `validate_bridge_r6` real-proof run;
  - adapter tests: routing, `NO_ROUTE`, the route timelock, the activation gate, `MAX_ROUTES` and
    `MAX_PENDING`, a V5 message getting `NO_ROUTE`, and `get_route_proposals`;
  - the bucket check;
  - a pool end to end.

  Also: measurements from a V6 virtual-OS run on live Sepolia state, and a Math implementation
  review.
- **D.** The Sepolia deployment and the dual-version release (§11.1).
- **E.** The cutover and the drill (§11.2–§11.4).
- **F.** The vault, including the submitter-funding constraint (§7.2).
- **G.** Specs and guide.

## 16. Evidence

- R0 V5, its bridge and pool V3: account-bound spec §15–§16, P2–P6 (`client-port/results`,
  `bench/m31-pool/results/pool-v3`, `bench/account-bound-p5`, `bench/account-bound-p6`).
- The reviews behind ADR-0027 (`docs/reviews/adr-0027-review.md`) and this spec's design review
  (`docs/reviews/pool-v3-spec-design-review.md`).
- The bound code stays in git history, at or before the commit that removes it.

## 17. Design questions (answered by revision 1's review)

1. **Small-proof facts.** The nine-felt Snos layout is shared by PROOF1 and PROOF2
   (`bench/controlled-push-e2e/cairo/src/proof_adapter.cairo:44-59` against `adapter.cairo:58-73`).
   `facts[0]` names the proof format, not its size, so a V2 small proof should carry `'PROOF2'`.
   Routes pin `facts[0]`, `facts[1]` and `facts[3]` (§6.1). **Open:** check the V2 small-path tag
   against the sequencer source before the device ADR, and add a small-proof route only after
   Starknet's verification of it is confirmed on the target network.
2. **Per-route proof ages:** adopted (§9.5). 1,024 for every route until a device route exists.
3. **Governance delegation:** read the owner and `T` live from the pool (§6.3). Copying the owner
   would leave a former owner in control after a transfer. Delegation is safe only together with
   the activation gate and enumerable proposals (§6.3).
4. **A bucket check,** not a class allowlist, before proving (§9.3). Keep the Blake cap.
5. **Free jobs:** a proof-of-work stamp on every free job, priced near one job's cost (§7.5).
