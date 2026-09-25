# Account-bound notes, expiry and M31 pool V3 (R0 V5)

Status: **design, revision 4.** Decided by the user on 2026-09-25
([ADR-0026](adr/0026-account-bound-notes.md)). Implemented so far: P2, the relation
(`client-port/results/stwo-client-r5`), and P3, the bridge and statement account
(`client-port/results/r5-bridge`). Nothing is deployed.

- Revision 1 was reviewed in `docs/reviews/account-bound-design-{math,protocol}-review.md` (both
  CONDITIONAL GO).
- Revisions 2 and 3 resolved every finding. The math re-review gave GO; the protocol re-review
  gave CONDITIONAL GO, with its conditions resolved in revision 3.
- **Revision 4 simplifies the design** at the user's direction:
  - no relayer fee output (V4's two outputs and V4's conservation);
  - no protocol fees and no gating: the pool is permissionless and free;
  - Templar's prover and relayer are paid off-chain with blind tickets checked before proving;
  - a random product-1 seed instead of a signature-derived one.
- Revision 4's changed sections were re-reviewed: math GO; protocol CONDITIONAL GO. Their
  findings (AB-M13, AB-M14, AB-P28–P32) are applied here. §17 lists the findings each change
  closes or makes moot.
- P0b feasibility evidence is in §16.

Targets the compact client-proof path: a new relation `client-port/src/payment5.rs`, a new bridge
and statement account (`client-port/cairo-r5`), a fresh pool (M31 pool V3, `bench/m31-pool`), the
prover server (`server/`), the SDK (`sdk/`) and a relayer. Finding IDs: `AB-M*` (math), `AB-P*`
(protocol).

## 1. Purpose and scope

Templar has two products on one pool (ADR-0026):

1. **Existing Starknet wallets** (Ready, Braavos) in a web app. The browser makes the compact
   client proof. The prover server's statement account calls the owner account's
   `is_valid_signature` inside the proven execution. The server learns which account made which
   spend; it cannot move funds.
2. **The Templar wallet**, whose own key authorizes spends; the server learns nothing about the
   spender (ADR-0024 unchanged).

This design adds, in one relation version **R0 V5** and one fresh pool **M31 pool V3**:

1. **Account-bound notes**: spending needs the Templar spending key *and* a valid signature from
   a named Starknet account.
2. **In-circuit expiry**: a public `valid_until`, enforced by the pool (F07).
3. **Pool fixes** that need a new pool anyway:
   - roots expire only a window after being replaced (F02);
   - every verifier change is timelocked, with events (F01, F19);
   - F17, F18 and F30.

A spend keeps V4's two outputs. The pool is **permissionless and free** (§8.6): it charges no
fee and checks no pass. Templar's service, the prover server and the relayer, is paid off-chain
with blind tickets that the server checks before proving (§7.2).

Out of scope:

- P-256 and WebAuthn signers (Stark keys only at launch);
- guardian and multisig accounts for bound setup at launch (§6.3);
- an escape path (rejected, ADR-0026);
- the Templar Pass, ticket issuance and relayer operations beyond §7 (`docs/relayer-spec.md`,
  P7);
- identity-scope rules (F40);
- policy notes in account mode (§6.4).

## 2. Baseline (unchanged)

Everything in [hidden-asset-spec.md](hidden-asset-spec.md) (R0 V4, pool V2) not changed below:

- the hash `H(kind, level, payload)` (framed rate-15 Poseidon2-M31 sponge, nine-word digests);
- felt limbs (nine 28-bit little-endian limbs) and amount limbs (eight 16-bit limbs);
- the note format `cm = H(NOTE, chain₉ ‖ pool₉ ‖ asset₉ ‖ amount₈ ‖ inner)`, with
  `inner = H(INNER, receiver ‖ rho)`;
- nullifiers `nf = H(NF, nk ‖ cm ‖ pos_lo ‖ pos_hi)`;
- the private asset and exit bit, the dummy input 1, delivery digests, two outputs and the
  conservation gadget;
- assets and their registry, deposits and payouts.

**Ordinary receivers are unchanged:** `receiver = H(OWNER, H(AUTH, sk) ‖ H(NK, sk))`.

## 3. Account-bound receivers

### 3.1 Hash kind

One new kind: **`WAUTH = 16`**. The math review verified it unused by every M31 hash in the
repository; the implementation adds a test that enumerates the kinds. WAUTH's framed input is 22
words, the same block shape as OWNER and INNER (a 15-word block, then 7 words padded), so it adds
no new sponge length or mode (AB-M10).

### 3.2 Receiver

For a Starknet account `A` (`0 < A < 2^251`) and a spending key `sk` (nine words):

```text
ak_w      = H(WAUTH, 0, felt_limbs(A) ‖ sk)
nk        = H(NK, 0, sk)
receiver  = H(OWNER, 0, ak_w ‖ nk)
```

`felt_limbs(A)` is the canonical encoding of the integer `A`. The commitment, nullifier, tree and
delivery formats are unchanged, so a payer cannot tell a bound receiver from an ordinary one, and
any wallet can pay a bound address.

### 3.3 Mode

A spend has one **mode bit** `m`, shared by both inputs:

- `m = 0` (ordinary): each input's `ak = H(AUTH, sk)`; the published `account` is 0.
- `m = 1` (bound): each input's `ak = H(WAUTH, felt_limbs(account) ‖ sk)`; the published `account`
  is nonzero, and the statement account requires that account's signature (§5.4).

Both inputs are bound to the same account, or both are ordinary. Outputs are unconstrained.

### 3.4 Security properties

- **S1 (no ordinary spend of a bound note).** An ordinary spend of a note with receiver
  `R = H(OWNER, ak_w ‖ nk)` needs `sk′` with `H(OWNER, H(AUTH, sk′) ‖ H(NK, sk′)) = R`: a second
  preimage of the receiver.
- **S2 (no spend under another account).** It needs `(A′, sk′) ≠ (A, sk)` with
  `H(OWNER, H(WAUTH, A′ ‖ sk′) ‖ H(NK, sk′)) = R`: a second preimage. Even with `sk` leaked, fixing
  `sk′ = sk` leaves 251 bits of `A′` against a 279-bit target.
- **S3 (the signer is the bound account).** The account the statement account calls is the one
  hashed into every input's `ak`. Two rules give this:
  - the WAUTH input words and the published `account` limbs are the same circuit variables
    (§4.3, load-bearing, with its own mutation test);
  - the bridge decodes them canonically (§5.1).
- **S4 (a leaked key at rest is privacy only, for bound notes).**
  - Holding `S_w` or `sk` without the account's signing key reveals the wallet's bound notes,
    amounts and spends.
  - It cannot move those notes or act through the wallet's shadow accounts (§4.3 identity rule).
  - It does not protect value the SDK places outside bound receivers (§6.4 forbids that).
  - It does not hold against a compromised signing interface (§12).

S1–S2 hold at Poseidon2-M31's 128-bit design level, the level every V4 note hash relies on:

- F42: rounds (8,22) against a minimum of (6,20);
- generic bounds 2²⁷⁹ from the output and 2¹³⁹·⁵ from the capacity.

## 4. Relation R0 V5

### 4.1 Public statement

```text
tag₂, chain₉, pool₉, token_out₉, root₉, nf₀₉, nf₁₉, cm₀₉, d₀₉, cm₁₉, d₁₉,
recipient₉, w_amount₈, intent₉, identity₉, account₉, valid_until₂
```

- V4's 127 limbs plus `account` and `valid_until` give 138 limbs.
- They are padded with two zero limbs to 140 and emitted as **35 QM31 outputs**.
- `valid_until` is a block number below 2^56, as two 28-bit little-endian limbs.
- Tags: `R0V5` (`0x52305635`, sponge tree) and `R0C5` (`0x52304335`, compress tree).
- V3 and V4 keep their modules and `N_OUTPUTS = 32`; V5 defines its own.

### 4.2 Witness variables

As V4 (hidden-asset-spec §4.2), plus the following. Each is created once and shared by every rule
that names it.

- `account`: nine guessed words, hashed by WAUTH and published (the same variables);
- `m`: the mode bit, a guessed boolean;
- `valid_until`: two guessed words, published.

The outputs are V4's two slots.

### 4.3 Constraints (normative)

V4's constraints 1–8 hold, with these changes:

1. **Mode.**
   - `m·(m − 1) = 0`.
   - For every limb `ℓ`: `accountₗ · (1 − m) = 0`.
   - `nonzero_vector_if(account, (m, …))`: nine boolean selector bits summing to 1, with
     `picked · inv = m`.

   So `m = 1 ⇔ account ≠ 0`.
2. **Keys.** For both inputs:
   - compute `a_i = H(AUTH, skᵢ)` and `w_i = H(WAUTH, account ‖ skᵢ)` (a separate batch of two);
     both hashes are always computed;
   - select per word: `akᵢ,ₗ = a_i,ₗ + m · (w_i,ₗ − a_i,ₗ)`;
   - `receiverᵢ = H(OWNER, akᵢ ‖ nkᵢ)` feeds `cmᵢ`.

   The dummy input 1 uses the same `m` and `account`. **The WAUTH input words are the published
   `account` variables** (load-bearing for S3).
3. **Identity** (AB-M1).
   - `handle = H(IDENTITY, ak₀ ‖ scope)`, masked by the identity flag, where `ak₀` is input 0's
     selected key (`H(AUTH, sk₀)` or `H(WAUTH, account ‖ sk₀)`).
   - Reproducing a bound wallet's handle needs a second preimage of `ak_w`. A leaked `sk` therefore
     cannot act through the wallet's shadow accounts without the account's signature.
   - A full viewing key holder knows `ak` but cannot publish a handle, because the circuit derives
     `ak` from `sk`.
   - This changes ordinary handles from V4's `H(IDENTITY, sk₀ ‖ scope)`. Pool V3 is fresh, so no
     V2 shadow account needs to stay addressable.
   - Never feed `sk₀` and `ak_w` into the same input slot of one hash.
4. **Published limbs.** `[tag, pub_ctx, token_out, cur₀, nf₀, nf₁, cm₀, d₀, cm₁, d₁, recipient,
   withdrawn, intent, identity, account, valid_until]`, then two zero limbs. The circuit does not
   range-check `account` or `valid_until`; the bridge does.

**Outputs and conservation are V4's, unchanged:** two output slots and
`conservation([amt₀, amt₁], [out₀, out₁, withdrawn])`, carries in {−2, …, 1}. Revision 3's
`conservation5` for a third output is gone (AB-M2 does not arise with two outputs).

**Invariant B (binding determines the account)** (AB-M5).

- Every accepted statement's binding contains `nf₀` (and `nf₁`).
- `nf₀` is a collision-resistant function of `(m, account)` through
  `nf → cm → inner → receiver → ak`.
- So two statements with equal bindings and different `(m, account)` imply a Poseidon2 collision
  or second preimage. This holds whether or not input 0 is real.
- It breaks if a future nullifier or commitment format stops deriving from `ak`.

### 4.4 Tests (required)

Malicious witnesses, each failing to prove or rejected by the bridge, in addition to V4's list:

- `m = 1` with `account = 0`; `m = 0` with `account ≠ 0`; `m = 2`;
- a bound note spent with `m = 0`; an ordinary note spent with `m = 1`;
- a note bound to `A` spent with `account = A′ ≠ A`;
- input 0 bound and input 1 ordinary, or bound to another account (`e₁ = 1`);
- non-canonical `account` limbs (a limb at 2^28, a value at or above 2^251), rejected by the
  bridge; a nonzero padding limb, rejected by the bridge;
- `valid_until = 0`, and a `valid_until` limb at 2^28, rejected by the bridge (AB-M14);
- an ordinary-mode spend with a nonzero identity reproducing a bound wallet's handle.

Tamper hooks (AB-M6): a published `account` different from the hashed `account`; a separate `m`
per input.

**Mutation kills (F09):** each new constraint fails a test if deleted:

- both mode legs;
- the select;
- the published-equals-hashed wiring;
- the `ak₀` input to the identity hash.

V4's conservation tests and mutation list carry over unchanged.

Positive tests:

- both modes for every V4 shape;
- a bound spend with a dummy input 1;
- ordinary and bound receivers paying each other;
- an ordinary V5 statement equal to V4's on every shared field except `identity`;
- for one `sk` and `scope`, ordinary and bound handles differ, and a bound spend under `M ≠ A`
  with `A`'s `sk` does not reproduce `A`'s handle;
- `valid_until = 2^56 − 1`; an account just below 2^251.

### 4.5 Budget

- R0 V4 proves at trace 2^18 for every shape.
- V5 adds two WAUTH hashes, the selects and eleven published limbs. The target is 2^18.
- If V5 needs 2^19, the WASM proof time and memory are re-measured and accepted before the circuit
  freezes.

## 5. Bridge and statement account (`cairo-r5`)

### 5.1 Bridge checks

The bridge decodes and range-checks every limb as V4 does. It checks everything V4's bridge checks
(hidden-asset-spec §4.5), and also:

- `account` decodes by `felt_from_limbs` (limbs below 2^28, value below p) and is below 2^251;
- both `valid_until` limbs are below 2^28, and `valid_until ≠ 0`;
- both padding limbs are zero.

The Rust mirror `bridge_checks` matches `felt_from_limbs` exactly, including canonicity (F15).

### 5.2 Binding

```text
binding = Poseidon('TMR0_BIND_V5', chain, pool, token_out, root₉, nf₀₉, nf₁₉, cm₀₉, d₀, cm₁₉, d₁,
                   recipient, w_amount, intent, identity₉, valid_until)
```

- It omits `account`, which never reaches the chain (Invariant B binds it).
- Message tag: `'TMPZR0_PAYMENT_V5'`.

### 5.3 Spend message (SNIP-12 revision 1)

```text
StarknetDomain { name: 'Templar', version: 'V5', chainId: <chain, shortstring>, revision: 1 }

TemplarSpend {
  pool: ContractAddress,
  binding_commitment: felt,          Poseidon(binding, salt)
  token_out: ContractAddress,
  withdrawal_recipient: ContractAddress,
  withdrawal_amount: u128,
  intent: felt,
}

hash = Poseidon('StarkNet Message', domain_hash, account, struct_hash)
```

- Every field comes from the decoded statement; the client supplies only `salt` and the signature.
- `valid_until` is not displayed (AB-P9). It is public on chain and would let parties that saw the
  typed data match the spend. It stays authorized through `binding_commitment`, which commits to
  the binding and so to `valid_until`.
- `version` is non-numeric so no wallet encodes it as a number (P0b S1).
- **`salt`:**
  - uniform in `[1, 2^251)` and fresh per signature;
  - sent only to the prover server;
  - required nonzero in bound mode (§5.4).

  It keeps the wallet vendor, a guardian service and scanners from matching an in-pool transfer by
  its binding. On a low-traffic pool, signing time alone can still link; the salt helps at volume.
- **What the wallet screen lets a user check** (AB-M9):
  - only a plain withdrawal (`intent = 0`) can be checked: `token_out`, recipient and amount;
  - in-pool transfers show an opaque commitment;
  - `INVOKE` and `COMPUTE` intents show a bare felt;
  - an NFT's `token_out` is an asset hash displayed as an address.
- Before the circuit freezes, two things are required:
  - cross-KATs between the SDK core, the Cairo module and starknet.js. The Cairo module and
    starknet.js agree (P3, `cairo-r5/kat`); the SDK core joins in P4;
  - real-wallet signatures of this exact struct and domain. Done in P3: Ready X 5.33.11 and
    Braavos 4.19.6 signed the V5 message for real proofs naming their accounts, and the statement
    account accepted both from the live account classes on a Sepolia fork
    (`client-port/results/r5-bridge`). The P0b wallets had signed a predecessor with
    `version: '1'` and a `valid_until` field.

### 5.4 Statement account

`__validate__(proof_data, salt, signature)` checks zero tip and zero prices only (R4's rule with
V5's calldata; AB-M11).

`__execute__(proof_data: Span<felt252>, salt: felt252, signature: Span<felt252>)`:

1. Caller 0 (`OS_ONLY`).
2. `statement = verify_payment(proof_data)`; `statement.chain` equals the transaction's chain id.
3. If `statement.account = 0` (ordinary): require `salt = 0` and `signature` empty.
4. Otherwise (bound):
   - require `salt ≠ 0` and `statement.account ≠` this contract's address;
   - require a contract is deployed at `statement.account` (`get_class_hash_at ≠ 0`). The check is
     diagnostic: calling an undeployed address aborts the whole execution instead of returning an
     `Err`, and the check turns that into an explicit rejection (P3, AB-IP1). Other failures inside
     the callee can still abort rather than err (the callee calling an undeployed address, running
     out of steps, recursion depth, Cairo 0 VM errors). Either way no message is emitted and no
     proof exists;
   - compute `hash` (§5.3);
   - call `call_contract_syscall(statement.account, selector!("is_valid_signature"),
     [hash, signature.len(), signature…])`; an `Err` reverts;
   - require the return is exactly `['VALID']`.
5. Emit one message `[class_hash, 'TMPZR0_PAYMENT_V5', chain, pool, binding]`.

The account call is in `__execute__` only and comes before the message. Around it:

- The adapter's `MESSAGE_COUNT = 1` rejects a callee that emits a message.
- The caller-0 guard blocks re-entry.
- The statement account exposes no `is_valid_signature`.
- Any padding contract (§12) that answers `is_valid_signature` must never be a bound account:
  the SDK never binds to it, and when one is added (P5) the statement account must reject its
  address as it rejects its own (AB-IP4).

### 5.5 Class size

R4's account is 61,395 CASM felts (limit 81,920). V5's is 63,483 (P3 build record,
`client-port/results/r5-bridge/bridge-build-record.json`).

## 6. Product-1 wallet: seed and keys

### 6.1 Seed

The product-1 seed `S_w` is **random**. It does not depend on the account or its keys.

1. At setup, and only after the setup checks pass (§6.3), the SDK core draws `S_w`: 28 bytes
   from the core's CSPRNG (sdk-spec §2, Randomness).
2. `A` comes from the connected wallet, never from typed input (AB-M4).
3. **Backup:** `S_w` as a **21-word** BIP-39 English mnemonic (224 bits of entropy plus BIP-39's
   7-bit checksum). Import rules follow sdk-spec §3.1.
   - The word count is the origin marker: ordinary (Templar-wallet) imports take 24 words only,
     bound imports 21 only. Both directions are tested.
   - The backup screen shows `A` beside the words.
   - Setup confirms the backup with a word check before it shows the first bound address
     (AB-P12). Nothing can be received before the check.
4. Setup cannot detect earlier use, because nothing on chain names the account. So before
   creating a seed, it asks whether this account was used with Templar before, and offers restore
   first.
5. **Restore** takes the 21 words and `A` from the connected wallet. The same words under another
   account give an unrelated, empty wallet (§6.2).

**Secrecy (normative, AB-P3).** `S_w` and every spending, nullifier and decryption key derived from
it follow sdk-spec §2's secret rules:

- They never leave the SDK core. No RPC call, simulation, prover-server or relayer request, log,
  error report or analytics event carries them.
- They are zeroized after use.
- A network-trace test (sdk-spec §12) shows that no request carries `S_w` or a spending key.

**Storage** (AB-M8).

- `S_w` is stored per device, wrapped under a non-extractable WebCrypto key.
- A second device needs the 21 words.
- Unlocking never asks the wallet for a signature.

**Key change.** Rotating the account's signing key (a recovery, a new signer) changes neither
`S_w` nor any receiver. Bound notes stay spendable as long as the new signer is in the
compatibility matrix (§13, §14).

### 6.2 Keys

```text
PRK_w       = HKDF-Extract(salt = "TEMPLAR_BOUND_WALLET_V1", IKM = S_w)
actx        = felt₃₂(chain) ‖ felt₃₂(pool) ‖ felt₃₂(A)
sk_w(i)     = wide9(HKDF-Expand(PRK_w, "TEMPLAR_BOUND_SPEND_V1"    ‖ actx ‖ u32₄(i), 144))
ivk_w(i)    = clamp(HKDF-Expand(PRK_w, "TEMPLAR_BOUND_INCOMING_V1" ‖ actx ‖ u32₄(i), 32))
kstore_w    = HKDF-Expand(PRK_w, "TEMPLAR_BOUND_STORE_V1" ‖ actx, 32)
receiver(i) = H(OWNER, H(WAUTH, felt_limbs(A) ‖ sk_w(i)) ‖ H(NK, sk_w(i)))
```

- `A` is in every context, so one phrase used with two accounts gives unrelated spending,
  nullifier and viewing keys. Their notes cannot be linked through a shared `nk` or `ivk`.
- A known-answer vector pins the derivation.
- Account indexes, addresses (unchanged format; they do not reveal `A`), viewing keys and scanning
  follow sdk-spec §3–§6 with these keys.

**Companions** follow sdk-spec §3.3 and HA-M6 unchanged: random, stored with the note, never
seed-derived.

- A bound note's companion is a dummy input in bound mode with the same account (§4.3.2). The
  SDK's pre-proof "companion not spent" check computes its nullifier that way (AB-M14).
- As with the Templar wallet, a second device needs the phrase, and two devices cannot coordinate
  records (sdk-spec §9.1).
- A server's duplicate-nullifier refusal means "in flight elsewhere" and never triggers a re-plan,
  in both products.

### 6.3 Setup checks (AB-M4, AB-M7, AB-P3)

Before generating a seed, setup requires:

- the account is deployed, and its class and signers are in the compatibility matrix (§13).
  Guardian, multisig and non-Stark-signer accounts are refused at launch;
- a **setup-check signature**, which the account's `is_valid_signature` accepts. The account must
  also reject a tampered copy, and the same signature over a different hash.
  - The checks run at one fixed block through `starknet_call`, never node simulation (§16).
  - The signature is over a `TemplarSpend` with `pool = 0` and a random `binding_commitment`. It
    exercises the exact spend encoding and can never authorize a spend.

### 6.4 What a bound seed may create (normative; decides theft versus privacy, AB-M3)

- The SDK never derives an ordinary receiver from `S_w`. Every self-directed receiver is a bound
  receiver of the same account: change, deposits, open-note destinations and returns.
- The SDK derives no policy seed (`s_pol`), capability or policy note from `S_w`. It refuses to
  create policy notes from a bound wallet, since P1 settles with no account call.
- Shadow scopes may be derived from `S_w`. With §4.3.3, acting through a shadow account needs a
  bound spend.

## 7. Submission and paying for the service

### 7.1 Outputs

A spend has V4's two outputs (payment and change, or dummies) in uniformly random order
(sdk-spec §7.2, unchanged). No output pays the relayer or the pool.

### 7.2 Templar Pass and blind tickets

This section is a summary; P7 specifies it in `docs/relayer-spec.md`.

**The service.**

- Templar runs the prover server and the relayer as one service.
- The pool never sees payment. It is free and permissionless (§8.6).
- Anyone can prove (the server is self-hostable, about 29 GiB) and submit for themselves.

**Tickets.**

- The server charges per job in tickets and checks them at admission, before any proving or
  account call (§9).
- A ticket is a publicly verifiable blind RSA signature (RFC 9474) on a random nonce. So a future
  third-party relayer can verify it too.
- One issuer key per period serves every payment source, so a ticket does not say how it was
  paid for.
- Redemption is unlinkable to issuance: the server learns that a valid ticket was spent, not whose.
- **One spent set per issuer key**, shared by every redeemer of that key: every server instance
  and any third-party relayer. It is kept until the key expires, so a ticket cannot be spent at
  two redeemers (AB-P30).
- Reservation, spending and refunds follow §9.

**Templar Pass.**

- At launch, tickets are claimed with a soulbound (non-transferable) Templar Pass NFT. A minter
  role mints it, and no price is fixed in the contract.
- The holder proves ownership and claims tickets in blinded batches.
- The remaining count is kept off chain, shown only to the holder, and never published.
- Entitlements are pluggable, so a later token can pay, stake or discount under the same issuer
  keys.
- The pass is sold only as prepaid relays.
- A soulbound NFT's owner is public on chain. So the SDK lets the pass sit in an account other
  than the owner or depositing account, and recommends it (AB-P32).

**Costs** (initial policy; P7 finalizes):

| Action | Tickets |
| --- | --- |
| Deposit | 0 (a direct pool call; no service involved) |
| In-pool transfer | 1 |
| Partial withdrawal | 1 |
| Full withdrawal of a priced asset, at or above its minimum | 0 |
| Any other full withdrawal (dust, NFTs, unpriced assets) | 1 |
| `INVOKE` / `COMPUTE` spend | 2 (about 150M L2 gas against about 53M) |
| Policy settlement (P1) | 1, paid by the executor |

**Free full withdrawals** (AB-M13, AB-P29).

- A user with a note worth exiting never needs a ticket to leave. The price table lists the
  priced assets and their per-asset minimums; P7 may add NFT collections.
- **Who is still not free.** Holders of dust, NFTs or unpriced assets who have no tickets can exit
  only by self-hosting. This is stated in the product.
- **The check.** The server requires all of the following:
  - `intent = 0`, so the spend is a plain `apply_spend` (the bridge then forces `identity = 0`);
  - `token_out` is a priced asset, and `w_amount` is at or above its minimum;
  - the openings `(asset, inner_j)` of both outputs, in canonical words, with `asset` taken from
    the decoded `token_out`, never from the client;
  - each `cm_j = H(NOTE, chain ‖ pool ‖ asset ‖ 0₈ ‖ inner_j)`.

  So both outputs hold zero, and V4's conservation sends the whole input value out through the
  withdrawal. This rests on NOTE collision resistance, since the client picks the openings.
- **What it reveals, to the server only.** Both output leaves are zero-value dummies, and the
  spent notes held exactly `w_amount`. On-chain observers learn nothing new. The reveal is
  optional: the client can pay one ticket instead.
- **Griefing.** Each free job costs the service a PROOF2 (about 80 s at about 29 GiB) and relayer
  gas, while the attacker gets its deposit back. So:
  - free jobs run in their own lower-priority queue, and never take slots from paid jobs;
  - they are rate-bounded overall, and per account in product 1. A job counts against an
    account only once its signature check has passed (§9). Otherwise anyone could exhaust a
    victim's allowance with notes bound to the victim's account and junk signatures.

**Claim timing and key periods.**

- In product 1 the server already knows the account; tickets still hide which pass paid.
- Claiming just before a spend links the two by timing, so the SDK claims in batches, ahead of
  need.
- Per-period issuer keys partition redemptions by claim period. On a small service this adds to
  the timing link (§12).

### 7.3 Relayer acceptance (normative, AB-P8)

Before submitting, the relayer:

1. requires `send_deadline ≥ latest + margin` (§9), a root the pool accepts (§8.3) and unspent
   nullifiers;
2. simulates with validation, and keeps a deduplication set of nullifiers across its own
   submissions until each statement's deadline;
3. for `INVOKE` spends, relays only with the SDK's tight minimums (F06). A relayer that sees the
   spend first could otherwise sandwich it down to `minimum`.

**Handoff** (AB-P28).

- The job body carries the full pool calldata (§9), so the server holds everything needed to
  settle. The relayer takes each result straight from the server that proved it.
- The client also receives the result, to verify it and for the fallback (§7.4).
- The relayer answers each job with its transaction hash, or with a refusal and its reason (a
  failed acceptance check) (AB-P31).
- The relayer keeps the nullifiers until the deadline, and nothing else after submission.

### 7.4 Submitters

- **The service submits every spend it proves.** The submitting account then does not tell
  products, modes or users apart.
- **Fallback.** The SDK submits a spend from a user-chosen account when:
  - its proof came from a self-hosted server;
  - the relayer refused it (at once, on the refusal); or
  - at `send_deadline − margin`, it is not included and no relayer transaction for it is pending
    (AB-P31). `margin` is at least the expected inclusion latency. Otherwise a pending relayer
    transaction and the fallback would both land, and the reverted duplicate would publish the
    fallback account beside the spend.

  The fallback account is **not** the owner account, and the spend is marked `linkable: true`
  (AB-P4).
- Product 1's owner account never submits its own spends.
- A standard paymaster does not replace the relayer, because the user's account would be the
  transaction's account.

## 8. M31 pool V3

- A fresh deployment: commitments bind the pool address, and pools have no upgrade path.
- **Permissionless and free** (§8.6).
- V2 notes move by withdrawal and deposit (Sepolia test tokens only).

### 8.1 Spends

`apply_spend` and `apply_spend_with_invoke` take a V5 `Spend`: V4's plus `valid_until`. Under the
lock the pool checks, in addition to V2's rules:

- the binding `TMR0_BIND_V5`, recomputed from the spend;
- the expiry rules of §8.2;
- the root rule of §8.3;
- V2's output rules: both commitments nonzero, ciphertexts present and matching their digests, and
  one batched `insert_two`;
- V2's single nullifier set, exit rule and invoke rules;
- `MAX_NOTES = 4`, as in V2: two outputs plus up to two open-note destinations.

`apply_policy_spend` (P1, unchanged relation) uses the root rule of §8.3 and its own adapter.

### 8.2 Expiry (F07, AB-P11, AB-P17)

- The pool requires:
  - `block_number ≤ valid_until`;
  - `valid_until % Q = 0`;
  - `valid_until ≤ block_number + E + Q`.

  `E` and `Q` are constructor constants.
- The SDK sets `valid_until = ceil((latest + E) / Q) · Q`.
  - An honest statement always satisfies the rules at inclusion.
  - A far-future one cannot land before `valid_until − E − Q`, which bounds withholding for every
    client.
- `E` comes from the measured worst-case pipeline: server queue wait, proving,
  `submit_after = base + 11`, relay.
  - Proposed `E = 1,500` and `Q = 100` blocks: about 42 min and 3 min at Sepolia's measured
    1.69 s per block.
  - They are fixed from P5 measurements.

### 8.3 Roots (F02, AB-P1)

- The current root is always accepted.
- When an append replaces root `R`, the pool writes `superseded_at[R] = block_number`.
- `R` is accepted while `block_number − superseded_at[R] ≤ W` (proposed `W = 4,096`).
- A root never recorded reads as 0 and is unknown.
- Junk deposits cannot age a root out early, and a quiet pool never freezes.
- The rule applies to `apply_policy_spend` too.

### 8.4 Owner functions, timelock and bootstrap (F01, F19, AB-P2, AB-P4, AB-P5)

- **Verifier changes are timelocked.** Every verifier the pool trusts (R0 V5 and P1) changes only
  through `propose_*` → wait `T` → `apply_*`, with `cancel_*`, each emitting an event.
  - `T` is a constructor constant: on mainnet at least 7 days and above `E + Q + margin`; shorter
    on Sepolia.
  - Views return, for each verifier, the current value, the pending value and its `eta`.
- **Bootstrap.** The constructor takes no verifiers.
  - A one-time `initialize(r0_verifier, p1_verifier)` by the owner is allowed only while no
    verifier is set and the tree is empty. It emits the change events.
  - Deposits and spends revert until it has run.
- Owner transfer is two-step with events. Mainnet ownership is a multisig.
- **No other owner function moves funds**, and none charges or gates users. Shadow-class
  allowlisting cannot move funds either:
  - a `COMPUTE` budget goes only to the adapter bound in the user's own intent;
  - an `INVOKE` target must not be an allowlisted shadow class (F18).
- **OS rotation.** The adapter pins one virtual-OS program. A new program needs a new adapter
  through the timelock.
  - The owner proposes it as soon as a new version is announced.
  - If the lead time is shorter than `T`, the pool freezes for the difference. This is recorded as
    a known risk.
  - The SDK reads pending proposals, shows them with their eta, offers an exit and ships new pins
    before eta.
- **V5 adapter.** A new instance of the existing class, with `account_tag = 'TMPZR0_PAYMENT_V5'`
  and **`max_proof_age = 1,024`** (V2: 4,096).
  - The smaller age bounds the key-rotation window (§12).
  - It must stay well above PROOF2 latency.

### 8.5 Other entry points and carried fixes (AB-P18)

Deposits (ERC20, ERC721, ERC1155), the asset registry, `held` accounting and solvency, payouts,
open-note invokes, shadow classes and views are V2's, with these fixes:

- F17: an ERC20 deposit also checks that the caller's balance fell by `amount`;
- F18: an `INVOKE` target is not an allowlisted shadow class;
- F30: the tree format is fixed to the compress tree (`R0C5`) in the constructor;
- F19: the constructor and `initialize` emit the verifier events.

### 8.6 No fees and no gating (normative)

- **Nothing in the pool charges or gates.** It has:
  - no fee parameter, fee collector or accrued-fee balance;
  - no allowlist of depositors or submitters;
  - no pass or ticket check.

  Any account can deposit, and any account can submit a spend that carries a valid proof.
- **Why.**
  - A spend gate could freeze exits: a lapsed pass or a failed issuer would lock funds.
  - A deposit gate turns away self-hosters, who add to the anonymity set and to TVL.
  - Revenue comes from the service (§7.2).
- **Consequence.** Pools cannot be upgraded, so pool V3 can never charge a fee. A protocol fee
  would need a new pool, with notes moved by withdrawal and deposit.

## 9. Prover server

- **Job body** (AB-P28).
  - The V5 proof and the statement.
  - The full pool calldata: the `Spend` with both ciphertexts, and for an invoke the
    `ExecutionIntent` preimage (for P1, its `data` and ciphertexts).
  - Payment: tickets (§7.2), or the output openings of a free full withdrawal.
  - Blinded refund requests, one per ticket, so that any replacement ticket is issued blind and
    cannot link the job to the client's later spends (AB-P30).
  - In bound mode, `salt` and the signature (at most 32 felts).
- **Admission** (AB-P11, AB-P16, AB-P30). This merges with prover-server-spec §4's pre-checks. In
  order, cheapest first:
  1. size and encoding;
  2. configuration match;
  3. payment: tickets are verified locally and **reserved**; or the free-withdrawal check (§7.2)
     routes the job to the free queue;
  4. work deduplication;
  5. expiry: a statement whose `valid_until` is below
     `latest + expected wait + proving + 11 + relay margin` is refused;
  6. chain state (root known, nullifiers unspent);
  7. the bridge. The server also checks that the calldata matches the statement: its delivery
     digests, the intent hash, and the binding recomputed from the `Spend`;
  8. in bound mode, the account's `is_valid_signature` at the latest block through
     `starknet_call`. A failure asks the SDK to re-authorize, not to retry. The check is
     advisory (AB-IP2): it runs with caller 0, while inside the virtual OS the caller is the
     statement account, so a hostile class can pass it and then fail. The virtual-OS run is
     authoritative.

  A job without valid payment is refused before any proving or account call. A self-hosted
  server can turn off the payment check.
- **Ticket states** (AB-P30).
  - A refusal at steps 4–6 (a server-side or timing reason) releases the reservation.
  - A bridge rejection or a calldata mismatch at step 7 consumes the tickets. Honest clients check
    these first; releasing them would let one ticket fund any number of invalid jobs.
  - A signature failure at step 8 releases the reservation. It costs the server one call, and an
    honest client may meet it after a key rotation.
    - Repeated failures back off **per note**, keyed by input 0's nullifier, in prover-server-spec
      §4's existing refusal table with a new reason. The first failure is free; after that the
      wait doubles, as for duplicates.
    - The back-off is never keyed by the account. Anyone can create a note bound to a victim's
      account under their own `sk`, send valid proofs with junk signatures, and so lock out an
      account-keyed back-off.
    - Each further attempt therefore needs a freshly deposited note, and the per-address buckets
      (prover-server-spec §7) bound the total.
  - The SDK checks the signature itself before submitting: `is_valid_signature` through the
    relayer or OHTTP (§10). So honest clients rarely meet a server-side failure.
  - At job start, the tickets are **spent** only after the job-start checks pass. A job-start
    expiry failure comes from the server's own queue, so it releases them.
  - After that, a virtual-OS revert, an aborted execution (AB-IP1) or a cap violation is the
    client's fault and keeps them spent. Otherwise a hostile account class could burn OS time for
    free.
  - A job the server itself fails (a crash, a prover error) earns replacement tickets, signed on
    the job's blinded refund requests.
- **Job start.**
  - The same expiry check, and the signature check again at the chosen base block.
  - Statement fields go into the virtual transaction's calldata as §5.4 requires.
- **Bounds before proving.**
  - Caps on virtual-OS steps, builtin counts and Blake compressions. They are set from P5
    measurements, so that an accepted job stays in the measured leaf bucket and within
    `job_memory`.
  - A lower L2 gas bound on the virtual transaction, set from the measured cost of `__execute__`
    rather than today's 10^9 (AB-IP2). P3's snforge runs measured about 364–372M L2 gas per bound
    `__execute__`; P5 measures it in the virtual OS.
- **Deadline.** The result reports `send_deadline = min(statement.valid_until, base +
  max_proof_age)`, a name distinct from the statement field. Deduplication is released at it. The
  relayer submits the result (§7.4), so the service chooses when to settle, up to
  `send_deadline`.
- **Bound-mode data** (AB-P16).
  - The account, salt and signature sit in `bridge-args.json`, `os-job.json`, `os.pie.zip`,
    `check.log`, `os.log` and streamed commitment files.
  - These are kept on tmpfs, swap is encrypted or off, and they are deleted as soon as proving
    ends.
  - Results are deleted when the client acknowledges receipt, or after a short retention.
  - Logs never contain the account, salt or signature.
  - A retained signature over a public binding is third-party-verifiable proof that the account
    made the spend.
- **RPC** (AB-P10). The server serves bound mode only with an operator-controlled node, and says
  so.
- **Info.** `/v1/info` publishes:
  - the spend domain and type hashes;
  - the relation version, E and Q;
  - the ticket issuer keys and the cost table.

## 10. Web-app RPC use (AB-P10)

In bound mode, spend-specific reads never go through a provider that has seen the account in that
session. These reads are fee estimates, simulation, nullifier and root checks, recipient checks
and status polling. Submission follows the same rule. All of them go through the relayer or a
separate provider over OHTTP.

## 11. Amendments to other specs (AB-P15)

Applied when the corresponding phase lands.

**sdk-spec.md:**

- §3: the bound seed (random, 21-word mnemonic, `A` in every key context), and the setup checks;
- §6: receive rules unchanged;
- §7.2: outputs unchanged (two, in random order);
- §8: the job body (full pool calldata, salt, signature, tickets or full-withdrawal openings,
  blinded refund requests); the pins (spend domain and type hashes, E, Q, relayer, issuer keys);
  `send_deadline`;
- §9.1:
  - the dead-record rule becomes "`valid_until` buried by 10 blocks", replacing leaf count
    `m + 512`;
  - in-flight records use `send_deadline`;
  - a duplicate-nullifier refusal never triggers a re-plan;
- §9.2: relayer submission (transaction hash or refusal), the non-owner fallback and its timing
  (§7.4), and the ticket wallet (batched claims, a holder-only count, the pass in a separate
  account);
- §10.2: network constants;
- §11: versions (R0 V5, `TMR0_BIND_V5`), and the privacy table.

**prover-server-spec.md:**

- §2: the server learns the account in bound mode, and that a free full withdrawal empties its
  inputs. It now holds the full pool calldata, so it can settle, and it chooses when, up to
  `send_deadline` (replacing "cannot submit", PS-7);
- §4: the merged admission order of §9, including payment and the calldata match; job-start
  checks; the ticket states; signature failure as a new per-note refusal reason;
- §5: calldata `(proof_data, salt, signature)` and `send_deadline`;
- §7: caps;
- §8: the relation config;
- §10: logging, and the data rules of §9.

**hidden-asset-spec.md:** §5.7, pool V3's entry points: `valid_until`, roots by supersession,
timelocked verifiers, `initialize`, and no fees or gating.

## 12. Threat model and privacy

| Party | Learns | Cannot |
| --- | --- | --- |
| Prover server, bound mode | account ↔ statement, and the signature (proof of it) | move funds or change outputs. It can delay until `valid_until` or refuse, and so censor chosen accounts |
| Prover server, ordinary mode | the statement (ADR-0024) | as above |
| Relayer (same operator as the server) | job ↔ submission, since it submits what the server proves; submission metadata. It chooses when to settle, up to `send_deadline` | as above |
| Ticket issuer | which pass claimed how many tickets, and when | link a redeemed ticket to a pass, except by claim timing and the issuer-key period it was claimed in (§7.2) |
| On-chain observer of the pass | which accounts hold a pass (a soulbound NFT's owner is public) | link the pass to spends or to the owner account, if the pass sits in a separate account (§7.2) |
| Server, free full withdrawal | that both outputs are empty, so the inputs held exactly `w_amount` | — |
| RPC provider of the web app | the account (setup, wallet reads); not spend-specific reads (§10) | — |
| Server's RPC node | account ↔ nullifiers, unless operator-controlled (§9) | — |
| Wallet vendor, guardian service, scanners | the signed fields: pool and plain exit fields, not the salted binding | match an in-pool transfer except by signing time |
| StarkWare gateway / sequencer operator | the PROOF2 object; whether it hides the account depends on PROOF2's own hiding (ADR-0024 gate) | — |
| On-chain observer | V4's public data plus `valid_until`; not the account | — |

- **Leaked backup phrase or device store.** It gives `S_w`, and with it every bound note, amount
  and spend of that account. Without the account's signature it moves nothing (S4). No wallet
  signing prompt yields the seed, so a phishing site has to ask for the words themselves.
- **Compromised frontend at spend time.** It can have the user sign a theft of anything not
  checkable on the wallet screen (§5.3). Product claims say "a leaked key at rest".
- **Every signer the account accepts** can authorize bound spends: owner, guardian, a guardian
  escape after its delay, session or secondary signers. The compatibility matrix records them per
  class (AB-M7).
- **Key-rotation window.** Anyone holding `S_w` and a rotated-out owner key can prove against a base
  block before the rotation, up to `max_proof_age` (1,024) blocks back.
- **Uniformity** (AB-P20). On-chain data is identical in both modes. Three things can still differ:
  - the mode is visible to the server;
  - signing delay shapes the gap between `valid_until` and inclusion;
  - the PROOF2 object can differ by mode and wallet vendor. The P0b probes differ: 172k steps and
    1,203 OS Blake for Ready, 161k and 1,124 for Braavos.

  **Gate (P5):** ordinary, Ready and Braavos spends give the same leaf bucket (preprocessed root)
  and the same component log sizes. Otherwise every mode is padded to the maximum before
  production.

## 13. Compatibility matrix

A regression harness per supported class records:

- `is_valid_signature` (snake case) and the signature layouts;
- every signer the class accepts;
- where the wallet signs (local or remote);
- guardian and multisig support;
- upgrade targets.

Launch rows: Ready X with Argent 0.5.0 (no guardian) and Braavos 1.2.0 (single Stark signer).
Setup refuses accounts outside the matrix and warns on remote signing.

## 14. Liveness without an escape path

Bound notes need both the Templar key and the account's `VALID`, always. They freeze while:

- the account's signer changes in a way the prover cannot satisfy: a guardian cosignature the
  wallet will not produce, or a signer type not yet supported;
- the account upgrades to a class the pinned virtual OS cannot run, or one without SNIP-6;
- the account is undeployed;
- the seed is lost: no device holds it and the 21-word backup is gone. A key change never changes
  the seed.

All spends, in both modes, also stop while:

- Templar's service refuses and nobody self-hosts. The pool is free, so anyone may run the prover
  (about 29 GiB) and submit through the fallback. A full withdrawal of a priced asset at or above
  its minimum costs no ticket. Dust, NFTs and unpriced assets need a ticket or self-hosting
  (§7.2);
- the gateway rejects PROOF2 (today on Sepolia; mainnet 0.14.4 pending);
- the adapter's OS program is retired before a new adapter applies (§8.4).

Other liveness limits:

- **The log20 small path** (ADR-0024's fallback) moves further away with V5: about +171k steps and
  +1.2k Blake for the account call, and a 35-output statement. Its fit is measured in P5.
- **Block-denominated constants.** `E`, `Q`, `W` and `max_proof_age` are counted in blocks. A
  faster block time shrinks every window, and changing them needs a new adapter or pool.

Mitigations:

- the matrix and the setup checks;
- warnings before enabling 2FA or changing signers while holding bound notes;
- the confirmed 21-word backup;
- free full withdrawals and the fallback submitter;
- bridge updates through the timelocked verifier change.

Losing the account's keys entirely is the same as for the wallet's public funds.

## 15. Implementation phases and acceptance

- **P2 relation:**
  - `payment5.rs` with V4's conservation;
  - the tests of §4.4 and the budget of §4.5;
  - manifest and circuit hash;
  - V5 hiding regression examples (F27).

  Math Reviewer implementation review.
- **P3 bridge and statement account:**
  - §5;
  - standalone and snforge negatives with mock accounts: `VALID`, `0`, panic, undeployed,
    emitting a message, re-entering, returning `VALID` for its own address;
  - real-proof negatives (F11); KATs; real-wallet signing of §5.3; build record;
  - F13, F34 and F38 fixes if in scope.

  Reviews.
- **P3b pool V3** (AB-P14). Acceptance covers:
  - the root rule: the current root after more than `W` idle blocks, junk deposits within `W`,
    `W + 1` blocks after supersession, the P1 path;
  - the expiry boundaries: `block = valid_until` accepted, one block later rejected, the `Q` and
    `E + Q` rules;
  - the V5 binding field matrix including `valid_until`;
  - the timelock for both verifiers: apply before eta, cancel, re-propose, events;
  - bootstrap;
  - no fee or gating path: a fresh account deposits and a third-party account submits;
  - V2's `insert_two` tests carried over;
  - F17, F18, F28's tests committed, and F30;
  - the real statement account end to end.

  Protocol review.
- **P4 server and SDK:**
  - §6, §7, §9, §10 and §11;
  - the job body with full pool calldata, and the calldata-to-statement match at admission;
  - the server's ticket check, ticket states and free full-withdrawal check (including
    `intent = 0` and the free queue), with a test issuer.

  Math review of the SDK key code; protocol review.
- **P4b minimal relayer:** before P5:
  - §7.3 acceptance, handoff and deduplication;
  - submission of every proved spend;
  - a transaction hash or a refusal for every job, and the SDK's fallback timing (§7.4).
- **P5 local end to end:**
  - both modes on live Sepolia state with real Ready and Braavos accounts, with the V5 statement
    account in the pinned virtual OS (P3's real-wallet evidence ran in snforge with a cheated
    caller and chain, AB-IP2);
  - real-wallet signatures of the V5 struct for an in-pool transfer and an invoke (P3 signed
    withdrawals, AB-IP6);
  - PROOF2 per mode and vendor;
  - the uniformity gate (§12);
  - the expiry rate against `E`;
  - WASM proof time and small-path fit.
- **P6 Sepolia:** declare and deploy pool V3, the statement account, the adapters, and run
  `initialize`. The user approves every on-chain action.
- **P7 paying for the service:**
  - `docs/relayer-spec.md`;
  - the Templar Pass contract (soulbound, minter role, no price in code);
  - the issuer: RFC 9474 blind RSA, key periods, the claim flow, the holder-only count;
  - the ticket costs and the free full-withdrawal rule;
  - provisions for a later token.

  Protocol review. The paid service on mainnet needs P7; Sepolia does not.

## 16. Evidence (P0b, 2026-09-25)

`bench/wallet-sig-spike/`, outputs in `target/wallet-sig-spike/`:

- **SNIP-12.** A Cairo module matches starknet.js 10.8 on six vectors; an independent
  recomputation agrees.
- **Real wallets.**
  - Ready X 5.33.11 (Argent 0.5.0) and Braavos 4.19.6 (Braavos 1.2.0) signed the spike's spend
    message and the rev-3 derivation message on Sepolia. Revision 4 no longer uses the
    derivation message.
  - All eight signatures return `VALID`, and repeats are identical.
  - Layouts are `[r, s]` and `[1, r, s]`, raw Stark ECDSA by the owner key.
- **Inline Stark ECDSA in the R4 account.**
  - +17.9k OS steps (+0.5%), +149 Blake, no component log-size change.
  - PROOF2 stays in the same leaf bucket (log 25): 80 s (8 cores) and 64 s (16 cores), about
    29 GiB, within noise of the baseline.
  - **PROOF2 was measured only with this inline check.**
- **Live virtual-OS probe of the real account call.**
  - Accepted for the real signatures, rejected for tampered ones.
  - The whole probe transaction is at most 172k OS steps and 1.2k Blake, against about 12.3k Blake
    of headroom before `blake_g` grows.
  - PROOF2 for the real call is inferred to stay in the same bucket; P5 measures it.
- **Guardian.** Argent 0.5.0 with a guardian rejects owner-only signatures (fork test).
- **Open.** Node simulation on two independent RPC nodes rejects the SigProbe → Ready call. The
  virtual OS, direct calls and fork tests all accept it. Until this is explained, pre-checks use
  `starknet_call` (which agrees), never node simulation.

## 17. Review resolutions

Revision 2:

| Finding | Resolution |
| --- | --- |
| AB-M1 | §4.3.3 handle over `ak₀`; §4.4 tests |
| AB-M2 | `conservation5` (moot in revision 4) |
| AB-M3 | §6.4 no policy seed or notes, every self-directed receiver bound; §3.4 S4 restated |
| AB-M4 | `A` from the wallet, guardian accounts refused, ECDSA verification, `s` canonical |
| AB-M5 | §4.3 Invariant B |
| AB-M6 | §4.3.2 wiring stated; §4.4 tamper hooks |
| AB-M7 | §6.3 reject checks; §12, §13 signers per class |
| AB-M8 | storage and prompts |
| AB-M9 | §5.3 what the screen lets a user check |
| AB-M10 | §3.1, §3.4 second preimages, block shape |
| AB-M11 | §5.4 V5 `__validate__`, own address rejected, no `is_valid_signature`, `salt ≠ 0` |
| AB-P1 | §8.3 validity from supersession |
| AB-P2 | §8.4 every verifier timelocked |
| AB-P3 | secrecy rule and trace test; setup-check signature |
| AB-P4 | §8.4 OS rotation, pending proposals in the SDK; §7.4 fallback submitter |
| AB-P5 | §8.4 one-time `initialize` |
| AB-P6 | optional, sponsored relayer fee; fallback |
| AB-P7 | random output order |
| AB-P8 | relayer acceptance, handoff; §12 combined operator |
| AB-P9 | §5.3 `valid_until` removed from the signed struct |
| AB-P10 | §9 operator node; §10 web-app reads |
| AB-P11 | §8.2 `E` from the pipeline; §9 admission and job-start checks, `send_deadline` |
| AB-P12 | confirmed backup, fingerprint, sweep |
| AB-P13 | deterministic companions |
| AB-P14 | §15 P3b pool phase, P4b relayer |
| AB-P15 | §11 amendments; §16 and the ADR state PROOF2 evidence precisely |
| AB-P16 | §9 caps before proving, data locations, two signature checks |
| AB-P17 | §8.2 pool enforces `Q` and `E + Q`; §5.4 `salt ≠ 0` |
| AB-P18 | §8.5 F17, F18, F30, F19; `MAX_NOTES` |
| AB-P19 | §14 service, gateway, small path, block-denominated constants |
| AB-P20 | §12 uniformity gate and qualifications |
| AB-P21 | §5.3 NFT display noted; cost of the third output |

Revision 3:

| Finding | Resolution |
| --- | --- |
| AB-M12 | companion encoding and KAT; derivation KATs and wallet signing; §4.4 handle test under `M ≠ A` |
| AB-P22 | push-deposit fees from the transaction's account |
| AB-P23 | fees accrue in the pool, `claim_fees` |
| AB-P24 | fee table, F17 on `amount + fee` |
| AB-P25 | exit percentage on invoke budgets |
| AB-P26 | sponsorship limited to what the relayer sees; `send_deadline` |
| AB-P27 | ADR decision 5 corrected; §9 results deleted on acknowledgement |

Revision 4 (the simplification; the user's decisions, ADR-0026):

| Finding | Status in revision 4 |
| --- | --- |
| AB-M2 | Moot. Two outputs use V4's gadget, with carries {−2..1}; `conservation5` is removed |
| AB-M4 | Kept: `A` from the wallet (§6.1); guardian accounts refused (§6.3). Moot: the layout table, the ECDSA check and `s` canonicalization, since there is no derivation signature |
| AB-M8 | Kept: per-device wrapped storage (§6.1). Moot: derivation prompts |
| AB-M12 | Kept: the handle test under `M ≠ A` (§4.4); a key KAT (§6.2). Moot: the companion and derivation-message KATs |
| AB-P3 | Kept: the secrecy rule and trace test, now for `S_w` and spending keys (§6.1); the setup-check signature (§6.3). Moot: the derivation signature |
| AB-P6 | Moot. There is no fee output: tickets pay for the service (§7.2), full withdrawals are free, and the fallback submitter remains (§7.4) |
| AB-P7 | Kept for two outputs (unchanged sdk-spec rule). No fee slot exists |
| AB-P8 | Kept: acceptance, deduplication and handoff (§7.3), the operator rows (§12). Moot: the fee-note checks and the fee allowlist |
| AB-P12 | Kept: the confirmed backup (§6.1). Moot: the fingerprint and the sweep, since a key change no longer changes the seed |
| AB-P13 | Moot. A random seed reaches a second device only through its phrase, as in the Templar wallet, so HA-M6 is unchanged. The duplicate-nullifier rule is kept for both products (§6.2) |
| AB-P14 | P3b and P4b updated; P7 added (§15) |
| AB-P18 | Kept: F17, F18, F30, F19. `MAX_NOTES` back to V2's 4, with V2's `insert_two` |
| AB-P21 | No third output. The cost of `valid_until` and the binding change is measured in P3b |
| AB-P22–P25 | Moot. There are no protocol fees (§8.6) |
| AB-P26 | Sponsorship is moot. `send_deadline` is kept |

Revision 4 re-review (math GO; protocol CONDITIONAL GO, with conditions AB-P28 and AB-P29):

| Finding | Resolution |
| --- | --- |
| AB-M13 | §7.2 the free path requires `intent = 0`, a priced asset at or above its minimum, `asset` from the decoded `token_out`, and canonical openings |
| AB-M14 | §6.2 a bound note's companion is built in bound mode with the same account; §4.4 `valid_until` bridge negatives |
| AB-P28 | §9 the job body carries the full pool calldata, matched to the statement at admission; §7.3 handoff; §11 prover-server-spec §2 amended |
| AB-P29 | §7.2 `intent = 0`; the table prices dust, NFTs and unpriced assets at one ticket, and says who is still not free; a separate low-priority queue and rate bounds; §14 corrected |
| AB-P30 | §9 the merged admission order and the ticket states; blinded refund requests; §7.2 one spent set per issuer key across all redeemers. One deviation: a signature failure releases the reservation (it costs one call, and honest clients meet it after a key rotation), with a per-note back-off (never per account: a victim's account could be locked out) and an SDK pre-check |
| AB-P31 | §7.3 the relayer returns a transaction hash or a refusal; §7.4 the fallback timing and `margin` |
| AB-P32 | §12 the issuer-key period and a pass-holder row; §7.2 the pass in a separate account; ADR decision 3 states why there is no escape path |
