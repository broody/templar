# Templar client SDK

Status: **revision 3, implemented on branch `feat/sdk`; implementation reviewed (math GO,
protocol GO: `docs/reviews/sdk-impl-{math,protocol}-review.md`); funded Sepolia run done (`sdk/results/sepolia-e2e.json`). Design, after the design reviews (`docs/reviews/sdk-design-math-review.md`,
`docs/reviews/sdk-design-protocol-review.md`: both CONDITIONAL GO on revision 1; on revision 2,
math GO and protocol CONDITIONAL GO, whose items revision 3 resolves). Finding IDs
`SDK-M*` and `SDK-P*` are cited where they changed the text; §16 lists every resolution. Nothing is
implemented.** **Revision 4 amendments** (`docs/account-bound-note-spec.md` §11, P4 on
`feat/account-bound`) add R0 V5 on pool V3 and bound wallets (product 1): §3.4, and the
"Pool V3 (R0 V5)" paragraphs in §8, §9, §10.2, §11 and §14. R0 V4 on pool V2 is unchanged.
**Revision 5 amendments** (`docs/pool-v3-spec.md` §14, ADR-0027) remove bound wallets and add
R0 V6 on pool V3, whose R0 and P1 verifiers become routing adapters (pool-v3-spec §6): §3.1,
§3.4, §8, §9.1, §9.2, §10.2, §11 and §14. The code implements R0 V5 and bound mode until
ADR-0027's phases B–E land, so each changed passage is marked "(R0 V6, ADR-0027: pending
implementation)" or "(ADR-0027: pending implementation)", and bound-mode text that the code still
has is marked "(removed by ADR-0027, phase B)".
Defines the maintained client side of the compact client-proof path (TODO item
4): a Rust core compiled to WebAssembly, and a TypeScript package on top that uses starknet.js for
every chain interaction.

## 1. Purpose and scope

Today the client side exists only as bench tooling: the Rust `wallet` example
(`bench/m31-private-wrapper/client-port/examples/wallet.rs`), Python helpers
(`bench/m31-pool/{hidden_asset,policy_wallet,policy_note}.py`) and `sncast`-driven flows
(`bench/m31-sepolia/`). The wallet keys there are **fixture derivations**
(`TEMPLAR_FIXTURE_*` labels), and there is no receiving-address format.

**This design:**

- `templar-core` (Rust, `sdk/core`): every format, derivation, hash, encryption, check and the
  client proof. No I/O, no clock, randomness injected, no panics on any input (§2).
- `templar-wasm` (Rust, `sdk/wasm`): a `wasm-bindgen` façade over the core, JSON in and out.
- `@templar/sdk` (TypeScript, `sdk/ts`): sync, in-flight state, the prover-server client and
  submission, over starknet.js. Note selection and ordering are in the core (§7.2).

**One canonical implementation.** Cryptography and encodings exist only in the Rust core. The
TypeScript layer never hashes, encrypts or encodes a protocol value itself. The core reuses the
reviewed relation code (`client-port/src/payment.rs`, `payment4.rs`, and the in-repo sources they
include) rather than copying it.

In scope (v1), on M31 pool V2 (Sepolia, `bench/m31-sepolia/README.md`):

- production key derivation, receiving addresses, incoming and full viewing keys (§3, §4);
- deposits of ERC20, ERC721 and ERC1155 assets to any address (§7.1);
- receiving and seed recovery: `M301` notes, and `PS01` split outputs of policy settlements (§6);
- R0 V4 spends: hidden-asset transfers of any asset, consolidations and withdrawals (§7.2);
- the prover-server client, with optional Oblivious HTTP (§8);
- submission through a caller-supplied, signer-backed starknet.js `Account` (§9).

Out of scope for v1: creating or settling policy notes (P1), open notes (`intent ≠ 0`), shadow
identity handles, a relayer or fee payment (TODO item 5), an indexer or private sync service
(TODO item 2), browser-extension wallets as submitters (`WalletAccount`, SDK-P4), React Native
(Hermes has no WebAssembly), and the legacy pool. Unused V4 fields are fixed to zero by the core.

**Current limits (SDK-P15).** No spend can be included yet: the Sepolia gateway rejects large
proofs (`PROOF_VERSION_NOT_ALLOWED`) and mainnet 0.14.3 does not accept them. Simulation does not
verify the large proof itself. A spend costs about 3.1–3.5 STRK on Sepolia.

## 2. Architecture

```text
 app ──► @templar/sdk (TS) ──► starknet.js (peer dependency) ──► RPC node   (events, calls, submission)
            │     │
            │     └──────────► prover server  (HTTP, or only through an OHTTP relay)
            ▼
        templar-wasm ──► templar-core ──► client-port relation (R0 V4) ──► stwo-circuits (arith fork)
        (the tree on the main instance; proving in a Web Worker / worker_threads, a fresh instance per proof)
```

**Secrets.** The application holds one secret: the 32-byte seed (§3.1). It necessarily lives in
JavaScript (and is copied to the proving worker), so the WASM boundary is hygiene, not isolation
(SDK-M14). Every WASM function that needs a key takes the seed as bytes and derives the key
internally; spending, nullifier and decryption keys are **never returned to JavaScript**, except
by the explicit viewing-key export (§4.2). The core zeroizes derived keys (`zeroize`). The
proving worker is terminated after each proof, since linear memory never shrinks. Only the
mnemonic import takes words.

**No panics.** Every core function returns `Result`; no input (a hostile ciphertext, a malformed
address, a bad plan) may panic in the core's own code, since a panic traps the WASM instance
(SDK-M2, SDK-P1). The proving dependencies cannot be audited to that standard; a crash while
proving is contained by the per-proof worker instance and reported as a failed proof. The
release WASM is built with `panic = "abort"` and a CI test feeds malformed inputs to every export.

**Randomness.** The core takes an RNG argument. In WASM it is `getrandom` with the `js` backend
(0.2) and `wasm_js` backend (0.3), both configured (SDK-P11); natively, the OS CSPRNG. A seeded
RNG exists only under the `test-rng` cargo feature, which builds a separately named test artifact;
CI checks that the release `.wasm` exports no seeded function (SDK-M13, SDK-P12).

## 3. Keys (normative, new)

### 3.1 Seed and backup

- The wallet seed `S` is 32 bytes from a CSPRNG.
- The backup is `S` as a 24-word BIP-39 English mnemonic (the 32 bytes are the BIP-39 entropy;
  the 8-bit checksum is BIP-39's). The BIP-39 PBKDF2 seed is **not** used and there is no
  passphrase in v1. Import rejects a bad checksum, a wrong word count, and words outside the
  list.
- The mnemonic carries no version (SDK-M12). Recovery therefore tries every derivation version
  the package knows (v1: only `TEMPLAR_*_V1`) against every pool in the network constants, past
  and present (§10.2). The documentation and UI say the mnemonic is Templar-only: never import
  another wallet's mnemonic, and never type this one into another wallet.
- **Backup check** (`docs/pool-v3-spec.md` §10.2; ADR-0027: pending implementation). The backup
  is confirmed with a word check before the first address is shown: addresses are gated on it.

### 3.2 Derivations

`HKDF` is HKDF-SHA256 (RFC 5869). `felt₃₂(x)` is a felt as 32 big-endian bytes; `u32₄(i)` four
big-endian bytes.

```text
PRK        = HKDF-Extract(salt = "TEMPLAR_WALLET_V1", IKM = S)
ctx(i)     = felt₃₂(chain) ‖ felt₃₂(pool) ‖ u32₄(i)                 i ∈ [0, 2^32): the account index
sk(i)      = wide9(HKDF-Expand(PRK, "TEMPLAR_SPEND_V1"    ‖ ctx(i), 144))
ivk(i)     = clamp(HKDF-Expand(PRK, "TEMPLAR_INCOMING_V1" ‖ ctx(i), 32))
pk(i)      = X25519(ivk(i), 9)
kstore     = HKDF-Expand(PRK, "TEMPLAR_STORE_V1" ‖ felt₃₂(chain) ‖ felt₃₂(pool), 32)
ak, nk, receiver   = as the relation: ak = H(AUTH, sk), nk = H(NK, sk), receiver = H(OWNER, ak ‖ nk)
```

- `wide9(b)`: nine M31 words, word `k` = `int_be(b[16k .. 16k+16]) mod p` (statistical distance
  from uniform about 2⁻⁹⁹ per word). An all-zero result is an error (probability ≈ 2⁻²⁷⁹).
- `clamp`: RFC 7748 scalar clamping. `kstore` keys the store encryption (§10.3).
- `chain` is the chain id felt (`SN_SEPOLIA`, `SN_MAIN`); `pool` the pool address. Keys are
  unrelated across pools and chains (ADR-0020).
- The policy-note seed `s_pol = HKDF(empty salt, S, "TEMPLAR_POLICY_SEED")` is unchanged
  (`docs/policy-note-spec.md` §9.1) and reserved; v1 does not use it.
- Fixture keys (`TEMPLAR_FIXTURE_*`) are test-only and never produced by the SDK.

**Account indexes (SDK-M3, SDK-P14).** Index 0 is the default. Let `u` be the highest index with
any credited note at least 10 blocks deep, spent or not, in a complete sync (SDK-M18) (`u = 0` if none). The core refuses to derive
an address for `i > u + 3`; the store also records the highest index created, and the wallet
scans every index up to `max(u, created) + 3`. Recovery scans `0 ..= u + 3`, and whenever a note
is found at an index above `u`, raises `u` and rescans the new indexes, until the last four
indexes hold nothing. It costs `u + 4` sealed-box opens per ciphertext. A spend's inputs come
from one account and its change goes to that account.

### 3.3 Note randomness and dummies

- Every output's `rho` is nine words drawn uniformly in `[0, p)` by rejection sampling, not all
  zero, fresh from the CSPRNG (payer-chosen; never seed-derived). Change to oneself is found again
  by scanning, since its ciphertext is sealed to one's own `pk`.
- Dummy inputs and dummy outputs follow `docs/hidden-asset-spec.md` §6 (fresh per proof, a real
  sealed box of a random 256-byte plaintext to a fresh key pair), with one amendment (SDK-M10,
  SDK-M17): a note's dummy input is **sticky**. The first time a statement naming the note as a
  single real input leaves the wallet (to a prover server or the chain), its dummy witness (`sk`,
  `rho`, position, siblings) becomes the note's **companion**, stored with the note, and every
  later single-input statement naming that note reuses it until the note is spent. Once a
  statement has left the wallet, the real nullifier may be seen again (a published revert, the
  server's view, a late publication), and a fresh dummy next to it would single out the real
  nullifier; reuse reveals nothing new. Before proving, the core checks that the companion's
  nullifier is not spent. A companion is never used with another note. `docs/hidden-asset-spec.md`
  §6 carries the same amendment.

### 3.4 Bound seeds (removed by ADR-0027, phase B)

ADR-0027 removes bound wallets (product 1): every user holds ordinary notes under the §3.1 seed,
and an external wallet connects only for login, deposits, withdrawals and paying for the service
(`docs/pool-v3-spec.md` §1, §7). Wallets never create bound receivers again, and every bound
receiver already in pool V3's tree becomes unspendable at the Sepolia cutover (pool-v3-spec
§11.5). The code keeps bound seeds until phase B lands. Their normative text (the 21-word seed,
the `TEMPLAR_BOUND_*_V1` labels, the `WAUTH` receiver, `KNOWN_V4_POOLS` and the setup checks)
stays recorded in `docs/account-bound-note-spec.md` §6. The hash kind `WAUTH = 16` is reserved
permanently (pool-v3-spec §3).

## 4. Addresses and viewing keys (normative, new)

### 4.1 Receiving address

Encoded as in ZIP-316 (SDK-M4): F4Jumble over the payload and a padding block, then Bech32m, so
every character depends on every field.

```text
payload  = 0x01 (version) ‖ 0x01 (type: address) ‖ felt₃₂(chain) ‖ felt₃₂(pool) ‖ receiver (nine u32, big-endian: 36 bytes) ‖ pk (32 bytes)
           (exactly 134 bytes)
jumbled  = F4Jumble(payload ‖ hrp padded with zero bytes to 16 bytes)
address  = Bech32m(hrp, jumbled)            hrp: "templar" (SN_MAIN), "templarsep" (SN_SEPOLIA)
```

F4Jumble is ZIP-316's (BLAKE2b with its personalizations). The string is about 255 characters
(under 1023, the maximum a decoder accepts; Bech32m padding bits must be zero). Decoding reverses the
steps and rejects: a length other than 150 bytes after Bech32m; a padding block that is not the
HRP followed by zeros; an unknown version; a type other than the one this decoder accepts (each
decoder accepts exactly one HRP and one type, SDK-M16); an HRP that does not match `chain`; `chain` or `pool`
zero or not below 2²⁵¹; a receiver word not below `p`, or an all-zero receiver; a `pk` with bit
255 set, with `u ≥ 2²⁵⁵ − 19`, or equal to one of libsodium's seven blocked u-values (0, 1,
`p − 1`, `p`, `p + 1` and the two order-8 u-coordinates, listed as bytes in the code) (SDK-M6).
Sealing and opening in the core both reject an all-zero shared secret, as libsodium does.

A payer's wallet rejects an address whose `chain` and `pool` are not those of the pool it pays
into: a note sent to another pool's receiver is lost to the recipient.

Addresses must be authenticated out of band (contact exchange, QR); encryption cannot
authenticate them. The **only supported human check** is the full fingerprint:
`fingerprint(address)` = the first 10 bytes of `SHA-256("TEMPLAR_ADDRESS_FP_V1" ‖ payload)` as
five groups of four hex digits, all compared.

### 4.2 Viewing keys

Same encoding (F4Jumble, then Bech32m with a zero-padded HRP block). HRPs `templarivk`,
`templarfvk` (`templarivksep`, `templarfvksep` on Sepolia). Exact payload lengths:

```text
incoming (134 bytes): 0x01 ‖ 0x02 (type) ‖ felt₃₂(chain) ‖ felt₃₂(pool) ‖ receiver₃₆ ‖ ivk₃₂
full     (174 bytes): 0x01 ‖ 0x03 (type) ‖ felt₃₂(chain) ‖ felt₃₂(pool) ‖ ak₃₆ ‖ nk₃₆ ‖ ivk₃₂

The type byte keeps a secret incoming key from ever decoding as a public address (a clamped `ivk`
is also a valid X25519 public key): each decoder accepts one HRP and one type, and cross-type
inputs are negative tests (SDK-M16).
```

- The account index is not included (SDK-M11). `ivk` must equal `clamp(ivk)` (SDK-M6).
- Import requires the expected address, authenticated independently, and checks that the key's
  chain, pool, receiver (for a full key, `H(OWNER, ak ‖ nk)`) and `X25519(ivk)` equal the
  address's. A self-consistent key for another address is rejected.
- **An incoming viewing key** decrypts and validates every note to the address, **including the
  account's change notes**, so it sees the rhythm of spends and approximate outflows. It cannot
  compute nullifiers, so it reports received notes, not an unspent balance.
- **A full viewing key** also computes `nf = H(NF, nk ‖ cm ‖ pos_lo ‖ pos_hi)`, so spent status.
  From change it learns each spend's outgoing amount (inputs minus change), and it can tell the
  account's own spends' dummy nullifiers from real ones. It holds no `sk` and cannot spend.
- Exports are sensitive and not revocable; the SDK exports only on an explicit call. A separate
  internal change key per account (ZIP-316's internal/external split), which would keep change
  out of an incoming viewing key, is a later format version.

## 5. Notes, delivery and the tree (existing formats)

Unchanged from the deployed pool; the core implements them once and the KATs pin them (§12):

- `inner = H(INNER, receiver ‖ rho)`, `cm = H(NOTE, chain₉ ‖ pool₉ ‖ asset₉ ‖ amount₈ ‖ inner)`,
  `nf = H(NF, nk ‖ cm ‖ pos_lo ‖ pos_hi)` (`payment.rs`); tree format `Tree::Compress` (pool V2).
- Asset identifiers: ERC20 = contract address; ERC721/ERC1155 =
  `Poseidon('TEMPLAR_ASSET_V1', standard, contract, id.low, id.high)`, below 2²⁵¹
  (`docs/hidden-asset-spec.md` §3.1).
- Plaintexts: `M301` (256 bytes) and, for receiving only, `PS01` (`bench/m31-pool/policy_wallet.py`).
- Delivery: libsodium `crypto_box_seal` (X25519, XSalsa20-Poly1305), 304 bytes; ten words (nine
  31-byte, one 25-byte, big-endian); `delivery = Poseidon('CTRL_DELIVERY_V1', 304, words)`.
- The binding `Poseidon('TMR0_BIND_V4', …)` and the pool's `Spend` serialization, as
  `bench/m31-pool/hidden_asset.py` (`binding`, `encode_spend`) and `cairo/src/spend4.cairo`.

**The tree** is a WASM handle on the main instance holding every leaf in index order (36 bytes
each) with cached levels. It appends leaves, truncates to a leaf count (for reorgs), and returns
the root and membership paths. Paths are always computed locally from the full leaf list, never
requested from a server. A spend plan carries its root and paths, so proving is a pure function
of the plan and runs in a separate worker instance (SDK-P8).

## 6. Receiving and recovery (normative)

**Events.** The SDK fetches pool events only by `starknet_getEvents` with
`address = pool` and `keys = [[selectors of NotePublished, NullifierSpent, AssetRegistered,
PolicySettled, Deposited]]`, paged by continuation token, and accepts an event only if its `from_address` is
the pool and its first key is one of those selectors (SDK-M7). Each event carries only its
selector as a key, so no filter names a note.

**Scan.** `scan` takes the published notes `(index, commitment, ciphertext words)`, the asset
registry, the policy settlements and the key material (seed with account indexes, or a viewing
key), and returns owned notes. It is total: every step below that fails means "not ours", and no
input can make it panic (SDK-M2). A note is credited only if, in this order:

1. the ciphertext is exactly ten words, nine below 2²⁴⁸ and the last below 2²⁰⁰;
2. it opens under `ivk(i)` for a scanned index `i` (a nonzero shared secret);
3. the plaintext is `M301` with bytes 124..256 zero, or `PS01` with bytes 125..256 zero and side
   0 or 1 (SDK-M1);
4. its fields are in range, before any hashing: asset nonzero and below 2²⁵¹; every `rho` word
   below `p` and not all zero (SDK-M1); receiver words below `p`; and the amount: for `M301`,
   `0 < amount < 2^128`; for `PS01`, a `PolicySettled` with `x > 0` and
   `index == first_index + side` must exist, and the amount is `x` (side 0) or `amount − x` by
   checked subtraction, nonzero (side 1) (SDK-M7);
5. its receiver equals `receiver(j)` for some scanned index `j` (the note is credited to `j`);
6. `cm` recomputed from `(chain, pool, asset, amount, receiver, rho)` with the core's fallible
   encoders equals the published commitment at that index;
7. if `asset` is in the registry (`AssetRegistered`), it re-derives from its
   `(standard, contract, id)`. An identifier not in the registry is treated as an ERC20 address
   only when the registry has been synced through the note's block; otherwise it is shown as an
   unknown asset (SDK-M15).

Every leaf's `NotePublished.digest` is checked against `delivery(words)`; a mismatch makes the
sync incomplete (SDK-M7).

Notes are keyed by leaf index. A repeated identical event for one index credits once; two
**conflicting** events for one index make the sync incomplete (SDK-M7, SDK-P8).

**Spent status** comes from the bulk `NullifierSpent` events matched locally against owned notes'
nullifiers. The SDK never calls `get_nullifier_spent` or any other per-note query.

**Metadata (SDK-P5).** ERC20 assets are identified by address and checked against the pinned
token list in the network constants; others are shown by address and flagged unverified. Token
metadata (`symbol`, `decimals`) comes from the pinned list only in v1 (reading it for every ERC20
ever deposited, from bulk `Deposited` events, is a later option), never read only for assets the
wallet holds. NFT `token_uri` resolution is off by default; when enabled it goes through an
application-supplied proxy.

**Blocks and completeness (SDK-P8).** A sync targets `N`, the `latest` block (in RPC 0.10,
`latest` is `ACCEPTED_ON_L2`; `pre_confirmed` data has no block hash and is never appended to the
tree; notes seen there are shown as pending). A sync is complete only if the leaf indexes are
contiguous from 0, their count equals `get_leaf_count()` at `N`, the tree's root equals
`get_root()` at `N`, every delivery digest matches, and no conflicting duplicate was seen.
Otherwise the result is *incomplete* and balances say so (a missing ciphertext could be the
wallet's). The RPC provider is trusted for integrity: a dishonest provider could fabricate a
complete history, so the SDK optionally cross-checks `get_root()` at `N` against a second provider
before treating a receipt as final (SDK-M8).

**Spendable.** A note is selectable only if the latest sync is complete, the note is at least 10
blocks deep, it is not spent, and no live in-flight record names it (§9.1).

**Reorgs.** The sync state keeps checkpoints every 1,000 blocks, each with the block number and
hash, the leaf count, and the spent-set and credited-note deltas since the previous checkpoint.
Each sync rolls back to the latest checkpoint whose block hash still matches the chain (reading
only checkpoint hashes, never the exact last block, which would link sessions), undoing the
deltas after it and truncating the tree, and re-fetches from that checkpoint. So a reorg of any
depth is repaired, and `from_block` values are always checkpoint boundaries (SDK-P5, SDK-P19).

**Recovery** is a sync from each known pool's deployment block with the gap-limit index scan
(§3.2).

## 7. Operations

### 7.1 Deposits

A deposit creates a note for any address (one's own or another's): `inner` and the sealed `M301`
for the address, then:

- ERC20: one multicall, `approve(pool, amount)` then `deposit(token, amount, inner₉, ct₁₀)`.
- ERC721: `safe_transfer_from(from, pool, id, data = inner₉ ‖ ct₁₀)`; amount 1.
- ERC1155: `safe_transfer_from(from, pool, id, value, data = inner₉ ‖ ct₁₀)`.

Deposits are public (depositor, asset, amount). Before a deposit the SDK checks that the pool's
verifier still equals the pinned adapter, and refuses otherwise (SDK-P15). After inclusion it
checks the note's commitment against the `NotePublished` event.

### 7.2 Spends (R0 V4)

Every spend has two inputs (the second a dummy when one note suffices) and two outputs (dummies
for missing ones). All selection, ordering and dummies happen in the core with its CSPRNG
(SDK-P10).

- **Transfer** `(asset, amount, to)`: choose notes of `asset` from one account (the smallest single
  note covering `amount`, else the pair with the smallest total that covers it; more than two
  notes needed → an error suggesting `consolidate`). Outputs: the payment to `to` and change to
  the same account (or a dummy if the change is zero), in uniformly random order. A single real
  input is input 0 with a fresh dummy as input 1 (the relation requires it); two real inputs are
  in random order. `asset` is not published.
- **Withdraw** `(asset, amount, recipient)`: outputs are change (or a dummy) and a dummy, in random
  order; the asset, amount and recipient are published. For ERC1155 the SDK first checks the
  recipient supports SRC5 with `IERC1155_RECEIVER_ID` or `ISRC6_ID` (HA-P7). For ERC721 it warns
  when the recipient has no class or does not support `ISRC6_ID`, since `pay_out` uses
  `transfer_from` and a contract that cannot move the NFT strands it (SDK-P14).
- **Consolidate** `(asset)`: two notes into one note to the same account.
- ERC721 notes: amount 1, one input and a dummy.

The root is always the root of the latest complete sync (SDK-P8, SDK-P10). The core rebuilds and
checks everything the plan says: conservation, ranges, that every input is the wallet's, unspent
and at the plan's root, `payment4::statement`, and `payment4::bridge_checks`. It then proves
(§7.3) and returns the proof, the public statement, the binding, the ciphertexts, the dummy
witness (for the in-flight record) and the pool calldata.

### 7.3 The client proof

The core proves as the bench wallet (`wallet.rs` `prove_relation`) does: arithmetic profile,
`Tree::Compress`, the blinding-budget loop, bounded FRI columns (16). The proving helpers move
from `client-port/examples/support` into a `prove` module of the client-port library, which the
bench examples then call (SDK-P1):

- the bridge FRI configuration (blowup 2, 35 queries, PoW 26) and the other shape constants are
  compile-time constants, with a native test that they equal the pinned files in the fork; the
  library has no `TEMPLAR_FRI` override (that stays a bench-only wrapper);
- no `Instant`, no `catch_unwind`, no negative or forgery runs in the library (they stay in the
  bench);
- every check returns `Result`: the blinding budget (`revealed + NON_QUERY_INFO_LEAK ≤ blinding`)
  and **native verification of its own proof** are mandatory errors on every proof, in WASM
  included (SDK-M13);
- the TMPZK002 oracle is an optional feature, off for the SDK (done: `oracle`, default on for the
  bench).

Proving runs in a Web Worker (browsers) or `worker_threads` (Node), single-threaded (rayon's
wasm32 fallback), in a fresh instance per proof, built with WebAssembly's 128-bit SIMD
(`+simd128`: about 3x faster than scalar; every current browser and Node, Safari from 16.4). Multi-threaded WASM (`wasm-bindgen-rayon`,
cross-origin isolation) is a later option. Native cost today: log 18, ~0.6 s at four threads.

**Milestone 0 (gating, SDK-P1).** Before the rest of the core: build R4 proving for
`wasm32-unknown-unknown`, prove an R4 spend in a worker, check it byte-identical to the native
proof under the test RNG, and pass it through `templar-prover check`. Thresholds for v1 (desktop,
single thread): proof time ≤ 30 s in Node and in desktop Chrome, peak linear memory ≤ 1.5 GiB,
`.wasm` ≤ 16 MB uncompressed; the grinding share of proof time is reported. A mobile browser is
measured when a device is available and is not a v1 gate.

## 8. The prover-server client

**Pinned constants, not the server's word (SDK-P7).** The network constants (§10.2) pin the pool,
the R4 adapter address and **class hash**, the statement account and class, the account tag, the
OS program, `max_proof_age`, the virtual-OS config hash (`facts[6]`), and the client circuit hash.
Before first use in a session the SDK checks the chain against them: `pool.get_verifier()` equals
the adapter; the adapter's class equals the pinned class; the adapter's storage, read by slot
(`sn_keccak` of `pool`, `statement`, `statement_class`, `os_program`, `max_proof_age`,
`account_tag`, as the server's startup does), equals the pins; the statement account's class
equals the pin. `GET /v1/info` must agree with the pins; a disagreement makes the SDK refuse that
server. The client's own circuit hash, computed when proving, must equal the pin. For a routing
adapter (pool V3 under R0 V6), the adapter's views replace these storage-slot reads, and the
per-adapter pins become route pins ("Pool V3 (R0 V6)" below; R0 V6, ADR-0027: pending
implementation).

**Jobs (SDK-P3).** `submit` posts `{relation: "r4", proof, statement}` once and stores the job id
and the exact body in the in-flight record before anything else (§9.1). Recovery polls the stored
job id; the SDK never resubmits automatically. On `409` or `429` it does not retry: it reports the
server's retention time (from `/v1/info`) and offers to wait or to use another server. A note is
free at a server when its job is dropped at the end of retention, or (with the server change in
§16, SDK-P3) when a finished job's `valid_until` has passed (SDK-P18).

**Result checks** (`check_result` takes the pinned constants, never `info`; any failure discards
the result):

- `proof_facts` has exactly 9 entries: `'PROOF2'`, `'VIRTUAL_SNOS'`, the pinned OS program,
  `'VIRTUAL_SNOS0'`, `base_block`, the base-block hash, the pinned config hash, `1`, and the message
  hash;
- the message hash equals `Poseidon(statement, 0, 5, [statement_class, account_tag, chain, pool,
  binding])` with the pinned values and the SDK's own binding;
- `result.binding` equals the SDK's binding; `result.base_block == facts[4]`, and it is at most
  the latest block; the proof is valid base64 no larger than 480,000 bytes;
- `submit_after = base_block + 11` and `valid_until = base_block + max_proof_age` are computed
  locally from `facts[4]` and the pinned `max_proof_age`, never taken from the server (SDK-M9).

The base-block hash is not read separately (SDK-P5): the sequencer checks it statelessly, and a
wrong one is rejected without a fee.

**Pool V3 (R0 V5; revision 4).**

- **Pins.** Each pool also pins its relation (`version: 'v5'`) and pool V3's constructor
  constants `E`, `Q`, `W`, which must equal `get_parameters`. The relation served is `r5`
  (account tag `TMPZR0_PAYMENT_V5`, the R0 V5 circuit hash). The spend message's domain and type
  hashes are the core's constants, never configuration (removed by ADR-0027, phase B, with the
  `spend_message` check on servers).
- **Verifier and proposals** (AB-PV7). The verifier check reads `get_verifier('R0')`. The SDK
  reads `get_proposal` for `'R0'`, `'P1'` and every shadow class it uses, and shows each pending
  change with its lapse time `eta + T`. A deposit is refused while a verifier change is pending
  and not lapsed (judged at the latest block's timestamp); a shadow-class change is shown but
  does not block deposits, since allowlisting cannot move funds. `T` is pinned too, and on
  SN_MAIN must be at least 7 days, with `W ≥ E + Q`.
- **Job body:** `{relation: "r5", proof, statement, pool_call: {entry_point, calldata}, salt?,
  signature?, payment?}`. The bound-only `salt` and `signature` are removed by ADR-0027, phase B.
  - `statement` is the core's own JSON text, never re-serialized, since its u128 amount and
    `valid_until` would not survive a JS number.
  - `pool_call` is pool V3's exact calldata, with an empty proof span.
  - (Removed by ADR-0027, phase B.) A bound spend carries the salt and signature from
    `authorize()`, which asks the connected wallet to sign the core's SNIP-12 message and checks
    `is_valid_signature` itself through the spend provider (account-bound spec §10) before
    anything leaves. The body is refused unless the stored authorization signs this very
    statement; `authorize({ fresh: true })` signs the same statement again after a refusal (for
    example a key rotation).
  - `payment` holds tickets (supplied by the application in P4; the ticket wallet is P7's), or,
    for a full withdrawal of a priced asset, `freeWithdrawalPayment()`: both outputs' openings,
    shown to the server only.
- **Result checks** add: the window ends at `min(statement.valid_until, base_block +
  max_proof_age)`, computed locally (the server's `send_deadline` is not trusted), and
  `result.pool_call` must be `apply_spend` with the wallet's own calldata. `/v1/info` must publish
  the core's spend domain and type hashes (removed by ADR-0027, phase B) and the pinned `E`, `Q`,
  `W`, `T`.
- **Refusals.** After an admission refusal (400, 402, 403) the stored body is dropped, so the next
  wrap builds one with new payment or a fresh authorization (removed by ADR-0027, phase B); the
  statement and proof stay. When the statement's own `valid_until` bounds the window, another job
  cannot help: `wrap` asks for a re-plan.

**Pool V3 (R0 V6; revision 5).** Normative text: `docs/pool-v3-spec.md` §9 and §10 (R0 V6,
ADR-0027: pending implementation). Pool V3's R0 and P1 verifiers become routing adapters
(pool-v3-spec §6); each route pins eight fields: the statement account (the route's key), its
class, its account tag, the OS program, the proof version, variant and output version, and
`max_proof_age` (pool-v3-spec §6.1).

- **Pins.** The relation is `r6` (version `v6`, account tag `TMPZR0_PAYMENT_V6`, the R0 V6
  circuit hash), with no spend message. For each kind, a pool pins a list of generations (§10.2):
  an adapter, its class, and every pinned state of its route set (PV3-5, PR2-2). The SDK plans
  with the R0 generation whose adapter is `get_verifier('R0')`.
- **Verifier and route checks** (PV3-2, PV3-A2, PR2-1). For **both kinds**, wherever the SDK
  checks a verifier, it also requires:
  - `get_verifier(kind)` equals a pinned adapter, and `get_class_hash_at(adapter)` its pinned
    class;
  - `get_pool()` equals the pool;
  - `get_routes()` equals a pinned state of that adapter's route set: the count, and all eight
    fields of each route. The SDK accepts any pinned state of the current adapter;
  - `get_class_hash_at(route.statement) == route.statement_class` for each active route;
  - `get_route_proposals()` holds nothing but pinned planned changes, or removals of pinned
    routes that leave a usable route.

  Any mismatch is treated as `verifier_changed`. These views replace the storage-slot reads of
  the first paragraph of this section.
- **Pending changes** (pool-v3-spec §10.3). The SDK shows every pending proposal with its `eta`
  and lapse time, and surfaces `OwnershipTransferStarted` and `OwnershipTransferred`. For both
  kinds it reads `get_route_proposals()` on the current adapter, and on any adapter that is the
  value of a pending verifier proposal. An unpinned change on either kind refuses deposits, even
  though the SDK does not plan P1 spends yet.
  - A pending change that equals one pinned in the running SDK release (PV3-8) shows a notice and
    does not block deposits. That is either a verifier proposal whose adapter has exactly the
    pinned route set and no pending route proposals, re-checked on every poll until apply; or a
    route proposal equal to a pinned planned route, or a pending removal of a pinned route, unless
    it would remove every route the SDK can use (PR2-2).
  - Any other pending verifier or route change refuses deposits and offers an exit: a route is as
    strong as a verifier.
  - A pending shadow-class change is unchanged: a warning, and routes that would break are not
    built.

  For the Sepolia cutover, the owner may keep the stricter rule (deposits refused even for the
  pinned change) as a drill.
- **Job body:** `{relation: "r6", proof, statement, pool_call: {entry_point, calldata},
  payment?}`, with no salt and no signature. A free full withdrawal's payment carries both
  outputs' openings and a proof-of-work stamp (pool-v3-spec §7.5, §9.1).
- **Result checks** add: each result names its route key `statement` (the statement account's
  address, distinct from the job body's public statement). The SDK checks `facts[0..3]`, the age
  and the message hash against that route, in the pinned state whose route's message hash matches
  `facts[8]`, and takes `max_proof_age` from that route (pool-v3-spec §9.5). `/v1/info`'s `r6`
  section must agree with the pins: the pool parameters (`E`, `Q`, `W`, `T`), the adapter, the
  server's route and the circuit hash. It has no spend-message hashes.
- **Refunds** (PR2-7, PR2-12). When the service fails to settle for a cause that is not the
  client's (a relayer refusal or late take-up, a deadline or root margin the server admitted, a
  verifier or route change after admission, or a bucket-check failure that is the server's
  fault), the server returns blind refunds on the job's stored refund requests, and the SDK plans
  again with them (pool-v3-spec §7.2, §9.3).

**OHTTP** (RFC 9458; SDK-M5, SDK-P6). The key configuration comes from the network constants
(pinned per known server; rotation ships as a package update) or, for another server, from the
application, which obtained it outside the proving session. A configuration that differs from the
pin is refused. When OHTTP is configured, **every** server request (`/v1/info`, jobs, polls) goes
through the relay and the SDK makes no direct request to the server in that session. On a
decapsulation error the SDK stops and reports it; it never falls back to a direct request.
Encapsulation is in the core (the `ohttp` crate with the `rust-hpke` backend, and `bhttp`). The
relay must be configured to forward to the server's gateway and to carry requests of at least
4 MB and responses of at least 1 MB (the client proof is about 2 MB as JSON, a result about
340 KB).

## 9. Submission

### 9.1 In-flight records (SDK-P2)

A spend is an **in-flight record** in the store, written before each network step and updated
after it: the plan id, the account, the input notes and their nullifiers, the root, the dummy
witness (§3.3), the statement, binding, ciphertexts and calldata, the server URL, job id and exact
job body, the result, and the signed transaction's hash, nonce and resource bounds.

- Notes named in a live record are not selectable.
- **Once a record's statement has left the wallet, anyone holding it can settle it** (SDK-P16):
  `apply_spend` does not check its caller, the prover server holds the client proof and can wrap
  it again with a fresh base block, and the RPC provider has seen the signed transaction. A
  `REJECTED` or `REVERTED` attempt, a passed `valid_until`, or an advanced nonce therefore does
  **not** end the record.
- A record whose statement has left the wallet is **dead** only when its root can no longer be
  used. The pool keeps the last 256 recorded roots (`tree.cairo`) and records one root per insert
  call, which adds one leaf (a deposit, `insert_leaf`) or two (a spend, `insert_two`). A root
  taken at leaf count `m` is therefore certainly evicted once at least 256 later insert calls
  have happened, which a leaf count of `m + 512` guarantees (SDK-P20). The record is dead when a
  complete sync shows a leaf count of at least `m + 512` at a block at least 10 blocks deep (so a
  reorg cannot bring the root back), with none of the record's nullifiers spent. The wallet computes this from its own sync, with no
  targeted query (SDK-P18). A record that never left the wallet is dead at once.
- Until then, re-planning a live record reuses exactly its input notes (and companion dummy,
  §3.3). Any number of re-plans may change outputs, amounts or recipients, and at most one of
  them can settle, since they share nullifiers. Mixing the notes with other notes waits for the
  record to die; on a quiet pool that can take a while, and the documentation says so.
- A record **settles** when its nullifiers appear in `NullifierSpent`, and the wallet then
  reconciles which attempt landed (by the published commitments). A dead record's notes are
  released; they keep their companion (§3.3).
- After a published revert, the same result is resubmitted if still inside its window; otherwise
  the record is re-proved with its identical witness (SDK-M10).
- Two devices using one seed cannot coordinate records; the documentation says so.

**Pool V3 (R0 V5; revision 4).**

- A plan takes its root, paths and `valid_until = ⌈(latest + E) / Q⌉ · Q` from one synced block.
  A re-proof keeps its inputs and companion but takes a fresh root, paths and `valid_until` from
  one latest block, never the old root with a fresh `valid_until`, which could fail late with
  `UNKNOWN_ROOT` (AB-PV6). The root is public and the nullifiers do not depend on it.
- The core refuses to prove a plan that is off the grid, at or behind the latest block, or more
  than `E + Q` ahead (`stale_plan`); the wallet then re-plans.
- A record whose statement left the wallet is dead once every attempt's `valid_until` is buried by
  10 blocks, with none of its nullifiers spent. This replaces the leaf count `m + 512`.
- The in-flight window ends at the result's deadline, `min(valid_until, base + max_proof_age)`.
- A duplicate-nullifier refusal (409) is reported and never triggers a re-plan.
- (Removed by ADR-0027, phase B.) A bound spend's authorization (salt and signature) is stored in
  the record before the body leaves. A re-plan clears it (it signed the old statement), and the
  new statement is authorized afresh; a closed or expiring record never prompts the wallet.

**Pool V3 (R0 V6; revision 5;** R0 V6, ADR-0027: pending implementation**).** The rules above
carry over to R0 V6, with the deadline's `max_proof_age` taken from the result's route (§8).
Records planned under V5 before the swap applies finish or expire: they die at `valid_until` plus
the record depth, and the wallet plans their notes again under V6 (`docs/pool-v3-spec.md` §10.2,
§11.3).

### 9.2 Sending (SDK-P4)

**Pool V3 (revision 4).** A bound spend is never submitted by its own account `A`: `submit`
refuses it (`owner_submits`), and another account or the relayer submits instead, never through
the provider that has seen `A` (removed by ADR-0027, phase B; generalized to every connected
account below).

**Connected accounts and consent (revision 5;** `docs/pool-v3-spec.md` §7.2, §7.4; ADR-0027:
pending implementation**).** A connected account is the external wallet a user connects for
login, deposits, withdrawals and paying for the service. It never authorizes spends.

- **A connected account never submits by default.** It submits only through an explicit,
  linkable override. That needs a wallet API that signs and sends a proof-carrying transaction;
  until one exists and is tested on Ready, Braavos and Controller, the override is unavailable.
- **Who submits.** The relayer submits every plain spend (`apply_spend`) the server proves.
  Invokes and P1 settlements (`apply_spend_with_invoke`, including `COMPUTE`, and
  `apply_policy_spend`) are not relayed until the tight minimums exist (F06); until then the
  vault's submitter account (ADR-0027 decision 4) submits them, after consent. SDK submission of
  invokes and P1 settlements from the vault is a deliverable of phases C and F.
- **Fallback for plain spends,** in order: a second, independently operated relayer, once P7
  defines its job intake; then the vault's submitter account, with consent. The timing below is
  unchanged.
- **Every linkable submission asks first** (PV3-7, PV3-A4). Before any submission that links an
  account to the spend (from the vault's submitter account, or an override), the SDK asks the
  user. It names the account, says how the account was funded, and offers the alternatives: wait
  and retry the relayer until `send_deadline − FALLBACK_MARGIN`; a second relayer, once one
  exists; or let the record die and plan again. A relayer refusal never triggers a linkable
  submission by itself.
- **RPC and identity separation.** The vault owns the spend provider, and refuses one that shares
  a node with the application's provider. Spend-specific reads (fee estimates, simulation,
  nullifier, root and recipient checks, status polling) go through the relayer, or through a
  provider that has not seen the connected account, over OHTTP where available. No login
  session, cookie or wallet credential reaches the prover server, the relayer or the ticket
  redeemer; job requests carry no session; OHTTP is recommended for job submission.
- The vault's submitter account is never funded from the connected account. The vault split
  itself (ADR-0027 decision 4) is specified in phase F.

**The relayer and the fallback (revision 4, P4b; account-bound spec §7.4).** A server that relays
submits every R0 V5 spend it proves (under R0 V6, every `r6` `apply_spend` it proves, and during
the cutover both `r5` and `r6` until apply; pool-v3-spec §7.3; R0 V6, ADR-0027: pending
implementation). `wrap` records whether it does, and a re-wrap keeps each
earlier job's relay. `relayStatus(prover)` reads the relayer's answer from the job; only a job gone
at retention leaves the last answer standing. `submit(account, { prover })` needs the prover while
the relayer may still submit, and reads it first. For every job of the record whose relayer may
still submit it, the wallet submits:

- at once when the server does not relay, or the relayer refused the spend, let it expire, or its
  transaction failed;
- otherwise only from that job's `send_deadline − FALLBACK_MARGIN` (40 blocks), and never while
  the relayer's transaction is pending or after it landed. The status is read through the spend
  provider in bound mode (removed by ADR-0027, phase B), else the submitter's own (revision 5:
  through the relayer or a provider that has not seen the connected account); only RPC error 29
  counts as unknown, and any other failure is no answer.

Either way the submitting account is linkable (`linkable: true`); revision 5 asks for consent
before each such submission (above). The relayer (P4b) and the ticket wallet (P7) are specified
with those phases.

- **Window.** Send only when the latest block is at least `submit_after` and at most
  `valid_until − 20`; otherwise wait, or re-prove the record (same inputs and companion) when the
  window has passed, or re-plan it at a new root when its root has been evicted (§9.1). A re-proof
  at the same server waits for that server's retention to end (§8).
- **Verifier.** Re-read `pool.get_verifier()` immediately before simulating; refuse if it differs
  from the pin. For a routing adapter, the route checks of §8's "Pool V3 (R0 V6)" run too (R0 V6,
  ADR-0027: pending implementation).
- **The exact transaction** (SDK-P4, SDK-P17). With a signer-backed starknet.js `Account`, every
  spend-specific call through `account.provider`, whose RPC spec version must be at least 0.10.1
  (`starknet_specVersion`, checked once per session):
  1. the **raw** fee estimate: the invocation built with `account.accountInvocationsFactory`
     (with `proof`, `proofFacts`, `tip: 0`) and passed to
     `account.provider.channel.getEstimateFee(invocations, { skipValidate: false })`, which returns
     the RPC result unparsed (`l1_gas_consumed`, `l1_gas_price`, `l1_data_gas_consumed`,
     `l1_data_gas_price`, `l2_gas_consumed`, `l2_gas_price`). `estimateInvokeFee` is not used: it
     returns only bounds already inflated by an application-configurable overhead (SDK-P21);
  2. resource bounds: for each resource, the raw amount × 1.5 and the raw price × 2; `tip = 0`
     passed explicitly (SDK-P10). The maximum fee `Σ bound × price` is shown before sending and
     the account's STRK balance must cover it (about 3× the expected fee: ~10 STRK per spend on
     Sepolia);
  3. `account.getSignedTransaction(calls, { proof, proofFacts, resourceBounds, tip: 0 })`;
  4. `starknet_simulateTransactions` on that exact object, at block `pre_confirmed` (so a pending
     transaction's nonce is counted) with empty simulation flags (validation and fee charge on),
     as a plain JSON-RPC request through the provider's channel (`channel.fetch`), since the
     built-in helpers skip validation; any revert stops here;
  5. `account.provider.invokeSignedTx(signedTx)` of the same object.

  `calls = [{ contractAddress: pool, entrypoint: "apply_spend", calldata: Spend ‖ 0 }]` (an empty
  `proof` span; the adapter requires it); `proof` is the server's base64.
- **Status** is polled only through the provider that received the transaction (SDK-P5).
- **Reconcile.** The inputs are marked spent only on seeing their nullifiers in `NullifierSpent`;
  the outputs are recorded as notes once `NotePublished` matches.
- **Linkability (SDK-P10).** The submitting account pays and is public, and is linked to the
  spend. v1 has no relayer, so `submit` returns `linkable: true` and the documentation says how a
  relayer's account would change that. The SDK warns when the account's class was compiled with
  Sierra older than 1.7, which is billed in Cairo steps at about 2.7× the fee
  (`bench/m31-sepolia/README.md`).
- **starknet.js** is a peer dependency, `>=10.5 <11` (v10 is the current `latest` on npm;
  `getSignedTransaction` and `invokeSignedTx` exist throughout), tested against 10.8. v11 follows
  when it becomes `latest`.

## 10. APIs

### 10.1 WASM (`templar-wasm`)

Types in JSON: felts as `0x` hex strings; digests as arrays of nine numbers; amounts as decimal
strings; bytes as `Uint8Array`. Errors are returned as `{code, message}` (never a trap).

| Function | Returns |
| --- | --- |
| `seed_generate()`, `seed_from_mnemonic(words)`, `mnemonic_from_seed(seed)` | seed / words |
| `account(seed, chain, pool, i, highest_used)` | `{address, receiver, fingerprint}` (refuses `i > highest_used + 3`) |
| `address_decode(address)` | `{chain, pool, receiver, pk, fingerprint}` |
| `viewing_key_export(seed, chain, pool, i, kind)` / `viewing_key_import(key, expected_address)` | string / opaque key JSON |
| `asset_id(standard, contract, id)` | felt |
| `pool_commitment(chain, pool, asset, amount, inner)`, `delivery_digest(words)` | what the pool computes and records (checks and test doubles) |
| `note_for(address, asset, amount, chain, pool)` | `{inner, ciphertext, commitment}` (a deposit's note) |
| `Tree.new()`, `.append(leaves)`, `.truncate(n)`, `.root()`, `.len()`, `.paths(positions)` | handle |
| `scan(keys, chain, pool, indexes, notes, registry, settlements)` | owned notes with nullifiers (spending or full viewing) |
| `plan_spend(seed, request, notes, root, paths)` | a checked plan (selection, ordering, outputs, dummies) |
| `prove_spend(seed, plan)` (in a worker) | `{proof, statement, binding, ciphertexts, calldata, circuit_hash, dummy}` |
| `check_result(pins, statement, binding, result, latest_block)` | `{submit_after, valid_until}` or an error |
| `store_seal(seed, chain, pool, bytes)`, `store_open(…)` | bytes |
| `Ohttp.new(key_config)`, `.encapsulate(request)`, `.decapsulate(context, response)` | handle / bytes |

### 10.2 TypeScript (`@templar/sdk`)

```ts
const tpl = await Templar.connect({ provider, network: SEPOLIA, store })
const wallet = await tpl.wallet(seed)       // or Templar.seedFromMnemonic(words)
wallet.address(0)                            // { address, fingerprint }
await wallet.sync()                          // → { complete, block, balances, pending }
await wallet.deposit(account, { asset, amount, to })
const spend = await wallet.transfer({ asset, amount, to })   // or withdraw / consolidate
await spend.prove()                          // in a worker; recorded in flight
await spend.wrap(tpl.prover({ url, ohttp }))  // server job; recorded
const receipt = await spend.submit(account)  // window, verifier, estimate, sign, simulate, send
```

`network` constants pin, for each pool in the network, past and present (SDK-M12): the chain, the
pool and its deployment block, the R4 adapter and its class hash, the statement account and class,
the account tag, the OS program, the config hash, `max_proof_age`, the client circuit hash, known
prover servers with their OHTTP key configurations, and the token list.

**Pool V3 (revision 4).** Each pool also pins `version` (`'v4'` or `'v5'`) and, for pool V3,
`parameters` (`E`, `Q`, `W`). Bound wallets (removed by ADR-0027, phase B):

```ts
const seed = Templar.generateBoundSeed()             // 28 bytes; Templar.boundMnemonic(seed): 21 words
await tpl.boundSetupCheck(A, signer)                  // signer = { address: A, signTypedData }, from the connected wallet
const bw = await tpl.boundWallet(seed, A, signer, { spendProvider })  // OHTTP or the relayer, never the main node
const spend = await bw.withdraw(asset, amount, recipient)
await spend.prove()
await spend.authorize()                               // the account signs; checked with is_valid_signature
                                                      // (authorize({ fresh: true }) after a 403 re-signs the same statement)
await spend.wrap(prover, { url, payment: await spend.freeWithdrawalPayment() })
await spend.submit(otherAccount, { confirmFee })      // never A itself
await bw.proposals(shadowClasses)                     // pending owner changes on pool V3
```

`BOUND_ACCOUNT_CLASSES` is the launch matrix of account classes and their signer checks (removed
by ADR-0027, phase B).

**Pool V3 (R0 V6; revision 5;** `docs/pool-v3-spec.md` §10; R0 V6, ADR-0027: pending
implementation**).**

- **Versions.** The relation version (`'v4'`, `'v5'`, `'v6'`) is separated from the pool's ABI
  generation (pool V2, pool V3) in the network, chain and prover modules and in core `pool.rs`.
- **Generations** (PV3-5, PR2-2). For each kind, a pool V3 entry holds a list of generations. A
  generation is an adapter, its class, and every pinned state of its route set, each route with
  its eight fields and its own `max_proof_age`. These route pins take the place of the per-pool
  adapter, statement account, class, account tag, OS program and `max_proof_age` pins above.
  - A release pins every state a planned change passes through: before and after each addition
    and each removal. It also pins each planned removal as a proposal.
  - The SDK accepts `get_routes()` equal to any pinned state of the current adapter, and checks a
    result against the route in that state whose message hash matches `facts[8]` (§8).
- **Removed by ADR-0027, phase B** (pool-v3-spec §10.1): bound wallets (`boundWallet`,
  `boundSetupCheck`, `BoundSigner`, `authorize`, `BOUND_ACCOUNT_CLASSES`) and the
  `prover_account_class` error code; the core's bound keys and `snip12`; the `spend_message`
  check on servers; `bound_seeds` in `sdk/vectors/keys.json`, regenerated with `check_keys.py`
  and `vectors_keys.rs`; and only the SNIP-12 vectors and tests (`cairo-r5/kat`'s SNIP-12 part,
  `bench/wallet-sig-spike/snip12`). The starknet.js `TMR0_BIND_V5` vectors in `cairo-r5/kat` are
  kept and moved to `cairo-r6/kat` or `sdk/vectors`, since they anchor the binding test
  (re-check F3).

### 10.3 Storage (SDK-P9)

`WalletStore` holds, per chain and pool: the sync state (leaves, checkpoints, owned notes, the
spent set, the registry), the highest account index created, in-flight records (§9.1), and a
local sent-payment history (not recoverable from the seed; documented). Owned notes and nullifiers
are equivalent to a full viewing key, and records hold statements, so the shipped persistent store
(IndexedDB in browsers, a file in Node) **encrypts every record by default**: XChaCha20-Poly1305
under `kstore` (§3.2) with a random nonce, in the core (`store_seal`), with associated data
`"TEMPLAR_STORE_V1" ‖ schema version ‖ felt₃₂(chain) ‖ felt₃₂(pool) ‖ record type ‖ record key`,
so a record cannot be swapped for another or moved between keys (SDK-M18). Record names are opaque:
`HMAC-SHA256(kid, len ‖ type ‖ len ‖ key)` under a separate key
`kid = HKDF-Expand(PRK, "TEMPLAR_STORE_ID_V1" ‖ felt₃₂(chain) ‖ felt₃₂(pool), 32)` (SDK-P19, SDK-IM11). Rolling back the whole
store to an older copy is not detected; the documentation says so. After the first release, any change to
record naming or encoding bumps the schema version and migrates (review N2). The store has a schema
version with migrations, and takes a lock per chain and pool (Web Locks in browsers, a lock file
in Node) so two tabs never sync or submit at once. An in-memory store is provided for tests.

## 11. Versioning

The package is semver. Every format has a version label, and decoders reject unknown versions:
key derivation `TEMPLAR_*_V1`, address and viewing-key version byte 1, store `TEMPLAR_STORE_V1`
and its schema version, plaintext `M301`, relation R0 V4 (`R0C4`), binding `TMR0_BIND_V4`.
Changing a format adds a version; old formats stay readable where funds could depend on them, and
recovery tries every derivation version (§3.1).

**Revision 4** adds relation R0 V5 (`R0C5`) with binding `TMR0_BIND_V5`, the bound derivation
labels `TEMPLAR_BOUND_*_V1` (§3.4), the SNIP-12 spend domain `('Templar', 'V5', chain, 1)` with
the `TemplarSpend` type, and job relation `r5`. Recovery of a bound seed tries only pools that
settle R0 V5. (The bound labels, the SNIP-12 domain and bound recovery are removed by ADR-0027,
phase B.)

**Revision 5** (R0 V6, ADR-0027: pending implementation) adds relation R0 V6 (`R0V6`, `R0C6`;
33 outputs) with binding `TMR0_BIND_V5` unchanged, account tag `TMPZR0_PAYMENT_V6`, job relation
`r6`, and relation version `v6`, pinned apart from the pool's ABI generation (§10.2;
`docs/pool-v3-spec.md` §3). The hash kind `WAUTH = 16` stays reserved permanently: bound receivers
already in pool V3's tree contain it.

## 12. Tests and acceptance

1. **KATs.** `sdk/vectors/*.json`, generated by the core, checked by the core, by the TypeScript
   tests through WASM, and by an independent Python reference: the bench's existing helpers for
   plaintexts, sealing, delivery, binding and calldata, and a new small reference for §3 and §4
   (HKDF, `wide9`, F4Jumble, Bech32m, fingerprints). Sealed-box compatibility with PyNaCl both
   ways, including the blocked-point and all-zero-shared-secret cases (SDK-M6).
2. **Relation compatibility.** Under the test RNG, the WASM proof is byte-identical to the native
   core's, and the native core's to the bench `wallet prove4` for the same inputs (the bench's
   RNG draws plumbed to the same seeded RNG). An SDK proof passes `templar-prover check`.
3. **Negative tests.** Every §4 decoding rejection; every §6 scan rule (a token at or above 2²⁵²,
   `rho` non-canonical or zero, nonzero padding, `x > amount`, a wrong `PolicySettled` index,
   foreign events, conflicting duplicates, a digest mismatch); every §8 result check; plans that
   break conservation, ranges, ownership or the one-account rule are refused before proving;
   malformed input to every WASM export returns an error, never a trap.
4. **WASM measurement** against the §7.3 thresholds: proof time and peak linear memory in Node and
   in headless Chrome, three runs each; `.wasm` size; grinding share.
5. **Network trace (SDK-P13).** A recording RPC and server proxy checks that a full sync, a
   transfer and a withdrawal make only bulk `getEvents` calls and reads of pinned public
   constants (no per-note, per-nullifier, per-root or per-asset call), and no direct server
   contact when OHTTP is configured.
6. **Fault injection (SDK-P13).** An omitted or conflicting event gives `complete: false`; a reorg
   across a checkpoint rolls back and resyncs; a crash and resume at each in-flight stage; a 409
   or 429; window expiry; root eviction before submission; an OHTTP key mismatch; an attempt to
   re-plan a live record with different inputs is refused, including after a `REJECTED` or
   `REVERTED` attempt, until the record's root is evicted (SDK-P16); fee bounds are the same under
   two different starknet.js overhead settings (SDK-P17, SDK-P21); 255 two-output spends after a
   record's root do not yet release its notes, and 256 (512 leaves) do once buried (SDK-P20).
7. **End to end on Sepolia, with the SDK only** (no `sncast`): a deposit (live, with the user's
   confirmation), sync and recovery in a fresh process, a hidden transfer and an NFT withdrawal
   proved in WASM, wrapped by the prover server (directly and through an OHTTP relay), and
   submitted with starknet.js. While the gateway rejects large proofs, the exact signed
   transaction's simulation with validation must succeed and the gateway response is recorded.

## 13. Dependencies, supply chain and release (SDK-P11)

- The client proof needs the arithmetic-profile fork of `proving` (`templar/arithmetic-profile`,
  commit `250cc9c1e`, which also drops `stwo_cairo_prover` from the circuit prover so it builds for
  wasm32), which also carries an unreleased prover fix. It exists only in the local checkout
  (`target/proving-arith`). It is pushed to the **private** `broody/proving-private` and pinned by
  commit; a check script verifies the checkout. It must not go to the public fork.
- **Release gate.** A public npm or WASM release would reveal that fix by binary diffing. No public
  package ships before the owner releases it; until then builds are private.
- Every other build input is pinned by commit or sha256 and checked by the same script: the
  `bench/m31-private-blake` sources the relation includes, the `stwo-cairo-prover` and `cairo-vm`
  chain and every other crate (through the SDK workspace's own committed `Cargo.lock`, built with
  `--locked`), the toolchain (`nightly-2026-01-15`, from the fork),
  `wasm-bindgen` and `wasm-bindgen-cli` at the same version (`wasm-opt` is not used in v1). The build recipe is
  reproducible and publishes the `.wasm` sha256; npm provenance is enabled when releases are
  public.
- TypeScript runtime dependencies: none besides the peer dependency `starknet`.

## 14. Privacy summary

| Party | Learns |
| --- | --- |
| RPC provider | the wallet downloads the pool's events in bulk (from checkpoint boundaries); public constants for the §8 checks; token metadata only for the whole deposited universe; its public deposits and withdrawals; and, **specific to a spend**: the estimate, simulation and submission of the exact transaction (for an exit, including the asset), the `get_verifier` re-read and the ERC1155/ERC721 recipient checks before an exit (SDK-M8). It is trusted for integrity. |
| Prover server | the public statement (what the chain sees, earlier), and the client's IP unless OHTTP is used; with OHTTP, the relay's address |
| OHTTP relay | the client's IP and the fact of using the server, not the content |
| Submitting account | public and linked to the spend (`linkable: true` in v1) |
| Everyone | per `docs/hidden-asset-spec.md` §7: a transfer shows no asset; an exit shows asset, amount, recipient; a published revert shows its calldata |

**Pool V3 and bound wallets (revision 4;** account-bound spec §3, §10**):**

- The prover server learns the bound account `A` of a bound spend (removed by ADR-0027, phase
  B), and that a free full withdrawal empties its inputs. It holds the full pool calldata, so it
  can settle the spend, and it chooses when, up to `send_deadline`.
- (Removed by ADR-0027, phase B; generalized below.) Bound spend-specific reads (estimates,
  simulation, nullifier, root and recipient checks, status polls) and submission go through the
  spend provider or the relayer, never a provider that has seen `A` in that session.
- (Removed by ADR-0027, phase B.) A retained signature over a public binding is
  third-party-verifiable proof that `A` made the spend; servers delete bound inputs when proving
  ends and results on acknowledgement.

**Pool V3 under R0 V6 (revision 5;** `docs/pool-v3-spec.md` §7.4, §12; ADR-0027: pending
implementation**):**

- No job carries an account, in any mode. No login session, cookie or wallet credential reaches
  the prover server, the relayer or the ticket redeemer, and spend-specific reads go through the
  relayer or a provider that has not seen the connected account (§9.2).
- The vault's submitter account, and whoever funded it, is publicly linked to each invoke, P1
  settlement or fallback it submits, and one reused submitter account links its submissions to
  each other. The SDK asks before each such submission (§9.2).
- On chain, each spend shows its route (the proof version, the OS program, and the statement
  account, derivable from the message hash) and its base block. Concurrent routes partition the
  anonymity set (pool-v3-spec §6.4).

Timing between the prover request and the chain submission can link them for a party that sees
both; a relayer that also simulates for the wallet (TODO item 5) removes the spend-specific RPC
reads from the wallet's session.

## 15. Review questions (revision 1)

1. Key derivation (§3.2): the construction, domain separation and pool scoping; `wide9`; using the
   BIP-39 entropy directly with no passphrase.
2. Address and viewing-key formats (§4): Bech32m beyond 90 characters; the rejection list; import
   checks.
3. The secret boundary (§2): stateless WASM taking the seed per call; nothing but explicit
   exports leaves WASM.
4. Receiving (§6) and completeness and reorg rules.
5. Spend planning (§7.2): output and input ordering; dummies; anything the plan reveals.
6. Result checks (§8) and the submission window (§9).
7. Supply chain (§13).

## 16. Review resolutions (revision 2)

| Finding | Resolution |
| --- | --- |
| SDK-M1 | §6 rules 3–4: canonical nonzero `rho`, zero padding; §12.3 tests |
| SDK-M2 | §2 no panics; §6 total scan in a fixed order with fallible encoders; §12.3 |
| SDK-M3 | §3.2 gap-limit issuance, iterative recovery, one account per spend |
| SDK-M4 | §4.1 ZIP-316 F4Jumble + Bech32m, max length, full fingerprint as the only human check |
| SDK-M5 | §8 OHTTP key configuration pinned or application-supplied, never fetched in-session |
| SDK-M6 | §4.1 exact rejection rules and lengths; `ivk` clamped; nonzero shared secret both ways |
| SDK-M7 | §6 event filtering by address and selector; exact `PS01` match; digest check; conflicts |
| SDK-M8 | §6 RPC integrity trust and optional cross-check; §14 lists spend-specific reads |
| SDK-M9 | §8 window computed locally; 9 facts with `facts[6]` pinned; adapter by storage slot and class pin |
| SDK-M10 | §3.3 and §9.1: a record's re-proofs reuse its dummy; hidden-asset spec §6 amended |
| SDK-M11 | §4.2 capabilities stated; index dropped from exports; internal change key deferred |
| SDK-M12 | §3.1 recovery over versions and every pool; mnemonic warning; §10.2 pool list |
| SDK-M13 | §2 `test-rng` feature and CI check; §7.3 budget and self-verification mandatory |
| SDK-M14 | §2 zeroize, worker per proof; §10.3 encrypted store under `kstore` |
| SDK-M15 | §4.2/§5 nullifier split index; §6 rule 7 registry sync; §6 metadata by address; §7.2 root; §13 release gate |
| SDK-P1 | §7.3 milestone 0 spike with thresholds; library `prove` module rewritten, not moved unchanged. The `#[path]` sources stay in-repo (pinned by the repo commit and the check script) rather than vendored, to keep one implementation |
| SDK-P2 | §9.1 in-flight records |
| SDK-P3 | §8 jobs persisted, no automatic retry; server change: an identical resubmission returns its job even under backoff, and a finished job's deduplication is released once its `valid_until` has passed |
| SDK-P4 | §9.2 exact-transaction sequence; signer-backed accounts only; peer dependency `>=10.5 <11`; Sierra warning |
| SDK-P5 | §6 metadata rules and checkpoint-aligned `from_block`; §8 no base-block hash read; §9.2 status polling |
| SDK-P6 | §8 all requests through the relay; pinned keys; relay requirements; `rust-hpke` |
| SDK-P7 | §8 pinned constants, adapter class and storage reads, full result checks, verifier re-read |
| SDK-P8 | §5 tree truncate, pure proving from plan paths; §6 blocks, checkpoints, spendable rule, conflicts |
| SDK-P9 | §10.3 encryption by default, schema version, locks, created-index and sent history |
| SDK-P10 | §9.2 fee rule; §7.2 root rule and core shuffling; `linkable: true` |
| SDK-P11 | §13 release gate, pins, reproducible build, both getrandom backends |
| SDK-P12 | §2 `test-rng` feature and CI check; §12.2 bench RNG plumbing |
| SDK-P13 | §12.5 network trace; §12.6 fault injection |
| SDK-P14 | §3.2 index guard; §7.2 ERC721 recipient warning; §6 unverified ERC20s |
| SDK-P15 | §1 current limits; §7.1 deposits refused on a verifier mismatch |
| SDK-M16 (re-review) | §4.1, §4.2 type byte per format; one HRP and type per decoder |
| SDK-M17 (re-review) | §3.3 sticky companion dummy per note; §9.1 dead-attempt rules; hidden-asset spec §6 |
| SDK-M18 (re-review) | §10.3 AEAD associated data; rollback documented; §3.2 `u` from notes 10 blocks deep |
| SDK-P16 (re-review) | §9.1 a record whose statement left the wallet dies only on root eviction, computed locally; re-plans share its inputs |
| SDK-P17 (re-review) | §9.2 raw estimate amounts, explicit `tip = 0`, max fee shown, simulation at `pre_confirmed` through `channel.fetch`, RPC ≥ 0.10.1 |
| SDK-P18 (re-review) | §8 root-eviction server clause removed; §9.1 local eviction rule; §9.2 same-server wait |
| SDK-P20 (re-review 3) | §9.1 eviction counted conservatively: leaf count `m + 512` (one root per insert call, up to two leaves each), 10 blocks deep; §12.6 test |
| SDK-P21 (re-review 3) | §9.2 raw estimate through `channel.getEstimateFee`; §12.6 test |
| SDK-P19 (re-review) | §1 selection in the core; §2 proving crashes contained; §6 `Deposited` filtered, checkpoint-hash reorg check; §10.3 opaque keys; §13 lock file |
