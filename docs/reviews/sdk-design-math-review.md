# Client SDK: math review (design, pre-implementation)

- **Role:** independent Math Reviewer. I did not write the design.
- **Date:** 2026-09-24
- **Reviewed:** `docs/sdk-spec.md`, revision 1 (untracked working copy on `feat/hidden-assets`,
  based on `7688c9f`).
- **Scope:** the new constructions (§3 keys, §4 addresses and viewing keys) and how the design
  uses existing ones (§5–§9), checked against the code:
  - `client-port/src/payment.rs`, `payment4.rs`, `examples/wallet.rs`, `examples/support`;
  - `bench/m31-pool/{policy_wallet,hidden_asset,policy_note}.py`;
  - `cairo/src/{pool_v2,spend,spend4,assets,hash,tree,adapter}.cairo`;
  - `docs/hidden-asset-spec.md`, `policy-note-spec.md` §9, ADR-0020 and
    `prover-server-spec.md` §2–§5.
- **Changes made:** none, apart from this file.

## Verdict: CONDITIONAL GO

The key derivation is sound. Its domain separation, pool and chain scoping, the `wide9`
reduction, clamping and use of the BIP-39 entropy all hold. It reuses the relation's key
hierarchy correctly, and the viewing-key contents give exactly the stated capabilities. I found
no Critical or High issue.

Before implementation starts, the spec must fix SDK-M1 to SDK-M5:

- two receiving-rule gaps: a note can be credited but unspendable, and scanning can panic;
- account indexes that recovery cannot find;
- an address layout that defeats visual comparison;
- an OHTTP key-configuration channel that lets the server tag clients.

SDK-M6 to SDK-M13 are Low: fix them in revision 2. Info items are advisory.

## Findings

### SDK-M1 — Medium — §6 rules 2–3: `rho` is not range-checked, so a credited note can be unspendable

**Problem.** Rule 3 recomputes `cm` from the decrypted `rho`, but no rule requires `rho` to be
canonical or nonzero.

- The native hash reduces its input: `M31::from(u32)` is `M31::reduce`
  (`stwo/src/core/fields/m31.rs:152`), and `payment::h` uses it.
- So a plaintext word `r + p` hashes like `r`, and the leaf matches.
- Then `payment4::statement` rejects the input as `"input encoding"` (a non-canonical `rho`), so
  the note cannot be spent as stored.
- A deposit can also commit to `rho = 0`: the pool checks only that `inner` is nonzero
  (`pool_v2.cairo` `deposit`, `parse_hook_data`). Such a note is spendable by no one, because the
  relation requires an input's `rho` to be nonzero (`payment4::build`, `nonzero_vector`).
- In both cases the recipient is shown a balance it cannot spend.
- The existing reference scanners have the same gap: `policy_wallet.find_notes` and
  `hidden_asset.find_notes` pass `bytes_words` output, which can be up to 2³², straight to Rust.

**Required change.** Add to §6 rule 2:

- every `rho` word is below `p`, and not all words are zero;
- the plaintext's padding is all zero (bytes 124..256 for `M301`, 125..256 for `PS01`).

A note that fails these is not credited. Add both cases to the §12.3 negative tests.

### SDK-M2 — Medium — §6: hostile plaintexts can crash the scan, so range checks must precede hashing

**Problem.** Anyone can seal an arbitrary 256-byte plaintext to a public `pk` and publish it
with a one-unit deposit. The core reuses `payment::commitment`, whose `felt_limbs` panics on a
felt of 64 hex digits (`assert!(nibbles.len() <= 63)`). A decrypted `M301` whose token is at
least 2²⁵² therefore aborts the scan before rule 4's range check runs.

In WASM a panic traps the instance. Every later sync hits the same leaf, so this is a persistent
denial of service against one address, and against its viewers.

The `PS01` remainder side is also exposed: `amount − x` underflows when `x > amount` (a panic in
debug builds, a wrapped value in release builds).

**Required change.** State that `scan` is total, in the order below; any failure means "not
ours" (the lesson of PI-3 in `policy_wallet.recover`):

1. decode the words;
2. open the box;
3. check the version and the zero padding;
4. check the ranges: token nonzero and below 2²⁵¹, `rho` as in SDK-M1, and the amount with
   `checked_sub`;
5. only then hash.

The core must also expose fallible, non-panicking encoders in place of `felt_limbs(&str)` on
this path. Add negative tests for a token at or above 2²⁵², `x > amount`, and every other
malformed field.

### SDK-M3 — Medium — §3.2 account indexes: recovery can miss issued addresses

**Problem.** `account(seed, chain, pool, i)` and `wallet.address(i)` accept any `i < 2³²`.
Recovery scans only `0 ..= k + 3`. Suppose a user creates or shares an address at index
`i > k + 3` (for example several unused accounts, then one that is paid). Notes to it are
invisible to a seed-only restore. They are not destroyed, but the user must remember the index.

"Highest index with a note" is also undefined for spent notes. The spec does not say that the
scan repeats after the bound grows. It does not say which account's notes a spend may combine,
or where change goes.

**Required change.**

- The core refuses to derive an address for `i > u + 3`, where `u` is the highest index with any
  credited note (spent or unspent) from a complete sync. This is BIP-44's rule.
- Recovery extends the bound and rescans until no note is found in the last four indexes.
- Planning selects inputs from one account, and change goes to that account.
- State that recovery costs `(k + 4)` sealed-box opens per ciphertext.

### SDK-M4 — Medium — §4.1: the address layout defeats visual comparison, and Bech32m is used past its guarantees

**Problem.** The first 65 data bytes are the same in every address of a pool: version, chain
and pool, which is exactly 104 of the 213 data characters. The per-user data (`receiver`, `pk`)
sits at the end, next to the checksum.

A user who checks "the first and last few characters" therefore checks a constant prefix and a
suffix the attacker can grind. Matching the last 8 characters (the 6 checksum characters plus 2
of `pk`) costs about 2⁴⁰ key generations.

Separately, Bech32m's guaranteed detection (any four errors) is established only for strings up
to 90 characters. At 227 characters only the random-error bound of about 2⁻³⁰ remains, and the
code is defined only to length 1023.

The fingerprint is 80 bits, which is adequate against a targeted second preimage, but only if
all five groups are compared.

**Required change.** Choose one:

- apply F4Jumble (ZIP-316) to the payload before Bech32m, so every character depends on all
  fields; or
- move the constant fields after the per-user fields, and shorten `pool` to a tag. The payer's
  pool check can then compare the tag and the HRP. Note that commitments bind the full pool
  regardless.

In either case:

- state a maximum length (at most 1023) and use a Bech32m decoder mode that enforces it;
- state that the fingerprint, compared in full, is the only supported human check.

### SDK-M5 — Medium — §8 OHTTP: the key configuration comes from the server, per client

**Problem.** The client fetches the key configuration by a direct `info()` connection, which
reveals its IP. The server can therefore serve each client a unique key configuration and
recognise that client's later encapsulated requests by key id. This is the key-consistency
problem in RFC 9458's security considerations. It voids §14's claim that OHTTP hides the
client's IP from the server. The direct fetch shortly before an OHTTP job also correlates the
two by timing.

**Required change.** The client must get a configuration that every client provably shares:

- pinned in the package's network constants, with rotation by package update or another
  consistent channel; or
- fetched through the relay from a cache that the relay or a third party shares across users.

The client never fetches the configuration directly in the same session it proves in. A
configuration that differs from the pinned one is refused.

### SDK-M6 — Low — §4: canonical encodings and the X25519 checks are underspecified

**Problem.** Several encodings admit more than one form, and one check cites a list that does
not exist.

- RFC 7748 has no low-order list. The known blocklist (libsodium) is seven u-values: 0, 1, the
  two order-8 u-coordinates, `p − 1`, `p` and `p + 1`. It is not "eight points".
- Masking the top bit makes two `pk` encodings valid for one key, so one recipient has two
  distinct addresses and fingerprints.
- `ivk` has 2⁵ encodings that clamp to the same scalar.
- The spec gives neither the Bech32m padding-bit rule nor exact data lengths.
- RustCrypto's X25519 does not reject a non-contributory result by default (`was_contributory`),
  unlike libsodium, on both sealing and opening. KATs against PyNaCl would diverge on such
  inputs.

**Required change.**

- Reject a `pk` with bit 255 set, or with `u ≥ p`.
- Enumerate the blocklist as exact bytes.
- Require an exported `ivk` to equal `clamp(ivk)`.
- Require exact payload lengths (133, 137 and 173 bytes) and zero padding bits.
- Require a nonzero shared secret on both seal and open in the Rust core. Add the PyNaCl
  parity cases to the KATs.

### SDK-M7 — Low — §6: event authenticity and the `PS01` match

**Problem.**

- Only `AssetRegistered` is required to come from the pool's address.
  - A `NullifierSpent` with the same selector from any contract would mark an owned note spent
    in the wallet. That is display and selection denial of service, not loss.
  - Foreign `NotePublished` or `PolicySettled` events would feed the scan.
- A "matching `PolicySettled`" is undefined. The code accepts `first ≤ index ≤ first + 1`
  whatever the side. This is safe only because rule 3 recomputes `cm`.
- Two conflicting events for one index are not addressed.

**Required change.**

- Filter every event by `from_address == pool` and its exact selector.
- Match `PS01` by `index == first_index + side`, and require the event's `x > 0`.
- Mark the sync incomplete on conflicting duplicates (ADR-0020).
- Optionally, check `NotePublished.digest == delivery(words)` for every leaf. It is cheap and
  detects a corrupted archive.

### SDK-M8 — Low — §6, §8, §9, §14: integrity trust in the RPC, and reads that are specific to one spend

**Problem.**

- The completeness check uses leaves, `get_leaf_count()` and `get_root()`, all from the same
  provider. A dishonest RPC can therefore fabricate a "complete" history containing a receipt
  that does not exist.
- Several reads made before submission belong to one spend:
  - §8's base-block hash at `base_block`;
  - §9's check that the root is still in the 256-root history;
  - §9's simulation of the full signed transaction, which for an exit includes the asset;
  - the ERC1155 recipient check.

  These link the wallet's RPC session to a particular spend. When a relayer submits, which §9
  names as the path to unlinkability, they undo it. §14 lists only some of them.

**Required change.**

- State that the RPC is trusted for integrity, and that a receipt should be treated as final
  only after a root cross-check against a second source.
- Read recent block hashes as a range during sync.
- Let the submitter (the relayer) simulate.
- List every spend-specific read in §14.

### SDK-M9 — Low — §8, §9: the submission window is taken from the server, and the adapter checks are not implementable as written

**Problem.**

- The window uses the server's `submit_after` and `valid_until`, which are untrusted. With wrong
  values the wallet submits outside the window: a revert that publishes calldata (for an exit,
  the asset: HA-M11) and costs fees.
- The fact checks do not state `len == 9` or what `facts[6]` must hold.
- `Proof2Adapter` has no view functions (`adapter.cairo`). "The adapter's stored pool,
  statement, …" can only be read from raw storage slots, and those are meaningful only for a
  known class.

**Required change.**

- Compute `submit_after = base_block + 11` and `valid_until = base_block + max_proof_age`
  locally, from the verified `facts[4]` and the pinned `max_proof_age`.
- Check the facts length and specify `facts[6]`.
- Pin the adapter's class hash, and read its storage by slot address.

### SDK-M10 — Low — §9 and HA-M6: re-proving after a revert that was published reveals which input is real

**Problem.** A reverted Starknet transaction publishes its calldata, including both nullifiers.
HA-M6 requires a fresh dummy when a spend is re-proved. The real input's nullifier then appears
in two transactions, each time next to a different dummy. That identifies the real nullifier
and reveals a spend with one real input.

**Required change.** After a revert that was included on chain, resubmit the same proof if it is
still valid. Otherwise re-prove with the identical witness, dummy included: this leaks nothing
new, because the attempts are already linked by the real nullifier. Scope HA-M6's "never reused"
to attempts that were never published. Raise this with the owners of the hidden-asset spec.

### SDK-M11 — Low — §4.2: the stated viewing capabilities understate what a viewer learns

**Problem.**

- Change is sealed to the account's own `pk` and `receiver`, so an incoming viewing key sees
  every change note, and with it the rhythm of spends and approximate outflows (ADR-0020's
  example, "sees 100 and 40", includes the change).
- A full viewing key also yields each spend's outgoing amount (inputs minus change), and
  distinguishes dummy nullifiers from real ones (HA-M7b).
- `u32 i` in both exports cannot be authenticated against the address and reveals the account
  count.

**Required change.**

- State these capabilities in §4.2.
- Drop `i` from the exports, or mark it informational.
- If handing an incoming viewing key to an auditor is a goal, consider a separate internal
  change key per account (as ZIP-316's internal and external keys do).

### SDK-M12 — Low — §3.1, §11: the backup carries no version, and it is interchangeable with other wallets' mnemonics

**Problem.**

- A 24-word BIP-39 mnemonic carries no derivation version and no pool list. Future derivations
  or pools therefore require trial recovery forever.
- Users may import an existing wallet's mnemonic, a hardware wallet's included. The derived keys
  are independent (PBKDF2 against HKDF), but compromising either wallet exposes both.
- The reverse also holds: typing the Templar mnemonic into another wallet exposes it.

**Required change.**

- Network constants list every pool, past and present, with its deployment block.
- Recovery tries every known derivation version.
- The documentation and UI warn against sharing a mnemonic across wallets. Optionally, use an
  Electrum-style version marker so that the mnemonic is recognisably Templar-only.

### SDK-M13 — Low — §2, §12.2: the seeded RNG and the zero-knowledge budget

**Problem.**

- §12.2 needs a seeded RNG through WASM, while §2 forbids one. A caller-chosen blinding seed
  would break hiding.
- `prove_relation` asserts `revealed + NON_QUERY_INFO_LEAK ≤ blinding`. That is the H2-relevant
  hiding budget, and "unchanged" does not say it survives as a hard error.

**Required change.**

- The seeded-RNG export exists only under a test feature that is absent from release artifacts,
  and CI checks that it is absent.
- The budget check is a mandatory error on every proof, in WASM included, as is native
  verification.

### SDK-M14 — Info — secrets and storage (§2, §10.3)

- The seed lives in JavaScript and is strictly stronger than every key kept inside WASM, so the
  boundary is hygiene, not isolation. The core should zeroize derived keys in linear memory and
  accept the seed as bytes, never as a mnemonic string, on every call except the import.
- Stored owned notes (`rho`, nullifiers, the spent set) equal full-viewing-key knowledge.
  Encrypt storage by default under a key derived from the seed with its own label (for example
  `TEMPLAR_STORE_V1`).

### SDK-M15 — Info — consistency and minor points

- §4.2 writes `nf = H(NF, nk ‖ cm ‖ pos)`. It should read `pos_lo ‖ pos_hi` (16-bit halves of
  the u32 leaf index), as §5 and `payment::nullifier` have it.
- Rule 4: treat an unregistered identifier as ERC20 only when `AssetRegistered` has been synced
  through the note's block. The registry is written in the same transaction as the asset's first
  note. Otherwise show the asset as unknown.
- Display ERC20 notes by contract address, not metadata: spoofed "USDC" tokens can be deposited
  to anyone.
- Scanning could accept an opened note whose receiver is `receiver(j)` for any scanned `j`. This
  is sound because of the `cm` check, and it avoids losing a note sent to a mixed address pair.
- Root selection is a fingerprint (HA-P8.5). Fix it as the root at the latest `ACCEPTED_ON_L2`
  block of the sync.
- §13: a public npm or WASM release of the arithmetic fork discloses the H2 fix by binary
  diffing. Gate a public release on the H2 disclosure.

## §15 review questions within scope

1. **Key derivation.**
   - The construction is sound:
     - HKDF-Extract with a fixed application salt suits a uniform 256-bit input key.
     - The labels differ at byte 8 (`S` against `I`), and `ctx` has a fixed 68 bytes, so the
       infos cannot collide.
     - The policy seed uses a different PRK (empty salt), so there is no cross-context reuse.
   - `wide9` has statistical distance at most `p/(4·2¹²⁸) ≈ 2⁻⁹⁹` per word (the spec's "below
     2⁻⁹⁶" holds). The all-zero case has probability `p⁻⁹ ≈ 2⁻²⁷⁹`. `sk` words are canonical,
     as `payment4::statement` requires.
   - Pool and chain scoping works as stated.
   - Using the BIP-39 entropy directly is fine, since PBKDF2 adds nothing to 256 uniform bits.
     The costs are interoperability and versioning (SDK-M12).
   - The account scheme needs SDK-M3.
2. **Formats.**
   - Bech32m beyond 90 characters is acceptable given an explicit maximum and the fingerprint,
     but the layout must change (SDK-M4).
   - The rejection list needs SDK-M6.
   - The import checks are right: `H(OWNER, ak ‖ nk) = receiver`, and `X25519(ivk) = pk` with
     `chain` and `pool` equal to the address's, against an independently authenticated address.
     They also give ADR-0020's `nk` binding.
3. **Secret boundary.** The design is acceptable as hygiene (SDK-M14). No derived secret needs to
   leave WASM: `scan` returns nullifiers and `rho`, which are not spending authority.
4. **Receiving.**
   - The ciphertext word bounds (2²⁴⁸, and 2²⁰⁰ for the last word) match
     `spend.cairo::delivery_digest`.
   - The commitment recomputation makes crediting sound for both `M301` and `PS01`.
   - Gaps: SDK-M1, SDK-M2 and SDK-M7.
   - Completeness and reorg handling are correct relative to a trusted RPC (SDK-M8).
5. **Spend planning.**
   - Input 0 is necessarily the real input when there is one (`payment4` forces it). That is
     invisible publicly, because a dummy's nullifier is pseudorandom.
   - Random output order and uniform shape are right, and one circuit topology serves every
     shape, so the server learns nothing from the proof's size.
   - Remaining leaks: the root (SDK-M15), the submitting account (as stated), and published
     reverts (SDK-M10).
6. **Result checks and window.**
   - The message-hash check against the SDK's own binding is the essential check, and it is
     correct: `Poseidon(statement, 0, 5, class, tag, chain, pool, binding)` matches
     `adapter.cairo`.
   - The window and fact-layout details need SDK-M9.
7. **Supply chain.** Within scope only: the hiding budget and the H2 dependency (SDK-M13, and
   SDK-M15's last item).

## Re-review (revision 2)

- **Date:** 2026-09-24.
- **Reviewed:** `docs/sdk-spec.md` revision 2 (§16 lists its resolutions), and the amendment to
  the dummy-input rule in `docs/hidden-asset-spec.md` §6 (working tree).
- **Scope:** only the text that changed within the math focus. I re-checked it against the same
  code as the first review.

### Verdict: GO

SDK-M1 to SDK-M9 and SDK-M11 to SDK-M15 are resolved. SDK-M10 is resolved only while a spend's
record is live (SDK-M17). The new text introduces three Low findings (SDK-M16 to SDK-M18) and no
Medium or higher. Fix all three in the spec before the store and the in-flight records are
implemented. None of them gates the key, address or scan code.

### Status of the first review's findings

| Finding | Status | Check |
| --- | --- | --- |
| SDK-M1 | Resolved | §6 rule 3 requires zero padding (bytes 124.. for `M301`, 125.. for `PS01`). Rule 4 requires every `rho` word below `p` and not all zero, before any hashing. |
| SDK-M2 | Resolved | §2 forbids panics, and §6 is a total scan in a fixed order. The asset is range-checked (nonzero, below 2²⁵¹) before `cm` is computed, so a token of 64 hex digits never reaches the encoder. The subtraction is checked. §12.3 tests these cases. |
| SDK-M3 | Resolved | The core refuses to derive an address above `u + 3`. Recovery is iterative until the last four indexes are empty; any index ever created is at most `u_then + 3 ≤ u + 3`, so recovery finds it. Inputs come from one account. See SDK-M18's note on pending notes. |
| SDK-M4 | Resolved | The encoding is ZIP-316 F4Jumble over `payload ‖ HRP padded to 16 bytes`, then Bech32m. I checked the lengths: 149 bytes, giving 253 and 256 characters for addresses, 256 and 259 for incoming keys, 320 and 323 for full keys, all below 1023. The only human check is the full fingerprint. Reusing Zcash's BLAKE2b personalizations is harmless, since F4Jumble is an unkeyed permutation. |
| SDK-M5 | Resolved | The key configuration is pinned per server, or supplied by the application, and is the same for every client. With OHTTP, every request goes through the relay, and there is no direct fallback. |
| SDK-M6 | Resolved | A `pk` with bit 255 set, or with `u ≥ p`, is rejected. Given that, the listed `p` and `p + 1` are redundant but harmless. The blocklist is libsodium's seven values; `ivk` must be in clamped form; lengths are exact; padding bits must be zero; both sealing and opening reject an all-zero shared secret; and the PyNaCl parity KATs are included. |
| SDK-M7 | Resolved | Events are filtered by address and selector, with `from_address` re-checked. A `PS01` matches when `index == first_index + side` with `x > 0`. That is consistent with `apply_policy_spend`: P1 forces `x ≥ 1`, so side 0 is always active and appended at `first`. Digests are checked, and conflicting duplicates make the sync incomplete. |
| SDK-M8 | Resolved | The RPC is stated as trusted for integrity, with an optional cross-check against a second provider. §14 lists the reads specific to one spend, and the separate base-block hash read is dropped. |
| SDK-M9 | Resolved | The window is computed locally from `facts[4]` and the pinned `max_proof_age`. The facts must number exactly 9, with `facts[6]` pinned. The adapter is checked by class pin and storage slots. The message-hash formula still matches `adapter.cairo`. |
| SDK-M10 | Partly resolved | See SDK-M17. |
| SDK-M11 | Resolved | §4.2 states the capabilities, the index is dropped from the exports, and the internal change key is deferred. |
| SDK-M12 | Resolved | Recovery tries every derivation version against every pool, the warnings are in place, and the network constants list every pool. |
| SDK-M13 | Resolved | The seeded RNG exists only under the `test-rng` feature, and CI checks that release builds lack it. The budget check and self-verification are mandatory errors. |
| SDK-M14 | Resolved | The core zeroizes derived keys, starts a worker per proof, and encrypts the store by default. For the encryption itself, see SDK-M18. |
| SDK-M15 | Resolved | The nullifier formula now splits the index into `pos_lo ‖ pos_hi`, rule 7 requires the registry to be synced, ERC20 metadata is keyed by address, the root rule is fixed, and the release gate is in place. |

The new key `kstore` uses the label `TEMPLAR_STORE_V1 ‖ chain ‖ pool`. Its info differs from
`TEMPLAR_SPEND_V1 ‖ ctx` at byte 9 and in length, so no two infos collide. Its PRK is shared with
the other keys, which is sound under HKDF.

### New findings

#### SDK-M16 — Low — §4.1/§4.2: the address and the incoming viewing key are one format apart from the HRP

**Problem.** Both payloads are 133 bytes, with the same version byte `0x01` and the same layout
(`chain ‖ pool ‖ receiver ‖ 32 bytes`). A clamped `ivk` (bit 255 clear, below `p`, not
blocklisted) is also a valid `pk` encoding. The HRP alone, which is bound by the F4Jumble padding
block and by the checksum, decides whether a string is a public address or a secret key. A
decoder that accepts any `templar*` HRP, or code that reuses one decode path, could treat an
incoming key as an address, or display one as the other.

**Required change.** Give each format its own type byte, for example `0x01` address,
`0x02` incoming key and `0x03` full key. Each decoder accepts exactly one HRP pair and one type
byte. Add cross-type decoding to the negative tests.

#### SDK-M17 — Low — §3.3, §9.1 and the hidden-asset amendment: dummy reuse is scoped to one record, but the leak outlives the record

**Problem.** The dummy is reused only for re-proofs of the same live record. Three cases escape
that scope:

1. **A published revert.** §9.1 declares a record *dead* when it was `REVERTED` and its
   nullifiers are unspent, and then releases its notes. A later record may spend the same note
   `N` with a fresh dummy, or with a different second note. `N` then appears on chain next to two
   different companions, which singles it out as real. That is the leak SDK-M10 addressed. The
   amendment's "until it settles or is abandoned" leaves the same gap.
2. **The prover server.** The server sees every wrapped statement, whether or not it is
   published. PS-2 already correlates re-submissions by `nf₀`, and input 0 is always real. A
   second job for `N` with a different `nf₁` therefore tells the server the spend had one real
   input.
3. **The window.** "Past `valid_until`" does not prove an attempt was never published. A
   transaction still pending with the old nonce can be included later as a `PROOF_AGE` revert,
   and that publishes its calldata.

**Required change.**

- Make the companion **sticky per note, not per record.** From the first time a statement
  naming `N` leaves the wallet (a server job or a sent transaction), store `N`'s companion: its
  dummy witness, or its paired real note. Every later spend of `N` uses the same pair until `N`
  settles. This is safe because only one spend of `N` can ever settle, and the dummy's nullifier
  is then marked spent with it. Before proving, the core also checks that the dummy's nullifier
  is not in the spent set.
- Treat an attempt as unpublishable only when it is `REJECTED`, or when the account's nonce has
  advanced past it without it.
- Word the hidden-asset amendment the same way: per note, from first disclosure, until the note
  is spent.

#### SDK-M18 — Low — §10.3: store encryption has no associated data, and one guard reads pending notes

**Problem.** Records are sealed by XChaCha20-Poly1305 under `kstore` with a random nonce, but
nothing binds a ciphertext to its location. Anyone who can write the store without the seed can
swap sealed records or roll them back without detection. Examples are a Node file store, a
restored backup or a sync tool. They could replay an older in-flight record, dummy included,
under another key, or an older copy of the created-index counter, and cause the reuse that
SDK-M17 forbids.

Separately, `u` for the SDK-M3 guard could be raised by a note that a reorg later removes.

**Required change.**

- Use associated data `TEMPLAR_STORE_V1 ‖ schema version ‖ chain ‖ pool ‖ record type ‖ record
  key`.
- Document that rollback of the whole store is not detected. Sync repairs the notes and the spent
  set; the in-flight records rely on SDK-M17's check of the spent set.
- Compute `u` for the issuance guard only from notes at least 10 blocks deep, as the spendable
  rule does.
