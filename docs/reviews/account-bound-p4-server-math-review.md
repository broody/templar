# Prover server cryptography (P4, M4): math review

- Reviewer: independent Math Reviewer
- Date: 2026-09-26
- Scope: `server/prover/src/{tickets,m31,v5}.rs` and the admission wiring they depend on
  (`api.rs`, `pipeline.rs`, `statement.rs`), uncommitted on `feat/account-bound`.
- Against: `docs/account-bound-note-spec.md` §7.2 and §9, including "Implementation (P4)".

## Verdict

**GO.**

The ticket scheme, the free full-withdrawal check, the Poseidon2-M31 port and the V5 encodings are
sound and match their references. Two low findings (AB-SM5, AB-SM6) concern operational fail-open
cases. Fix them before a production issuer or a second redeemer exists. The rest is info.

## Checked

### Tickets (RFC 9474, `blind-rsa-signatures` 0.18)

- **Scheme and verification.** RSABSSA-SHA384-PSS-Randomized over
  `"TEMPLAR_TICKET_V1" ‖ nonce₃₂`. `verify` in the crate:
  - requires `|sig| = |n|`;
  - requires the randomizer;
  - verifies PSS over `SHA-384(randomizer ‖ msg)`.

  The server adds: the key is known and `now < not_after`.
- **No double spend through malleability.** The spent set and reservations are keyed by
  `(key id, nonce)`. Another valid signature or randomizer over the same nonce is therefore the
  same ticket. A different nonce needs a new issuer signature (one-more unforgeability of RSA
  blind signatures). Distinctness within a job and against other reservations is checked under
  one lock, and all tickets are reserved or none.
- **Refunds.** The refund signer blind-signs whatever value < n the client sends. The crate
  checks `|m| = |n|`, `m < n` and signs with a check-after-sign against faults. So a client *can*
  obtain a signature on something other than a ticket message. That does not matter:
  - each signature finalizes into at most one valid ticket (one-more unforgeability);
  - refunds are issued only when the job's tickets were spent and the failure is in proving or
    facts;
  - they are issued once per job, as `j.refund` computed in the failure handler;
  - RSA blind signing is deterministic, so a repeated request yields the same ticket.

  A job's refund count equals its spent-ticket count. The requirement is that the issuer key is
  used for nothing else (no decryption, no other signed formats).
- **Unlinkability.** Refund requests are blinded client-side, so they are perfectly hiding under
  RSA blinding. Refunds use the same issuer key as purchases, so refunded tickets form no separate
  class.
- **Free full withdrawal.**
  - Payment (step 3) runs on the client's claimed statement. The bridge (step 7) then verifies the
    proof, and its standalone `main` asserts every claimed field equals the proven statement. The
    free check and the bridge arguments are parsed from the same JSON. `PoolCall::matches` then
    binds the calldata to it.
  - Given acceptance: `intent = 0`, a priced `token_out ≠ 0` (so the bridge's exit rule forces
    `w_amount ≠ 0` and `x = 1`, hence `token_out = token`), and both
    `cm_j = H(NOTE, chain ‖ pool ‖ token_out ‖ 0₈ ‖ inner_j)`.
  - By NOTE collision resistance, both outputs have amount 0 under the spend's asset. V4's
    conservation then gives `amt₀ + amt₁ = w_amount`: the spent notes held exactly `w_amount`.
  - The openings must be nine canonical words, and the asset is taken from the statement.

### Poseidon2-M31 port (`m31.rs`)

- The round constants are identical to `bench/m31-private-blake/client/src/constants.rs` (all
  three arrays compared).
- `external` (M4 plus column sums) and `internal` (diagonal `P−2, 2^(i−1)`) are identical to the
  client's `hash.rs`.
- The round schedule is `membership::permute`'s. The sponge is `payment::native_sponge`'s
  (overwrite rate 15, 10* padding, +1 on word 15 for a full final block). The frame is
  `[TAG, 1, kind, level]`.
- `felt_limbs` is 9 × 28-bit little-endian limbs of the big-endian felt, and amounts are
  8 × 16-bit little-endian limbs.
- **Differential test (mine).** 80 random cases against the client wallet's
  `commitment` (`payment`'s NOTE hash): 251-bit felts including `2^251 − 1`, 37 tokens
  ≥ 2^250, 20 cases with amount 0, u128 maximum, and inner words 0 and p − 1. All 80 are equal.

### V5 encodings (`v5.rs`)

- `binding` (`TMR0_BIND_V5`, `valid_until` as one felt, no account) and `message_hash` (domain
  `('Templar', 'V5', chain, 1)`, the spend struct, the account in the signer slot) match the Cairo
  bridge and the starknet.js KAT.
- `delivery_digest` ranges (2^248, and 2^200 for word 9) match `spend::delivery_digest`.
- `Intent::hash` matches `open_note::hash_intent_of`'s field order, nonce 0, the destination
  checks and `selector!` (`sn_keccak`). **Cross-check (mine):** for INVOKE and COMPUTE with two
  destinations it equals `bench/m31-pool/open_note.py`'s `hash_intent`:
  - INVOKE: `0x1441baf8…ac875`;
  - COMPUTE: `0x7a5d3fd6…52163`.
- The pool-call parse is strict, and `matches` binds every field, the binding (equal to the
  bridge's) and the intent (equal to the preimage hash, or `intent = 0` and `identity = 0` with
  `apply_spend`).

## Findings

### AB-SM5 (low): a failed durable spend is logged, not acted on, so a refund can coexist with reusable tickets

- **Where:** `api.rs` stage callback. It sets `j.spent = true` and then calls `t.spend(&r)`, which
  only logs an error. The same happens in `Held::consume`.
- **Failure.**
  1. The spent-log write or fsync fails at job start. The nonces are not in the log, and the
     reservation stays in memory only.
  2. The job goes on. If proving then fails, a refund is issued.
  3. After a restart the original tickets are unreserved and unspent, so they are usable again
     alongside the refund. That is one extra ticket per failed write.

  A bridge-rejected job's tickets likewise come back after a restart.
- **Fix.** Spend fail-closed:
  - on a spend error at job start, fail the job as the server's own, and release, with no refund;
  - set `spent` only after `spend` succeeds;
  - refund only when the spend was durable;
  - on a consume error, keep the reservation and refuse new jobs until the log is writable.

### AB-SM6 (low): the spent set is local to one instance, and depends on the wall clock at expiry

- **Where:** `Tickets` keeps `data_dir/spent/<key>.log` per process, and drops a key's log at load
  when `not_after ≤ now`.
- **Failure.**
  - Two server instances, or a future third-party relayer, each accept the same ticket. Spec §7.2
    (AB-P30) requires one spent set per issuer key, shared by every redeemer.
  - A clock set back across `not_after`, followed by a restart, makes the key valid again with an
    empty spent set.
- **Fix.**
  - State that P4 is single-redeemer, and before a second redeemer exists use a shared
    linearizable spent store, or partition issuer keys per redeemer.
  - Keep the logs past `not_after` plus a margin, and refuse to start if the clock is behind the
    newest log entry.

### AB-SM7 (info): duplicate public keys

- `load` rejects duplicate key ids but not the same public key under two ids.
- Under two ids, one signature would spend once per id.
- Fix: reject duplicate SPKIs, or key the spent set by the key's SPKI hash.

### AB-SM8 (info): scheme notes

- Keep each issuer key single-purpose.
- 2048-bit keys suit P4 test keys and short periods; P7 should fix the production size (at least
  2048, and 3072 is worth considering).
- Commit the INVOKE and COMPUTE intent-hash vectors above as a server KAT; today's intent test is
  self-referential.
- Config hygiene: reject a zero priced asset.

## What I ran

- **Copy.** `server/` copied to `~/.local/share/templar/runs/review-p4-math/server`.
- **Suite.** `cargo test --release` gives 24 original tests plus 2 of mine, all passing, with 1
  ignored (`admission_r5_with_tickets`, which needs the built bridge).
- **My additions** (in my copy only): `m31::review_diff`, 80 wallet cases; and
  `v5::review_intent`, compared with `open_note.py`.
- **Crate source read:** `blind-rsa-signatures` 0.18 `blind_sign` and `verify`.
- **Nothing** in the repository was modified.

**Not run.** The ignored end-to-end admission test.

## Resolution (implementer, 2026-09-26)

| Finding | Change |
| --- | --- |
| AB-SM5 | Spends fail closed. `Tickets::spend` leaves the tickets reserved on an error and marks the ledger broken; `reserve` then refuses until a probe write to the log syncs. The job's stage callback returns an error, so `pipeline::run` stops before the virtual OS; `spent` is set only after the spend succeeded, and a refund needs `spent`. A consume that fails keeps the tickets held. Test: `ledger_fails_closed` |
| AB-SM6 | Every spent log is loaded at startup, expired keys' included, so a clock set back cannot revive a key with an empty set; logs are never deleted in P4. Spec §9 states P4's single redeemer, and that a second one needs a shared spent set or partitioned keys (P7). Test: `spent_logs_outlive_their_keys_and_config_is_strict` |
| AB-SM7 | `Tickets::load` refuses one SPKI under two key ids. Same test |
| AB-SM8 | The INVOKE and COMPUTE intent hashes are committed as a KAT computed with `bench/m31-pool/open_note.py` (`intent_hash_matches_the_python_reference`). A zero priced asset, a zero minimum and an asset listed twice are refused. Keys stay single-purpose and the P7 key size is carried to P7 in spec §9 |
