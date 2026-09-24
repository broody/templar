# SDK implementation review: protocol and engineering

- **Role:** independent protocol and engineering reviewer (did not write the change). The Rust core's
  cryptography is out of scope (Math Reviewer).
- **Date:** 2026-09-24
- **Commit:** `fee4419 Client SDK: docs, guide page, milestone-0 results, Sepolia scripts` (SDK code
  identical to `9fbdd6a`; server change `git diff 7688c9f -- server/`)
- **Against:** `docs/sdk-spec.md` revision 3 (§16 resolutions), the pool V2 sources, the server spec.
- **Scope:** `sdk/ts/src/*`, `sdk/wasm/src/lib.rs` (as an API), `sdk/ts/test/*`, `sdk/scripts/*`,
  `sdk/ts/bench/*`, `server/prover/src/api.rs` (dedup change).

## How I checked it

- `npx tsc && npx vitest run`: 8/8 pass (63 s).
- Read-only against the local Sepolia node: `verifyPins` passes; a full `Wallet.sync()` from the
  deployment block is complete (3 leaves; the root matches). The pins in `network.ts` equal
  `bench/m31-sepolia/results/v4-hidden-asset/deployment.json` and `sdk/vectors/sepolia-s1.json`, and
  the deployment block is correct (the pool does not exist at 15554631).
- The event parsers match `pool_v2.cairo`: NotePublished 23 felts, NullifierSpent 10,
  AssetRegistered 5, PolicySettled 8 (`x` = d[5], `first_index` = d[6]), Deposited 2. Every event has
  only its selector as a key.
- starknet.js 10.8 source (`node_modules/starknet/dist/index.mjs`): `channel.getEstimateFee` returns
  the unparsed RPC result; `getSignedTransaction` uses the given `resourceBounds` without estimating
  or adding overhead, and uses `tip: 0` as given (`resolveDetailsWithTip` uses `??`); `v3Details`
  carries `proof`/`proofFacts`, and the transaction hash includes `proofFacts`;
  `channel.buildTransaction(…,"transaction")` emits `type: INVOKE`, `proof`, `proof_facts`;
  `channel.fetch` returns a raw `Response`; `provider.invokeSignedTx` exists. `prepare`/`send` use
  these APIs correctly, except for SDK-IP9.
- Scratch reproductions (a JS copy of the mock chain importing `dist/`; no repository file changed)
  confirmed SDK-IP1, SDK-IP2 and SDK-IP4. SDK-IP3 was confirmed in the `serde_json` 1.0.151 source.

## Verdict: **NO-GO** until SDK-IP1 to SDK-IP5 are fixed; CONDITIONAL GO after that

Chain reads, event parsing, pin checks, OHTTP routing and the starknet.js transaction sequence are
sound. Five High findings block: one breaks recovery, one lets a single transient RPC fault leave
the sync state wrong for good, one makes large withdrawals unprovable, one loses deposits, and one
breaks the sticky-companion property (SDK-M17).

## Findings

### SDK-IP1 — High — the gap limit is bypassed through `created`
`sdk/ts/src/wallet.ts:239` passes `max(highestUsed(), created)` to `wasm.account` as `highest_used`.
Each `address(i)` raises `created`, so addresses can be created one after another without limit
(reproduced: indexes 0 to 12 with no notes at all). Spec §3.2 refuses `i > u + 3`, where `u` comes
only from credited notes. Recovery scans `0 ..= u + 3`, so a note at a stepped-to index is never
recovered from the seed.
**Required:** pass `highestUsed()` (`u`, from a complete sync) as the bound; keep `created` only
for the scan range. Test: `address(4)` fails after `address(3)`, and still fails after creating
0 to 3.

### SDK-IP2 — High — checkpoints taken during an incomplete sync freeze the bad state
`wallet.ts:279–287, 321, 340–341`. Checkpoints are pushed during every sync, complete or not, and
the next sync re-fetches only from the newest one. Problems are not persistent.
- A NotePublished event that the RPC drops once, in a block behind a new checkpoint, leaves the
  wallet **incomplete for good** (reproduced: `leaf count 0, the pool has 2` on every later sync).
  Only wiping the store fixes it.
- A delivery-digest mismatch (tampered words), a malformed event or a conflicting duplicate is
  reported once. The next sync reports **complete** while the owned note stays missing (reproduced:
  a 5-unit deposit, then `complete: true, balances: []`). Spec §6 says a mismatch makes the sync
  incomplete.

**Required:** keep only checkpoints created by a complete sync. On an incomplete result, discard
the checkpoints this sync added and roll back to the last checkpoint of a complete sync, so the next
sync fetches the range again. Also pass `registry_complete: false` (`wallet.ts:419`) when the sync
is incomplete. Tests: a leaf dropped once, and tampered words once, each behind a checkpoint.

### SDK-IP3 — High — no withdrawal above 2^64 − 1 base units can be proved
`sdk/wasm/src/lib.rs:324`: `proved_json` calls `serde_json::to_value(p)`. `Public.withdrawal_amount`
is `u128`, and without `arbitrary_precision` (not enabled; `cargo tree` confirms) `Value`'s
`serialize_u128` returns `NumberOutOfRange` above `u64::MAX`. `prove_spend` (and
`test_prove_spend_seeded`) therefore fails with `internal` after a full proof for any withdrawal
above about 18.4 tokens at 18 decimals. The comment says this path exists to keep u128 exact.
**Required:** build the output without `Value` (for example a `Serialize` wrapper struct holding
`statement_json: String`, serialized with `to_string`), or send the amount as a string. Test: a
withdrawal of `2^100` through the WASM export.

### SDK-IP4 — High — a deposit does not check the address's chain and pool
`wallet.ts:482–488` and `lib.rs:113` (`note_for(address, asset, amount)`). The spec's
`note_for(address, asset, amount, chain, pool)` (§10.1) and §4.1 ("a payer's wallet rejects an
address whose chain and pool are not those of the pool it pays into") are not implemented.
`note_for` computes the commitment from the address's own pool (reproduced with pool `0x123`), and
the pool publishes a note that the recipient's keys for this pool cannot recognise, so the funds
are lost. Transfers check this in the core (`spend.rs:233`); deposits do not.
**Required:** `note_for` takes `chain` and `pool` and refuses a mismatch with `wrong_pool`;
`deposit` passes the wallet's. Test: a deposit to another pool's address is refused.

### SDK-IP5 — High — stale `Spend` objects and unlocked record steps break the sticky companion and resurrect dead records
- `plan()` (`wallet.ts:540–542`) marks every record that has not left as `dead: superseded`.
  `Spend.prove/wrap/submit` (`655–707`) never re-read the stored record, and write back their
  in-memory copy. A superseded, dead or settled record can therefore be sent to a server or the
  chain again.
- `leaving()` (`601–609`) keeps an existing companion silently and still lets the statement go out
  with the plan's different, fresh companion. Sequence: R1 plans note X with fresh companion c1;
  R2 supersedes R1 and plans X with c2; R2 wraps (c2 is persisted); the old R1 `Spend` wraps, and
  X's real nullifier leaves with two different dummies. This is exactly what SDK-M17 forbids. Two
  tabs reach the same state, because plan, wrap and submit run outside the store lock (spec §10.3:
  "two tabs never sync or submit at once").
- The same stale-object path can also let two records with disjoint inputs both settle: a double
  payment the user believed was superseded.

**Required:** every network step (`wrap` before `leaving`, `submit`) takes the store lock,
re-reads the record and refuses if it is `dead` or `settled` or has changed. `leaving()` refuses
(`companion_mismatch`, re-plan) when the note already has a different companion. Add
`wallet.resume(id)` instead of relying on the exported constructor. Tests: a superseded `Spend`
cannot wrap; two plans of one note cannot both leave with different companions.

### SDK-IP6 — Medium — re-plans lose the nullifiers and earlier attempts; the settle and eviction rules use incomplete data
- `replan` resets `proved` (`wallet.ts:555–556`). `updateRecords` takes nullifiers only from
  `r.proved` (`616`), so a left record re-planned but not yet proved cannot settle when an earlier
  attempt lands. It is then marked dead by eviction without the spec's check that none of its
  nullifiers is spent (§9.1). The record should hold its input nullifiers from plan time (spec
  §9.1 lists "the input notes and their nullifiers"; `OwnedNote.nullifier` is available).
- Earlier attempts' job id, body and result are dropped, so "reconciles which attempt landed" and
  the sent-payment history (§9.1, §10.3) are impossible.
- `replan()` reads the record before `plan()` syncs. If that sync settles the record, `plan()`
  writes the stale copy back as `planned` and plans with spent inputs (`547`: required inputs are
  not checked against the spent set; the core cannot check this).
- Death by eviction (`622–627`) does not require `state.complete` (§9.1: "a complete sync").

**Required:** store input nullifiers (companion included) at plan time and use them for settling;
keep a list of attempts; re-read the record after the sync and refuse if it is not live; refuse
spent required inputs; gate the transition to dead on a complete sync.

### SDK-IP7 — Medium — re-proving and re-wrapping after the window passes is not reachable
`wrap` (`wallet.ts:666–678`) never submits again once `server.jobId` is set, and `prove()` (`658`)
keeps the old `server`, `result` and `window`. After the window passes, or after the job fails or
is dropped at retention (a 404 from `status`, `prover.ts:121`), `wrap` returns the stale result or
throws for ever. The only way out is `replan`, which changes the outputs and, at the same server,
is refused with 409 until `valid_until`. Spec §9.1 and §9.2 (resubmit the same result after a
revert; re-prove with the identical witness when the window has passed) depend on this path, as
does the server change it relies on (identical body, released after `valid_until`).
**Required:** an explicit re-wrap: if the window has passed, or the job failed or is gone, clear
`jobId`/`result`/`window` and resubmit the stored exact `server.body`. Tests: window expiry; a
failed job; a dropped job.

### SDK-IP8 — Medium — the circuit hash is never checked, and a refused server still locks the notes
- Spec §8 says the client's own circuit hash, computed when proving, must equal the pin.
  `Proved.circuit_hash` is compared nowhere.
- `wrap` calls `leaving()` (`wallet.ts:672`) before `prover.submit` runs `info()`
  (`prover.ts:105`). A server refused on its `/v1/info` still marks the record as left, which locks
  its notes until 512 more leaves on a quiet pool.

**Required:** compare `proved.circuit_hash` with `pool.circuitHash` in `prove()` and refuse on a
mismatch; call `prover.info()` before `leaving()`.

### SDK-IP9 — Low — the fee estimate is signed with the real version, not the query version
`submit.ts:196–199` builds the estimate with `versions: [V3]` and `skipValidate: false`, so the RPC
receives a valid signature over a non-query transaction (zero bounds, same nonce). starknet.js's
own `estimateFeeBulk` uses `F3`. It cannot be included today (zero bounds), but it is an avoidable
signed artifact and one extra signer prompt.
**Required:** `versions: [ETransactionVersion3.F3]` for the estimate; the signed transaction stays
V3.

### SDK-IP10 — Low — sync persistence is not atomic
Leaf chunks are written for each leaf (`wallet.ts:387–397`) and during rollback (`368–373`), but
`state` only at the end (`343`). `load()` appends whole chunks (`211–215`), including entries past
`state.leaves`. After a sync fails (for example a transient `get_leaf_count` error) and the process
restarts, the tree has extra leaves: the next sync is incomplete, and the one after repairs itself
through the checkpoint rollback (reproduced). A commitment word ≥ p makes `tree.append` throw
after its chunk was written, which misaligns the chunk and makes every sync throw.
**Required:** load exactly `state.leaves` entries; check `parseEvent` words < p (a malformed
event, not a throw); write `state` together with the chunks, or make `state` the commit point.

### SDK-IP11 — Low — in-flight record contents and the resume path
The record stores `tx.hash` only after `invokeSignedTx` returns (`wallet.ts:702–706`), and stores
neither the resource bounds nor the signed transaction (§9.1). After a crash during send, the hash
is lost; settlement still works through nullifiers. There is no resume API (SDK-IP5) and no
sent-payment history (§10.3). `FileKV.lock` (`store.ts:322–331`) leaves a stale `.lock-*` after a
crash, which blocks the wallet until the file is deleted by hand.
**Required:** compute and persist the transaction hash, bounds and nonce before sending; recover
stale lock files (a pid or age check).

### SDK-IP12 — Low — `balances().spendable` overstates
`wallet.ts:452` counts notes held by live records, although the field's doc comment says it
excludes them. The UI would show funds that `transfer` then refuses (`insufficient_notes`).
**Required:** exclude live-record inputs (`liveInputs()`), or make `balances` async.

### SDK-IP13 — Low — smaller spec deviations
- The RPC spec version (≥ 0.10.1) is checked on `opts.provider` only, not on `account.provider`
  (§9.2).
- There is no STRK balance check against the maximum fee. `confirmFee` is optional, so a spend can
  be sent without the fee ever being shown (§9.2).
- There is no Sierra < 1.7 warning, and no `pending` in `SyncResult` (§6, §10.2).
- No commitment check against `NotePublished` after a deposit (§7.1).
- Token metadata for deposited ERC20s is not read (they are shown unverified: private, but less
  than §6).
- `checkRecipient` skips `Unknown` assets and uses `t.provider` instead of `account.provider`.
- The companion's spent check runs only at plan time, not before proving (§3.3).
- Spec §13 pins the fork at `4de7408a6`; `check-pins.sh` pins `250cc9c1e`. Also, `wasm-opt` is not
  pinned.

**Required:** fix these, or record them as accepted deviations in the spec.

### SDK-IP14 — Medium — normative tests missing
`test/wallet.test.ts` covers sync, one transfer, one reorg, conflicts, eviction and addresses. It
has no tests for `prover.ts`, `submit.ts` (prepare/send against a mock account; "fee bounds equal
under two overhead settings" is only a `boundsFrom` unit test), OHTTP (key mismatch, no direct
contact), 409/429, crash and resume at each stage, window expiry, root eviction before submission,
withdrawals (ERC721/1155 recipient checks), deposits and calldata, PS01, gap-limit recovery, or
`FileKV`/`IndexedDBKV` (`fake-indexeddb` is an unused dev dependency). The eviction test inserts
512 single leaves, not "256 two-output spends". Every §12.6 item and the tests named in SDK-IP1 to
SDK-IP8 are needed. `bench/sepolia-e2e.mjs` sets `relayUrl = proverUrl`, so no relay is involved.
Its withdraw stage re-plans the same note at the same server and will get 409 until the transfer
job's `valid_until` (SDK-IP7).

### SDK-IP15 — Low — server: identical resubmission is still behind the rate and queue checks
`server/prover/src/api.rs:176–205`. The change itself is correct:
- the stale release reads `valid_until` from the job's own result, holds no lock across the RPC
  await, and re-checks `dedup == id` before removing;
- `admit` re-checks the dedup key, so concurrent releases cannot admit two jobs;
- the retention sweep and the failure path stay consistent.

But a client resending an identical body after a lost 202 still spends a rate token, and can
receive 429 (bucket, or `queued_per_address` counting its own job) or 503 instead of its job id.
There is no test of either new path.
**Required:** move the identical-body lookup (hash, then dedup, then job) before the bucket and
queue checks, and add tests for "identical under backoff → 202 with the same id" and "Done past
`valid_until` → a new job is admitted".

## Checked and correct

- Events are fetched only by `address = pool` and all five selectors, paged by continuation token,
  and filtered again by `from_address` and first key.
- Checkpoint reads fall on the fixed 1000-block grid, and rollback reads only checkpoint hashes.
- The network-trace test passes.
- `verifyPins`: chain, verifier, adapter and statement classes, and the six adapter storage slots
  by `sn_keccak`.
- `check_result` uses the pins, never `info`, and computes the window locally.
- The window check uses a 20-block margin.
- `get_verifier` is re-read through `account.provider` before the estimate and simulation.
- Fee margins are fixed (amount × 3/2 rounded up, price × 2), with `tip: 0` everywhere.
- Simulation runs at `pre_confirmed` with empty flags; any error or revert reason stops the send,
  and the exact object is then sent.
- OHTTP: every request goes to the relay, a relay or decapsulation error stops, and there is no
  direct fallback.
- One submission per job: 409 and 429 are surfaced and never retried.
- Store records are sealed in the core under opaque ids, with an atomic rename in `FileKV`.
- Deposit calldata matches `deposit`, `safe_transfer_from` (721/1155) and `parse_hook_data`
  (19 felts).
- The eviction rule `leaf_count + 512` with the ≥ 10-block-deep leaf is right, and a re-plan
  (newer `leaf_count`) is conservative.
- The worker runs one fresh instance per proof and is terminated afterwards.

## Re-review (5bd6ac6)

- **Date:** 2026-09-24. **Commit:** `5bd6ac6 Client SDK: implementation review fixes (SDK-IM1 to IM12, SDK-IP1 to IP15)`.
- **Diff reviewed:** `git diff fee4419 5bd6ac6 -- sdk server docs/sdk-spec.md`. I reviewed the TypeScript layer, the WASM
  API, `spend.rs` planning (the `spent` set) and `server/prover/src/api.rs`.
- **Runs:**
  - `npx tsc && npx vitest run`: 14/14 pass (63 s).
  - `cargo test --release` in `server/prover`: 8/8, including the two new tokio tests.
  - Scratch reproductions against `dist/` (repository unchanged): my IP1, IP2 and IP4 reproductions now behave correctly;
    two new issues were reproduced (SDK-IP16, SDK-IP17).

### Verdict: **CONDITIONAL GO**

The 15 findings are resolved, with SDK-IP14 partly resolved. One new Medium (SDK-IP16) must be fixed before
the live end-to-end run or any release. The new Lows (SDK-IP17 to SDK-IP19) and the remaining SDK-IP14 tests are
needed before release.

### Status of SDK-IP1 to SDK-IP15

| Finding | Status | Evidence |
| --- | --- | --- |
| IP1 | Resolved | `address()` bounds by `highestUsed()`, which is `u` from complete syncs only (`usedAtComplete`); `created` only widens the scan. Addresses 0–3 are issued and 4 is refused (test); recovery past the first gap works (test). |
| IP2 | Resolved (see IP16) | An incomplete sync truncates `checkpoints` to `kept`; `registry_complete` follows the sync. The drop-once and tamper-once tests pass, and my reproductions now recover on the next sync. |
| IP3 | Resolved | `ProvedOut` is serialized directly; a Rust test checks `withdrawal_amount = 2^100` in both the output and `statement_json`. |
| IP4 | Resolved | `note_for(…, chain, pool)` refuses with `wrong_pool`; `deposit` passes the wallet's chain and pool (test). |
| IP5 | Resolved | `Spend` holds only an id. Every step goes through `Wallet.step` under the store lock, re-reads the record, and refuses it if closed or at a different version. `leaving` refuses a different companion. `resume(id)` exists. A superseded `Spend` is refused (test). |
| IP6 | Resolved | `nullifiers` are fixed at plan time (inputs plus companion). `attempts` keeps the history. `replan` re-reads the record under the lock after the sync. The core refuses spent inputs and a spent companion (`spent`). Eviction requires a complete sync and uses the largest `leaf_count` across attempts. The "earlier attempt lands after a re-plan and the record settles" case is tested. |
| IP7 | Resolved | `wrap` resubmits the stored identical body when the window has passed, the job failed, or the job is gone (at most two rounds). Tested for an expired window and for a failed job. |
| IP8 | Resolved | `prove()` checks the circuit hash against the pin (test); `prover.info()` runs before `leaving` (test: a refused server leaves `left = false`). |
| IP9 | Resolved | The estimate uses F3 (checked in the test). Not yet exercised against a real account's `__validate__` on Sepolia; confirm it in the live end-to-end run. |
| IP10 | Resolved (see IP16) | `load()` takes exactly `state.leaves` leaves; `appendLeaf` overwrites entries past the committed count; commitment and nullifier words ≥ p are counted as malformed. |
| IP11 | Resolved (see IP18) | Signed transaction, bounds and nonce are stored before `invokeSignedTx`. `FileKV` uses a pid lock with takeover of a stale lock (test). |
| IP12 | Resolved (see IP17) | `spendable` excludes live-record inputs. |
| IP13 | Resolved | Spec version on `account.provider`, STRK `balance_of` against the maximum fee, required `confirmFee`, Sierra warning, pending notes, deposit confirmation, `Unknown` withdrawals refused. The metadata, fork-pin and `wasm-opt` deviations are recorded in the spec. `checkRecipient` still reads through `t.provider`; acceptable. |
| IP14 | Partly resolved | Now tested: submission sequence, re-wrap, circuit mismatch, bad data behind a checkpoint, two-output eviction, supersede, companion, deposits and ERC1155, gap recovery, FileKV and IndexedDB, WASM malformed input. **Still missing:** OHTTP (key mismatch; no direct server contact), 409/429 surfaced without retry, crash and `resume` at each stage, window expiry and root eviction before `submit`. `sepolia-e2e.mjs` still has no real relay (documented). |
| IP15 | Resolved (see IP19) | `existing_job` runs before the rate and queue checks, matches only an identical body whose job still holds the dedup key, and releases a finished job past `valid_until`. Two tokio tests cover this. The later `stale` block for different bodies is kept. |

### New findings

#### SDK-IP16 — Medium — a sync that throws keeps its unchecked checkpoints, which freezes a gap for good
`wallet.ts:285–383`. Checkpoints are trimmed to `kept` only when the sync reaches its completeness check. If the
sync throws after checkpoints were pushed (for example a transient `get_leaf_count` or `getBlockWithTxHashes`
error), the in-memory `state` keeps those checkpoints and the partial leaves. The next sync starts after the
unchecked checkpoint, and then persists it.

Reproduced: one leaf dropped by the RPC and one `get_leaf_count` failure in the same sync. Every later sync in
that process is incomplete (`leaf count 0, the pool has 2`), and so is a freshly loaded wallet on the same store.
Only wiping the store fixes it. This is SDK-IP2 again, reached through an exception.

`address()` also calls `save()` outside the lock, so it can persist the state of a sync still in progress.

**Required:**
- On any throw in `syncLocked`, restore the committed state (`await this.load()` in a `catch`, then rethrow).
- Make `address()` save under the store lock.
- Test: a dropped leaf plus a thrown call in the same sync recovers on the next sync.

#### SDK-IP17 — Low — the live-input cache belongs to one `Wallet` instance
`this.live` (`wallet.ts:495`) is refreshed only by that instance's own `writeRecord` or `load`. `plan()` uses it
through `spendable()` under the lock without re-reading the records. Reproduced: tab B planned note 0 while
tab A's left record held note 0.

No double payment is possible (the nullifier is shared, and B reuses the stored companion), but it breaks
"notes named in a live record are not selectable" across tabs, which the Web Locks design is meant to support.
This was a regression: before 5bd6ac6, the records were read on every `spendable()` call.

**Required:** refresh `this.live = await this.liveInputs()` inside the lock in `plan()`, and in `balances()`
callers after `sync`.

#### SDK-IP18 — Low — `FileKV` stale-lock takeover races
`store.ts:113–130`.
- **Race 1 (fresh lock):** another process that finds the lock between `open('wx')` and `writeFile(pid)` reads
  an empty pid (`0`), treats the lock as stale, deletes it, and takes it. Both processes then hold the lock.
- **Race 2 (stale lock):** two processes taking over the same stale lock can both `rm` it and one removes the
  other's fresh lock.

**Required:** make creation and takeover atomic. For example, write `lock.<pid>.<rand>` completely, then `link()`
it to the lock path (fails if the lock exists). On takeover, `rename()` the stale lock to a unique name and
check it still holds the dead pid. Treat an empty or unreadable lock as held.

#### SDK-IP19 — Low — server: the identical-body lookup is unmetered
`api.rs:185–187, 345–367`. `existing_job` runs before any token is spent. It scans all jobs linearly and, for a
finished job, calls the node's `block_number`. Anyone holding one finished body can call the RPC node without
limit. The pool of bodies is small and the harm is bounded.

**Required:**
- Index jobs by `body_hash`.
- Cache the latest block for a few seconds, or charge the rate bucket when the lookup reaches the RPC call.

### Other notes (no action required for GO)

- **Replan companion:** a re-plan of a record that has not left draws a fresh companion, while `nullifiers` keeps
  the first plan's companion nullifier. Harmless, since the real input nullifier is shared, but recompute it on
  re-plan.
- **Overwritten history:** a re-wrap at a different URL, or a second `submit`, overwrites `server`/`tx` without
  adding it to `attempts`. Keep them there for the sent history.
