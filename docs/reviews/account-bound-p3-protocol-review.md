# R0 V5 statement account (P3): protocol review

- **Reviewer role:** independent Protocol Reviewer. I did not write the code. The bridge's
  decoding belongs to the Math Reviewer.
- **Date:** 2026-09-26.
- **Scope:** the statement account and its authorization flow, as uncommitted under
  `bench/m31-private-wrapper/client-port/`:
  - `cairo-r5/account/src/lib.cairo`;
  - `cairo-r5/bridge/src/snip12.cairo`, as the account uses it;
  - `cairo-r5/account_tests/`;
  - `cairo-r5/kat/` and `cairo-r5/sign/`;
  - `results/r5-bridge/`.
- **Checked against:** `docs/account-bound-note-spec.md` §5.3–§5.5 (with the P3 change to §5.4),
  §9, §12 and §15 P3.
- **Output:** this file is the only change I made. Nothing was sent on chain.

## Verdict: GO

The account conforms to §5.4 step by step:
1. The caller must be 0.
2. The statement's chain must equal the transaction's.
3. Ordinary mode requires `salt = 0` and an empty signature.
4. Bound mode requires `salt ≠ 0`, rejects its own address and checks that a contract is deployed.
   - It computes the spend hash from statement fields and the salt only.
   - It calls `is_valid_signature` with `[hash, len, sig…]`. An `Err` panics, and anything other
     than exactly `['VALID']` is rejected.
5. It emits one message `[class_hash, 'TMPZR0_PAYMENT_V5', chain, pool, binding]`.

The contract exposes only `__validate__` and `__execute__`. `__validate__` is R4's zero-tip,
zero-price rule over V5's calldata.

Tests and evidence:
- The mock suite covers every case §15 P3 lists.
- Nine mutations of the account are each killed by the suite.
- The SNIP-12 hash the account computes is pinned to starknet.js twice: by the `MODE_CHECK` mock
  and by the KATs.
- Real Ready X and Braavos signatures of the exact V5 struct pass against the live classes on a
  Sepolia fork, and fail under another salt.
- The signing page and server handled the wallets safely. The one gap, AB-IP5, concerns the
  integrity of the saved evidence only.

None of the findings below blocks P3. AB-IP1 and AB-IP2 are rules for the P4 server and for P5.

## Findings

| ID | Severity | Where | Title |
| --- | --- | --- | --- |
| AB-IP1 | low | §5.4, account | The deployment check is sound, but diagnostic only; other callee failures still abort |
| AB-IP2 | low | §9 | The admission pre-check can disagree with the virtual OS; the OS run must be authoritative and bounded |
| AB-IP3 | info | tests | The re-entry test does not isolate the caller-0 guard |
| AB-IP4 | info | §5.4 | The padding-contract rejection the spec claims is not in the code |
| AB-IP5 | low | `cairo-r5/sign/serve.py` | No Host or Origin check on the local signing server |
| AB-IP6 | info | tests, kat | Unpinned fork block; odd-only test salts; real V5 signatures cover only exit shapes |

### AB-IP1 (low) — the deployment check is sound, but diagnostic only

**What holds.**
- A deployed contract always has a nonzero class hash, including after `replace_class`.
- An undeployed address reads 0. So `get_class_hash_at ≠ 0` never rejects a real account.
- It turns exactly one uncatchable failure into an explicit `ACCOUNT_NOT_DEPLOYED`. Without it,
  snforge reports "Requested contract address … is not deployed" as a hint exception
  (mutation M4, below).

**What is catchable.**
- In blockifier (`execution_utils.rs`, `execute_entry_point_call_wrapper`, with reverts enabled),
  a callee panic is returned to the caller as an `Err`.
- So are a missing entry point (`ENTRYPOINT_NOT_FOUND`) and too little entry-point gas.
- Probe: a deployed contract with no `is_valid_signature` makes the spend fail with
  `SIG_CALL_FAILED`.

**What still aborts the whole execution.**
- An undeployed address called *by the callee*. Probe: "Requested contract address 0x777 is not
  deployed" as a hint exception.
- Recursion-depth overflow.
- Step exhaustion under snforge's run limits. Probe: a gas burner stops with "RunResources has no
  remaining steps".
- Cairo 0 VM errors.

**Why none of this affects soundness.**
- A failed or aborted execution emits no message.
- The pinned runner refuses reverted transactions ("Reverted transactions are not supported";
  P0b `probe/runs/live-*-bad`), so no facts exist.

**Required change.**
- §5.4 and `results/r5-bridge/README.md` state that the check is diagnostic, and that failures
  inside the callee may still abort the whole execution.
- §9 and AB-P30 treat both an OS revert and an OS abort in bound mode as the client's failure.
- Add a test with a deployed contract that has no `is_valid_signature`, expecting
  `SIG_CALL_FAILED`. This is the likeliest real misconfiguration: a non-SNIP-6 contract, or an old
  account with only `isValidSignature`.

### AB-IP2 (low) — §9: the admission pre-check can disagree with the virtual OS

**Problem.**
- An account's `is_valid_signature` can depend on its caller or on the transaction context.
- §9's admission pre-check is a `starknet_call`: caller 0, no transaction. Inside the virtual OS
  the caller is the statement account.
- Probe: a class that returns `'VALID'` only for caller 0 passes a direct call, but fails in the
  account with `SIG_NOT_VALID`.
- A hostile class can therefore:
  - pass admission;
  - then burn the virtual transaction's whole L2-gas bound in the OS run;
  - or fail there after passing admission.
- The cost is bounded by the OS-run timeout, the gas bound and the ticket, but only if the server
  treats the OS run as authoritative and charges for it.
- The snforge runs measure `__execute__` at about 364–372M L2 gas (`account-tests.json`), against
  the 10^9 bound the server uses today.

**Required change.**
- §9 states that the pre-check is advisory, and that the OS run is authoritative and charged.
- The "lower L2 gas bound" for the virtual transaction is set from this measurement plus a margin
  for the account call, not left at 10^9.
- P5 runs the V5 account with the real wallets inside the pinned virtual OS.
  - P3's real-wallet evidence comes from snforge's executor, with a cheated caller and chain.
  - The only virtual-OS evidence for these classes is P0b's SigProbe.

### AB-IP3 (info) — the re-entry test does not isolate the guard

**Problem.**
- With the caller-0 guard deleted (mutation M5), `bound_account_reenters` still passes. Only
  `nonzero_caller` fails.
- The mock re-enters `__execute__` with an empty proof, which `verify_payment` rejects anyway.
- Starknet also blocks direct calls to `__execute__` when `block_direct_execute_call` is set.

**Required change.** The guard itself is covered by `nonzero_caller`. Either re-enter with the
fixture's real proof, salt and signature, so only the guard can stop the call, or describe the
test as "a failing callee fails the spend".

### AB-IP4 (info) — §5.4: the padding-contract claim

**Problem.**
- §5.4 says a padding contract (§12) that answers `is_valid_signature` "must never be a bound
  account: the statement account rejects it".
- The account rejects only its own address.
- No padding contract exists yet.

**Required change.** When P5 introduces a padding contract, either reject its address in the
account, or reword the spec. Binding to it could only weaken that user's own notes, and the SDK
never does it.

### AB-IP5 (low) — the signing server has no Host or Origin check

**Problem.**
- `serve.py` binds 127.0.0.1 and forwards only four read-only RPC methods, which is good.
- But while it runs, any page the user visits can POST `/save` as a simple `text/plain` request.
  That overwrites a result file, whose name comes from the posted wallet id and account.
- A DNS-rebinding page can also read `/requests.json`.
- At stake is only the integrity of the saved evidence: the signed messages name synthetic pools
  with no contract. I checked `0x163012afc4029a33` and `0xd840fce2e0004cc0` with
  `starknet_getClassHashAt`, and both return "Contract not found".

**Required change.** Before reuse, check `Host` and `Origin` and require `application/json`. The
P0b `sign-live` server has the same pattern.

**Otherwise the wallets were handled safely:**
- one `wallet_signTypedData` prompt and no invoke;
- signing enabled only on `SN_SEPOLIA`;
- starknet.js served from a local copy, not a CDN;
- signatures kept in the run directory only;
- committed records redacted: `real-wallets.json` truncates the accounts and holds no signatures.

### AB-IP6 (info) — test hygiene

- **Fork block.** The fork tests use `block_id.tag = "latest"`, so a later account change alters
  the result. Pin the block (the recorded run used 15,637,581).
- **Test salts.** The generators force salts odd (`% 2^251 | 1`). That is fine for tests, but the
  SDK must draw salts uniformly from `[1, 2^251)` (§5.3).
- **Signed shapes.** Real-wallet signatures of the exact V5 struct cover partial withdrawals only.
  The all-zero in-pool shape was signed only under P0b's predecessor struct. P5 should have the
  wallets sign an in-pool transfer and an invoke with the V5 struct.

## What I checked, and how

**Read:**
- the account, the SNIP-12 module, the mocks, all 23 tests, the generators (`v5.cjs`,
  `gen_fixtures.cjs`, `gen_sign_requests.cjs`), the signing page and server, and the P3 results;
- the R4 account, for the diff (only the authorization block and the tag are new);
- blockifier's inner-call handling in the local sequencer checkout
  (`syscall_base.rs:execute_inner_call`, `entry_point.rs:execute`,
  `execution_utils.rs:execute_entry_point_call_wrapper`);
- P0b's virtual-OS runs for tampered signatures.

**Ran** in a copy, `~/.local/share/templar/runs/review-p3-protocol/bridge`, with scarb 2.18.0 and
snforge 0.63.0:
- **Baseline:** 19/19 mock tests pass.
- **Mutations** of `account/src/lib.cairo`, each killed:

  | Mutation | Killed by |
  | --- | --- |
  | M1: no self check | `bound_account_is_the_statement_account` |
  | M2: no salt check | `bound_zero_salt` |
  | M3: no length check | `bound_account_returns_two_felts` |
  | M4: no deployment check | `bound_account_undeployed` |
  | M5: no caller-0 guard | `nonzero_caller` |
  | M6: no ordinary rule | both ordinary negatives |
  | M7: no chain check | `other_chain` |
  | M8: ordinary rule checks the signature only | `ordinary_rejects_a_salt` |
  | M9: hash without the salt | `bound_valid_signature_emits_one_message` |

- **Four probe callees** (AB-IP1, AB-IP2): no entry point, gas burner, calls an undeployed
  address, caller-sensitive.
- **Read-only RPC:** class-hash lookups for the two test pool addresses.

**Not run:** the real-wallet fork tests. I read their recorded log (4/4 pass at block 15,637,581).

**Not checked:**
- the bridge's decoding (Math Reviewer);
- the V5 account inside the actual virtual OS, and PROOF2 (P5);
- the server's §9 implementation (P4).
