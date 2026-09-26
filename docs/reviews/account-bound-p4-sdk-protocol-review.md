# SDK TS and WASM for R0 V5, pool V3 and bound wallets (P4 M6): protocol review

- **Date:** 2026-09-26.
- **Reviewer:** an independent protocol reviewer, who did not write the change.
- **Scope:** uncommitted `sdk/ts/src/*`, `sdk/wasm/src/lib.rs` and `sdk/ts/test/{bound,wallet}.test.ts`
  with `mockchain.ts`.
- **Checked against:** account-bound spec §5.3, §6, §7.4, §8, §9 and §10, and the sdk-spec revision 4
  amendments. The Rust core had passed its Math review (`account-bound-p4-math-review.md`).
- **Where the reviewer worked:** only in a copy; nothing was sent on chain.

## Verdict: CONDITIONAL GO

No path lets a lying server or RPC node make the wallet sign or send something that could move funds
wrongly:

- the core builds every signed message from the proved statement's own JSON;
- the job body carries that text verbatim, with the core's calldata;
- the result window is computed locally, and a server returning another pool call is refused;
- bound keys cannot exist for an R0 V4 pool.

**Conditions:** AB-SP12 and AB-SP13, before bound wallets are exposed to apps.

## Findings

**AB-SP12 (medium): a re-plan kept the stale authorization, and there was no way to re-authorize.**
- **Problem:**
  - `replan` spread the record, so its `authorization` survived.
  - `authorize()` returned any stored authorization, and `body()` sent it.
- **Scenario:**
  1. A re-plan is proved, and its new statement is sent with the old signature.
  2. The server refuses it (403) and backs off the note.
  3. The stored body is reused on every later wrap, and the inputs stay locked until
     `valid_until + 10`.
- The same trap applies after any signature refusal, for example a key rotation: there was no API to
  re-authorize.

**AB-SP13 (medium): §10 was not enforced for bound spend reads and submission.**
- (a) `checkRecipient` (ERC721 and ERC1155 exits) always went through the provider that has seen `A`.
- (b) `submit()` accepted an account whose provider was that provider.
- (c) `boundWallet` compared the spend provider with it only by object identity, and never checked the
  spend provider's chain or spec version.
- (d) The docs did not say that the spend provider must be OHTTP or the relayer, although the
  signature pre-check names `A` to it.

**AB-SP14 (low): `spend_message` trapped on malformed felt text.** The relation's `canonical_felt`
accepts text that `felt_limbs` then fails to parse (`RuntimeError: unreachable`). Production input is
the core's own statement JSON, so this was not attacker-reachable.

**AB-SP15 (low): lapsed proposals blocked deposits forever, and T was never pinned.**
- `pendingProposals` counted any `eta ≠ 0`, and pool V3 keeps a lapsed proposal.
- `Proposal` had no lapse time.
- `verifyPins` did not check T, so a pool with T = 1 s passed `connect`, and nothing enforced the
  mainnet floor.

**AB-SP16 (low): the setup-check order was not enforced, and `A` was not bound to the signer.**
- `boundWallet` did not require the checks and never re-ran them on open, for example after a guardian
  is added.
- `BoundSigner` had no address to compare with `A`.
- The setup check read transport errors as refusals, so a flaky node passed the tampered-signature and
  other-hash checks.

**AB-SP17 (low): `authorize()` prompted on a closed record.** A cancelled record still reached the
wallet prompt and the `is_valid_signature` pre-check.

**AB-SP18 (low): `wrap` made retries that could not help, and a stored body could not be fixed.**
- It re-wrapped the identical V5 body when the statement's own `valid_until` bounded the window.
- It reused a stored body even after an admission refusal, so new payment was ignored.

**AB-SP19 (info):**
- the result's `pool_call.entry_point` was not compared;
- malformed felts threw an untyped `SyntaxError` through `canon`;
- `Templar.wallet()` accepted bound key material;
- the §7.4 fallback timing comes with P4b;
- `JobStatus.refund` reaches the app only through `onStatus`;
- `ProverClient.info()` did not check E, Q or the spend domain and type hashes.

**AB-SM3 (carried from the Math review): resolved.**
- `companion_nullifier` uses the key source's account.
- The pool's version is passed everywhere.
- The u128 amount and `valid_until` never pass through a JS number where it matters.

## Resolution (implementer, 2026-09-26)

| Finding | Change |
| --- | --- |
| AB-SP12 | `replan` clears `authorization` and keeps it in the attempt it archives. `body()` recomputes `spend_message(statement_json, salt).hash` and refuses a mismatch (`reauthorize`). `authorize({ fresh: true })` archives the current authorization and body and asks the wallet again for the same statement. After a 403 at admission, `wrap` drops the stored body (below). Test: `a re-plan or a signature refusal is authorized afresh, never with a stale signature` |
| AB-SP13 | In bound mode, `checkRecipient` uses the spend provider. `submit` refuses an account whose provider is the wallet's main provider or the same node URL (`spend_provider`). `boundWallet` refuses a spend provider on the same node URL or another chain, and checks its spec version. The `Bound` and sdk-spec text state that the spend provider must be OHTTP or the relayer. Tests: the bound flow's submit through the main provider, and a spend provider on SN_MAIN |
| AB-SP14 | `SpendMessage::of` rebuilds every felt field from its parsed value before the relation's checks (as `witness()` does, SDK-IM1). Tests: `malformed_statement_text_is_an_error` (core), and four malformed-statement cases in the WASM no-trap test |
| AB-SP15 | `parameters.timelock` is pinned and checked against `get_parameters`. On SN_MAIN, T must be at least 7 days and W at least E + Q. `Proposal` gains `lapsesAt` and `lapsed`, judged at the latest block's timestamp, and a lapsed verifier proposal no longer blocks deposits. Tests: the timelock mismatch, the mainnet floor, and a lapsed proposal that lets a deposit through |
| AB-SP16 | `BoundSigner.address` must equal `A` in `boundSetupCheck` and `boundWallet` (`account_mismatch`). `boundWallet` re-runs the class and signer checks (`starknet_call` only) before any address exists. The setup check's `is_valid_signature` treats an error that is not the node's `RpcError` as `rpc_unavailable`, not as a refusal. Tests: a mismatched signer, a guardian added after setup, a transport failure |
| AB-SP17 | `authorize()` refuses a closed record, or a statement within `WINDOW_MARGIN` of its `valid_until`, before prompting (`record_closed`, `replan`). Test: a dead record's `authorize` makes no prompt |
| AB-SP18 | `wrap` fails with `replan` when the statement's own `valid_until` bounds the window, both up front and on a stale result. On `prover_rejected`, `prover_payment` (402) or `prover_forbidden` (403) it drops the stored body, so the next wrap builds one with the new payment or authorization. Tests: the bound flow's `replan`, and the 403 path |
| AB-SP19 | The result's `entry_point` is compared. `canon` throws `bad_felt`. `Templar.wallet()` takes only 32-byte seeds (`bad_seed`). `ProverClient.info()` checks the published spend domain and type hashes against the core's (`spend_domain()`, a new WASM export) and the pool parameters against the pins. The §7.4 fallback timing is P4b's, and surfacing refunds is P7's ticket wallet |

**Tests after the changes:** 24 TS tests (bound 6, wallet 18) and the Rust SDK suite pass.

## Verification of the fixes (same reviewer, 2026-09-26): GO

All eight resolutions hold, checked by code reading and by the reviewer's probes ported to the new
API: 24 TS tests and 7 probes pass. Non-blocking notes and what was done:

| Note | Change |
| --- | --- |
| Low: `boundWallet` refused to open after a class or signer change, blocking sync and withdrawals too | It opens, and exposes `accountIssue`; `address()` and `deposit()` refuse while it is set. Spends proceed, and the account decides whether it signs. Test: a guardian added after setup |
| Info: `sameNode` compared URL strings exactly | Node URLs are normalized with `new URL()` |
| Info: a 403 did not say whether the signature or the account class was refused | The server adds `reason` (`signature` or `account_class`); the SDK reports `prover_forbidden` or `prover_account_class`, and drops the stored body either way. Test: both 403s |
| Info: `sameFelt` threw a raw `SyntaxError` | It compares through `canon`, so garbage is `bad_felt` |
| Info: strict mode relies on `instanceof RpcError` (a second bundled starknet.js reads an honest revert as `rpc_unavailable`) | Kept: fail-closed, liveness only |
| Info: the mainnet floor checks `W ≥ E + Q`, not AB-PV8's sync margin | Carried to P6, which fixes the number |
