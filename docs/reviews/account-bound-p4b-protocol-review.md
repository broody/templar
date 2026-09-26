# P4b minimal relayer: protocol review

- **Date:** 2026-09-26.
- **Reviewer:** an independent protocol reviewer, who did not write the change.
- **Scope:** the uncommitted P4b tree on `feat/account-bound`:
  - the prover's relay handoff (`server/prover/src/{api,config,main}.rs`);
  - the relayer (`sdk/ts/src/relayer.ts`, `server/relayer/`);
  - the SDK fallback (`sdk/ts/src/{wallet,prover}.ts`);
  - their tests.
- **Checked against:** account-bound spec §7.3, §7.4 and §10, §15 P4b, F06 and AB-P31.
- **Where the reviewer worked:** only in copies; nothing was sent on chain.

## Verdict: CONDITIONAL GO

**Sound:**
- the handoff API: its own listener, a copy the client's acknowledgement cannot take, one atomic
  answer per job, expiry at the deadline, and a constant-time token compare;
- the §7.3 checks, which match pool V3, including the root rule against `tree_v3.cairo`.

**The problem:** five reproducible paths let the relayer's transaction and the wallet's fallback
both go out, which is the AB-P31 harm P4b exists to close.

## Findings

**AB-RL1 (medium): refusals for transactions that may have left.**
- An ambiguous send error was answered as a refusal.
- A report that did not reach the server was lost, and the next pass refused the item as a
  duplicate of the relayer's own transaction.

In both cases the wallet falls back at once, beside the pending transaction.

**AB-RL2 (medium): a re-wrap dropped a pending relay.** Re-wrapping at a server that does not relay
overwrote the record's relay with `none`, while the first relayer could still submit.

**AB-RL3 (medium): the fallback guard failed open.**
- The prover was optional, so a record left at `pending` fell back without the relayer's answer.
- Any status error kept the stale answer.
- Any `getTransactionStatus` error read as "not found".

**AB-RL4 (medium): nonces.**
- The relayer's nonce was read at `latest`, so two spends in one block collided, and the second
  client fell back with its own linkable account.
- The relayer never tracked its own transactions, so a stuck one blocked the rest unseen.

**AB-RL5 (medium/low): the retention sweep dropped a job whose relay item still waited.** The
relayer's answer then never reached the client, and the note's dedup was released.

**AB-RL6 (low): relay state lived only in memory.** A relayer restart lost its dedup set.

**AB-RL7 (low): cheap griefing.** An asset or receiver that reverts once included passes
simulation. Its notes could be relayed again after the deadline.

**AB-RL8 (low): a fragile margin.**
- `latest` was read before preparing and never again.
- A margin of 41 was accepted.
- A lagging node was not detected.

**AB-RL9 (low, liveness): `expired` never allowed an early fallback.** With the relayer down,
wallets had only `[D − 40, D − 20]` to fall back.

**AB-RL10 (low): handoff access.** A loopback listener without a token let any local process read
results and forge answers.

**AB-RL11 (low, privacy):**
- the fallback polled the relayer's transaction through the fallback account's provider;
- `relayStatus` ran before the closed-record check.

**Info:**
- invokes were queued only to be refused;
- `submitted` was pruned only while deciding;
- the full list is sent every pass.

## Resolution (implementer, 2026-09-26)

| Finding | Change |
| --- | --- |
| AB-RL1 | The relayer takes the transaction hash from its signer (`CapturingSigner`, the hash `signRaw` signs) and records the notes with it before sending. A send whose outcome is unknown, and any later job for those notes, are answered with that hash; a refusal only when nothing was sent. An answer the server did not acknowledge is kept and sent again first, and the job is not decided twice. Test: `an ambiguous send, a lost report, a restart` |
| AB-RL2 | `wrap` archives each job with its `relay`. `fallbackAllowed` checks every job of the record whose relayer may still submit it, up to its own deadline. Test: re-wrapped at a server that does not relay, the wallet waits for the first job's `D − 40` |
| AB-RL3 | `submit` needs the prover while the relay is pending or submitted (`prover_required`). `ProverClient.status` reports a 404 as `prover_job_gone`, the only error that leaves the last answer standing; any other is `relay_unknown`. Only RPC error 29 reads as an unknown transaction; any other status error is `relay_unknown`. Tests: `prover_required`, a 503 against a 404, and a transport failure |
| AB-RL4 | `prepare` takes an explicit nonce. The relayer keeps its own sequence, never below the chain's at `pre_confirmed`, and its provider defaults to `pre_confirmed`. It tracks its own transactions: a rejection or a lost transaction resets the nonce, and one pending past `stuckBlocks` pauses new jobs. Test: two jobs in one pass take nonces 7 and 8; a stuck one pauses the next |
| AB-RL5 | The sweep keeps a job whose relay item waits, or whose relay answer is still within its deadline, and drops only its result. Test: `relay_handoff` retention |
| AB-RL6 | The relayer's nullifiers (with hashes), denials, transactions and nonce persist in `stateFile`, replaced atomically. A server restart losing its queue is stated as a P4b limit. Test: a restarted relayer answers with the earlier hash |
| AB-RL7 | Exits are relayed only for allowlisted `assets`. A relayed transaction that reverts denies those notes for good. Tests: an asset outside the list, and a revert that denies |
| AB-RL8 | The margin must be at least `FALLBACK_MARGIN + 20`. The relayer re-reads the latest block just before sending, sends nothing while its node's latest block is older than `staleSecs`, and warns when the server's `relay_margin_blocks` is below its margin. Tests: margin floor, lagging node |
| AB-RL9 | A claim step: the relayer claims just before sending and sends only on a 200. The server refuses unclaimed items once their deadline is within `relay_margin_blocks`, so the fallback window widens to `[D − 60, D − 20]` when the relayer is down. Tests: server claims and lateness; the relayer skipping a refused claim |
| AB-RL10 | `[relay] token_file` is always required, of at least 16 characters; a listener that is not loopback is warned about (private network or TLS) |
| AB-RL11 | The fallback reads the relayer's transaction through the spend provider in bound mode; `submit` checks the closed record before reading the relay answer |
| Info | Invokes are refused at once by the server (their clients submit without waiting); `submitted` is pruned every pass. The full list per pass is kept (loopback, a few items) |

**Tests after the changes:** 37 server unit tests and the end-to-end admission test; 31 TS tests
(relayer 7, bound 6, wallet 18).

## Verification of the fixes (same reviewer, 2026-09-26): CONDITIONAL GO

Probes P1 to P5 and the retention probe no longer reproduce. The signer capture was checked with
the real starknet.js 10.8: `lastHash` is the final transaction's hash, not the fee estimate's
query hash. A new probe found one more path to two transactions:

| Finding | Change |
| --- | --- |
| AB-RL2b (medium): a job abandoned before its result had no relay state and no window, so the fallback skipped it while its relayer could still submit | `wrap` records the relay state when the job is admitted, not when the result arrives, and keeps an answer the relayer already gave. `fallbackAllowed` bounds a job without a window by the statement's `valid_until` (a `send_deadline` is never later). Test: `a job abandoned before its result still counts` (the probe's case) |
| AB-RL8b (low): `staleSecs` defaulted to 120 s, looser than the 20-block margin gap; `staleSecs` and `stuckBlocks` were not configurable | Default 30 s; both are `RelayerConfig` fields |
| Info: a failed `save()` after an ambiguous send could turn the answer into a refusal | Caught and logged; the answer stays the signed hash |
| Info: `RelayState.token` was an `Option` with an open `None` branch | A required `String`; an empty token authorizes nothing |
| Info: a definitive send rejection is still answered with the hash; a lost relayer transaction leaves later jobs for those notes answered with it | Kept: conservative. The wallet reads a rejected hash as failed and falls back at once, and an unknown one from `D − 40` |

**Tests:** 37 server unit tests and the end-to-end admission test; 32 TS tests (relayer 8).
