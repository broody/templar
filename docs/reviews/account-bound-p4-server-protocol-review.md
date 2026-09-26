# Prover server R0 V5, admission and tickets (P4, M3 and M4): protocol review

- **Date:** 2026-09-26.
- **Scope:** uncommitted `server/prover` on `feat/account-bound`:
  - `api.rs`, `pipeline.rs`, `tickets.rs`, `v5.rs`, `statement.rs`, `config.rs`, `main.rs`, `rpc.rs`;
  - `deploy/prover.example.toml`.
- **Checked against:** spec §7.2, §9 (including "Implementation (P4)"), §10, and the P3b
  carry-forwards AB-PV6 and AB-PV7.
- **Where I worked:** only in `~/.local/share/templar/runs/review-p4-protocol/`. I edited nothing in
  the repository and sent nothing on chain.

## Verdict: CONDITIONAL GO

**What holds:**
- **Admission order** matches §9: parse, configuration, payment, deduplication, expiry, chain state
  with root freshness, bridge with calldata match, signature.
- **Bound spends** need `operator_node`, and are refused before payment without it.
- **The `Held` guard** releases the reservation on every early return, on a task panic and when the
  client disconnects. A bridge rejection or calldata mismatch consumes; a signature failure
  releases.
- **Job start** spends the tickets at the OS stage. Refunds are blind signatures on the job's own
  requests.
- **Signature back-off** is per note, with the first failure free. The bound free allowance is
  counted only after the signature passes.
- **The pool call** is parsed strictly and matched field by field, including the binding against
  the bridge's and the intent preimage.
- **Deadlines and roots.** `send_deadline` has its own name. The root is checked against the
  deadline at admission and again at job start (AB-PV6).
- **Pool V3's ABI** is used: `get_verifier(kind)` and `get_proposal` (AB-PV7).
- **Bound job directories** are deleted when proving ends.
- **Tests:** the 24 unit tests and the ignored end-to-end admission test all pass in my copy.

**Conditions.** Fix AB-SP1 to AB-SP4 before this server serves pool V3 with payment or free
withdrawals switched on. Each one is a liveness failure or a free-work loop.

## Findings

**AB-SP1 (medium) — `pipeline::verifier_unchanged`: a lapsed proposal stops the server for good.**
- **Problem.** Refusal is `eta ≠ 0 && eta ≤ now + pending_margin`. Pool V3 lets a proposal apply
  only within `[eta, eta + T]`, but keeps a lapsed one in storage until it is cancelled or replaced.
- **Scenario.**
  - Probe `review_lapsed_proposal`: eta 1,000,000, now 10,000,000, T = 86,400. The job is refused:
    "a change … is due".
  - Every R5 (or P1) job is refused at job start after its tickets were reserved. Worse, `startup()`
    calls the same check, so the server refuses to start.
  - During a live window `[eta, eta + T]` (T ≥ 7 days on mainnet), the server also refuses
    everything until the owner applies or cancels.
- **Fix.**
  - Refuse only while the change can apply before the job's deadline:
    `eta − margin ≤ now ≤ eta + T`. Take T from `get_parameters`, and treat `now > eta + T` as no
    proposal.
  - Do not fail startup on a pending proposal; warn instead.
  - Document the outage during an armed window, or serve with a warning, since the pool accepts the
    old verifier until `apply`.

**AB-SP2 (medium) — `api.rs` step 3: the free allowance is spent before anything is proven.**
- **Problem.**
  - The free hourly bucket (default 30 per hour) is debited, and the free-queue capacity checked, at
    step 3.
  - At that point the statement is unverified. The free check needs only a statement whose two
    output commitments open to zero-value notes, which anyone can compute without a proof.
  - Refusals at steps 4–8 never return the token.
- **Scenario.**
  - Junk free bodies with a priced `token_out`, the public current root and random nullifiers pass
    step 3.
  - They then fail cheaply at step 5, 6 or 7.
  - Two IPv4 addresses (2 × 20 per hour), or one OHTTP relay (400 per hour), drain the global
    bucket. Every real free full withdrawal is then refused ("rate-limited").
  - A bound spend refused by the per-account cap also burns a global token.
- **Fix.**
  - Debit the free bucket (and count the free queue) only after the bridge, the calldata match and
    the signature pass, where the per-account cap is already counted.
  - Add a per-address free counter.

**AB-SP3 (medium) — free jobs take paid capacity.**
- **Problem.** §7.2 says free jobs never take slots from paid ones, but three things let them:
  - the global `queue_capacity` check counts every queued job, free ones included, so a full free
    queue shrinks the paid queue;
  - a running free job holds the only worker (`max_concurrent_jobs = 1`) for up to `prove_seconds`,
    since the biased select orders only the queue;
  - `expiry_admits` counts free jobs ahead of paid jobs. That is too strict for paid jobs, and too
    loose for free ones, which paid jobs pre-empt, so free jobs can starve past their
    `valid_until`.
- **Scenario.** At the default 30 free per hour × about 80 s, free jobs occupy about 40 minutes of
  every hour of the single prover.
- **Fix.**
  - Count only paid jobs against `queue_capacity`.
  - Budget free execution time: a per-hour cap × job time below a stated share, or a separate
    worker.
  - Estimate the expiry wait per queue.
  - State that free exits are best-effort under paid load. During an exit rush in a verifier
    window, the free cap, not the prover, sets how fast free users can leave.

**AB-SP4 (medium) — `work()`: prove failures are refunded, but there are no caps before proving.**
- **Problem.**
  - `os_steps` is read, but never checked before the `prove` stage.
  - A `prove` or `facts` failure refunds the tickets.
  - A failed job releases its note, with no back-off.
  - A hostile bound-account class can inflate the virtual-OS trace up to the 450M L2 gas bound
    (about 80M above `__execute__`), or its hashed bytecode, and push the proof past `job_memory`
    or `prove_seconds`.
- **Scenario.** One ticket and one note give unlimited attempts, each costing the prover up to
  about 30 minutes, with the ticket refunded every time.
- **Fix.**
  - Enforce §9's caps now, on `os-result.json` resources: steps, builtins and Blake counts, from the
    P0b envelope. A cap violation is the client's fault.
  - Refund a prove failure only when the OS resources were inside the envelope.
  - Back off per note after any job failure.

**AB-SP5 (low) — ticket fault classification is by stage, not by cause.**
- **Problem.**
  - Any error in the OS stage keeps the tickets spent, including ones that are not the client's
    fault: a sandbox that fails to spawn, the RPC node failing during the OS run, or a timeout
    under load.
  - Likewise, any `pipeline::check` error consumes the tickets, including a sandbox failure, a disk
    write error, or `check_seconds` running out on a loaded host.
- **Fix.**
  - Classify by cause. Revert, abort, message mismatch and cap violation are the client's. Parse the
    runner's output for "Reverted transactions are not supported" or an execution failure.
    Transport, spawn and IO errors are the server's.
  - Only a bridge panic or a calldata mismatch consumes at step 7.

**AB-SP6 (low) — `pipeline::run`: the job-start expiry check omits proving time.**
- **Problem.**
  - Job start requires `valid_until ≥ base + 11 + relay_margin`.
  - Spec §9 says "the same expiry check" as admission, which includes `blocks_per_job` for proving.
- **Scenario.** A job that waited in the queue starts with `valid_until = base + 41`. Proving takes
  about 50 blocks, and the relayer then refuses `send_deadline < latest + margin`. The tickets were
  spent at the OS stage.
- **Fix.** At job start, require `valid_until ≥ base + blocks_per_job + 11 + relay_margin`, and
  release otherwise, since the delay was the server's queue.

**AB-SP7 (low) — the server proves spends the pool will always reject.**
- **Problem.** None of the following is checked, so the tickets are spent and the relayer refuses
  later:
  - **Expiry rules:** `valid_until % Q = 0`, and `valid_until − E − Q ≤ send_deadline`. Otherwise no
    block satisfies `VALID_UNTIL_AHEAD`.
  - **Invoke spends:**
    - intent `expiry ≥` the earliest landing block;
    - adapter nonzero and not the pool;
    - `COMPUTE ⇔ identity ≠ 0`;
    - the input asset an ERC20, and destination tokens not registered NFTs;
    - `INVOKE` target not allowlisted, `COMPUTE` target allowlisted, and no pending shadow-class
      proposal for the target's class before the deadline.
- **Fix.** Mirror these at admission and job start. They are cheap: `get_parameters` is already
  loaded, and the rest are one `get_class_hash_at`, one `is_shadow_class` and one `get_proposal`
  each.

**AB-SP8 (low) — a crash after the spend loses the tickets.**
- **Problem.**
  - Tickets are spent durably at the OS stage, but jobs and their refund requests live only in
    memory. Startup purges job directories, and job ids are lost.
  - §9 says a crash earns replacement tickets. This implementation cannot provide them.
- **Fix, either:**
  - journal `(job id, refund requests, spent)` fsynced beside the spent log, and on startup mark
    spent, unfinished jobs as failed with a refund; or
  - state it in §9 as a P4 limitation.

**AB-SP9 (low) — a failed ticket write is ignored.**
- **Problem.**
  - In the stage closure, a failed `spend` (an IO error on the spent log) is only logged, and the
    job goes on to the OS run and proving.
  - The tickets stay reserved in memory, and after a restart they are unspent and reusable, so the
    proof was free.
  - The consume path leaves tickets reserved on the same error.
  - The spent log shares `data_dir` with the job directories, so a full volume triggers this.
- **Fix.**
  - Fail the job before the OS run if the spend cannot be synced, and release.
  - Keep the spent logs on a separate volume from the job directories.

**AB-SP10 (low) — bound-mode data is not on tmpfs as §9 specifies.**
- **Problem.**
  - Bound job directories (bridge arguments, `os-job.json` with salt and signature, the PIE, logs)
    live on the persistent `data_dir` volume. Deletion when proving ends leaves the blocks
    recoverable.
  - Swap is off in the README's `docker run` (`--memory-swap` equal to `--memory`).
  - `free_accounts` keeps raw bound accounts in memory for a day.
- **Fix.**
  - Put bound jobs in a separate `bound_data_dir` on tmpfs.
  - Key `free_accounts` by an HMAC of the account under a per-process random key.

**AB-SP11 (info) — follow-ups for P7 and P4b.**
- **Spent set.** "One spent set per issuer key, shared by every redeemer" is per-process files
  today. Two server instances, or a third-party relayer, would each accept the same ticket. P7
  needs a shared spent set.
- **Acknowledgement.** `DELETE /v1/jobs/{id}` drops the result. In P4b the relayer must take the
  result when the job completes, before the client can delete it.

## Your points

- **Refusal paths:**
  - No double release: `release` checks the reservation id.
  - The only case where tickets are neither released nor consumed is a spend IO error (AB-SP9).
- **Spend timing:** correct, spent at the OS stage after the job-start checks. But the job-start
  expiry check is weaker than specified (AB-SP6), and faults are classified by stage (AB-SP4,
  AB-SP5).
- **Crash after spend:** tickets are lost, contrary to §9 (AB-SP8).
- **Free queue and allowance:** AB-SP2 and AB-SP3.
- **Pending-verifier margin:** AB-SP1.
- **Server accepts, pool or relayer rejects:** AB-SP6 and AB-SP7. `send_deadline`, root freshness
  and `max_proof_age` are otherwise consistent.
- **Exact cost:** fine. It is computed from the claimed statement, and the bridge's statement
  equality then binds it (a mismatch consumes the tickets).
- **`operator_node`:** a self-declared flag, enforced at step 2 before payment and published as
  `bound_mode`. Fine.
- **Logs:** no path found that writes the account, salt or signature to a log. The error texts are
  generic.

## What I ran

In a copy of `server/prover`, with the two included KAT files copied beside it:
- `cargo test --release`: 24 pass;
- the ignored `admission_r5_with_tickets`, against my copy of the r5-p3b bridge, the p4-m1 SDK
  proofs and the delegated cgroup: passes;
- probe `review_lapsed_proposal` (AB-SP1): the job is refused.

The rest is code reading, labelled as such above.

## Resolution (implementer, 2026-09-26)

| Finding | Change |
| --- | --- |
| AB-SP1 | `pipeline::change_due(key)`: refused only while `eta − pending_margin_secs ≤ now ≤ eta + T` (T from `get_parameters`); a lapsed proposal is none. Startup checks only the current verifier and logs a pending change (`verifier_current`, `warn_pending`). Admission also checks it at step 6, so a refusal comes before the bridge. The outage during an armed window is stated in spec §9. Tests: `v3_verifier_and_pending_changes` (the review's lapsed probe now passes), `proposal_windows` |
| AB-SP2 | Step 3 only looks at the free allowances (`free_allowance(…, debit = false)`); `admission_tail` debits them after the bridge, the calldata match and the signature, all under one lock: the global bucket, a new per-address bucket (`per_address_per_hour`, default 4; relays share the global bound), and a bound account's daily count. Tests: `free_allowances`, and the end-to-end test checks one global token taken per admitted free job |
| AB-SP3 | Only paid queued jobs count against `queue_capacity`. `expiry_admits` counts running jobs plus queued paid jobs for a paid job, and every queued job for a free one. Workers serve the free queue only while free jobs of the last hour took less than `max_share_percent` (default 25) of the workers' time. Spec §9 states free exits are best-effort |
| AB-SP4 | Bound spends are served only for `bound_account_classes` (required with `operator_node`), checked at admission and at the base block, so the account code in the virtual OS is measured code. `within_caps` enforces `caps.os_steps` (default 4M) and named builtin caps on `os-result.json` before proving, as a client fault. Any job failure backs its note off, doubling. A Blake and component-size check in `templar-prove` is P5's, with the final cap numbers. Tests: `bound_classes_served`, `caps_before_proving`, and the end-to-end test's back-off |
| AB-SP5 | `pipeline::ClientFault` marks the client's failures: a bridge panic, an output or calldata mismatch, a virtual-OS revert or failed execution (from the runner's error, with node-failure markers taking precedence), a message mismatch, a cap violation, a pool-rule violation. Everything else is the server's: released before job start, refunded after. A pre-check time-out or sandbox failure releases the tickets. Test: `faults_by_cause` |
| AB-SP6 | Job start runs `expiry_admits(valid_until, base, 0)`, proving time included; the failure comes before the spend, so the tickets are released |
| AB-SP7 | `pool_rules` (the Q grid, a settling block up to `send_deadline` less the relay margin, intent expiry, adapter, `COMPUTE ⇔ identity`) and `invoke_state` (ERC20 asset, unregistered destinations, shadow-class status, no due change of the adapter's class) at admission and at the base block. Tests: `pool_rules_mirror_the_pool`, `invoke_state_mirrors_the_pool` |
| AB-SP8 | Stated in spec §9 as a P4 limitation; the journal comes with P7's issuer |
| AB-SP9 | As AB-SM5, and `payment.spent_dir` puts the logs on their own volume (README) |
| AB-SP10 | `server.bound_data_dir` (a tmpfs, required with `operator_node`) holds bound jobs and is purged at startup. The free account counter is keyed by `sha256(per-process key ‖ account)`. README: the tmpfs mount and swap off |
| AB-SP11 | Carried to P7 (shared spent set) and P4b (the relayer takes results before the client acknowledges) |

**Tests after the changes:** 34 unit tests pass, and `admission_r5_with_tickets` passes end to end
against the real R5 bridge with the p4-m1 SDK proofs (now also checking the failure back-off, the
free allowance debit and the empty bound tmpfs).

## Re-check (independent reviewer, 2026-09-26): CONDITIONAL GO

An independent re-check found the AB-SM and AB-SP resolutions held, except AB-SP2 (N1), AB-SP5
(N3) and AB-SP7 (N4), which were partial, and the AB-SM8 and AB-SP11 documentation items. It ran
the 34 unit tests, the end-to-end test, and four probes of its own in a copy. New findings and
their resolution:

| Finding | Change |
| --- | --- |
| N1 (medium): the free allowance was debited for submissions that were never admitted (the client disconnected, a duplicate, a full queue) | `admission_tail` only looks at the allowances. `admit` takes them under the registry lock (then the free lock, the only order), after the duplicate check, and gives them back if the queue refuses the job (`free_credit`). The end-to-end test abandons a free submission during the pre-check and checks that no job was made and that the honest free job took exactly one global token |
| N2 (low): a torn spent-log line stopped the next startup | `append` starts a fresh line after a torn one; `load` skips a torn line, and for a torn part that ran into a whole line keeps the last 64 hex characters. Test: `torn_spent_lines` |
| N3 (low): any failed bridge run counted as the client's | Only an output with a Cairo panic line is the client's; any other failure is the server's and releases the tickets. Real bridge rejections print `Panicked with …` (the bench-proof checks) |
| N4 (low): invokes the pool always refuses | The intent must last to `max(valid_until − E − Q, latest + blocks_per_job + 11)` plus the relay margin; a destination whose `get_contract_standard` is not 0 or 20 is refused; `send_deadline` is capped by the intent's expiry. Tests: the probe's case in `pool_rules_mirror_the_pool`, and an NFT destination in `invoke_state_mirrors_the_pool` |
| N5 (info) | Spec §9: issuer keys single-purpose; P4's 2048-bit test keys, P7's production size |
| N6 (info): a failed consume was never retried | `Tickets::consume` keeps the reservation pending; the next reservation, once the probe passes, spends pending ones first. Test: `ledger_fails_closed` |
| N7 (info) | Startup warns when `pending_margin_secs < max_proof_age × 6 s` on pool V3; spec §9 |
| N8 (info) | Spec §9: a free job held back by the share can expire in the queue |
| N9 (info): a server-side pre-check failure released the tickets with no back-off | Any pre-check failure backs the note off (the end-to-end test checks it) |
| AB-SP10 (info): the tmpfs was not checked | `serve` refuses to start unless `bound_data_dir` is on a tmpfs or ramfs (`/proc/self/mounts`). Test: `tmpfs_detection` |
| AB-SP11 (doc) | Spec §9 P4 limitations: the relayer takes a result when its job completes, before the client's acknowledgement |

**Tests after the changes:** 36 unit tests pass, and `admission_r5_with_tickets` passes end to end.

## Verification of the re-check fixes (same reviewer, 2026-09-26): CONDITIONAL GO

Every finding above holds, probed end to end with the real bridge: the disconnect drain leaves
the buckets untouched, a torn spent line reloads, a forged proof is the client's ("Panicked with
Merkle Verification Error") and an ENOSPC stand-in the server's, and the intent-expiry case is
refused. New:

| Finding | Change |
| --- | --- |
| N10 (low-medium): the N9 back-off was keyed by the note before any proof was verified, so anyone who knows a note's input-0 nullifier could lock it out | A pre-check failure backs off the note only when the bridge had accepted the proof (`ClientFault { proven }`: an output or calldata mismatch). A bridge rejection or a server-side pre-check failure backs off the exact body (`body:<sha256>`), checked at step 4; varied junk is left to the address and relay rate limits. The end-to-end test sends a forged proof for a note (400, then 429 for the same body) and then the owner's honest body, which is admitted |
| N11 (info): `panicked` also matched scarb's own crashes | The client's verdict is only a Cairo `Panicked with …` line |
| N7 (info): the default margin always triggered the warning | `pending_margin_secs` defaults to `max_proof_age × 6` seconds |
| N12 (info): a bridge run that ends without a verdict (memory, time-out) releases the tickets | Kept: such a run is the server's side. It holds one of the check slots for at most `check_seconds`, bounded by the submission rate limits, and its body backs off |

**Tests:** 36 unit tests and `admission_r5_with_tickets` pass.
