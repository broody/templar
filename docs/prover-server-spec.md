# Templar prover server

Status: **design, revision 3, after the design review and its re-review (`docs/reviews/prover-server-design-review.md`, CONDITIONAL GO; findings `PS-*` cited where they changed the text). Nothing is implemented.** A runnable wrapping server for the
compact client-proof path, replacing the research scripts under `bench/` for serving proofs.
**Revision 4 amendments** (`docs/account-bound-note-spec.md` §9, §11; P4 implemented in
`server/prover` on `feat/account-bound`) add R0 V5 on pool V3, bound spends and payment: the
"Pool V3 (R0 V5)" paragraphs in §2, §4, §5, §6, §7, §8 and §10. The normative detail is
account-bound spec §9. **Revision 5 amendments** (`docs/pool-v3-spec.md` §9, §14; ADR-0027)
remove bound mode and add R0 V6 (`r6`), served through routing adapters (pool-v3-spec §6), in the
same sections. The code implements R0 V5 and bound mode until ADR-0027's phases B–E land, so each
changed passage is marked "(R0 V6, ADR-0027: pending implementation)", and bound-mode text that
the code still has is marked "(removed by ADR-0027, phase B)".

## 1. Purpose and scope

A wallet proves a spend as a compact client proof (R0 V4 or P1) and needs a native Starknet large
proof to submit it. Producing that proof means running the statement account on the client proof
in the virtual OS and proving the execution: minutes of CPU and about 28 GiB, but no secret
material. Anyone should be able to run this service.

Today it exists only as bench tooling:

- a bridge pre-check (`validate_bridge_r4.py`, `validate_bridge_p1.py`, scarb-executed Cairo);
- the virtual-OS run, a `capture` binary compiled from a `/tmp` checkout of the sequencer's
  `starknet_transaction_prover` sources (the checkout is already partly gone, so it cannot be
  rebuilt);
- the large proof, `prove_large` from the bounded-memory proving branch, run by `run.sh` under a
  cgroup cap;
- Python glue with deployment addresses and runtime paths built in.

**This design:** one Rust binary, `templar-prover`, in `server/`, with an HTTP API, a job queue,
native pre-checks, the upstream virtual-OS runner as a pinned dependency, the bounded-memory
large-proof prover as a pinned dependency, and a Docker image.

In scope: R0 V4 (ordinary spends, open notes, shadow accounts) and P1 (policy-note settlement) on
M31 pool V2, on Sepolia first. Out of scope: the legacy pool and R0 V3, submission of the
transaction (the wallet or a relayer submits), fees or payment, access control beyond rate
limits (IP or domain allowlists later).

## 2. What the server may learn

The server receives a zero-knowledge client proof and its public statement: the same data the
chain sees at settlement, earlier. It never receives keys, notes, amounts or membership paths,
and cannot forge or alter a spend: every validity rule is in the client proof, the statement
account's bridge re-checks it inside the proven execution, and the pool recomputes the binding.

It does learn, as any relay would:

- the client's network address and timing, and the statement (nullifiers included) before it is
  public; the pre-checks also send the nullifiers and root to the configured RPC node, so a local
  node matters for privacy as well as speed;
- the effects of an exit before settlement: a withdrawal's asset, amount and recipient, or an
  execution's intent digest and budget. An operator could trade ahead of a swap within the
  user's slippage bound (PS-7);
- links between one client's jobs by address and timing, including pure in-pool transfers.

It **cannot** submit the transaction itself: that needs the output ciphertexts, the execution
intent's preimage or a policy's data, which the client never sends (only their digests are in
the statement). It can refuse, delay or drop jobs.

**Pool V3 (R0 V5; revision 4).** This replaces "cannot submit" (PS-7) for R0 V5. The job body
carries pool V3's full calldata, so the server **can** settle the spend, and it chooses when, up
to `send_deadline`. In bound mode it learns the account `A`, with the salt and the account's
signature; a retained signature over a public binding is third-party-verifiable proof that `A`
made the spend, so bound inputs are deleted when proving ends and results on acknowledgement
(bound mode: removed by ADR-0027, phase B). A free full withdrawal tells it that the spend empties
its inputs.

**R0 V6 (revision 5;** `docs/pool-v3-spec.md` §7.4, §9.4; R0 V6, ADR-0027: pending
implementation**).** No job carries an account, in any mode: the R0 V6 statement has no account
limbs, and the `r6` body has no salt and no signature. The full-calldata and free-withdrawal
rules above carry over. No login session, cookie or wallet credential reaches the server, and
job requests carry no session. The pre-checks still send each statement's root and nullifiers to
the server's node, so a self-hoster should use their own node for privacy, but an
operator-controlled node is no longer required.

**Transport privacy.** The server accepts every request, submissions and job polling alike,
over oblivious HTTP (OHTTP), with the same gateway layer the upstream transaction prover uses
(`tower_ohttp`): a client going through an OHTTP relay hides its address from the server, and the
relay sees no content. A client that submits over OHTTP must also poll over it, or the poll links
its address to the job (PS-13). The gateway's key configuration is served at `/ohttp-keys` and in
`/v1/info`. Upstream's gateway holds one key, so rotation replaces the key and restarts the server;
clients re-fetch the configuration (cached for an hour), and a client holding the old one gets a
decapsulation error and retries. Plain HTTPS remains available.

## 3. Architecture

```text
client ──POST /v1/jobs──► front end ──► pre-checks ──► queue ──► worker (child process)
                            │                                  ├─ virtual OS on live state
                            │                                  ├─ bounded large proof
client ◄─GET /v1/jobs/{id}──┘                                  └─ local verify, result
```

- **Front end** (tokio, axum): the API, rate limits, the queue, job state. It parses nothing
  expensive itself: pre-checks and jobs run in child processes (§4, §9 isolation).
- **`templar-prover`**: modes `serve`, `check JOB_DIR` (the pre-checks: the bridge executed with
  `scarb execute` on the pinned bridge build) and `info`.
- **`templar-prove`** (nightly toolchain): `prove JOB_DIR`, the large proof from a PIE, then
  local verification.
- **`templar-os-runner`** (the sequencer's toolchain): one mode, `run JOB_DIR`: builds the
  transaction, runs the virtual OS against the RPC endpoint and writes the PIE and the message.
  A separate binary because the sequencer and the proving stack pin different Rust toolchains
  (PS-11); the PIE file is the boundary.

## 4. Pre-checks (before any heavy work)

The pre-checks **execute the compiled Cairo bridge itself** (`verify_payment` / `verify_policy`
through the bridge package's standalone `main`, which also compares the decoded statement with
the submitted one), from the very bridge build the deployed statement account was compiled from.
Nothing the bridge would reject reaches proving and nothing it accepts is refused, by
construction (PS-1): the pre-check and the proven execution run the same Cairo. It costs about
2M Cairo steps, a few seconds, against minutes for the job. (A Rust port was the first plan;
the Cairo proof encoding has no inverse to a native proof, and executing the bridge is exact.)

Steps 1–4 are cheap and run in the front end with fallible parsing (no panics on malformed
input) and allocation bounded by the configured sizes; step 5 runs in a `check` child process
under a CPU-time and memory limit, never in the front end (PS-4). In order, cheapest first:

1. **Size and encoding.** The body is at most a configured size; the relation is `r4` or `p1`;
   the proof is a length-prefixed span of canonical felts no longer than the pinned proof size;
   the statement's fields are well-formed.
2. **Configuration match.** Chain and pool are the ones this server serves.
3. **Work deduplication** (PS-2). At most one job per input-0 nullifier may be queued, running
   or completed within the retention window (a failed job does not count, so a retry after a
   failure is allowed); a second submission for the same nullifier is refused, and repeated
   refusals for one nullifier back off. The key is input 0's nullifier for
   R4 (always a real note) and the policy note's for P1, so one note buys at most one proof per window however the dummy input, outputs or
   recipient are varied.
4. **Chain state** (RPC): the root is known to the pool and no nullifier is spent.
5. **The bridge**, in the `check` child process. Execute the relation's bridge on `(statement, proof)`: it deserializes the
   proof exactly (no trailing data), checks the pinned circuit hash, the proof shape baked into
   its verifier (FRI configuration, component sizes, output count) and the statement tag,
   decodes canonical limbs, applies every bridge rule (R4: the exit rule, both outputs, distinct
   nonzero nullifiers, recipient ⇔ amount, identity ⇒ intent, ranges; P1: its rules), verifies
   the circuit proof, and requires the decoded statement to equal the submitted one. Its output
   `[chain, pool, token, binding]` gives the binding used in §5.

The authoritative checks remain in the proven execution and the pool.

**Pool V3 (R0 V5; revision 4).** The admission order is account-bound spec §9's:

1. parse (the body adds `pool_call`, parsed strictly, and for bound spends `salt` and
   `signature`, removed by ADR-0027, phase B; an `r6` body has neither);
2. configuration (a bound spend needs an operator-controlled node: removed by ADR-0027, phase B);
3. payment: tickets verified and reserved, or the free full withdrawal's check, whose allowances
   are taken only when the job is queued. For `r6` the free check includes the job's
   proof-of-work stamp (§7) and routes the job to the free queue (R0 V6, ADR-0027: pending
   implementation);
4. deduplication and back-off;
5. expiry: `valid_until ≥ latest + (jobs ahead + 1) · blocks_per_job + 11 + relay margin`, with
   the queue counted per queue, and pool V3's `valid_until` rules;
6. chain state: root and nullifiers, the root still accepted at `send_deadline`, the verifier
   with no change due (`get_verifier('R0')`, `get_proposal('R0')`; for `r6`, the verifier and
   route checks below), an invoke's pool state (AB-SP7), and a bound account's class (removed by
   ADR-0027, phase B);
7. the bridge, and the pool call matched field by field to the bridge-checked statement;
8. the bound account's `is_valid_signature`, advisory, whose failure backs off the note (the
   first is free), never the account (removed by ADR-0027, phase B: `r6` admission has no
   step 8).

After phase B and until the swap, `r5` admission refuses a statement with `account ≠ 0` as a
client fault that consumes tickets (ADR-0027 phase B: pending implementation).

**Verifier and route checks (R0 V6;** `docs/pool-v3-spec.md` §9.2; R0 V6, ADR-0027: pending
implementation**).** At admission and again at job start, for the relation's kind (`'R0'` for
`r6`, `'P1'` for `p1`), the server also requires:

- `get_verifier(kind)` is a pinned adapter, with its pinned class, and `get_routes()` is a pinned
  state of its route set;
- the relation's route (keyed by the statement account in the relation's configuration, §8) is
  active and equal to its pin in all eight fields;
- no verifier change for that kind, and no change to its own route, is due (§8).

Ticket states: released on a refusal or a server-side failure before job start; consumed by a
bridge rejection or a calldata mismatch; spent, once synced, when the OS stage begins; kept spent
for the client's faults after that; refunded, blind, for the server's own. For `r6` they follow
the same causes without the signature-failure case, plus blind refunds when the service fails to
settle for a cause that is not the client's (a relayer refusal or late take-up, a deadline or
root margin the server admitted, a verifier or route change after admission;
`docs/pool-v3-spec.md` §7.2), and for bucket-check failures that are the server's fault (§5)
(R0 V6, ADR-0027: pending implementation).

## 5. The job

1. **Re-check** the root and nullifiers (the job may have queued for a while).
2. **Base block**: the latest block at job start (PS-3). The statement account reads nothing
   from the pool; the root is checked by the pool at settlement, against its 256-root history.
3. **Transaction.** An `INVOKE_V3` from the relation's pinned statement account, calldata = the
   client proof, zero tip and zero prices (the account's `__validate__` requires them), an L2-gas
   bound of 10^9 (as the bench), nonce read at the base block.
4. **Virtual OS.** The upstream runner (`starknet_transaction_prover::running::runner`,
   `RpcRunnerFactory::run_virtual_os`) against the configured RPC endpoint, with the chain id
   from configuration (not hard-coded). Its output crosses to the prover as a PIE file, keeping
   the runner and the prover in separate steps (PS-8). The single L2→L1 message must be from the
   statement account and equal `[statement class, account tag, chain, pool, binding]` for the
   binding recomputed from the statement.
5. **Large proof.** The bounded-memory prover, then local verification.
6. **Facts** (PS-9). Every field the adapter checks: `'PROOF2'`, `'VIRTUAL_SNOS'`, the pinned OS
   program, `'VIRTUAL_SNOS0'`, the base block and its hash as returned by the node, the message
   count 1, and the message hash `Poseidon(statement account, 0, 5, payload)`.
7. **Result.** `{proof (base64), proof_facts, base_block, submit_after, valid_until, binding,
   message_hash, timings}`, where `submit_after = base_block + 11` (the sequencer accepts only
   base blocks it can already hash) and `valid_until = base_block + max_proof_age` (the adapter's
   bound). Wallets submit in that window.

A failed job reports its stage; resubmission is safe.

**Pool V3 (R0 V5; revision 4).**

- **Job start** repeats the expiry rule at the base block (proving time included), the root at
  the deadline, the pool rules, and for a bound spend the account's class and signature (removed
  by ADR-0027, phase B). For `r6` it repeats the expiry, chain, verifier and route checks (§4) at
  the chosen base block (R0 V6, ADR-0027: pending implementation).
- **Transaction calldata** is `(proof_data, salt, signature)`, with a configurable L2 gas bound
  (default 450M) in place of 10^9. For `r6` the calldata is `(proof_data)`, and `os_l2_gas`
  (default 450M, sized from the bound `__execute__`) is measured again (R0 V6, ADR-0027: pending
  implementation).
- **Before proving,** the OS run's steps and named builtins must be within the configured caps
  (a violation is the client's fault). For `r6` the caps also cover Blake compressions, and all
  are measured again from a V6 virtual-OS run on live Sepolia state (ADR-0027 phase C); if the
  OS result does not report Blake, the prover binary checks it (R0 V6, ADR-0027: pending
  implementation).
- **The bucket check** (`docs/pool-v3-spec.md` §9.3; R0 V6, ADR-0027: pending implementation).
  Before proving, the server asserts that the job's component sizes fit the pinned PROOF2 leaf
  bucket, so that every spend has the same public PROOF2 header. This replaces the account-class
  allowlist and the padding.
  - **Fault** (PR2-12). A failure is the client's fault only when `proof_data` deviates from the
    pinned proof structure for the statement's shape; its tickets then stay spent. Otherwise it
    is the server's fault, and the tickets are refunded.
  - The server runs a reference job against the bucket at startup and after every route switch.
- **Result:** `send_deadline = min(statement.valid_until, base_block + max_proof_age)` in place
  of `valid_until`, and the `pool_call` the relayer settles. A failed job releases its note, which
  backs off, doubling per failure. For `r6`, `max_proof_age` is the route's (§8), and each result
  names its route key `statement` (the statement account's address, `docs/pool-v3-spec.md` §6.1),
  distinct from the job body's public statement (PR2-3; R0 V6, ADR-0027: pending
  implementation).

## 6. API

- `POST /v1/jobs` `{relation: "r4" | "p1", proof: [felt hex...], statement: {...}}` → `202
  {id, position}`, or `400 {error}` from a pre-check, or `429` from rate limiting.
- `GET /v1/jobs/{id}` → `{status: queued | running | done | failed, position?, stage?, result?,
  error?}`. Job ids are random 128-bit values; knowing one reveals only that job.
- `GET /v1/info` → network, chain, pool, relations with their circuit hashes, statement accounts,
  classes and tags, OS program, limits, and the server's version and dependency revisions.
- **Pool V3 (revision 4).** `POST /v1/jobs` also takes `{relation: "r5", proof, statement,
  pool_call: {entry_point, calldata}, salt?, signature?, payment?}`; `402` means payment is
  required or refused, and `403` that the account refused the signature or its class is not
  served, told apart by `reason: "signature" | "account_class"`. `GET /v1/jobs/{id}` adds `refund` (blind signatures on the job's refund requests).
  `DELETE /v1/jobs/{id}` acknowledges a finished job's result and deletes it. `/v1/info` adds the
  `r5` section (spend domain and type hashes, `E`, `Q`, `W`, `T`, bound mode and classes, caps),
  `payment` (issuer keys, costs, priced assets, free bounds) and `relay: {enabled}`. The `salt`
  and `signature` fields, both `403` reasons, and the bound fields in `/v1/info` are removed by
  ADR-0027, phase B.
- **R0 V6 (revision 5;** `docs/pool-v3-spec.md` §9.1, §9.5; R0 V6, ADR-0027: pending
  implementation**).** `POST /v1/jobs` takes `{relation: "r6", proof, statement, pool_call:
  {entry_point: "apply_spend" | "apply_spend_with_invoke", calldata}, payment?}`, where `payment`
  is `{tickets, refund_requests}` or `{free_full_withdrawal: {openings: [inner₀, inner₁],
  stamp}}`. There is no salt and no signature. Each job result names its route key `statement`
  (§5). `/v1/info` gains an `r6` section: the pool parameters (`E`, `Q`, `W`, `T`), the adapter,
  the server's route and the circuit hash. It has no spend-message hashes.
- **Relay handoff (P4b),** on the `[relay]` listener only, always with the bearer token:
  - `GET /relay/v1/jobs` → `{jobs: [{id, result, nullifiers, root, send_deadline}],
    relay_margin_blocks}`, earliest deadline first;
  - `POST /relay/v1/jobs/{id}/claim` (200 once, 409 if already claimed, 404 if gone), before
    sending;
  - `POST /relay/v1/jobs/{id}` with `{transaction_hash}` or `{refused}`.

  Each R0 V5 `apply_spend` result stays in the queue, apart from the client's copy, until the
  relayer answers or it can no longer be relayed. An unclaimed one is refused once its deadline is
  within `relay_margin_blocks`; a claimed one expires at its deadline. Invokes are refused at once.
  `GET /v1/jobs/{id}` shows the answer as `relay: {status: pending | submitted | refused |
  expired, …}`, kept past retention until the deadline.

  During the cutover the server relays both `r5` and `r6` results until apply. Each relay item
  carries its relation and its route key, and the relayer checks the verifier and route per item
  (`docs/pool-v3-spec.md` §7.3, §9.5; R0 V6, ADR-0027: pending implementation).

Results are kept for a configured time (default one hour), then deleted with their inputs.

## 7. Limits and abuse

- **Rate limits:** a token bucket per IPv4 address and per IPv6 /64, a cap on queued jobs per
  address, a global queue cap; per-nullifier deduplication and backoff (§4.3). OHTTP submissions
  arrive from the relay's address, so they get per-relay buckets sized for many clients, plus an
  optional small proof-of-work stamp per submission so one abuser behind a relay cannot exhaust
  its bucket for everyone (PS-13); per-nullifier deduplication applies regardless of transport.
- **Concurrency:** `max_concurrent_jobs`, each needing about 4 cores and 30 GiB; the default is
  one.
- **Time:** a per-stage timeout (OS run, proof).
- Allowlists (IP or domain) are a later addition.
- **Pool V3 (revision 4).** Caps on virtual-OS steps and builtins before proving; bound spends
  only for configured account classes, whose resources were measured (removed by ADR-0027, phase
  B). Free full withdrawals have their own queue, never count against the paid queue, and take at
  most a configured share of the prover's time; they are rate-limited globally, per address and
  per bound account (the per-account cap: removed by ADR-0027, phase B), debited only when the
  job is queued.
- **R0 V6 (revision 5;** `docs/pool-v3-spec.md` §7.5; R0 V6, ADR-0027: pending
  implementation**).** Caps also cover Blake compressions (§5). Every free job, over OHTTP or
  not, carries a proof-of-work stamp (PS-13) priced near the service's cost of one job, with
  difficulty rising as the free queue fills. The global bucket is sized to the relayer's gas
  budget, and the 25% prover-time share stays. Free exits are best-effort and can be exhausted by
  one party; paid exits and self-hosting are unaffected.

## 8. Configuration

One TOML file per deployment. At startup the server checks it against the chain and refuses to
start on a mismatch (PS-5): the chain id; each statement account's deployed class equals the
configured class; each adapter's configuration (pool, statement account and class, OS program,
account tag, maximum proof age, read from its storage or view) equals the server's. `/v1/info`
publishes that tuple, and wallets compare it with the adapter before using a result. Also at
startup (PS-12): the OS program hash embedded in `templar-os-runner` equals the configured one
and the adapters'. Before each job the pool's current verifier addresses (`get_verifier`,
`get_policy_verifier`) are re-read and must still be the configured adapters, since the pool's
owner can re-point them.

Per-relation proof-shape constants (FRI configuration, component log sizes, output count,
statement tag, tree format, circuit hash) are not typed into the config: they are read from the
trusted bridge build record (`build-record.json` and its manifest) that produced the deployed
statement account, pinned by its sha256 in the config (PS-12). The file holds: network name, chain id, RPC URL (v0.10 API, state reads for the
virtual OS), pool address; per relation the statement account, its class, account tag and pinned
circuit hash; the OS program hash; prover settings (bounded columns, threads, memory cap); limits;
result retention; listen address. `info` prints it with the dependency revisions.

**Pool V3 (revision 4).** `pool_version = 3` serves `r5` (and `p1`) and reads `E`, `Q`, `W`, `T`
at startup. New settings: `operator_node`, `bound_account_classes` and `bound_data_dir` (a tmpfs)
for bound spends; `pending_margin_secs`; `blocks_per_job`, `relay_margin_blocks`, `os_l2_gas`,
`bound_retention_secs`; `[caps]`; `[payment]` (issuer keys, refund key, costs, priced assets,
free bounds, `spent_dir`); `[relay]` (`listen`, and `token_file`, always required). A pending verifier change at startup is a warning; jobs are refused while it is due.
`operator_node`, `bound_account_classes`, `bound_data_dir` and `bound_retention_secs` are removed
by ADR-0027, phase B, and `prover.example.toml` is updated.

**R0 V6 (revision 5;** `docs/pool-v3-spec.md` §9.5; R0 V6, ADR-0027: pending
implementation**).** `r6` and `p1` are each served through a routing adapter
(pool-v3-spec §6).

- **Per-route proof ages.** Each relation's configuration names its route: the statement
  account (the route key), its class, account tag, OS program, proof version, variant, output
  version and `max_proof_age` (pool-v3-spec §6.1). `max_proof_age` moves from the network section
  to each relation's route. The startup check compares each route, read through the adapter's
  views (`get_pool`, `get_kind`, `get_routes`, `get_route`) instead of its storage.
  `pending_margin_secs` defaults to the largest age served times 6 seconds.
- **Pending changes.** The server refuses a relation's jobs from `pending_margin_secs` before
  `eta` until `eta + T`, unless the change is applied, cancelled or lapsed, when either of these
  is due:
  - an R0 verifier change;
  - a change to the server's own route: the route keyed by the statement in the relation's
    configuration.

  A pending route addition under a new key does not stop the server. The same rules apply to
  `p1`, keyed on `'P1'` (PR2-1). Pending route changes are read from `get_route_proposals()`.
- **The config hash** (`facts[6]`) stays pinned. If an OS rotation changes it, it moves into that
  route's pin.
- **Dual-version operation, for the cutover only.**
  - The server starts with both `r5` and `r6` configured, and treats whichever is not the pool's
    current R0 verifier as dormant, not fatal. It switches on `get_verifier('R0')`, without a
    restart, when the swap applies.
  - For `p1`, no new relation version is needed, only an adapter switch. The old P1 adapter and
    the P1 routing adapter are both configured, and `get_verifier('P1')` selects one. The one not
    selected is dormant, not fatal at startup.
  - The release after apply removes the `r5` pins and the old P1 adapter.

## 9. Build and distribution

- Rust (`nightly-2026-01-15`, as the rest of the stack). `Cargo.lock` is committed and every
  build uses `--locked`; CI checks that every pinned revision can still be fetched (PS-8).
  Pinned dependencies:
  - for `templar-os-runner` only: `starknet_transaction_prover` at sequencer revision `e6b6fd2e…`
    (the revision whose virtual OS the adapters pin). Its runner module is public, but the
    runner's constructors are `pub(crate)` and the only public entry point continues into the
    crate's own small-proof prover (PS-11). The runner therefore builds from **the pinned fork
    `broody/sequencer`, branch `templar/runner-visibility`, commit `625929a`**: `e6b6fd2e…` plus
    one commit making `RpcRunnerFactory::new` public (`VirtualSnosRunner::run_virtual_os` and
    `RunnerOutput` are already public). The change is drafted for upstream; if accepted, the pin
    moves to the upstream revision and the fork is dropped. It builds with the sequencer's pinned toolchain;
  - `broody/proving` `templar/bounded-server` (`b54ed94f8`, public) for the bounded large-proof
    prover;
  - the bridge builds (`build-record.json`, the compiled executable) of the deployed statement
    accounts, pinned by sha256, and `scarb` 2.18.0 to execute them.
- `target-cpu=native` gives about 1.7× faster proofs but ties a binary to its CPU. The Docker
  image builds for a stated baseline (x86-64-v3) by default, with a build argument for native.
- Docker: multi-stage build, a non-root runtime user, read-only root filesystem, dropped
  capabilities, the config mounted read-only, a volume for job directories with a size quota.
- **Isolation** (PS-6, PS-14): each pre-check, OS run and proof runs in its own cgroup v2 group
  (memory, CPU, PIDs), and a timed-out or failed step's whole group is killed. The server needs a
  writable, delegated cgroup v2 subtree: outside containers, the systemd user manager's
  delegation; in Docker, `--cgroupns=private` with a delegated subtree (the shipped compose
  file and a startup self-test). **It refuses to start without one** rather than fall back to a
  shared limit. `prove` and `check` run in a fresh network namespace with no interfaces
  (`unshare --net`, or the equivalent seccomp and namespace setup in the image); only
  `templar-os-runner` reaches the RPC endpoint. The front end reserves memory outside the jobs'
  groups.
- The server links no client-prover code: it executes the compiled bridges. (The bridge sources
  vendor the Cairo verifier of the non-public client-proof branch; publishing the server means
  publishing the compiled bridge builds, which are already deployed on chain as the statement
  accounts.)

## 10. Operation

Hardware per concurrent job: 4 cores, 32 GiB RAM; an RPC node serving the v0.10 API with state
reads (a local node is recommended: the virtual OS makes many reads). Operators should read §2.

**Logging and retention** (PS-10): job ids, stages, timings and failure codes are logged; client
addresses, nullifiers and statements are not, by default. The in-memory address-to-job map used
for rate limiting holds only counters and expires with the window. Worker and runner logs go to
the job directory and are deleted with it at the end of retention. A reverse proxy in front of
the server must be configured not to keep access logs with client addresses; the Docker
compose example ships that way.

**Pool V3 (revision 4).** Logs never contain a bound account, salt or signature. Bound job
directories live on a tmpfs and are deleted when proving ends; swap is off or encrypted; results
go on acknowledgement or after `bound_retention_secs`. The free-withdrawal counter keys bound
accounts by a keyed hash. (These bound data rules are removed by ADR-0027, phase B: with no
tmpfs requirement, no memory-only retention for bound jobs and no operator-controlled node, jobs
follow the ordinary retention of §6; `docs/pool-v3-spec.md` §9.4.) The spent-ticket logs are kept
on their own volume and never deleted in P4.

## 11. Tests

- Pre-checks: every bench proof, honest and forged, gets the bridge validator's verdict; plus
  malformed encodings (non-canonical felts in delivery, intent and chain, trailing data, wrong
  proof shape, another circuit) are refused without reaching the bridge where the front end can
  tell, and by the bridge otherwise.
- Deduplication: resubmitting one note's spend with varied dummies and outputs is refused.
- Startup: each configuration mismatch (chain, class, adapter field) refuses to start.
- The worker on a recorded Sepolia job: the same message and facts as the bench flow.
- The Sepolia flow calls the server instead of the bench tools.

## 12. Review questions

- **S1.** Are the pre-checks (§4) equivalent to the Cairo bridges, so that nothing the bridge
  rejects is admitted to proving, and nothing it accepts is refused?
- **S2.** Anything in the API, job handling or logging that reveals more than §2 says?
- **S3.** Abuse: can a submitter make the server do expensive work cheaply (pre-check cost,
  queue flooding, a statement that passes pre-checks but fails the OS run)?
- **S4.** Is running the worker in a child process under a cgroup cap enough isolation, given
  the input is untrusted?

## 13. Review resolutions

| Finding | Resolution |
| --- | --- |
| PS-1 | §4: the pre-check executes the compiled bridge itself, so it is equivalent by construction (exact Serde, pinned circuit, shape, tag, canonical limbs, every rule) |
| PS-2 | §4.3 per-nullifier deduplication and backoff; §7 IPv6 /64 buckets |
| PS-3 | §5: base block at job start, re-check before proving, `submit_after` and `valid_until` |
| PS-4 | §4: pre-checks in a limited child process; fallible parsing; bounded allocation |
| PS-5 | §8: startup checks against chain, classes and adapter storage; `/v1/info` tuple; wallets compare |
| PS-6 | §9: a cgroup per job and pre-check, whole-group kill, no network while proving, container hardening |
| PS-7 | §2 corrected: cannot submit; learns exit effects early (front-running risk) and can link jobs |
| PS-8 | §9: the runner is a public module at the pinned revision; lockfile, `--locked`, fetchability check; PIE boundary (§5) |
| PS-9 | §5: L2-gas bound 10^9; every adapter-checked fact field |
| PS-10 | §10: logging and retention rules, proxy guidance |
| PS-11 | §3, §9: the OS run is a separate binary on the sequencer's toolchain, built from a pinned fork with one recorded visibility commit; the PIE is the boundary |
| PS-12 | §8: shape constants from the trusted build record; startup OS-program check; verifier addresses re-read per job; §3 and §9 aligned |
| PS-13 | §2, §7: polling over OHTTP, per-relay buckets with an optional proof-of-work stamp, key publication and rotation |
| PS-14 | §9: delegated cgroup v2 required (refuse to start otherwise), Docker recipe and self-test, network namespace for proving |
