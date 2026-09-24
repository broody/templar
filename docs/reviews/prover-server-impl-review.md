# Prover server: implementation review

Independent reviewer. I did not write the implementation. I also wrote the design review and
its re-review (`prover-server-design-review.md`).

Date 2026-09-24, branch `feat/hidden-assets` at `9957583`. The review is against
`docs/prover-server-spec.md` as updated in that commit: revision 3, plus the §4 change under which
the pre-check executes the compiled bridge. I modified no code or docs, only this new file.

**Evidence labels:**
- **D**: demonstrated by a command I ran.
- **R**: reasoned from the code.

## Scope

**Code:**
- `server/prover/src/`: `main.rs`, `api.rs`, `pipeline.rs`, `sandbox.rs`, `statement.rs`,
  `rpc.rs`, `config.rs`;
- `server/os-runner/src/main.rs`;
- `server/prove/src/main.rs`;
- `server/deploy/`: `Dockerfile`, `entrypoint.sh`, `templar-prover.service`,
  `prover.example.toml`;
- `server/README.md`.

**Compared against:**
- the bridges' executable `main` signatures (`cairo-r4/bridge/src/lib.cairo:189-220`,
  `cairo-p1/bridge/src/lib.cairo:26-48, 192-197`);
- `bench/m31-pool/cairo/src/adapter.cairo`;
- the pinned upstream: the fork diff `e6b6fd2e..625929a` in the cargo git database is exactly one
  line, making `RpcRunnerFactory::new` public (**D**); and `apollo_starknet_os_program`'s
  `PROGRAM_HASHES`, which is read from a checked-in `program_hash.json`, not computed.

**What I ran** (scratch output under `~/.local/share/templar/runs/pi-review`; I did not start
`serve`, submit jobs or build Docker):
- `cargo build --release --locked` of `templar-prover` into the scratch directory: clean.
- `templar-prover info` against `~/.local/share/templar/runs/prover-server/sepolia.toml`: every
  startup check passes, and the published tuple matches the configuration (**D**).
- `templar-prover check` on the six saved submissions:
  - `sub-s1` (R4) accepted: 2,026,613 steps, 1.85 s;
  - `sub-s3` (P1) accepted: 2,063,735 steps, 1.97 s;
  - both `*-badproof` rejected (`Merkle Verification Error`);
  - `sub-s1-tampered` rejected (`context`) and `sub-s3-tampered` rejected (`statement`) (**D**).
- `check` on ten malformed variants of `sub-s1`. Each was refused with an error and no panic
  (**D**). The front end refused these:
  - bad hex in the proof;
  - a delivery `= p` (not canonical);
  - an identity word `2^31`;
  - a JSON withdrawal of `2^70`;
  - no nullifiers;
  - the wrong relation;
  - an unknown root (by the RPC check).

  The bridge refused these:
  - a delivery `= p − 1` (`deliveries`);
  - an empty span (`INVALID_PROOF_ENCODING`);
  - trailing data (`trailing proof data`).

The crates contain no tests to run (`grep '#[test]'` finds nothing; see PI-7).

## Verdict

**CONDITIONAL GO.** The implementation does what the spec asks. Private, operator-supervised use
is fine now. Fix **PI-1 to PI-5** before exposing the server publicly.

**What works:**
- **The pipeline is correct end to end.** It uses the base block at job start, re-checks the
  chain before the job, builds the transaction as the bench did (tip 0, prices 0, L2 bound
  `10^9`), pins the message and its sender, checks the facts against the adapter and returns the
  submission window.
- **The bridge arguments match both Cairo `main` signatures field for field.**
- **The pre-check is exact.** Executing the compiled bridge makes it equivalent by construction
  (PS-1), and the malformed-input run shows the front end never panics on input.
- **The startup checks work**, including the per-job verifier re-read (PS-12).
- **The sandbox works.** It uses a per-step cgroup, kills the whole group on timeout and
  self-tests the no-network namespace, refusing to start without it.

**What to fix:**
- **PI-1:** a lock-order deadlock can hang the front end permanently.
- **PI-2:** a client that disconnects during the pre-check leaks its cgroup and job directory and
  orphans the bridge process, which bypasses the pre-check limit.
- **PI-3:** honest withdrawals of `2^64` or more are refused.
- **PI-4:** `X-Forwarded-For` is read from the client-controlled end.
- **PI-5:** the systemd unit runs as root, and the container keeps `CAP_SYS_ADMIN` without an
  init process.

## Conformance to the design findings

| ID | Status | Note |
|---|---|---|
| PS-1 | Resolved | The bridge is executed (`pipeline.rs:32-76`). **D**: honest inputs accepted, tampered and non-canonical rejected. The pinned artifact is not the executed one: see PI-6. |
| PS-2 | Resolved, with gaps | Deduplication on input 0's nullifier (R4) or the note's (P1), with backoff (`api.rs:165-181, 203-209`); /64 buckets. Gaps: PI-2 and PI-4. |
| PS-3 | Resolved | `pipeline.rs:111-117`; `submit_after` and `valid_until` in the result (`:195`). |
| PS-4 | Resolved, with one gap | Fallible, bounded front-end parsing (**D**); the bridge runs in a limited child. Gap: PI-3. |
| PS-5, PS-12(3) | Resolved | `main.rs:27-76`; `verifier_unchanged` per job (`pipeline.rs:113`). **D** `info`. |
| PS-6, PS-14 | Resolved in the sandbox | Cgroup per step, `cgroup.kill` on timeout, the no-network self-test refuses to start (`sandbox.rs:154-179`). Gaps: PI-2, PI-5, PI-9 and PI-10. |
| PS-8, PS-11 | Resolved | Fork `625929a` with a one-line diff (**D**); lockfiles; separate binaries per toolchain. There is no CI fetchability check yet (PI-11). |
| PS-9 | Resolved | `pipeline.rs:173-188`: length 9, OS program, `VIRTUAL_SNOS0`, base block, base hash, count 1 and message hash, exactly the adapter's checks (`adapter.cairo:59-73`); plus the message's sender and payload (`:150-157`). |
| PS-10 | Resolved, with one gap | Logs carry only job id, stage and "admitted/done/failed" (`api.rs:220, 291, 298`); no addresses or nullifiers; step logs live in the job directory. Gap: PI-8 (files survive a restart). |
| PS-12(2) | Partial | The OS-program check compares a recorded constant, not the compiled program (PI-6). |
| PS-13 | Not implemented | OHTTP is known to be missing (PI-11). |

## Findings

### PI-1: High. Lock-order inversion deadlocks the front end

**Location:** `server/prover/src/api.rs`:
- `submit` takes `refusals` then `dedup` (:168, :174), and `dedup` then `jobs` (:204, :210);
- `work` takes `jobs` then `dedup` (:282, :297);
- `sweep` takes `jobs` then `dedup` then `refusals`, holding all three (:307, :314, :323).

**Problem.** These are three `std::sync::Mutex`es taken in inconsistent orders:
- `dedup → jobs` in `submit`, against `jobs → dedup` in `work` and `sweep`;
- `refusals → dedup` in `submit`, against `dedup → refusals` in `sweep`.

They are blocking mutexes held on tokio worker threads.

**Failure scenario (R).**
1. The 60-second sweep holds `jobs` and waits for `dedup`.
2. At the same moment, an admission holds `dedup` (:204) and waits for `jobs` (:210).
3. Both block forever. Every later request that touches `jobs` (`status`, `submit`, `work`)
   blocks a worker thread too.
4. The process stays alive, so `Restart=on-failure` never fires, and the server hangs silently.

A failing job (:282 → :297) racing an admission deadlocks the same way. Each window is short,
but the sweep runs every minute for the life of the process.

**Required change.**
- Use one `Mutex<State>` for jobs, order, dedup and refusals, or fix a global lock order and take
  locks only in it.
- Never hold one of these locks while acquiring another in the opposite order.
- Add a concurrency test: many submissions while `sweep` and `work` failures run.

### PI-2: Medium. A client that disconnects during the pre-check leaks and orphans work

**Location:** `api.rs:186-202`; `sandbox.rs:69, 85-98`; `entrypoint.sh:49` (the server as PID 1).

**Problem.** The pre-check runs inside the request future. If the client disconnects, axum drops
the future mid-`await`:
- `kill_on_drop` sends SIGKILL to the direct child only. That is `scarb`, because `unshare` execs
  it.
- `scarb execute` runs the separate `scarb-execute` binary (present in the scarb 2.18.0
  install), which survives, orphaned.
- `remove()`, which writes `cgroup.kill` and removes the directory, never runs.
- The semaphore permit is released.
- The job directory (`bridge-args.json` with the statement, and `scarb-cache`) is never deleted.
  It is not in `jobs`, so the sweep never finds it.

**Failure scenario.** An attacker submits valid-looking bodies and disconnects immediately. Each
one leaves a bridge execution running outside the two-permit limit, bounded only by its own
4 GiB group, plus a permanent cgroup directory and job directory. Under Docker, the orphans are
reparented to the server, which is PID 1 and never reaps them, so zombies pile up toward
`pids.max`. Statement files also outlive the retention promise of §10.

**Required change.**
- Run the pre-check in a spawned task that owns the group and the directory, with a guard that
  always kills the group and removes both, even if the request is cancelled.
- Kill the cgroup, not the pid, on drop.
- In Docker, run under an init (`docker run --init`, or `tini` in the entrypoint).

### PI-3: Medium. Withdrawals of 2^64 or more are refused

**Location:** `statement.rs:63-74`.

**Problem.** The wallet's `public.json` serializes `withdrawal_amount` (and P1's `x`) as a JSON
**number**, because it is a Rust `u128` through serde. The server parses the body into
`serde_json::Value` without `arbitrary_precision`, so a number above `u64::MAX` becomes an
`f64`, and `n.as_u64()` fails. **D**: a withdrawal of `2^70` is refused with
`statement.withdrawal_amount: integer`.

**Failure scenario.** A user withdraws 20 units of an 18-decimal token, which is `2×10^19`, above
`2^64`. The server refuses the honest submission. This is a liveness failure for any large exit,
policy payout or split `x`.

**Required change.**
- Enable `serde_json`'s `arbitrary_precision`, or deserialize the statement into typed structs
  with `u128` fields.
- Or accept decimal strings, and have the wallets emit them.
- Add a test with an amount of `2^100`.

### PI-4: Medium. The client address comes from the client-controlled end of `X-Forwarded-For`, and IPv4-mapped addresses share one bucket

**Location:** `api.rs:83-105`.

**Problem.**
- **(a)** With `trust_forwarded_for = true`, the key is the **leftmost** `X-Forwarded-For`
  entry. Proxies append the peer they saw, so the leftmost entry is whatever the client sent.
  Every request can then claim a new address, which defeats per-address buckets and queue caps.
  Only per-nullifier deduplication remains, and the `buckets` map grows by one entry per forged
  address per hour.
- **(b)** On a dual-stack listener (`[::]`), IPv4 clients arrive as `::ffff:a.b.c.d`. Their /64
  key is `0:0:0:0::/64`, so all IPv4 clients share one bucket, and one client can exhaust it for
  everyone.

**Required change.**
- Take the rightmost entry, or the entry at a configured number of trusted hops.
- Normalize IPv4-mapped addresses with `to_ipv4_mapped()` before computing the key.

### PI-5: Medium. Privilege handling in the deployment files

**Location:** `deploy/templar-prover.service:8-29`; `deploy/entrypoint.sh`; `README.md:71-80`.

**Problem.**
- **(a) The unit runs as root.** It has no `User=`/`DynamicUser=`, so as a system unit (which the
  comment allows) the network-facing server, and every step it starts, runs as root.
  `Delegate=yes` works for a non-root `User=` as well.
- **(b) The container keeps `CAP_SYS_ADMIN`.** The entrypoint needs it only to remount and hand
  over the cgroup filesystem, and it drops every capability for the server (good). But the
  capability stays in the container's bounding set for its lifetime: anything started with
  `docker exec` gets it. It also relaxes Docker's default seccomp and AppArmor profiles for the
  container.
- **(c) The documented `docker run` lacks the promised hardening.** Spec §9 says "read-only root
  filesystem, dropped capabilities". The command has no `--read-only`, no `--cap-drop ALL` (with
  `--cap-add SYS_ADMIN`), no `--security-opt no-new-privileges` and no `--init` (PI-2).
- **(d) PID 1 has no signal handling.** The server runs as PID 1 and installs no signal handlers
  (`main.rs`), so `docker stop` waits for its timeout and then kills it.

**Required change.**
- Add `User=templar` (or `DynamicUser=yes` with `StateDirectory=`) and
  `CapabilityBoundingSet=` to the unit.
- Document the Docker command with `--init --read-only --tmpfs /tmp --cap-drop ALL --cap-add
  SYS_ADMIN --security-opt no-new-privileges`. Better, do the cgroup handover with a privileged
  one-shot init container, or systemd in the container, so that the serving container needs no
  added capability.
- Handle SIGTERM: stop admitting, kill the job groups and exit.

### PI-6: Low. The pinned artifacts are not the executed ones

**Location:** `main.rs:54-62, 73-76`; `os-runner/src/main.rs:27-33`.

**Problem.**
- **(a) The executable is not pinned.** The server pins the sha256 of `build-record.json` only.
  That record lists template and vendor hashes, but not the compiled
  `target/dev/templar_membership_bridge.executable.json` that `scarb execute --no-build` runs,
  nor the generated `pinned.cairo`. A rebuilt or modified executable in `bridge_dir` passes the
  startup check.
- **(b) The OS-program check reads a constant.** `templar-os-runner version` reports
  `PROGRAM_HASHES.virtual_os`, which is read from the checked-in `program_hash.json`. The OS
  actually run is `VIRTUAL_OS_PROGRAM_BYTES`, compiled at build time by whatever `cairo-lang` was
  on `PATH`. The Dockerfile's `pip install cairo-lang==0.14.3a3` has no hash pinning.

Neither can harm users. A wrong executable or program only wastes work or refuses honest proofs,
because the adapter checks `facts[2]` and the deployed class is what the pool trusts. But
"equivalent by construction" (PS-1) and the startup OS check (PS-12) both rest on these
artifacts.

**Required change.**
- Pin the executable's sha256 (and ideally the account's `contract_class.json` from the same
  build, whose class hash must equal `statement_class`).
- Compute the virtual OS program hash from `VIRTUAL_OS_PROGRAM` in `version`.
- Pin the scarb tarball and the `cairo-lang` wheel by hash in the Dockerfile.

### PI-7: Medium. None of the spec's §11 tests exist

**Location:** `server/`, where there are no `#[test]`s and no `tests/` directory.

**Problem.** §11 requires:
- a pre-check corpus: honest, forged and malformed inputs;
- deduplication with varied dummies;
- a startup refusal for each mismatch.

None is implemented. The README's end-to-end run was manual. PI-1, PI-3 and PI-4 are exactly the
kinds of bugs these tests, plus a concurrency test, would catch.

**Required change.**
- Add `prover/tests/`:
  - `Submission::parse` on the bench `public.json`s, including `u128` amounts and the malformed
    cases above;
  - `check` against the saved honest, bad-proof and tampered submissions, gated on the bridge
    builds;
  - admission and deduplication using a mocked `check` and RPC;
  - `sweep`, `work` and `submit` concurrency;
  - startup against a stub RPC returning each mismatch.
- Run them in CI.

### PI-8: Low. Cleanup gaps

**Location:** `api.rs:216-218, 303-325`; `sandbox.rs:47-55`; `main.rs:106-109`.

- **(a) A failed queue send leaves a job behind.** If `queue.try_send` fails after the job has
  been inserted, the client gets 503. But the job stays `Queued`, holds the note's
  deduplication key for up to 4× retention, and keeps its directory.
- **(b) Nothing is recovered or purged at startup.** Job directories, `check-*` directories and
  leftover cgroups from before a restart are never removed, so statement files outlive
  retention.
- **(c) `remove()` blocks a worker thread.** It sleeps with `std::thread::sleep` for up to 5 s
  on a tokio worker thread.
- **(d) CLI checks collide.** The `check` CLI uses the fixed group name `check-cli`, so two
  concurrent CLI checks collide. With `cgroup_root = "self"`, the CLI (which does not call
  `prepare_root`) fails.

**Required change.**
- Roll back on send failure: remove the job and its deduplication entry and delete its directory.
- Purge `data_dir` and stale child groups at startup.
- Use `spawn_blocking` or an async sleep in `remove()`.
- Give the CLI a unique group name and resolve `"self"`.

### PI-9: Low. Steps share the server's user and filesystem view

**Location:** `sandbox.rs:58-99`; `pipeline.rs:141, 172, 189`.

**Problem.** Every step runs as the server's user, with the server's filesystem. A step that
processes untrusted input could read or modify other jobs' directories: the OS run executes
attacker calldata in the Cairo VM, and the prover consumes the resulting PIE. The front end then
trusts `proof.bin`, `output-preimage.json` and `os-result.json` from the job directory. Exploiting
the Cairo VM or the prover from calldata is far-fetched, and a corrupted proof is rejected by the
sequencer. Still, the spec's isolation argument (PS-6) is about resources only.

**Required change (optional).** Run each step in a mount namespace with only its job directory
writable: `unshare --mount` plus bind mounts, or a systemd-run property set. Or document that
filesystem isolation between jobs is not provided.

### PI-10: Low. The front end's memory is not reserved

**Location:** `sandbox.rs:132-150`; `templar-prover.service:15`; README `--memory 40g`.

**Problem.** Job groups get `memory.max` (32 GiB), and there are two checks at 4 GiB each, inside
a 40 GiB parent. The server's own `server` leaf has no `memory.min`/`memory.low` and no
`oom_score_adj`. At the parent limit, the parent's OOM killer may pick the front end. Spec §9
says "the front end reserves memory outside the jobs' groups".

**Required change.** Set `memory.min` on the `server` leaf (for example 1 GiB) and
`memory.oom.group=1` on step groups. Size the parent as the job limit plus the check limits plus
the reserve.

### PI-11: Info. Missing or deferred items

- **OHTTP (spec §2, PS-13) is not implemented**, together with its per-relay buckets and optional
  proof-of-work (§7). This is known.
- **There is no CI job checking that pinned revisions can be fetched (PS-8).**
- **The chain-state checks run before the bridge**, on unverified statements. Each admitted
  request can cost up to three RPC calls before the proof is checked. That is bounded by the
  buckets and harmless with a local node. Moving them after the bridge would cost about 2 s of
  CPU per request instead; the current order is a reasonable choice.
- **The check semaphore is hard-coded to 2** (`api.rs:241`), and waiting requests queue without
  bound behind it. Make it configurable, and use `try_acquire` with 503 when saturated.
- **The pre-exec hook is sound.** It uses only `open`, `write` and `close`, on a `CString`
  allocated before `fork`; `last_os_error` does not allocate. It joins the group before `exec`,
  so `unshare` and everything below it are accounted for.
- **The bridge argument encoding matches both `main`s:**
  - R4: spans for root, nullifiers (18), commitments (18), deliveries (2) and identity.
  - P1: `Statement` Serde, where `[Span<u32>; 2]` and `[felt252; 2]` carry no outer length
    prefix; `u64` deadline and `not_before`; `u32` index and kind.
  - Both followed by the proof span.
  - **D**: s1 and s3 are accepted with the bench's bindings.

## Answers to the requested focus points

- **Admission ordering and races.**
  - The deduplication check-then-insert is correct: re-checked under the lock before insert
    (`api.rs:204-209`).
  - The semaphore bounds concurrent checks only while clients stay connected (PI-2).
  - Lock ordering is broken (PI-1).
- **Panics on untrusted input.** None found, and the malformed corpus shows none (**D**). The
  remaining `unwrap`s are on internal invariants or mutex poisoning.
- **Argument encoding.** It matches both bridges (PI-11).
- **Facts.** The checks match `adapter.cairo`, plus the sender and payload (PS-9).
- **Timeouts and cleanup.** Correct on timeout and failure; gaps on request cancellation (PI-2),
  restart and queue-send failure (PI-8).
- **`pre_exec`.** Sound (PI-11).
- **The Docker entrypoint.** Drops everything correctly for the server, but the container keeps
  `SYS_ADMIN` and has no init (PI-5, PI-2).
- **Logging.** Clean (PS-10). Addresses and nullifiers stay out of logs, but statements can
  persist on disk (PI-2, PI-8).
- **Missing against the spec.** OHTTP and its limits, the §11 tests (PI-7), the front-end memory
  reservation (PI-10) and the fetchability CI check.
