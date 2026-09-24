# Templar prover server

Status: **design, revision 3, after the design review and its re-review (`docs/reviews/prover-server-design-review.md`, CONDITIONAL GO; findings `PS-*` cited where they changed the text). Nothing is implemented.** A runnable wrapping server for the
compact client-proof path, replacing the research scripts under `bench/` for serving proofs.

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

**Transport privacy.** The server accepts every request, submissions and job polling alike,
over oblivious HTTP (OHTTP), with the same gateway layer the upstream transaction prover uses
(`tower_ohttp`): a client going through an OHTTP relay hides its address from the server, and the
relay sees no content. A client that submits over OHTTP must also poll over it, or the poll links
its address to the job (PS-13). The gateway's key configuration is served at a fixed path and in
`/v1/info`, rotated on a schedule with the previous key accepted for one rotation period. Plain
HTTPS remains available.

## 3. Architecture

```text
client ──POST /v1/jobs──► front end ──► pre-checks ──► queue ──► worker (child process)
                            │                                  ├─ virtual OS on live state
                            │                                  ├─ bounded large proof
client ◄─GET /v1/jobs/{id}──┘                                  └─ local verify, result
```

- **Front end** (tokio, axum): the API, rate limits, the queue, job state. It parses nothing
  expensive itself: pre-checks and jobs run in child processes (§4, §9 isolation).
- **`templar-prover`** (nightly toolchain): modes `serve`, `check PROOF_DIR` (the pre-checks),
  `prove JOB_DIR` (the large proof from a PIE, then local verification) and `info`.
- **`templar-os-runner`** (the sequencer's toolchain): one mode, `run JOB_DIR`: builds the
  transaction, runs the virtual OS against the RPC endpoint and writes the PIE and the message.
  A separate binary because the sequencer and the proving stack pin different Rust toolchains
  (PS-11); the PIE file is the boundary.

## 4. Pre-checks (before any heavy work)

The pre-checks are a **Rust port of the Cairo bridges** (`verify_payment`, `verify_policy`),
built from the same trusted manifest constants, so that nothing the bridge would reject reaches
proving and nothing it accepts is refused (PS-1). A differential test runs every bench proof,
honest and forged, through both and requires identical accept/reject results.

They run in a `check` child process under a CPU-time and memory limit, never in the front end
(PS-4). Parsing is fallible throughout (no panics on malformed input), and allocation is bounded
by the pinned proof shape. In order, cheapest first:

1. **Size and encoding.** The body is at most a configured size; the relation is `r4` or `p1`;
   the proof is a length-prefixed span of canonical felts that deserializes exactly (Cairo Serde)
   to one client proof with no trailing data.
2. **Pinned proof shape.** The proof's FRI configuration, component log sizes and output count
   equal the relation's manifest; its preprocessed commitment gives the pinned circuit hash
   (never one taken from the proof).
3. **Verification.** The circuit proof verifies, and its outputs decode to the statement:
   the statement tag and tree format pinned for the relation; 28-bit limbs forming **canonical**
   felts (below the field prime, as the bridge's `felt_from_limbs`); 16-bit amount limbs; the
   padding limb zero. The decoded statement must equal the submitted one field for field.
4. **Bridge rules.** R4: the exit rule, both commitments and deliveries nonzero, nonzero distinct
   nullifiers, recipient ⇔ amount, identity ⇒ intent, addresses and the asset below 2^251, chain
   and pool nonzero. P1: the P1 bridge's rules, ported the same way.
5. **Configuration match.** Chain and pool are the ones this server serves.
6. **Work deduplication** (PS-2). At most one job per input-0 nullifier may be queued, running
   or completed within the retention window (a failed job does not count, so a retry after a
   failure is allowed); a second submission for the same nullifier is refused, and repeated
   refusals for one nullifier back off. A nullifier is input 0's (always a
   real note), so one note buys at most one proof per window however the dummy input, outputs or
   recipient are varied.
7. **Chain state** (RPC): the root is known to the pool and neither nullifier is spent.

The authoritative checks remain in the proven execution and the pool.

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

## 6. API

- `POST /v1/jobs` `{relation: "r4" | "p1", proof: [felt hex...], statement: {...}}` → `202
  {id, position}`, or `400 {error}` from a pre-check, or `429` from rate limiting.
- `GET /v1/jobs/{id}` → `{status: queued | running | done | failed, position?, stage?, result?,
  error?}`. Job ids are random 128-bit values; knowing one reveals only that job.
- `GET /v1/info` → network, chain, pool, relations with their circuit hashes, statement accounts,
  classes and tags, OS program, limits, and the server's version and dependency revisions.

Results are kept for a configured time (default one hour), then deleted with their inputs.

## 7. Limits and abuse

- **Rate limits:** a token bucket per IPv4 address and per IPv6 /64, a cap on queued jobs per
  address, a global queue cap; per-nullifier deduplication and backoff (§4.6). OHTTP submissions
  arrive from the relay's address, so they get per-relay buckets sized for many clients, plus an
  optional small proof-of-work stamp per submission so one abuser behind a relay cannot exhaust
  its bucket for everyone (PS-13); per-nullifier deduplication applies regardless of transport.
- **Concurrency:** `max_concurrent_jobs`, each needing about 4 cores and 30 GiB; the default is
  one.
- **Time:** a per-stage timeout (OS run, proof).
- Allowlists (IP or domain) are a later addition.

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

## 9. Build and distribution

- Rust (`nightly-2026-01-15`, as the rest of the stack). `Cargo.lock` is committed and every
  build uses `--locked`; CI checks that every pinned revision can still be fetched (PS-8).
  Pinned dependencies:
  - for `templar-os-runner` only: `starknet_transaction_prover` at sequencer revision `e6b6fd2e…`
    (the revision whose virtual OS the adapters pin). Its runner module is public, but the
    runner's constructors are `pub(crate)` and the only public entry point continues into the
    crate's own small-proof prover (PS-11). The runner therefore builds from **a pinned fork
    `broody/sequencer`** at `e6b6fd2e…` plus one recorded commit making `RpcRunnerFactory::new`
    public (`VirtualSnosRunner::run_virtual_os` is already public); the change is also offered
    upstream. It builds with the sequencer's pinned toolchain;
  - `broody/proving` `templar/bounded-server` (`b54ed94f8`, public) for the bounded large-proof
    prover;
  - `client-port` (path) for the relations' statement layouts, `bridge_checks` and the circuit
    verifier's pinned-hash checks.
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
- Release blocker: the client-port crate currently builds against a non-public proving branch.
  Before the server is published, the parts it needs (the verifier side) must be available
  publicly; this does not block private use.

## 10. Operation

Hardware per concurrent job: 4 cores, 32 GiB RAM; an RPC node serving the v0.10 API with state
reads (a local node is recommended: the virtual OS makes many reads). Operators should read §2.

**Logging and retention** (PS-10): job ids, stages, timings and failure codes are logged; client
addresses, nullifiers and statements are not, by default. The in-memory address-to-job map used
for rate limiting holds only counters and expires with the window. Worker and runner logs go to
the job directory and are deleted with it at the end of retention. A reverse proxy in front of
the server must be configured not to keep access logs with client addresses; the Docker
compose example ships that way.

## 11. Tests

- Differential: every bench proof, honest and forged, through the Rust pre-checks and the Cairo
  bridge executable, with identical results; plus malformed encodings (non-canonical felts in
  delivery, intent and chain, trailing data, wrong proof shape, another circuit).
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
| PS-1 | §4: a Rust port of both bridges from the manifest constants, canonical felts, pinned tag, format, FRI configuration and component sizes, exact Serde; a differential test (§11) |
| PS-2 | §4.6 per-nullifier deduplication and backoff; §7 IPv6 /64 buckets |
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
