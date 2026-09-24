# Templar prover server

Status: **design, awaiting review. Nothing is implemented.** A runnable wrapping server for the
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
  public;
- enough to submit the finished transaction itself; that settles the spend exactly as its owner
  authorized, because the binding fixes every effect.

It can refuse, delay or drop jobs. Hiding the client from the server (transport privacy) is out
of scope; wallets that need it use a relay or several servers.

## 3. Architecture

```text
client ──POST /v1/jobs──► front end ──► pre-checks ──► queue ──► worker (child process)
                            │                                  ├─ virtual OS on live state
                            │                                  ├─ bounded large proof
client ◄─GET /v1/jobs/{id}──┘                                  └─ local verify, result
```

- **Front end** (tokio, axum): the API, per-IP rate limits, pre-checks, the queue, job state.
- **Worker**: the same binary in `worker` mode, one child process per job, so a crash or an
  out-of-memory proof never takes the front end down. It runs under a memory cap (cgroup v2 when
  available: `systemd-run --user` or the container's own limit).
- **Modes**: `serve`, `worker JOB_DIR` (internal), `check PROOF_DIR` (the pre-checks offline) and
  `info` (the pinned configuration and circuit hashes).

## 4. Pre-checks (before any heavy work)

In order, cheapest first; any failure rejects the submission with a stable error code:

1. **Size and encoding.** The body is at most a configured size; the proof is a span of felts
   below the field prime with its length prefix; the relation is `r4` or `p1`.
2. **Configuration match.** The statement's chain and pool are the ones this server serves.
3. **Client-proof verification, natively.** Deserialize the client proof and verify it with the
   circuit verifier against the **pinned** circuit hash of the relation (never one taken from the
   proof), exactly as the bridge does. The claimed outputs must equal the submitted statement's
   limbs.
4. **Bridge rules.** R4: `payment4::bridge_checks` (the exit rule, both outputs present, nonzero
   distinct nullifiers, recipient ⇔ amount, identity ⇒ intent, ranges). P1: the P1 bridge's
   statement checks. These mirror the Cairo bridges rule for rule.
5. **Chain state** (one RPC round trip each): the root is known to the pool; neither nullifier is
   spent. Stale or replayed work is rejected before it costs anything.

The authoritative checks remain in the proven execution (the Cairo bridge) and the pool; the
pre-checks exist to refuse bad input cheaply.

## 5. The job

1. **Base block.** The latest block at which the root is known; recorded.
2. **Transaction.** An `INVOKE_V3` from the relation's pinned statement account, calldata = the
   client proof, zero fees and tip (the account's `__validate__` requires them), nonce read at the
   base block.
3. **Virtual OS.** The upstream runner (`starknet_transaction_prover`'s `RpcRunnerFactory`,
   `run_virtual_os`) against the configured RPC endpoint, at the pinned OS program. The single
   L2→L1 message must equal `[statement class, account tag, chain, pool, binding]` for the
   binding recomputed from the statement.
4. **Large proof.** The bounded-memory prover (whole-tree commitments, FRI batches of 16 columns),
   then a local verification of the proof.
5. **Facts.** `['PROOF2', 'VIRTUAL_SNOS', os_program, 'VIRTUAL_SNOS0', base_block, base_hash, _,
   1, message_hash]`, checked against the expected message hash.
6. **Result.** `{proof (base64), proof_facts, base_block, binding, message_hash, timings}`.

A job that fails reports which stage failed; the client can resubmit (the server keeps no state
that would make a retry unsafe).

## 6. API

- `POST /v1/jobs` `{relation: "r4" | "p1", proof: [felt hex...], statement: {...}}` → `202
  {id, position}`, or `400 {error}` from a pre-check, or `429` from rate limiting.
- `GET /v1/jobs/{id}` → `{status: queued | running | done | failed, position?, stage?, result?,
  error?}`. Job ids are random 128-bit values; knowing one reveals only that job.
- `GET /v1/info` → network, chain, pool, relations with their circuit hashes, statement accounts,
  classes and tags, OS program, limits, and the server's version and dependency revisions.

Results are kept for a configured time (default one hour), then deleted with their inputs.

## 7. Limits and abuse

- **Rate limits:** per-IP token bucket for submissions, a cap on queued jobs per IP, a global
  queue cap; the pre-checks run before a job is admitted.
- **Concurrency:** `max_concurrent_jobs`, each needing about 4 cores and 30 GiB; the default is
  one.
- **Time:** a per-stage timeout (OS run, proof).
- Allowlists (IP or domain) are a later addition.

## 8. Configuration

One TOML file per deployment: network name, chain id, RPC URL (v0.10 API, state reads for the
virtual OS), pool address; per relation the statement account, its class, account tag and pinned
circuit hash; the OS program hash; prover settings (bounded columns, threads, memory cap); limits;
result retention; listen address. `info` prints it with the dependency revisions.

## 9. Build and distribution

- Rust (`nightly-2026-01-15`, as the rest of the stack). Pinned dependencies:
  - the sequencer at the revision the adapters pin (`e6b6fd2e…`), for the virtual-OS runner;
  - `broody/proving` `templar/bounded-server` (`b54ed94f8`) for the bounded large-proof prover;
  - `client-port` (path) for the relations' statement layouts, `bridge_checks` and the circuit
    verifier's pinned-hash checks.
- `target-cpu=native` gives about 1.7× faster proofs but ties a binary to its CPU. The Docker
  image builds for a stated baseline (x86-64-v3) by default, with a build argument for native.
- Docker: multi-stage build, a non-root runtime user, the config mounted read-only, a volume for
  job directories.
- Release blocker: the client-port crate currently builds against a non-public proving branch.
  Before the server is published, the parts it needs (the verifier side) must be available
  publicly; this does not block private use.

## 10. Operation

Hardware per concurrent job: 4 cores, 32 GiB RAM; an RPC node serving the v0.10 API with state
reads (a local node is recommended: the virtual OS makes many reads). Logs record job ids,
stages and timings; client addresses are not logged by default. Operators should read §2.

## 11. Tests

- Pre-checks against the bench's real proofs: every honest shape accepted; each forged statement
  (voluntary reveal, zero delivery, recipient without amount, identity without intent, duplicate
  nullifier, range violations, zero chain) rejected with its code; a proof for another circuit
  rejected.
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
