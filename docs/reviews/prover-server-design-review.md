# Prover server: design review (pre-implementation)

Independent reviewer; I did not write the design. Date 2026-09-24.

**What I reviewed.** `docs/prover-server-spec.md` as committed in `c4949b2` ("Prover server:
design for review"). That commit is on `feat/hidden-assets`, not on `main`, contrary to the
request, so I reviewed that revision. Nothing is implemented, so every finding is reasoned
(**R**). Where I read source I cite it. The only change I made is this new file.

## Scope

- **The spec.** In full.
- **The bench pieces it replaces:**
  - `bench/m31-sepolia/proof2.py` (base block, transaction, capture, facts checks);
  - `flow.py:121-126` (submission waits until `head ≥ base + 11`);
  - `deploy.py` and `hidden_asset_flow.py` (`MAX_PROOF_AGE = 4096`);
  - `bench/m31-private-wrapper/bridge-capacity/capture.rs`, which compiles the sequencer's
    `running` modules by `#[path]` from a `/tmp` checkout, asserts a loopback RPC and hard-codes
    `ChainId::Sepolia`;
  - `proof2-large/run.sh`, which runs the prover under `systemd-run --user` with a memory cap,
    zero swap and 4 pinned CPUs.
- **The bridges the pre-checks must mirror:**
  - `client-port/cairo-r4/bridge/src/lib.cairo` (`verify_payment`, lines 76-146);
  - `cairo-p1/bridge/src/lib.cairo` (`verify_policy`, lines 91-158);
  - the vendored `circuit_air` verifier as built for the R4 bridge
    (`~/.local/share/templar/runs/r4-bridge/vendor/circuit_air/src/lib.cairo`,
    `multiverifier_consts.cairo`). It pins the FRI configuration and component log sizes from the
    trusted manifest, not only the circuit hash.
- **Rust counterparts:**
  - `client-port/src/payment4.rs` (`bridge_checks` at 202-233, `statement_limbs`);
  - `payment.rs` `felt_limbs` (157-163);
  - `src/policy.rs`, which has no P1 counterpart of `bridge_checks` (only the witness-level
    `statement`, 247-313).
- **Statement accounts:** `cairo-r4/account` and `cairo-p1/account`. `__validate__` requires a
  zero tip and zero prices. `__execute__` requires caller 0 and `statement.chain == tx chain`, and
  emits `[class, tag, chain, pool, binding]`.
- **What the facts must satisfy:** `bench/m31-pool/cairo/src/adapter.cairo`:
  - length 9;
  - `PROOF2`, `VIRTUAL_SNOS`, the OS program and `VIRTUAL_SNOS0`;
  - `base < current ≤ base + max_proof_age`;
  - one message;
  - `message_hash = Poseidon(statement, 0, 5, class, tag, chain, pool, binding)`.

  Its configuration has no views.
- **The V4 statement:** `docs/hidden-asset-spec.md` §2 and §4.5.

Per the request, I do not discuss unpublished client-prover changes beyond what spec §9 says.

## Verdict

**CONDITIONAL GO.** The architecture is right:
- one binary;
- pre-checks before admission;
- a child worker per job under a memory cap;
- the authoritative checks left to the proven bridge, the sequencer and the pool.

The trust claim of §2 holds in its strong direction. A malicious or misconfigured server cannot
make a pool accept an effect the client did not prove:
- the binding fixes every effect;
- the adapter recomputes the message from its own configuration;
- the sequencer checks the base-block hash, which a lying RPC cannot forge.

Four gaps must be closed in the spec before implementation:
- **PS-2 (High).** Nothing stops one cheap note from buying unlimited large proofs.
- **PS-1.** The pre-checks as specified are not equivalent to the bridges, and P1 has no native
  mirror at all.
- **PS-3.** The job's base block is ill-defined, and the result omits the window in which the
  proof can be submitted.
- **PS-5.** A misconfigured server can hand users proofs that land on chain and revert, and users
  pay the fee. Nothing in the design detects this.

PS-4, PS-6 and PS-8 are Medium and should be settled in the spec too. The rest can be settled
during implementation.

## Findings

### PS-1: Medium. The §4 pre-checks are not rule-for-rule equivalent to the bridges; the P1 mirror does not exist

**Location:** spec §4.3-4.4, §11; `payment4.rs:202-233`; `payment.rs:157-163`; R4 bridge
:76-146; P1 bridge :91-158; `circuit_air` `lib.cairo:120-122` and `multiverifier_consts.cairo:16-38`.

**Problem.** §4 has the server take a submitted `statement`, check that the proof's claimed
outputs equal `statement_limbs(statement)`, and run `payment4::bridge_checks`. The Cairo bridge
instead decodes the statement from the proof's outputs and applies more rules than
`bridge_checks` does:

- **(a) Canonical felts.**
  - The bridge's `felt_from_limbs` rejects any felt field whose value is `≥ p`
    (`'non-canonical felt'`). That covers chain, pool, `token_out`, both deliveries, the recipient
    and the intent.
  - Rust `felt_limbs` accepts any 63-nibble value, including `[p, 2^252)`, and `bridge_checks`
    range-checks only pool, `token_out` and recipient (`< 2^251`).
  - So a statement whose delivery or intent limbs encode a value in `[p, 2^252)` passes the
    limb-equality check and `bridge_checks`, and fails in the OS run. The circuit publishes
    delivery and intent limbs unconstrained, so a client can produce such a proof.
- **(b) Statement tag and tree format.** The bridge pins the tag (`R0V4` or `R0C4`) and the
  padding limb. §4 never names the tree format, and §8 has no per-deployment tree format or
  statement tag.
- **(c) The verifier's pinned constants.** The Cairo `verify_circuit` requires the proof's FRI
  configuration to equal `circuit_fri_config()` (pow 26, blowup 2, 35 queries, fold 4, last layer
  0) and uses the manifest's component log sizes. "Verify against the pinned circuit hash" (§4.3)
  pins only the blowup and preprocessed root. A native verifier that accepts another FRI
  configuration admits proofs the bridge rejects, and a stricter one refuses honest proofs.
- **(d) Encoding.** The bridge rejects trailing felts after the `CircuitProof` Serde and any
  `INVALID_PROOF_ENCODING`. The native path must parse the *same Cairo-Serde felts* that become
  the calldata, not a separately serialized Rust proof.
- **(e) P1.** §4.4 says "P1: the P1 bridge's statement checks", but no Rust function implements
  them. `policy.rs` has only witness-level rules. The bridge rules to port are:
  - zero context;
  - address ranges for pool, token, recipient and controller;
  - nonzero nullifier;
  - delivery ⇔ active per slot;
  - recipient ⇔ amount;
  - `index < 4`, `kind ∈ {1,2}`, `(kind == 1) == (x == 0)` and `index ≠ 0 ∨ kind == 1`;
  - 16-bit limbs;
  - padding limb 163.

**Failure scenario.** A client submits an R4 proof whose delivery₁ limbs encode `p + 5`. Every
§4 pre-check passes. The server spends about 12 s in the OS run, which fails with
`non-canonical felt`, and if the OS stage is not separately gated it also spends about 2 minutes
proving. The inverse direction is a liveness bug: a native verifier stricter than the Cairo one
refuses honest users.

**Required spec change.**
- Define the pre-check as a Rust **port of `verify_payment` / `verify_policy`**:
  1. deserialize the calldata felts exactly as Cairo Serde does, with no trailing data;
  2. apply the pinned circuit hash, FRI configuration, component log sizes and statement tag,
     all read from the *same trusted manifest* the bridge was built from;
  3. decode the statement from the claimed outputs, with every limb-range, canonical-felt and
     padding check;
  4. apply every bridge assertion in the bridge's own words;
  5. apply the account's `chain == configured chain`;
  6. run native verification.

  The submitted `statement` becomes optional, used only for a cross-check.
- Add a **differential test** to §11. Run the Cairo bridge executable (`scarb execute`) and the
  native check on the same corpus:
  - the bench's honest proofs;
  - the `tamper`-feature forged proofs;
  - mutated encodings.

  Require identical verdicts. Add non-canonical deliveries and intents to the corpus.
- `info` prints the manifest's sha256.

### PS-2: High. Unlimited large proofs from one cheap note (no nullifier deduplication)

**Location:** spec §4.5, §5, §7; S3.

**Problem.** A valid client proof costs its maker about 0.3-0.9 s and 0.6 GiB. The server then
spends about 12 s on the OS run and about 2 minutes on 4 cores at about 28 GiB proving it. That
is roughly three orders of magnitude of asymmetry.

§4.5 rejects only *spent* nullifiers. Nothing rejects a nullifier that is **already queued,
running or done**.

An R4 proof's `nf₀` is the deterministic nullifier of a real, owned, nonzero note. Everything
else is free for the client to vary:
- the dummy input, and so `nf₁`;
- the outputs, their rho and deliveries;
- the recipient.

So one owned note, for example a one-unit deposit of a token the attacker deployed (cheap on
Sepolia), yields unlimited distinct valid proofs. The attacker never submits any of them, so the
nullifier stays unspent forever. Per-IP buckets do not bind an attacker with many addresses (an
IPv6 /64, or a botnet).

**Failure scenario.** An attacker deposits one unit once, then submits a fresh proof of the same
note every few seconds from rotating addresses. The single-job queue (§7 default) is permanently
occupied, and honest users wait indefinitely.

**Required spec change.**
- **Deduplicate on the input-0 nullifier (R4) and the nullifier (P1).** Allow at most one
  queued-or-running job per nullifier, and at most `k` completed jobs per nullifier per window
  (for example 2 per `max_proof_age`). Honest users re-prove only after a failure or expiry.
- Key the rate limits by IPv6 /64 as well as by address.
- Admit the job to the queue only after the chain-state checks.
- Give failed jobs a per-nullifier backoff.
- State in S3's answer that the admission cost is one owned note per concurrent job.

### PS-3: Medium. The base block is ill-defined, and the result omits the window in which it can be submitted

**Location:** spec §5.1, §5.6; `adapter.cairo:61-67`; `flow.py:123-124`; `proof2.py:35-38`.

**Problem.**
- **(a) The base block has nothing to do with the root.** "The latest block at which the root is
  known" confuses two things. The statement account never reads the pool. The root is checked by
  the pool at *settlement*, against its 256-root history. The bench asserts `root_is_known` at
  base only as a sanity check.
- **(b) Picking an older block wastes the proof's life.** If an implementation reads §5.1 as
  "search back for a block where the root was known", it spends the adapter's `max_proof_age`
  window and may prove against a root that has already rolled out of history. The base block
  should be the current `latest` (accepted) block, never pre-confirmed, at job start.
- **(c) The result omits when the proof can be submitted.** The sequencer only resolves the base
  block's hash once the head is at least `base + 11` (the bench waits for this). The adapter
  rejects once `current − base > max_proof_age`. The pool rejects if the root has left its
  256-root history or a nullifier has been spent in the meantime.

**Failure scenario.** A wallet submits as soon as the job completes, before `base + 11`, and is
refused. Or a busy queue delays a job long enough for the root to roll out of the pool's history,
and the wallet submits a transaction that reverts with `UNKNOWN_ROOT`.

**Required spec change.**
- Define the base block as the `latest` block at job start, with a root-known sanity check at
  that block.
- Add `submit_after = base + 11` and `valid_until = base + max_proof_age` to the result, with
  `max_proof_age` per relation in the configuration (see PS-5).
- Add a note that the root and nullifiers must still be valid at submission.
- Re-check the root and nullifiers immediately before proving, not only at admission.

### PS-4: Medium. Untrusted input is parsed and verified in the front end

**Location:** spec §3 (the front end runs the pre-checks), §4; `payment.rs:157-163`.

**Problem.** The pre-checks do three things on attacker bytes inside the long-lived front-end
process:
- JSON and felt parsing;
- Cairo-Serde deserialization of a roughly 30k-felt proof;
- native STARK verification.

The obvious building blocks panic on malformed input. `felt_limbs` does
`expect("0x hex")`, `expect("hex digit")` and `assert!(nibbles.len() <= 63)`.

Verification is CPU-bound. On an async executor thread it stalls every connection, and a panic
under `panic = abort`, an allocation driven by attacker-declared lengths, or a stack overflow in
a verifier path kills the server. §3 isolates only the worker.

**Failure scenario.** A malformed statement or span length crashes or wedges the front end.
Queued and running jobs lose their state, and every client's polling fails.

**Required spec change.** The pre-checks use fallible parsers only, with no library panics on
input. Allocation is bounded by the pinned proof shape: reject span lengths that differ from the
manifest's before allocating. Verification runs in `spawn_blocking` with a timeout and a
concurrency cap. Better still, the pre-checks run in a short-lived checker child with a small
memory cap: the same binary in `check` mode, which §3 already has. Build with `panic = unwind`
and a catch per request if the checks stay in process.

### PS-5: Medium. Nothing ties the server's configuration to the adapter's, so a misconfiguration costs users fees

**Location:** spec §8, §5.3, §5.5, §6; `adapter.cairo:27-45`, which has no views.

**Problem.** The adapter recomputes the message from its own `(statement, statement_class, tag,
os_program, max_proof_age)`. A server whose configuration differs in any of these produces a
proof that verifies and is admitted, carrying facts the adapter rejects. The transaction is
included and reverts with `PROOF_BINDING`, `OS_PROGRAM` or `PROOF_AGE`, and the submitter pays
the fee. The strong claim holds (no wrong statement is ever accepted), but "only wastes work" is
false: it wastes the *user's* fee.

The bench's `capture.rs` also hard-codes `ChainId::Sepolia` in the runner's chain info. A server
configured for another network would run the account under the wrong chain id, and the account
would fail with `"chain"`.

**Required spec change.** At startup, and periodically, the server verifies the following and
refuses to serve on any mismatch:
- `starknet_chainId` equals the configured chain;
- the configured statement accounts are deployed with the configured classes
  (`get_class_hash_at`);
- the pool's `get_verifier` and `get_policy_verifier` point to adapters whose storage
  (`statement`, `statement_class`, `os_program`, `max_proof_age`, `account_tag`, read with
  `starknet_getStorageAt`, or through views added to the adapter) equals the configuration;
- the runner's OS program hash equals the configured one.

`GET /v1/info` exposes this tuple. Add a client **acceptance check** to the spec: before
submitting, the wallet recomputes `message_hash` from its own binding and the pool's adapter
configuration, checks `facts[2]`, `facts[4]` and `facts[7]`, and respects the PS-3 window.

### PS-6: Medium. One container cgroup for all jobs, with no hardening beyond the memory cap (S4)

**Location:** spec §3, §7, §9 (Docker).

**Problem.** Inside Docker, `systemd-run --user` is normally unavailable. The design then falls
back to "the container's own limit", which is shared by the front end and every worker. With
`max_concurrent_jobs > 1`, or a PS-4 checker, one job reaching the limit triggers the container's
OOM killer, which may kill the front end or a healthy job.

The worker also needs network access only in the OS stage (to the RPC), and needs no network in
the proving stage. The spec states neither this, nor filesystem or disk limits (the PIE and the
proof per job), nor killing the whole process tree on timeout.

**Required spec change.**
- Give each job its own cgroup v2 sub-group, using a delegated cgroup inside the container, with
  `memory.max`, `memory.swap.max = 0`, `pids.max` and a CPU set.
- Failing that, set `oom_score_adj = 1000` on workers and `-1000` on the front end.
- Kill the job's cgroup, not just the pid, on timeout.
- Keep the job directory on a size-limited volume with a per-job quota, and delete the PIE after
  proving.
- Run with `no-new-privileges`, all capabilities dropped, a read-only root filesystem and
  seccomp at the default.
- Allow the OS stage to reach only the configured RPC, and give the proving stage no network.
- With these, a child process is sufficient isolation for this input class. The OS run executes
  only the pinned account and bridge in the Cairo VM, bounded by the transaction's L2 gas, and
  the prover's input is that deterministic PIE.

### PS-7: Low. §2 misstates what the server can do and omits what it learns early

**Location:** spec §2.

**Problem.**
- **(a) The server cannot submit the transaction.** "Enough to submit the finished transaction
  itself" is inaccurate. The server holds the proof, the facts and the statement. Submission
  also needs data the server never receives:
  - the output ciphertexts (the statement has only their digests);
  - for `apply_spend_with_invoke`, the `ExecutionIntent` preimage;
  - for P1, `data` and the ciphertexts.
- **(b) The server learns effects before settlement.** Before settlement, the server learns
  the exit asset, amount and recipient, and for an invoke also the budget and its recipient
  (usually the adapter, which identifies the venue). A server operator can therefore front-run
  open-note executions within the user's `minimum` slippage bound.
- **(c) The server can cluster a client's spends.** Across jobs, the server links every spend
  from one client address or session, pure in-pool transfers included. Against the server, this
  undoes in-pool unlinkability. "Network address and timing" understates it.

**Required spec change.** Correct (a). Add (b) and (c) to §2, and recommend separate servers or a
relay per spend for users who care.

### PS-8: Medium. How the sequencer's virtual-OS runner becomes a pinned dependency is unspecified

**Location:** spec §1 bullet 2, §9; `capture.rs:3-11`.

**Problem.** The bench compiles the runner's modules (`running::runner`, `storage_proofs`,
`virtual_block_executor`, …) by `#[path]` from a sequencer checkout because they are not a public
library surface. "The upstream virtual-OS runner as a pinned dependency" therefore needs one of:
- a fork that exposes the modules;
- a vendored copy with a hash manifest, as the bridge build record does for `circuit_air`.

The sequencer workspace also pins its own toolchain and versions of `cairo-vm`, `blockifier` and
`starknet_api`. These may not build on `nightly-2026-01-15`, or may conflict with the prover
dependency's versions if linked into one binary. The PIE handed between them is a cross-version
type.

**Required spec change.**
- State the mechanism: a fork at a pinned revision exposing `running`, or a vendored copy with a
  sha256 manifest checked at build time.
- Keep the PIE **file boundary** between the runner and the prover (`os.pie.zip`, as today), or
  build two binaries in one image, so the two dependency trees never have to unify.
- Commit `Cargo.lock` and build with `--locked`.
- Publish the image digest and every dependency revision in `info`.
- As a release check, confirm that every pinned git revision is fetchable from where the image is
  built. §9's blocker is one instance of that.
- Stated separately: the chain info (chain id, fee tokens) comes from the configuration, not a
  hard-coded `Sepolia`.

### PS-9: Low. Transaction and facts checks are under-specified compared with the bench

**Location:** spec §5.2, §5.5; `proof2.py:40-46, 61-74`.

**Problem.**
- **The transaction.** "Zero fees and tip" must also fix the L2-gas `max_amount`. The bench uses
  `10^9` at price 0; with a zero bound the bridge's roughly 2M steps would fail. It must also fix
  an empty signature and empty paymaster and deployment data, and the DA modes.
- **The facts.** §5.5 checks only the message hash. The bench checks, and the adapter requires:
  - `len == 9`;
  - `facts[0..4]` equal to `PROOF2`, `VIRTUAL_SNOS`, the configured OS program and
    `VIRTUAL_SNOS0`;
  - `facts[4] == base_block`;
  - `facts[7] == 1`;
  - the single message's `from_address` equal to the statement account.

**Required spec change.** List these checks in §5.2 and §5.5 and make them part of the job's
success criteria.

### PS-10: Low. Retention and logging of what §2 says the server learns

**Location:** spec §6, §7, §10.

**Problem.** A per-IP queued-job cap requires an in-memory IP → job association for the life of
each job. Worker and OS logs may include calldata or statement fields (nullifiers, deliveries).
A reverse proxy in front will log client addresses by default. §10's "client addresses are not
logged by default" covers none of these.

**Required spec change.** Specify three things:
- the IP ↔ job map is dropped when the job leaves the queue;
- worker and runner logs carry no statement or calldata fields, and share the one-hour retention
  of the job directory;
- the operator guide says to disable proxy access logs.

`GET /v1/jobs/{id}` returning `position` is fine.

## Answers

**S1: equivalence of the pre-checks and the bridges.** Not as written (PS-1).
- **Admitted but rejected by the bridge:** non-canonical felt fields, an unpinned FRI
  configuration, encoding differences, and every P1 rule, since P1 has no native mirror.
- **Refused but accepted by the bridge:** anything a stricter native verifier rejects. Also, by
  design, statements for other chains or pools and spent or unknown chain state. That design
  refusal is correct, because the pool would reject those too.

Equivalence is achievable if the pre-check is a Rust port of `verify_payment` / `verify_policy`
over the same manifest constants, gated by a differential test against the Cairo executable. The
statement accounts' own checks are then covered as well:
- `__validate__`'s zero tip and prices, because the server builds the transaction (PS-9);
- `chain == tx chain`, through configuration pinning (PS-5).

**S2: does anything reveal more than §2 says?**
- **The API** reveals no more. Job ids are unguessable, and a result is public at settlement
  anyway. A result without the ciphertexts cannot settle anything.
- **§2 itself** misstates the server's power to submit and omits early knowledge of exit and
  invoke effects and cross-job clustering (PS-7).
- **Job handling and logging** need the retention rules in PS-10.
- **RPC:** the chain-state pre-checks send nullifiers to the configured RPC before settlement.
  With a third-party RPC, that provider learns them too. A local node, recommended in §10 for
  performance, is also the privacy answer.

**S3: can a submitter make the server do expensive work cheaply?**
- **Yes: flooding with valid proofs from one note (PS-2, High).** Nullifier deduplication and
  backoff reduce the cost to one owned note per concurrent job.
- **Pre-check cost** is bounded, because verification is milliseconds, *if* it is isolated and
  capped (PS-4).
- **Statements that pass the pre-checks but fail the OS run** exist today through PS-1(a), (c)
  and (e). Closing PS-1 leaves only operational failures (RPC, deployment), which PS-5's startup
  checks catch.
- **Queue flooding** otherwise needs caps keyed by /64 and a global cap, which §7 has in part.

**S4: is a child process under a cgroup enough isolation?** The model is right. The OS run
executes only the pinned account and bridge in the Cairo VM, bounded by L2 gas. The prover's input
is the deterministic PIE. So memory, CPU, time and disk are the resources to bound, not code
execution. As specified, though, it falls short in two places:
- the pre-checks parse untrusted bytes in the front end (PS-4);
- under Docker all jobs share the container's limit (PS-6).

Per-job cgroups, killing the whole tree on timeout, disk quotas, no network while proving and
standard container hardening make it sufficient.

## Re-review of revision 2

Same reviewer, same day. I reviewed revision 2 of `docs/prover-server-spec.md` as committed in
`e0a1443`. That commit is on `feat/hidden-assets`, like revision 1: `main` still does not contain
the spec. This is still reasoning only. I checked the PS-8 claim against the sparse checkout of
the pinned sequencer at `~/development/sequencer-pin` (`HEAD e6b6fd2e9932…`), and changed nothing
but this file.

### Verdict

**CONDITIONAL GO.** Revision 2 resolves PS-1 to PS-7, PS-9 and PS-10 in substance.

The one condition is a new finding, **PS-11**. The pinned sequencer revision does *not* let
another crate construct or run the virtual-OS runner. "No fork or vendored copy is needed" (§9)
is therefore wrong, so PS-8 is only partially resolved.

The other new findings (PS-12 to PS-14) are Low and can be settled during implementation.

### Status of prior findings

| ID | Status | Note |
|---|---|---|
| PS-1 | **Resolved** | §4 is now a port of `verify_payment` / `verify_policy`: exact Cairo Serde with no trailing data; pinned FRI configuration, component sizes, output count and circuit hash; canonical felts; tag and tree format; padding; every bridge rule, for P1 too. §11 adds the differential test against the Cairo executable, including non-canonical deliveries, intents and chain. One consistency gap is left for PS-12: the §8 file does not say where the manifest constants come from, and §9 still describes `client-port` as supplying "`bridge_checks`". |
| PS-2 | **Resolved** | One job per input-0 nullifier (the single nullifier for P1) queued, running or completed within retention, with backoff and /64 buckets. That limits an attacker to one proof per owned note per retention window. Deduplication state held only in memory is lost on restart. It is worth persisting it with the job directories, but this is not required. |
| PS-3 | **Resolved** | The base block is `latest` at job start, the root and nullifiers are re-checked before proving, and the result carries `submit_after` and `valid_until`. `valid_until` is an upper bound only. The root can leave the pool's 256-root history or a nullifier can be spent earlier, and the wallet guidance should say so in one line. |
| PS-4 | **Resolved** | The pre-checks run in a `check` child with CPU-time and memory limits, parsing is fallible, and allocation is bounded by the pinned shape. |
| PS-5 | **Resolved** (startup) | Startup checks cover the chain id, the account classes and the adapter's storage, and the tuple is in `/v1/info` for wallets to compare. See PS-12 for what the check still misses. |
| PS-6 | **Resolved in design**, feasibility to confirm | Per-job and per-pre-check cgroups, whole-group kill, no network while proving, front-end reservation and container hardening. See PS-14. |
| PS-7 | **Resolved** | §2 now says the server cannot submit, learns exit and execution effects early (the front-running risk), and links jobs. OHTTP is added for transport privacy; see PS-13. |
| PS-8 | **Partially resolved** | The lockfile, `--locked`, the fetchability check and the PIE file boundary are all in. The dependency mechanism is not: see PS-11. |
| PS-9 | **Resolved** | L2-gas bound 10^9 and every fact field the adapter checks. |
| PS-10 | **Resolved** | Rules for logs, counters, job-directory log retention and the proxy. |

### New findings

#### PS-11: Medium (the condition). The pinned runner cannot be constructed from outside the crate

**Location:** spec §9 first sub-bullet, §5.4;
`sequencer-pin/crates/starknet_transaction_prover/src/running/runner.rs`.

**Problem.** It is true that `lib.rs:23` has `pub mod running` and `running.rs` has
`pub mod runner`. But at `e6b6fd2e` the pieces needed to use the runner are all crate-private:

- `RpcRunnerFactory::new` is `pub(crate)` (runner.rs:399);
- `create_runner` is private (:409);
- `Runner` and `Runner::new` are `pub(crate)` (:138, :159);
- the providers it needs are also `pub(crate) fn new`:
  - `RpcStorageProofsProvider` (`storage_proofs.rs:213`);
  - the virtual block executors (`virtual_block_executor.rs:97, 413`).

The only public way in is `VirtualSnosProver::new(&ProverConfig)`
(`proving/virtual_snos_prover.rs:77`). It holds the factory privately, and its only public
operation, `prove_transaction`, always continues into the crate's own small-proof prover. Without
the `stwo_proving` feature, that step is `unimplemented!()` (:284-296). There is no public call
that returns a `RunnerOutput` (the PIE) for the large prover.

This is exactly why the bench's `capture.rs` compiles these files by `#[path]`: inside its own
crate, `pub(crate)` becomes reachable.

**Failure scenario.** An implementation that follows §9 as written cannot create the runner, and
the build fails. The likely workaround is an ad-hoc `#[path]` copy or a local patch that is
unpinned and unhashed. That recreates the unrebuildable state §1 describes.

**Required spec change.** Name the mechanism.

- **(a)** A fork of `starkware-libs/sequencer` at `e6b6fd2e` with a minimal diff that makes
  `RpcRunnerFactory::new` public. The trait method
  `VirtualSnosRunner::run_virtual_os(&self, block_id, txs)` is already public and does the rest.
  Pin the fork by revision, record the diff in the repository, and have CI check that the fork
  differs from upstream only by that diff.
- **(b)** Alternatively, a vendored copy of the `running` modules with a sha256 manifest checked
  at build time, as the bridge build record already does for `circuit_air`.

Either way, the virtual OS program must stay byte-identical to the pinned one. Add a startup
check of the runner's OS program hash (PS-12).

Also confirm that the sequencer builds on `nightly-2026-01-15`. The pinned sequencer's
`rust-toolchain.toml` says `1.95`, and that nightly is a 1.95 pre-release. Features stabilized
later in the 1.95 cycle would not be available. If the build fails, the runner step can be a
separate binary on the sequencer's toolchain, because the PIE boundary already separates it from
the prover.

#### PS-12: Low. The configuration pinning has four gaps

**Location:** spec §8, §4, §9, §3.

1. **Where the manifest constants come from.** The §4 port depends on the trusted manifest (FRI
   configuration, component sizes, statement tag and tree format), but the §8 file lists only
   the circuit hash per relation. Add, per relation, the manifest path and its sha256, the tree
   format and the statement tag, and have `info` print them.
2. **The runner's OS program.** The startup checks compare the adapter's `os_program` with the
   *configuration*, but not with the OS program the runner actually embeds. Today a mismatch is
   found only after a full proof, at the §5.6 facts check. Hash the embedded program at startup.
3. **Re-reading the adapters.** The pool owner can re-point `set_verifier` or
   `set_policy_verifier`, while a running server keeps the adapter tuple it checked at start.
   Re-read the pool's verifier addresses, and on change their storage, at job start. That costs
   one RPC call.
4. **Stale text.** §3 still says the front end runs the pre-checks and that the worker's cap is
   "`systemd-run --user` or the container's own limit". §9 still says `client-port` supplies
   `bridge_checks`. Align both with §4 and §9's isolation paragraph.

#### PS-13: Low. OHTTP gaps: polling, a shared bucket and the key configuration

**Location:** spec §2 (transport privacy), §7.

1. **Polling.** Address hiding holds only if **every** request goes through the relay, including
   `GET /v1/jobs/{id}` polling. A client that submits through OHTTP but polls directly links its
   address to the job id, and so to the statement. State that clients use the relay for all
   requests.
2. **The shared bucket.** All OHTTP clients share "one relay-wide bucket". So one abuser behind
   the relay throttles every privacy-seeking user, and per-nullifier deduplication is the only
   real limiter for them. Size that bucket for it, or accept per-client tokens (for example
   Privacy Pass) forwarded by the relay.
3. **The key configuration.** Specify how the gateway's HPKE key configuration is published and
   rotated (in `/v1/info`, for instance), and that `tower_ohttp` comes from the same pinned
   sequencer revision.

#### PS-14: Low. The Docker isolation plan needs a stated, tested deployment recipe

**Location:** spec §9 (Isolation, Docker).

**Problem.** Per-job cgroups inside the container need a *writable, delegated* cgroup v2 subtree.
A default unprivileged Docker container, and especially one with a read-only root filesystem and
all capabilities dropped, mounts `/sys/fs/cgroup` read-only. The design then either fails to
start jobs or quietly falls back to one shared limit, which PS-6 was about.

"The proving worker has no network access" also needs a mechanism: a network namespace, or a
seccomp filter denying `socket` and `connect` in `worker` mode. Otherwise it is only a convention.

**Required change.**
- Ship one supported recipe: for example Podman or systemd with `Delegate=yes`, or Docker with
  `--cgroupns=private` and an rw cgroup mount.
- Have the server **refuse to start** if it cannot create a job cgroup, instead of falling back.
- Say how the prove stage's lack of network is enforced.
- Add both to the §11 startup tests.
