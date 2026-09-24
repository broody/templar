# Templar prover server

Turns a wallet's compact client proof into a native Starknet large proof. A wallet proves a spend
on its own device (R0 V4 for ordinary spends, open notes and shadow accounts; P1 for policy-note
settlement) and sends the zero-knowledge client proof and its public statement here. The server
runs the statement account on it in the virtual Starknet OS and proves that execution, then
returns the proof and its facts for the wallet (or a relayer) to submit. It never sees keys,
notes, amounts or membership paths, and it cannot change what a spend does. Anyone can run one.

Design and threat model: [`docs/prover-server-spec.md`](../docs/prover-server-spec.md), reviewed
in [`docs/reviews/prover-server-design-review.md`](../docs/reviews/prover-server-design-review.md).

## What runs

| Binary | Toolchain | Pinned on | Does |
| --- | --- | --- | --- |
| `templar-prover` | Rust 1.95 | — | HTTP API, rate limits, deduplication, queue, startup checks; the pre-check (executes the compiled bridge with `scarb`) |
| `templar-os-runner` | Rust 1.95 | `broody/sequencer` `625929a` (upstream `e6b6fd2e` plus one visibility commit) | Runs the statement account's transaction in the virtual OS against an RPC node; writes the Cairo PIE |
| `templar-prove` | nightly-2026-01-15 | `broody/proving` `b54ed94f8` (upstream plus bounded-memory storage) | Proves the PIE on the large-proof path in ~28 GiB, verifies it |

Every pre-check, OS run and proof runs as its own child process in its own cgroup v2 group
(memory, CPU and PID limits; the group is killed on timeout). The pre-check and the proof run
with no network.

## Requirements

- Per concurrent job: 16 cores and 32 GiB RAM for a ~65 s proof (4 cores: ~126 s; beyond 16
  cores there is almost no gain). The pre-check takes about 1 second and the OS run about 12. On
  one machine, throughput is memory-bound: two 16-core jobs need ~60 GiB.
- A Starknet RPC node with the v0.10 API. A local node is recommended: the OS run reads a lot of
  state, and the pre-checks send nullifiers and roots to it before settlement.
- A delegated cgroup v2 subtree (systemd `Delegate=yes`, or the Docker recipe below). The server
  refuses to start without one.
- Unprivileged user namespaces (`unshare --user --net`) for the no-network steps.
- The bridge builds the deployed statement accounts were compiled from (`build-record.json` and
  the compiled executable), one directory per relation.

## Build

```bash
cd server/os-runner && PATH=/path/to/cairo-lang-0.14.3a3/bin:$PATH cargo build --release --locked
cd server/prove && RUSTFLAGS="-C target-cpu=native" cargo build --release --locked
cd server/prover && cargo build --release --locked
```

`templar-os-runner` compiles the Cairo 0 virtual OS at build time and needs `cairo-compile` from
`cairo-lang==0.14.3a3` on `PATH`; the resulting program hash is checked at startup against the
one the adapters pin. `target-cpu=native` makes proofs about 1.7x faster than a portable build
but ties the binary to its CPU.

Or the image, from `server/`: `docker build -f deploy/Dockerfile -t templar-prover .`
(`--build-arg CPU=native` for a host-specific build).

## Run

Configuration: [`deploy/prover.example.toml`](deploy/prover.example.toml). At startup the server
checks the RPC node's chain, each statement account's class, each adapter's stored configuration,
the pool's verifiers, the bridge build records' hashes and the runner's OS program, and refuses to
start on any mismatch.

**systemd** ([`deploy/templar-prover.service`](deploy/templar-prover.service)): `Delegate=yes`
with `cgroup_root = "self"`.

```bash
templar-prover info /etc/templar/prover.toml     # the startup checks, then the published configuration
systemctl enable --now templar-prover
```

**Docker** (tested 2026-09-24 with Docker 26 on an AppArmor host, cgroup v2):

```bash
docker run -d --name templar-prover --network host --init --read-only --tmpfs /tmp \
  --cgroupns=private --cap-drop ALL --cap-add SYS_ADMIN --cap-add CHOWN --cap-add SETUID --cap-add SETGID \
  --security-opt no-new-privileges --security-opt apparmor=unconfined \
  --memory 38g --memory-swap 38g \
  -v /etc/templar/prover.toml:/etc/templar/prover.toml:ro \
  -v /etc/templar/ohttp.key:/etc/templar/ohttp.key:ro \
  -v /opt/templar/bridges:/opt/templar/bridges:ro \
  -v templar-jobs:/var/lib/templar-prover templar-prover
```

The added capabilities (and, on AppArmor hosts, the unconfined profile, since Docker's default
profile forbids the remount) are used only by the entrypoint: it remounts the container's private
cgroup namespace writable, moves every process into a `server` leaf, hands the subtree to the
unprivileged `templar` user (uid 999 in the image) and switches to it with every capability
dropped and `no_new_privs`. They stay in the container's bounding set, so anything started with
`docker exec` as root could use them: for a public server prefer the systemd unit, which needs
none. Mounted files must be readable by uid 999 (the OHTTP key: mode 0400, owner 999). Bridge
builds may be mounted read-only; the server copies what it executes into its data directory at
startup and hashes the copy. `--init` reaps step processes and forwards SIGTERM; on SIGTERM the
server stops accepting work and kills running steps.

`templar-prover check CONFIG SUBMISSION_JSON` runs the pre-checks on one submission without the
queue. `tests/check_bench_proofs.sh CONFIG PROOFS_DIR` runs every R0 V4 bench proof, honest and
forged, through it and checks each verdict; `cargo test` in `prover/` covers parsing and address
handling.

## API

- `POST /v1/jobs` — `{"relation": "r4" | "p1", "proof": [...], "statement": {...}}`, where `proof`
  is the wallet's `cairo-arguments.json` (a length-prefixed felt span) and `statement` its
  `public.json`. Returns `202 {"id", "position"}`, or `400` (a pre-check failed, with the reason),
  `409` (the root is unknown, a nullifier is spent, or this note already has a job for a different
  submission; resending the identical submission returns the existing job, even while the note is
  in backoff), `429` (rate limited) or `503` (queue full). A finished job stops holding its note once
  its `valid_until` has passed, so a wallet can re-prove it at the same server.
- `GET /v1/jobs/{id}` — `{"status": "queued" | "running" | "done" | "failed", "stage", "position",
  "result", "error"}`. A result carries `proof` (base64), `proof_facts`, `base_block`,
  `submit_after` (`base_block + 11`), `valid_until` (`base_block + max_proof_age`), `binding`,
  `message_hash` and timings. Submit the transaction within that window.
- `GET /ohttp-keys` — the OHTTP key configuration (when enabled).
- `GET /v1/info` — the network, pool, relations (statement accounts, classes, tags, adapters,
  circuit hashes), dependency revisions and limits. Wallets compare it with the adapters on chain
  before using a result.

## Status

Tested end to end on Sepolia (2026-09-24): an R0 V4 hidden-asset transfer and a P1 ERC1155 escrow
release, each through the API (as a systemd unit with a delegated cgroup; the R0 V4 job also in
the hardened container) (pre-check, OS run on live state, large proof, facts) and then
simulated with validation as the signed pool transaction: both succeed, with the same gas as the
bench-produced proofs. The large proof from `templar-prove` is byte-identical to the bench
prover's for the same PIE.

**Oblivious HTTP.** With an `[ohttp]` key configured, every endpoint is also reachable inside an
OHTTP envelope (`POST` any path with `content-type: message/ohttp-req`; the key configuration is
at `GET /ohttp-keys` and in `/v1/info`), so a client going through an OHTTP relay hides its address
from the server. Submit and poll through the relay alike. Submissions from the relays listed in
`[ohttp] relays` are rate-limited per relay; an envelope from any other address is limited like a
direct client. `examples/ohttp_client.rs` is a minimal client. The optional proof-of-work stamp for relayed
submissions (spec §7) is not implemented; per-note deduplication applies to every submission.
