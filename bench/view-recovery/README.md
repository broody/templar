# Full viewing and recovery experiment

**A watch-only wallet can calculate an unspent balance without the spending
secret. A seed-restored owner can recover and spend the same funds.** This isolated
prototype extends the earlier [push-receive experiment](../push-receive/README.md).
See [proposed ADR-0020](../../docs/adr/0020-full-viewing-and-recovery.md) for the key
construction, disclosure limits, recovery contract and adoption gates.

Production packages, the working Sepolia deployment, and the POC1 experiment are
unchanged. This is ordinary-note pathfinding, not an audited wallet or a live
chain integration. The Python ledger is a reference state model; it does not
verify cryptographic proofs or implement ERC20 custody.

## What the user gets

The small demo receives 100, sends 60, and receives 40 change:

| Access | Result after the payment | Can spend? |
|---|---|---|
| Incoming viewing key | Receipts of 100 and 40; no balance claim | No |
| Full viewing key | Original 100 spent; balance 40 | No |
| Restored seed + complete history | Same balance 40, with spend authority | Yes |
| Full viewing key + missing change payload | Incomplete history; balance unknown | No |

The demo also retries with a complete archive, rejects modified/stale data,
rebuilds after a simulated reorg, and reports a true zero after an actual model
spend of the remaining 40. [recovery.json](results/recovery.json) records each
result with block identity and completeness status.

The larger payment experiment repeats Alice/Carol paying Bob while he is offline.
Bob recovers 850, pays Dave 500, keeps 310 and withdraws 40. An exported full
viewer correctly reports 310, although incoming receipt totals are 1,160. A fresh
seed-restored wallet rebuilds the tree and spends the remaining 310; its Cairo
statement has a verified standalone recursive proof. The full viewer then reports
zero. No new transaction was submitted to Sepolia.

## How viewing stays separate from spending

The spend secret derives two separately tagged hashes: an authority value `ak`
and nullifier key `nk`. The receiving identity commits to **both**. Full viewing
exports those values and the independent incoming-decryption key. Spending still
requires the original secret and verifies its derivation of both values.

Binding the nullifier key to the receiving identity prevents a viewing export
from substituting a false key and making spent notes look unspent. Import checks
key consistency against an independently authenticated expected address. Cairo
rejects each viewing component when substituted for the spending secret. These
tests support feasibility; the construction still needs independent cryptographic
review of its hash assumptions and disclosure properties.

Full view covers received notes and spent status for this address. It does not
recover all outgoing destinations or memos, or prove that a person has disclosed
all their addresses. A copied viewing key cannot be revoked. Rotation must move
future payments to new receiving and encryption keys; old history remains visible.
The plaintext export API is for synthetic fixtures, not production key transport.

POC2 uses new domains, plaintext/version labels and seed derivation. Both spending and incoming keys are derived separately per
network/pool so exported keys are not reused across those contexts. It is
intentionally incompatible with POC1 and deployed V3. Old leaves must retain their
old nullifier rules; no migration or production upgrade is implemented here.

## What recovery trusts

`recovery.py` accepts a **trusted canonical checkpoint** and an untrusted payload
archive. The checkpoint supplies tree root/count, ordered commitment/delivery-
digest receipts, and the spent-nullifier set at an identified block. Recovery
rebuilds the tree, checks the archive against the trusted receipts, decrypts
matching notes, and evaluates spent status. Repeated identical events are
deduplicated; conflicting duplicates are rejected.

The checkpoint comes from the local test ledger. **Authenticating live RPC,
receipts, state and finality is not implemented.** A hash supplied by the archive
itself is not a trust anchor. The commitment root does not authenticate ciphertext;
the delivery digest must also come from authenticated transaction/receipt data.
The reported balance is as of the supplied block. Reorg handling here is a fresh
rebuild from the replacement checkpoint, not an incremental wallet database.

Missing any output payload marks history incomplete, including when known unspent
notes sum to zero. Valid historical checkpoints remain historical; known-stale
ones fail a requested minimum height. Tampered payloads fail even if the archive
recomputes its own digest. These checks require the checkpoint trust assumption.

Completeness covers recoverable, protocol-published notes for one address. Correct
encryption is not proved: an authenticated but undecryptable intended payment
cannot always be distinguished from another recipient's output. Recovery needs
retained ciphertext, not just its digest. The seed recreates keys, not note data
randomly chosen by payers. Network/pool, derivation version and future address
scan ranges must be part of the eventual backup/discovery standard.

## Evidence and cost

**48 Python tests pass; five valid Cairo vectors pass and 17 invalid witnesses
are rejected.** Four payment/withdrawal statements have verified standalone Stwo
proofs, with exact public-output matching and rejection of altered public output
and program identity. The fifth valid Cairo vector checks spending identical
commitments at two separately funded positions.

| Workload | POC1 steps → POC2 steps | POC1 Poseidon → POC2 Poseidon |
|---|---:|---:|
| Alice, 1 input / 2 outputs | 4,799 → 4,908 | 103 → 107 |
| Carol, 1 input / 2 outputs | 4,798 → 4,907 | 103 → 107 |
| Bob, 2 inputs / 2 outputs / 1 withdrawal | 7,981 → 8,199 | 179 → 187 |
| Restored owner, 1 input / 1 withdrawal | — → 4,505 | — → 93 |

The two-input statement adds 218 steps (2.7%) and eight Poseidon instances (4.5%).
Payload remains **304 bytes per output**. Encryption/decryption and the pool's
ciphertext hashing/emission are outside this Cairo statement.

A 10,000-event incoming scan with two matches took a median **1.03 seconds** over
three local runs, versus 0.74 seconds in the earlier prototype. POC2 also checks
the decryption-key/public-key pair on every attempted receipt; this is not an
isolated benchmark of full-view overhead. The corpus contains distinct decoys.
Ciphertext alone is 3.04 MB. This measures in-memory incoming scanning, excluding
networking, checkpoint authentication, persistence and complete tree rebuild.
It does not establish large-history sync performance or consumer-hardware results.

Proof process time, RSS, bytes and verifier results are in the four `*.stwo.json`
records and [report.json](results/report.json). Each proof runs in a fresh process
with four cores, a 10 GiB cgroup limit and no swap. Timings include proving and
verification, excluding compilation, PIE generation and wallet synchronization;
one run each is not a latency distribution.

The prover is the **earlier ADR-0018 staged-allocation standalone privacy harness**,
not the V1 virtual OS used in the working Sepolia lifecycle. Its binary hash is
checked against archived evidence, and source provenance is recorded. These
artifacts are not native transaction proofs. They do not replace the roughly
14 GiB live-V1 RSS baseline or qualify a standard desktop.

Scarb 2.18 compiles and executes the statement; scarb-execute 2.14 exports a direct
PIE from that same compiled artifact for compatibility with the preserved older
privacy harness. The exporter output is independently compared with the expected
public scalars before proving. Versions, hashes, execution logs and PIE files are
retained. See the earlier push-receive README for the wrapped-PIE incompatibility.

## Reproduce

From this directory, using the installed Python/PyNaCl and pinned toolchains:

```bash
python3 -m unittest -v test_protocol test_recovery > results/python-tests.log 2>&1
python3 experiment.py > results/experiment.log 2>&1
python3 recovery_experiment.py > results/recovery.log 2>&1
python3 run_cairo.py > results/cairo-driver.log 2>&1
# Requires the preserved ADR-0018 standalone harness.
python3 prove_standalone.py > results/standalone-driver.log 2>&1
python3 report.py
```

`PUSH_SCARB` and `PUSH_PIE_EXECUTOR` select the pinned compiler/exporter paths;
changing versions requires renewed qualification. `prove_standalone.py --help`
accepts source and binary paths and validates the archived binary hash. The
default external harness is under `/tmp`; it must be rebuilt from the preserved
ADR-0018 experiment if missing. It is not vendored into this directory.

All seeds and witnesses are deliberately public synthetic fixtures. Note
randomness and encryption are fresh each run, so regenerating the experiment
requires rerunning Cairo and proofs before checking artifact hashes. Do not
export real wallet witnesses, seeds or viewing keys using these scripts.

Next: review the key construction, then test the ciphertext/recovery contract
against the exact V1/Sepolia path and measure data cost and cold sync on the
target desktop. Watch-only viewing appears inexpensive inside the statement;
data availability, trustworthy synchronization and desktop proving remain the
larger integration work.
