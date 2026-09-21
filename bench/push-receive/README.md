# Offline push receiving experiment

**Recommendation: restore push payments using reusable receiving addresses and
independently encrypted notes first.** Persistent channels can later optimize
discovery and payload costs; the basic send experience does not require channel
maps, a recipient counter, a setup transaction, or a per-payment invoice.

Design and open decisions: [proposed ADR-0019](../../docs/adr/0019-offline-push-receiving.md).
This is an isolated, ordinary-note prototype. Production sources, the accepted
invoice format and the working Sepolia deployment are unchanged.

## What works locally

Alice and Carol independently send Bob 600 and 250 units using only his published
address. Bob is absent during both sends. He restores from a deterministic test
seed and the public encrypted event history, recovers both notes, then sends
500 to Dave, keeps 310 as change and withdraws 40. Final private balances are
Alice 400, Bob 310, Carol 250 and Dave 500; together with the withdrawal they
account for all 1,500 initially funded model units.

The Python ledger is a **reference state model**, not an ERC20 contract or proof
verifier. The separate Cairo executable checks ownership, depth-32 membership,
indexed nullifiers, duplicate inputs, output derivation, u128 conservation,
withdrawal destinations and ciphertext-digest binding. The three payment
statements also have independently verified standalone recursive privacy proofs.
No new transaction was submitted onchain.

There are **21 Python tests** and **17 Cairo vectors**: four valid cases and
13 rejected witnesses. The fourth valid case spends two identical commitments
at distinct funded tree positions. The rejected cases cover sender/viewing keys
used as spend keys, membership, nullifiers, amount range, zero randomness,
duplicate inputs, inflation, wrong output owner, changed delivery digest and
withdrawal destination/range. Local state checks also cover missing/swapped
delivery, replay and atomic rejection. These checks are pathfinding evidence,
not a cryptographic audit or formal proof of all security properties.

## Ownership, encryption and data contract

The address contains a hash-derived public receiving key and an independent
encryption public key. Inputs prove knowledge of the receiving key's preimage;
outputs need only the public receiving key and fresh randomness. The nullifier
includes the spending secret, commitment and membership leaf index. Thus a
payer knowing the full note opening is still missing spend authority, and two
separately funded duplicate commitments remain spendable.

The wallet encrypts canonical, fixed-length note data with libsodium sealed
boxes via PyNaCl. Each output carries **304 ciphertext bytes** (256 plaintext +
48 overhead), before commitment, framing and transaction encoding. Ciphertext
integrity does not authenticate the sender. See
[libsodium sealed boxes](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes).

The public statement binds `(commitment, delivery_digest)` pairs. In a production
implementation the pool must recompute that digest from the actual ciphertext,
publish the bytes with the insertion and reject missing/replaced data atomically.
The proof does not prove encryption correctness. Maliciously encrypted notes may
be unreceivable; recipient software must check decryption and commitment before
crediting a payment.

The incoming key allows receipt discovery but cannot derive nullifiers, spend,
or calculate a reliable unspent balance. Full viewing keys are an open design
decision. Sharing the spending key is not a view-only feature. Recovery requires
encrypted history as well as the seed; retaining only its digest is insufficient.

## Measurements

All on this development host, not a physical consumer desktop or browser.

| Workload | Cairo steps | Poseidon instances |
|---|---:|---:|
| Alice's 1-input / 2-output send | 4,799 | 103 |
| Carol's 1-input / 2-output send | 4,798 | 103 |
| Bob's 2-input / 2-output / 1-withdrawal spend | 7,981 | 179 |

These are Scarb 2.18 standalone execution counts. The old invoice 2/2/1
experiment recorded 170 Poseidon instances and 8,021 steps. The work remains
in the same range; this is not an isolated per-feature comparison because the
prototype also changes binding, context and ordinary-only control flow.
Ciphertext encryption/decryption is outside this Cairo statement. The pool-side
cost of hashing/emitting ciphertext is not included and needs measurement.

Scanning **10,000 events with two matches** took a median **0.74 seconds** in
three local Python runs; ciphertext alone totals **3.04 MB**. The corpus has
distinct encrypted decoys, not one repeated ciphertext. It measures in-memory
decryption, parsing and commitment checks, excluding network download, chain
authentication, persistence and tree synchronization. Most decoys are rejected
by decryption before Poseidon checks. At larger history sizes, bandwidth and
linear scanning warrant investigation; this result is not a scalable discovery
service benchmark.

Raw records: [experiment.json](results/experiment.json),
[Cairo results](results/cairo.json), [Python tests](results/python-tests.log).
The three `*.stwo.json` records contain proof bytes, hashes, elapsed process
time, RSS and verifier results. [Machine-readable report](results/report.json)
collects them without conflating the execution and proving configurations.

| Earlier standalone privacy harness | Whole process, including verification | Peak prover RSS | Proof bytes |
|---|---:|---:|---:|
| Alice sends | 12.39 s | 8.85 GiB | 238,313 |
| Carol sends | 12.07 s | 8.74 GiB | 234,337 |
| Bob spends recovered notes | 11.14 s | 8.89 GiB | 237,523 |

One run per proof; compilation, initial PIE execution, encryption, synchronization
and networking are excluded. These timings are not latency distributions or a
comparison with the stock virtual-OS prover. Small differences between rows
should not be interpreted as a scaling trend.

## Standalone proof scope and tool compatibility

The optional proof run reuses the **earlier ADR-0018 standalone staged-allocation
harness**, proving source revision `cd7bc5f4697fb188a27e09f9242f1dd76df8afdc`.
The script requires its binary hash to match the archived earlier benchmark.
It runs each fresh process with four cores, a 10 GiB cgroup cap and no swap.
The pinned recursive verifier accepts all three proofs and rejects changed
public output and changed program identity. Every returned public scalar is
checked against the Python reference. This harness changes allocation lifetime;
the experiment does not alter blinding or security parameters.

**These are not V1 virtual-OS/native transaction proofs.** Their measurements
must not replace the roughly 14 GiB observed in the existing live Sepolia flow.
The new statement/output format still needs the current V1 service, adapter,
pool integration and network qualification. Controlled notes are not implemented
in this prototype.

Scarb 2.18's current `--target bootloader` exports a wrapped PIE that the older
privacy runner rejects during relocation, before proving. The failure is
preserved as `results/failed-pie-2.18.*`. The working export uses **scarb-execute
2.14.0** to run the **same 2.18-compiled artifact** at its bootloader-compatible
entry point and generate a direct PIE. Standalone execution, compiler and
exporter versions/hashes are recorded separately in `results/cairo.json`.
The exported public output is checked again, and the full PIE must pass the
cryptographic prover/verifier; it is not a relabelled proof or edited trace.

## Reproduce

Python 3.12 and PyNaCl 1.5.0 are installed on this workstation. The reference
imports the existing Python Poseidon/tree implementation from `bench/stwo-e2e`.
Run from this directory:

```bash
python3 -m unittest -v test_protocol > results/python-tests.log 2>&1
python3 experiment.py > results/experiment.log 2>&1
python3 run_cairo.py > results/cairo-driver.log 2>&1
# Optional: needs the preserved, previously built ADR-0018 harness.
python3 prove_standalone.py > results/standalone-driver.log 2>&1
python3 report.py
```

`PUSH_SCARB` and `PUSH_PIE_EXECUTOR` override the explicit executable paths;
record a new qualification if changing versions. `prove_standalone.py --help`
describes the source/binary options. Its default path is under `/tmp` and must
be rebuilt from the archived experiment if missing; this directory does not
vendor that external toolchain. Source provenance and source hashes are saved.

All fixture keys are deliberately public synthetic keys. `experiment.py` uses
fresh note randomness and encryption, so regeneration changes witnesses and
requires rerunning Cairo/proofs before comparing hashes. PIE and arguments
contain these synthetic private witnesses; never use this result-export pattern
for real wallet secrets.

## Decision still needed

Proceed to an isolated Sepolia implementation after review of the proposed key
model, viewing requirements and output serialization. Measure onchain data/gas
and actual desktop resource use before choosing persistent channels. Address
authentication, rotation/diversification, spam/coin selection, reorg recovery,
full viewing, authenticated history and old-format migration remain open. See
ADR-0019 for explicit compatibility and adoption gates.
