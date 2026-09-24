# Blake authentication and PROOF1 cost experiment

2026-09-22. **The Blake2s component works through the preserved PROOF1 prover
and original verifier. The complete private-membership wrapper is not yet
implemented and would exceed the current direct-Cairo capacity.**

This experiment addresses the exact SHAKE96 incompatibility identified in
the [PCS review](../m31-private-e2e/independent-pcs-review.md). It led to a
separate, reviewed [Blake client candidate](../m31-private-blake/README.md).
The M31 application tree, private relation and existing frozen client remain
unchanged. No pool, production package or network deployment was modified.

## Server circuit follow-up

The [specialized server circuit experiment](server-circuit/README.md) now
produces a native proof and verifies it in Cairo with exact input/output batch
bindings. For 82 real public hash messages, proving takes **6.75 s / 3.53 GiB**;
native verification takes **2.16 ms**. Cairo verification takes **5,018,523
steps / 0.780 GiB** and passes seven malformed-proof controls.

The subsequent unchanged PROOF1 attempt **fails with `Not enough twiddles!`**
after 7,301,958 virtual-OS steps, at **34.35 GiB under a 64GiB cap**, with no
swap/OOM. No proof was produced. The intermediate circuit works, but the Cairo
bridge still exceeds the preserved final-wrapper capacity. Profile/reduce that
bridge or establish supported larger final-wrapper capacity before porting the
complete client verifier. [Postimplementation review](server-circuit-review.md).

The [capacity follow-up](bridge-capacity/README.md) measured a **15.37% bridge
step reduction** using checked M31 inversion; the same valid proof and seven
rejection controls pass. Actual OS steps fall to **6,206,195**. Its Blake
subcomponents still require log22. An isolated enlarged configuration builds,
but the actual proof run **OOMs at a96GiB server cap** before producing a proof.
This does not change the client prover or establish larger PROOF1 acceptance.

## Hash component

`blake/src/lib.cairo` implements unkeyed RFC7693 Blake2s-256 through Cairo's
constrained compression/finalization operations. It preserves all eight u32
output words and checks packed input lengths, byte ranges through typed
decoding, partial-word padding and a 65,536-byte input cap. There are no custom
hash hints or unchecked native hash results.

The [component report](results/blake-vectors-v3/report.json) records 17
full-output differentials: RFC `abc`, all requested padding boundaries, and
original/candidate framed messages. Four malformed encodings reject. The
later [candidate parity report](../m31-private-blake/results/cairo-hash-parity/report.json)
also covers all six actual Blake protocol domains.

For identical public framed input bytes, the initial software-SHAKE96 and
builtin-Blake32 implementations give:

| Payload | SHAKE96 Cairo steps | Blake32 Cairo steps |
| --- | ---: | ---: |
| 285-byte node frame | 143,651 | 1,778 |
| 5,053-byte trace-leaf frame | 1,836,535 | 24,114 |

These are approximately 76–81x reductions in executable steps, including the
different byte/u32 input handling. They are not equivalent hash outputs,
an optimized SHAKE lower bound, or a measured whole-prover speedup. Both
outputs were checked against independent standard implementations.
[Comparison](results/hash-comparison.json). Candidate 32-byte-child node
frames shrink to 161 bytes and take 1,195 steps in this harness.

## Actual outer proof

The public `BlakeCostAccount` computes and checks every supplied digest and
emits its class, actual chain, `BLAKE_COST_V1` domain, job/byte/compression
counts and a Poseidon aggregate of computed digests. This is a hash computation
statement; it cannot authorize membership or payment acceptance.

The [batch](results/batch-v1.json) contains one claims leaf, one trace leaf,
16 small leaves and 64 internal nodes: **82 jobs, 58,774 bytes and 954 Blake
compressions**. It retains conservative 192-byte salts for the component cost
test. Node children are public candidate-width stand-ins, not roots of a
completed Blake membership proof.

The original transaction prover and local verifier are byte-pinned in the
[anchor](results/outer-blake-v1-cap32/anchor.json). The synthetic state fixture
was compiled and reconstructed with the pinned sequencer libraries. No facts
were injected, proof parameters weakened or binaries patched.

| Measurement | Result |
| --- | ---: |
| Virtual OS execution | 589,958 Cairo steps; 0.790 s |
| Server proof stage | 27.419 s |
| End-to-end request | 28.223 s |
| Sampled process peak RSS | 29.05 GiB |
| Genuine PROOF1 artifact | 225,362 bytes |
| Original verifier | PASS; 159 ms |

Four pinned CPU workers, 32GiB cgroup cap, zero swap. These are one completed
server run, not latency distributions or client resource requirements. An
initial 16GiB cap OOMed and is retained separately. The state anchor is local
and synthetic: no Sepolia finality, transaction submission or node attachment
was tested.

The original verifier rejects a changed output-message digest, changed program
hash and corrupted proof bytes. A separate actual OS execution rejects a
one-bit change to an expected Blake digest with `HASH_MISMATCH`, before proof
production. [Successful run](results/outer-blake-v1-cap32/report.json),
[original verification](results/outer-blake-v1-cap32/local-verification.log),
[hash negative](results/outer-bad-digest/report.json).

## Full-workload capacity limit

`workload.py` independently authenticates retained public proof paths, replays
the final transcript/query schedule and verifies repeated-node consistency.
It does not substitute for the native AIR/FRI verifier. For the original SHAKE
proof, sharing identical internal nodes reduces 20,919 node evaluations to
5,678; expensive wide trace leaves remain.

For the newly retained Blake proof, authentication requires **43,166 Blake
compressions after shared-node reuse**. The pinned Cairo prover emits ten
rounds and eight Blake-G rows per round: at least 3,453,280 rows, padded to
trace log22. Its preserved configuration allows trace log20 with blowup log3
and lifting log23. Even the 233 trace leaves alone require 18,174 compressions
and 1,453,920 Blake-G rows, beyond log20 capacity.

This is a source-derived bound for this direct implementation and proof shape,
not a new failed full-verifier run or an impossibility theorem for Blake. It
excludes transcript, AIR/OOD/batch/FRI and OS work. More RAM cannot change those
fixed verifier parameters. [Analysis and source pins](results/capacity-analysis.json).

Do not launch another unchanged full workload solely to rediscover this
bound. The server circuit/bridge experiment above has now exposed a second capacity
gate. A narrower AIR that reduces authenticated leaf width remains another option. The standard Blake
operations provide a reusable implementation path for either, but the existing
recursive verifier does not automatically accept the custom proof format.

## Reviews and reproduction

The [Blake parameter review](blake-parameter-review.md) supplies pre- and
post-source approval for the component and approves a separately versioned
Blake32/salt96 research client. The
[independent original math review](../m31-private-e2e/independent-math-review.md)
corrects a theorem citation and qualifies knowledge-error and multi-proof
claims. Neither is production-security certification.

Build the `blake` and `blake_account` Scarb packages. `measure_blake.py` takes
`--public`, `--proof` and a fresh `--output`; `prepare_blake_batch.py` creates
the public batch. `run_blake_outer.py` takes `--fixture`, its pinned
`--fixture-sha256`, `--batch`, a fresh `--output`, and `--memory-cap-gib 32`.
Exact runtime commands and source/binary identities are retained with results.
The abandoned receipt-only account was removed; no receipt shortcut is used.
