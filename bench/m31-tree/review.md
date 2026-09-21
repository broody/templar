# M31 tree benchmark: construction and review

Status: frozen v2 source and recorded correctness evidence accepted for this isolated, entirely public validity/performance experiment. This review approves neither production migration nor a client privacy construction. Final resource/cost aggregation is recorded separately by the experiment owner.

## Exact construction

Reference: Plonky3 commit `00fe0a985b398d3ef1f10d69543ca2b8f9f236da`, `mersenne-31/src/poseidon2.rs::default_mersenne31_poseidon2_24`. The permutation has 24 Mersenne-31 coordinates, exponent 5, eight full rounds (four at either end) and 22 partial rounds. Import the fixed Grain-LFSR constants at this commit without regeneration or substitution. Apply the initial external linear layer before any rounds; use the current `MDSMat4`, not the older Horizen matrix. Full rounds add all 24 constants, apply all 24 S-boxes, then the external layer. Partial rounds add the scalar constant and apply the S-box to coordinate zero only, then the internal layer.

The external layer applies the matrix `[2,3,1,1; 1,2,3,1; 1,1,2,3; 3,1,1,2]` to each four-word block, then adds to each coordinate the sum of the corresponding coordinates across all transformed blocks. The internal layer is `all_ones + diag(V)`, where `V=[-2,1,2,4,...,2^22]` (24 entries). All arithmetic is modulo `P=2^31-1`.

Hash mode is the same commit's `Pad10Sponge` with width 24, rate 15, output length 9 and `Increment(1)`. Start with zero state. Overwrite the rate with each block; preserve capacity. On the last partial block, append field one and clear the remaining rate coordinates before permuting. Output the first nine coordinates. All messages below finish with a partial block, so the library's exact-full-block special case is not exercised by tree operations.

Every hash message begins with four M31 words `[0x544d5031, 1, kind, level]`:

| Operation | kind | level | Payload | Permutations |
| --- | ---: | ---: | --- | ---: |
| Funded leaf | 1 | 0 | Nine little-endian 28-bit limbs of the canonical felt252 commitment | 1 |
| Internal node | 2 | 1 through 32 | Nine left digest words followed by nine right digest words | 2 |
| Empty leaf | 3 | 0 | Empty | 1 |

The empty node at level `l>0` is `Node(l, empty[l-1], empty[l-1])`. A funded commitment of zero therefore differs from an empty leaf. Index bit zero selects the leaf's sibling ordering; bit 31 selects ordering immediately below the root. A parent at path step `i` uses level `i+1`. No commutative sorting of children is permitted.

The felt input encoder first requires the integer to lie in `[0, 2^251 + 17*2^192 + 1)`, then splits it without reduction into nine radix-`2^28` digits. This is lossless and every digit is below M31's modulus. A future private encoding would require constrained ranges and canonicality; the present public verifier performs these checks directly.

The nine-word digest is serialized canonically and packed into **two** Starknet felts: `low=sum(d[i]*2^(31*i), i=0..7)`, `high=d[8]`. Unpacking rejects `low>=2^248`, `high>=P`, or any unpacked digit `>=P`. Neither field reduction nor truncation is allowed. Contract frontier, root and history accounting must include this two-felt representation.

## Security scope and source evidence

Eight M31 words contain just under 248 bits, giving a generic birthday collision ceiling just under 124 bits. This benchmark deliberately uses nine-word output and nine-word capacity: each contains just under 279 bits, with a generic collision/capacity ceiling just under 139.5 bits. That supplies room for the reference permutation's **128-bit classical target**; it is not a proof of that target or a post-quantum claim. An existing single felt252 digest itself has a generic collision ceiling near 125.5 bits, so the candidates are not identical digest-size constructions.

The permutation design and round structure come from the [Poseidon2 paper](https://eprint.iacr.org/2023/323). Exact parameters, matrices, constants and sponge behavior are fixed by the [pinned Plonky3 sources](https://github.com/Plonky3/Plonky3/tree/00fe0a985b398d3ef1f10d69543ca2b8f9f236da), rather than S-two's illustrative Poseidon example. The latter has documented placeholder constants and is excluded.

The [November 2024 Least Authority report](https://leastauthority.com/polygon-plonky3-final-audit-report/) reviewed Plonky3 revisions `2edbd19b0482decf20443e90c78f375672da8241` and `7bb6db50594e159010f11c97d110aa3ee121069b`, including field and symmetric primitive code. It is useful historical evidence, not an audit of today's constants/matrices/sponge, this framing, this AIR, or this Cairo port. The report excluded hiding/zero-knowledge assessment. Production adoption requires a separate review of the exact deployed construction and current cryptanalytic assumptions.

The dated primary-source check also includes [Skipping Class (2026/306)](https://eprint.iacr.org/2026/306) and [Revisiting Linear Subspace Trails (2026/967)](https://eprint.iacr.org/2026/967). Their published abstracts describe stronger algebraic analyses of Poseidon families; the former explicitly distinguishes improvement over earlier analyses from a failure of claimed security. This review does not establish a dedicated concrete advantage bound for the exact width-24/rate-15/output-9 tuple. Full ePrint PDF retrieval was unavailable through the research tools; the accessible primary abstracts and pinned implementation were reviewed. No attack or disclosure diagnostic was executed.

PCS settings retain ordinary Blake2s, PoW 27, log blowup 3, 23 queries, fold step 4, last-layer degree log 0 and interaction PoW 24. The existing `27+3*23=96` metric is a configured PCS metric, distinct from the tree hash's 128-bit target and from an end-to-end soundness theorem. Lifting is verifier-derived from the largest component trace height plus log blowup. No stronger claim is inferred from passing proofs, or from using a much smaller trace domain.

For the 256-row pure-tree table, lifting log 11 follows from trace log 8 plus blowup log 3. This removes the felt252 closure's large fixed range-check tables; it does not reduce the configured queries or grinding. Mixed mode reinstates those fixed tables and lifting log 23.

## Approved AIR and statement boundary

One permutation per row; all intermediate round states are materialized. Each S-box has witnesses for `x²` and `x⁴`, with constraints `x²=x*x`, `x⁴=x²*x²`; each stored next state is constrained to the appropriate linear map applied to `x⁴*x` and unchanged coordinates. This gives 1,172 base columns (`24+8*72+22*26`) and quadratic constraints. The declared degree bound is trace-log plus one. The initial external linear layer is an expression before the first round and is applied exactly once.

A relation with a dedicated identifier binds the entire 24-word input and 24-word output of every row. The verifier derives its public boundary from the canonical statement; duplicates and deterministic padding retain their exact multiplicities. The public transcript and fixed shape/configuration are bound before lookup challenges. The AIR supplies negative lookup terms and the verifier supplies positive terms; the total must equal zero. This is the flat-AIR multiset consistency condition (`e:flat:AIR:consistency`, `prot:STARK:IOPP` in the local S-two whitepaper distillation), with quadratic quotient constraints as in `e:overall:identity` in the Circle STARKs distillation.

The verifier checks leaf encoding, tags, levels, sponge block wiring/capacity, padding, digest extraction, sibling order, depth, indices, chained parents and common root without computing Poseidon2. All permutation coordinates, including unused output coordinates, are bound. These are **public-transcript** checks, not a hidden-path membership circuit.

For mixed mode, preserve the latest ordinary `ctrl=0` RTN hash-call workload from `bench/return-note-e2e/cairo/src/statement.cairo`: two inputs, two outputs, no withdrawals. It contains 17 felt252 `hash_span` calls / 62 Hades permutations beyond the old tree's 128 permutations. Keep the original binding hash's felt252 root. The M31 tree and residual hashes form a labeled union workload, not a proposed new payment ABI or a proof of a complete migrated payment relation.

## Final source review

Reviewed the client AIR, statement, residual felt252 closure, orchestration, serialization and platform adapters, plus Cairo hash/tree and snapshot fixtures. The approved matrices/constants, state materialization, sponge wiring, canonical encoding and public lookup boundaries are implemented consistently. The RTN version is `TEMPLAR_RETURN_POC1`; the residual binding layout matches the selected reference. The combined lookup-count bound includes 256 new AIR occurrences and 256 corresponding public occurrences. No new unsafe arithmetic or copied dependency change was introduced.

The verifier derives configuration and preprocessing authority independently, binds the statement and claims before challenges, verifies interaction PoW, requires the public boundary plus component sums to vanish, and executes the full unchanged S-two verifier. Strict fixed-integer bincode decoding rejects trailing and truncated data. This benchmark parser is not a production hostile-input verifier review.

The initial v1 full proof exposed a pinned empty-preprocessing mismatch: `MerkleProverLifted::commit` represents zero columns with height zero, while the generic verifier constructor applied explicit lifting 11. Consequently the verifier requested nonexistent sibling hashes (`WitnessTooShort`). V2 normalizes only the first, independently trusted, zero-column verifier tree to height zero and requires its sampled values, queried values and hash witness to be empty. This also restores the prover's empty preprocessing query list. Root equality is checked first; the last/composition tree height, FRI settings, AIR, prover, transcript and generated proof bytes are unchanged. No core dependency patch or parameter reduction was used. The regression reproduces the original failure, confirms normalized success and checks identical configuration/channel state; three new malformed-opening controls exercise the guard.

The Cairo port reduces after each nonlinear product; operands are canonical and each product is below `P²<2^62`. Its matrix accumulations and shifted diagonal products fit in `u64`. Packing accumulates below `2^248`, so Starknet field arithmetic does not wrap. The contract retains the old append/root-history policy and zero-storage sentinel convention, while storing two felts for a digest; it is an isolated cost prototype, not a production tree review.

Snapshot installation restores every stored node, all 33 zero hashes, count/current root/initialization, ring index/slots and known roots. Raw-state tests bypass the empty-node fallback and include absent-node/root probes and all 256 ring slots. Genuine versus installed prefixes 1/2/8 pass for felt252 and 1/2 for M31. The M31 prefix-8 snapshot is independently reference-derived; it is not a completed eight-real-appends equivalence test. Fixture setup is excluded from measured append costs. Default local VM-step exhaustion is retained as evidence; a larger local budget does not establish on-chain executability.

## Recorded correctness evidence

- Six release unit tests pass, including independent Plonky3 vectors, quadratic degree metadata, four separately corrupted round masks, public-call binding, encoding boundaries, strict decoding and the empty-tree regression (`results/native-unit-v2/unit-tests.log`). The independent Python reference matched all 120 Plonky3 oracle cases.
- Native full-proof smoke tests pass in both modes. Pure mode rejects 19 unchanged-proof mutations plus two boundary controls; mixed rejects 17 plus three. These include structurally valid unused permutation outputs, actual proof samples/config/PoW/root mutations, omitted padding, discarded multiplicity, and the mixed memory dictionary. Reports are in `results/implementation-smoke-v2/tree-negatives` and `results/implementation-mixed-negatives-v2/checks`.
- Eight measured native proofs pass: three pure at a 1 GiB cap and five mixed (three at 3 GiB, two at 2 GiB). Eight Chrome proofs pass: three successive proofs plus a fresh-browser proof for each mode, under 1 GiB pure / 3 GiB mixed group caps. Each runtime verifies its complete proof; all browser envelopes equal the native envelope byte-for-byte within their mode. Browser suites repeat the same 19+2 / 17+3 checks. These are two distinct deterministic artifacts, not 16 independent statement/security cases.
- Thirty-six distinct Cairo correctness tests pass: 24 golden cases, four packing cases, five full-state snapshot cases, two rejection cases and root-history eviction. Earlier VM-step-limit failures remain archived; passing reruns used the recorded larger local budget where required (`results/cairo-correctness`).

| Envelope | Bytes | SHA-256 |
| --- | ---: | --- |
| Pure M31 membership | 197,320 | `d8f4881c20541419f45a4c96eb114dd82e9903b51bc41bc835a598576c68b332` |
| Mixed union workload | 464,900 | `d069e30789a0459126966b341e9921b1c21c1ade6ca822a08320bc700767e1fd` |

These checks support the stated public validity relation and implementation parity; they establish neither zero knowledge nor a complete migrated payment. Pure mode proves 130 permutations (two leaf hashes plus 64 two-permutation nodes), versus the older tree's 128 Hades permutations with raw felt leaves. Mixed mode includes the remaining large felt252 tables and retains an independent original binding root. Comparing their resource costs is meaningful; calling either a complete private payment cost is not.

Fresh-process repeats reuse the same grinding search, so latency describes runtime stability for these fixtures, not the distribution across payments. Native process RSS, WASM linear capacity and whole-browser cgroup charge are distinct metrics. The two successful mixed native 2 GiB runs have limited headroom and do not qualify a 2 GiB browser/device target. Browser runs use a beefy host under caps, not a physical consumer-device test. No cost or production migration conclusion follows from the isolated tree result alone.

## Frozen identities

All 18 client manifest entries and all 919 copied dependency entries (263 S-two, 656 stwo-cairo) match their recorded hashes at final review. The frozen source/artifacts are in `target/m31-tree/frozen-v2`; source manifests pin the complete set rather than only the files listed below.

| Reviewed item | SHA-256 |
| --- | --- |
| `client-source-manifest.json` | `017950352f49547e14d65dbe81ebfe279ecde228b4cb4e3f61f66ab189c5224f` |
| `copied-source-manifest.json` | `78724075824857191cde5530b76551eada56996ad620cbcdb89e8068dd0c1cca` |
| `implementation-handoff.json` | `c0e15a02330d27659d73fc68199388bc352d41c9bea2b77901de119b42eb10d5` |
| Client `src/lib.rs` | `ccd5785b70e1dc27fc5850a72c1f2b48a82c5994ada065e8caf8843ff5465bde` |
| Native executable | `afd206ceed8ebe44127840d4a3a908c48550934408e1c1a38bcba2dde0af6fc6` |
| WASM module | `5c67d4a66d880f1d1b199f53b49ce33bfdea61f5ebffda184cca6faa7588746c` |
| Cairo `m31_hash.cairo` | `d8d5f21a7c81523cadf0fb14ecd09d30e322ad8a11178068937fbf6a46d568ce` |
| Cairo `m31_tree.cairo` | `27cb1695d5eeed283c940514d027ab111b9aabeeb1efb49856ea99df366a379f` |
| Cairo `contracts.cairo` | `136728760a01e09ffb102ea6e93c64a195984d9a355b7b4090225f0d469b8916` |
| Cairo `tests.cairo` | `dfa01809754563c1f8c1e28ef515ccbdde17b2fd78713c6594968d28b8849116` |
| `generate-snapshots.py` | `fdea251cf97da4cf5992e83986317f44be4a8e31c53375b456e09f5ab68d8e95` |
