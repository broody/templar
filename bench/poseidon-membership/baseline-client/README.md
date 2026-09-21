# Public-transcript Poseidon membership client

This isolated executable proves the validity of two **public**, synthetic depth-32 Merkle paths. It does not implement private membership, the complete payment relation, zero knowledge, browser proving, or Cairo execution. No upstream dependency source is modified.

The client regenerates all 64 pair hashes and 128 Hades permutation states from the supplied leaves, indices, and siblings with `starknet-types-core` 0.2.4. It checks the saved fixture as an independent parity oracle. This regeneration is included in the timed process.

The public verifier checks canonical felts, exact shape, index bits, sibling ordering, leaf/root endpoints, intermediate path links, and the two-call `poseidon_hash_span([left,right])` sponge convention. It **does not evaluate Poseidon**. The unchanged upstream felt252 Poseidon AIR proves the 128 permutation obligations, with its full round, partial round, cube, key, and range-check dependency closure.

All felt values are public. An independently rebuilt, sorted public dictionary replaces the memory table AIR: the verifier computes each required `MemoryIdToBig` lookup yield. Requests are deduplicated by their three input IDs, conflicting outputs are rejected, and exact request multiplicities are retained. The fixture has 126 unique requests and 128 aggregator rows after padding. The public boundary contains 128 positive Poseidon terms and 768 negative memory terms, including the six reads of each zero-multiplicity padding row. The boundary plus all 12 component interaction sums must be zero.

The custom preprocessing subset is committed locally from pinned upstream column definitions. The verifier checks this trusted root and the exact PCS config. This is not the canonical Cairo preprocessing root, and the program does not call the stock Cairo verifier.

Configuration: ordinary Blake2s; FRI PoW 27, blowup log 3, 23 queries, fold step 4, last-layer degree log 0, lifting LDE log size 23 (maximum trace log size 20), plus Cairo interaction PoW 24. The PCS `security_bits()` metric is 96; it is not a new security proof. RangeCheck20 remains a fixed 2^20-row table. Cached coefficients and full evaluations are the baseline storage policy.

Invocation:

```
RAYON_NUM_THREADS=1 templar-poseidon-membership FIXTURE_JSON FRESH_OUTPUT_DIRECTORY
```

For verification-only checks, run `RAYON_NUM_THREADS=1 templar-poseidon-membership --verify-tests PROOF_BIN FRESH_OUTPUT_DIRECTORY`. This reads the saved proof and independently recomputes its trusted preprocessing root without proving again. Use this separate invocation to keep mutation tests outside timed process measurements.

The optional final argument `--negative-tests` on a proving invocation runs 13 unchanged-proof mutation checks and three public-boundary controls **after** the measured proof/verification phases. Mutation checks cover public links, a structurally valid permutation output, proof samples, configuration, preprocessing root, interaction nonce, and claimed sums. Boundary controls explicitly check that omitting padding reads, discarding duplicate multiplicities, or changing the public memory dictionary makes the verifier's sum equality fail. They do not claim a separate malformed proof was constructed.

Artifacts are `proof.bin`, `proof.json`, `shape.json`, `summary.json`, and optionally `negative-tests.json`. Proof envelopes contain the complete public statement, component claims, interaction sums and PoW nonce, and the STARK proof. The summary distinguishes public statement size, bare STARK size, and complete envelope size. Native verification deserializes only the public envelope and checks it against independently generated preprocessing authority.
