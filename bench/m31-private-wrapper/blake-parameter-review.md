# Blake2s compiler parameter review

2026-09-22. **GO for the exact public Blake2s component and its representative PROOF1 cost test. GO for implementing the separately versioned research candidate specified below, subject to subsequent source and cross-runtime review.** These are not approval of a completed inner verifier, production adoption, or an unconditional 96-bit security claim. The frozen SHAKE client is unchanged.

This review applies the nested S-two soundness checklist and relevant field, ZK-foundations and divergence instructions. Primary sources are [RFC 7693, sections 2–3 and Appendix B](https://www.rfc-editor.org/rfc/rfc7693), [BCS, Definitions 3.3/5.1, Lemmas 3.4/7.5 and Theorem 7.1](https://eprint.iacr.org/2016/116), and the independently checked Circle/Proximity Gaps derivation in [the companion review](../m31-private-e2e/independent-math-review.md). The sharper privacy estimate below is a derivation from BCS's proof, not a number quoted from its theorem. No implementation, tests, benchmarks or private-data diagnostics were executed by this reviewer.

## Exact proposed research version

Use ordinary, unkeyed **Blake2s-256**, with RFC parameter word `0x01010020`, ten compression rounds and all **32 output bytes**. Set `HASH=32` and `SALT=96` bytes. Salts are independent uniform application-level leaf randomness, not the optional Blake parameter-block salt. Preserve the six domains `circuit`, `public`, `state`, `coins`, `leaf`, `node`, and preserve their existing injective framing:

```text
ASCII("Templar-private-membership-BLAKE2S-v1")
|| u64le(tag length) || tag || u64le(part count)
|| for each part: u64le(part length) || part bytes
```

Use proof magic `TMPZK002`; reject the old magic in the new verifier and retain the frozen verifier for the old format. The prefix matches the current public cost fixtures. Pin the new source fingerprint independently; do not preserve the old fingerprint or accept a prover-supplied circuit identity.

Keep all AIR, masking, degree, OOD exclusion, quotient, batching, domain, FRI and **120 independent query draw** parameters unchanged. The M31 application-tree Poseidon2 hash also stays unchanged. New hash outputs change transcript coins and proof bytes, as expected for a new protocol version; byte identity with SHAKE proofs is not an acceptance criterion.

Hash bytes are arbitrary bytes. Cairo represents them as eight full little-endian `u32` words. Preserve bits 31 and 255 and every other bit; never reduce digest words modulo M31 or pack 256 bits into one Starknet felt. Field payloads retain their separate canonical M31 encoding. Existing field rejection sampling and domain-query bit selection operate only when interpreting transcript coins; they are not a digest representation.

The indexed `coins` function remains an independently framed Blake call per block. Each block supplies eight `u32` words, hence two QM31 candidates; 120 query words consume fifteen blocks. Blocks are used in order without repetition, counter wrap or truncation. For the ROM argument, sample the complete independent raw coin vector for a state on its first accessed block and reveal requested blocks lazily. This groups partial-block access into the same state-restoration opportunity; it does not treat concatenated digests as one wider collision-resistant hash.

## Knowledge error and the 96-bit research target

The unchanged IOP derivation gives `delta < 2^-98.143568`. With a 256-bit ideal RO, BCS's compiler term becomes

```text
e(m) <= m*delta + 3*(m^2+1)/2^256 + sampler-abort terms.
```

At `m=2^96`, these leading terms are approximately `0.22631936745` and `3*2^-64`. Thus the hash compiler term is small relative to the unchanged algebraic knowledge-error term. This supports the stated **classical RO-query research target at constant extraction loss**. It is not a statement that an adversary with that budget has success probability `2^-96`, nor does knowledge extraction alone prove a practical payment-forgery work bound. Honest proofs and replays verify; this AIR has no payment amounts, nullifiers or funding rules. Quantum-query claims are outside this review.

The numerical theorem assumes an ideal 256-bit random oracle. Concrete Blake2s is the specified cryptographic instantiation, not a proven random oracle. Longer salts do not raise its collision-output width. Concatenating independently framed Blake calls does not automatically justify reusing the old 768-bit compiler bound.

## Why 96-byte salts, and what privacy bound is justified

Substituting `lambda=256` into the published coarse BCS privacy corollary `p*2^(-lambda/4+2)` gives only a bound below `2^-32` using `p<2^30`. That corollary alone is insufficient for a stronger numerical privacy claim. A sharper fixed-block calculation is possible for this exact bounded construction.

For an ideal 256-bit RO, fix a leaf prefix, a payload of b bits and an output y. With an S-bit uniform salt, the number N of salts mapping to y is binomial with mean `mu=2^(S-256)`. For `0<eta<=1`, the multiplicative Chernoff bound gives

```text
Pr[|N-mu| > eta*mu] <= 2*exp(-eta^2*mu/3).
```

Uniform relative regularity implies total variation at most `eta/2`; use the weaker `eta` below. A union over every payload, output and fixed prefix makes the property simultaneous, including for payloads selected using earlier RO information. The largest actual payload is the 9,544-word claims leaf: `b=305408` bits. There are `L=40946` leaves and `I=40931` internal nodes across all fifteen trees. Fewer than 256 different `(tree, depth)` internal prefixes occur.

For **96-byte salts**, `S=768`, `mu=2^512`. Take `eta_leaf=2^-192`; its Chernoff exponent is `2^128/3`. A union over fewer than `2^16` leaf prefixes, all `2^305408` possible payloads and all `2^256` outputs still has failure far below `2^-256`.

For an internal node, the input after its fixed framing consists of two independently uniform 256-bit children in the BCS marked-node hybrid. Regardless of salt length, its entropy is only 512 bits and `mu=2^256`. Take `eta_node=2^-123`. The exponent is `2^10/3`. A union over outputs and fewer than `2^8` internal prefixes bounds the bad-oracle probability by

```text
2^(1+256+8) * exp(-1024/3) < 2^-227.
```

Condition on this simultaneous regularity. Replace unopened salted leaves by independent uniform labels, then replace nodes whose children have both been replaced, exactly as in BCS Lemma 3.4. At each replacement the above TV bound applies conditional on the fixed oracle; remaining tree computation cannot increase TV. Opened payloads and salts stay unchanged. Prefix reuse at a depth does not break this step: independent uniform child pairs passed through a fixed function give independent output variables. The terminal marked-tree simulator needs only disclosed payloads. Taking a deliberately conservative factor four for these hybrids and their bad-oracle accounting yields

```text
epsilon_Merkle <= 4*L*2^-192 + 4*I*2^-123 + 2^-227 + negligible
               < 2^-105.
```

The honest-verifier algebraic simulation remains the same joint simulation of base/Q/R/FRI observations described in the companion review. Applying BCS's single-proof programmable-ROM step therefore gives this fixed-shape, single-proof ideal-model privacy overhead, plus sampler-abort terms. It is not a new masking construction and is not inferred from passing tests.

Salt choices:

| Leaf salt | Effect on this derivation |
| --- | --- |
| 64 bytes | A tighter choice `eta_leaf=2^-116` still beats the union over the largest payload; a conservative total is below `2^-98`, with substantially less margin. Not selected. |
| **96 bytes** | Leaf term becomes negligible relative to internal nodes; selected bound is below `2^-105`. |
| 128 or 192 bytes | Further improves an already negligible leaf term; does not improve the internal-node bottleneck above. |

Keeping 192 bytes for an initial cost probe is acceptable and costs at least as many leaf compression blocks. A candidate claiming 96-byte salts must actually use that exact length in generation, parser and leaf framing; no silent mixed-format acceptance is approved.

## Finite and adaptive use

Every invocation and retry requires fresh independent masks, R and all leaf salts. A hash substitution does not repair randomness reuse. The public prover's `CryptoRng` bound cannot prevent callers from cloning or restoring RNG state.

For a fixed finite list of independently randomized proof instances, the algebraic oracle-view simulators compose. The private-Merkle replacement contribution grows at most linearly with the number of instances; for example, 512 times the displayed bound remains below `2^-96`. **That arithmetic is only the Merkle-hybrid contribution, not a complete shared-oracle service theorem.**

An online adaptive service additionally needs one consistent oracle/programming table, justified freshness of new state/coin addresses and explicit handling of previously answered queries. The companion review leaves that concrete composition lemma open. A conservative form would add `O((m+2^20*t+1)^2/2^256)` for t proofs and m adversarial RO queries, with constants still to be established. At `m=2^96`, its scale is `2^-64`, not `2^-96`. Do not advertise unlimited-session statistical privacy, adaptive simulation-extractability, or a `2^-96` distinguishing bound against a `2^96`-query adversary. These limitations are compatible with the labeled research prototype; stronger service claims require a completed composition argument.

## Public component source and evidence

**Scoped post-source GO** for `blake/src/lib.cairo` and the public `blake_account/src/lib.cairo` cost account. The hash function uses the standard initialized state, cumulative byte counts, full final block for exact multiples of64, one zero final block for an empty message, and zero padding only beyond the actual message. It checks the exact packed-word count and unused high bytes of a partial word. Its 65,536-byte cap makes the high half of RFC's byte counter zero and prevents arithmetic overflow. All eight output words are retained.

The source calls Cairo2.18's `core::blake` compression/finalization externs, whose documented packing matches RFC7693. It contains no custom hash hint, unconstrained host digest acceptance, or reduced-to-M31 conversion. VM execution alone does not establish compatibility with the preserved outer prover; the additional actual PROOF1 evidence below addresses that component gate.

The account deserializes bounded `u32` inputs, checks every expected digest word against the computed result, and publishes class/chain/domain, job count, total bytes, compression count and a Poseidon aggregate of all computed digest words. Its job and message caps keep both counters inside `u32`. The statement is only that these public hash jobs were evaluated; it does not assert membership or native inner-verifier acceptance. This public prove-only account is not approved for production authorization or funds.

Read-only inspection of `results/blake-vectors-v3/report.json` and the test-driver source records **17 full-output differentials and four encoding rejections**: RFC's `abc`, lengths0/1/63/64/65/127/128/129, and original/candidate framed node, small, base and claims messages; nonzero padding, wrong length, out-of-range `u32` and excessive length reject. I did not rerun them. The archived representative batch uses 192-byte salts, 82 jobs, 58,774 input bytes and **954 compression calls**. Its candidate children are public fixed-width cost stand-ins, not authenticated children of a completed Blake proof. Results must retain that label. This is not yet whole-verifier performance evidence.

The subsequently inspected `results/outer-blake-v1-cap32/report.json` and `local-verification.log` record a real preserved PROOF1 for that public batch: exact public binding, original local verifier acceptance and three rejected mutations (message digest, program hash, proof bytes). Request time was28.223 seconds, peak RSS29.052GiB, proof225,362 bytes, with four cores and a32GiB cap; swap was zero. This was a local authenticated synthetic fixture, not a node attachment or live-chain acceptance claim.

**The full wrapper still has a size gate.** The root's source-based inventory reports43,080 deduplicated compression calls for the full96-byte-salt candidate workload. At the pinned implementation's80 `blake_g` rows per compression, that is3,446,400 rows, requiring log22 rather than the preserved log20 trace ceiling. Even the239 base leaves at78 blocks each exceed that ceiling under this row construction. This is a source-based scale estimate, not a measured full verifier. The parameter GO authorizes an isolated new native candidate; it does not assert that changing the hash alone makes its complete Cairo verifier fit. A route or representation change needs its own concrete review and must retain full verification.

Before accepting a new native/Cairo inner verifier, require review of all six domain frames, version/fingerprint binding, full digest/salt parsing, indexed coin parity, and unchanged complete AIR/OOD/batch/FRI checks. Test full-byte hash and transcript parity, malformed encodings and changed high digest bits, rejection of old-format proofs and all existing semantic proof mutations. An actual preserved-PROOF1 run of the representative component is a feasibility gate; it cannot substitute for executing those verifier checks inside the proved wrapper.

## Reviewed identities

Frozen SHAKE client identities were rechecked and remain exactly those listed in the companion review. The reviewed report's SHA256 is `1f9e5d3c8f1453517871b0e5a5460a644cf54694890ea7ad6b044c4467344d63`.

```text
blake/src/lib.cairo
  5aa2d88b8f7e417a5b4778dc96456a8214f8e08620cd8fbdd9eca0d10533a817
blake_account/src/lib.cairo
  5b346ce058912a18ecfaf5eba33729661a30befe49fef4607ec0a8ddb371198b
blake/Scarb.toml
  cc1e74eb9fb58bc462f1d879d1d0b3ee23a2827fa8fe65516bd291cec81ffe00
blake_account/Scarb.toml
  62994153d7a84ac1349b80708b43b68ec5887b844e266c35038d32008cebd65b
results/blake-vectors-v3/report.json
  f7463a0cda729b658185fdbc5f7faea465b1d4db82e6e38a86ec579abd4afed3
results/outer-blake-v1-cap32/report.json
  8a24126d0a29a6c00c9747877c620c5f719e1590dbd062b6cd48221f0fbbe4e3
results/outer-blake-v1-cap32/local-verification.log
  af3deb3b85a3cc38ff7f189cfbcf5329bbe0fdaac296359a5f5efdab8994aadd
Scarb cached core v2.18.0/src/blake.cairo
  fdc34c24626ae22bed86fec83c37adce7549d6762d9ef49fbba6affcd9ba3410
```

Paths above are relative to `bench/m31-private-wrapper/`, except the explicitly identified Scarb core source. BCS's exact cached PDF identity is recorded in the companion review. The RFC specifies the primitive; it does not certify this compiler or the concrete application.
