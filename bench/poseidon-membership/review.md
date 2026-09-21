# Poseidon public-transcript membership review

Status: targeted source and final run review complete. The public-transcript benchmark and narrow storage integration passed correctness checks. The 2 GiB cap is unreliable; no private-payment or browser qualification is established.

Scope is two public depth-32 paths with the existing felt252 `poseidon_hash_span([left, right])` semantics. This review does not approve a private membership AIR, a complete payment proof, a new blinding construction, browser support, or deployment. The earlier `bench/direct-air` archive is preserved; no additional disclosure or recovery diagnostics are part of this work.

## Review basis

The Math Reviewer delegation follows `target/direct-air/stwo/AGENTS.md` and `stwo-cairo/AGENTS.md`. Required `soundness-review-checklist`, `air-constraint-engineering`, and `paper-implementation-divergence-log` skills were read. The governing whitepaper anchors are `def:flat:AIR`, `e:flat:AIR:consistency`, `e:constraint:uses`, `e:constraint:yields`, `e:constraint:sum:increment`, and `prot:STARK:IOPP`: every row constraint and every use/yield multiplicity, including public terms, must hold. The existing FRI, field arithmetic, commitments and verifier remain unchanged. This experiment does not use the unrelated M31 Poseidon2 example.

Upstream bases are S-two `489a0f3ee44a59e03944ad9aa4f3e5a91a3d3f08` and stwo-cairo `9b6be2710e4d7124bc93fe80a5af36556d42ed29`. The isolated dependencies retain earlier reviewed storage/allocation changes; these bases alone do not assert pristine source trees. `environment.json` records the archive identities. Final source identities and evidence appear below.

## Exact approved relation

The statement contains two canonical public leaves, two unsigned 32-bit indices, 32 siblings for each leaf, one common root, and all intermediate permutation inputs and outputs. All data is synthetic. The fixture uses sparse positions `0x13579bdf` and `0xeca86420`; this is no claim about a funded pool or append history.

For each path, the native verifier checks the following inexpensive relations itself, without evaluating Poseidon:

1. There are exactly 32 levels and two permutations per level, with an unambiguous path/level/phase order. Every felt encoding is canonical in the Stark field.
2. The direction at level `i` is bit `i` of the public index. It determines which of the current node and sibling occupies the left and right position.
3. The absorb permutation input is `[left, right, 0]`. The finalization permutation input is `[absorb_output[0] + 1 mod p, absorb_output[1], absorb_output[2]]`. The level's parent is `finalization_output[0]`.
4. The first current node is the stated leaf, each parent becomes the next current node, and the final parent equals the common public root.

The proof establishes that all 128 requested permutations are valid. There are 64 two-element `hash_span` evaluations, each requiring the final even-length padding permutation. These obligations, combined with the verifier's public bookkeeping, constitute **public-transcript membership validity**. Prover-side assertions alone would not establish the relation.

## Lookup boundary and dependency closure

Reuse the pinned `PoseidonAggregator`, full-round chain, three-partial-round chain, cube252, round-key and width-27 range-check components, together with fixed range-check tables `3_3_3_3_3`, `4_4_4_4`, `4_4`, `9_9`, `20` and `18`. Their constraints, range checks, round constants and interaction traces are preserved. The aggregator contains the existing complete Hades wiring. No Cairo CPU or virtual OS is needed for these components.

The public-input adapter may use the existing memory witness generator as a deterministic value oracle while omitting the memory AIR. This is safe for this public relation only because the native verifier independently supplies the exact missing public lookup terms:

- Positive `PoseidonAggregator` terms for all 128 requested occurrences, including repeated requests with their true multiplicity.
- Negative `MemoryIdToBig` terms for all six reads of **every actual aggregator row**, including deterministic zero-multiplicity padding rows. Those reads are unconditional in the aggregator AIR. Each term contains its relation ID, the independently assigned value ID and the exact 28 little-endian 9-bit limbs of the canonical public felt.

The verifier rebuilds the canonical public value dictionary and distinct-request list. It derives the aggregator height and its padding from that list, rather than trusting a proof-provided boundary sum or memory table. Public ID assignment must be deterministic; conflicting outputs for the same permutation input must be rejected or sorted with a fully specified total order so the padding row is unambiguous.

After deriving the lookup challenges, verification independently computes the public boundary and requires:

`public_boundary + sum(all included component interaction claims) == 0`.

All other dependency relations remain closed by their unchanged AIR tables. Replacing the memory yield does not permit omitting range checks generated by the aggregator, chains or cube component. All relation-use bounds must remain below the M31 characteristic. Public requests, configuration, component shape and the independently trusted preprocessed commitment must be bound before the lookup challenges. Prover and verifier must use identical transcript order, and the complete upstream STARK verifier must run.

An independent structural read of fixture SHA256 `019395a2feb2b2e7d49336bdef71c854acad3e57834c7fd95ccb7398f68fcf9a` confirmed canonical ranges, indices, child selection, chaining and the two-permutation padding links without recomputing Poseidon. Its 128 requested occurrences contain 126 unique permutations, padded to 128 aggregator rows. Thus the memory boundary contains 768 terms; the real fixture exercises both duplicate multiplicities and two zero-multiplicity padding rows. The paths have respectively 20 and 12 set direction bits.

The selected PCS configuration is the pinned Cairo `CAIRO_PCS_CONFIG`: PoW 27, log blowup 3, 23 queries, fold step 4, last-layer log degree 0, and `lifting_log_size = Some(23)` for maximum trace log 20. Its `security_bits()` arithmetic is 96; this is not an independent theorem for the entire application. The pinned Cairo interaction PoW is 24 bits. The application wrapper must grind, verify and mix that nonce before drawing the common lookup elements; generic `verify_ex` does not perform this outer step automatically. The synthetic artifact uses the supported ordinary Blake2s channel, whereas the existing payment Cairo prover selects Blake2sM31. No PROOF1 compatibility is claimed.

## Initial implementation review

The new code is confined to `client/src/statement.rs` and `client/src/main.rs`; dependency code is reused. `Statement::validate` performs all public bookkeeping without calling Poseidon. Witness preparation separately regenerates every permutation using `starknet-types-core` and compares the result with the Python fixture. The dictionary is sorted by canonical felt value; request aggregation rejects conflicting outputs for equal inputs, so the upstream input-only sort and first-row padding agree with the verifier's deterministic construction.

The reviewed verifier checks the exact PCS configuration, four commitments and the externally supplied trusted preprocessing root. The root used by this harness is generated from the pinned selected column definitions, independently of the witness or proof envelope. The adapter fixes the aggregator height from the public request set; other component heights are bounded to 4–20 and the sum of all positive relation-use bounds plus public terms is required to be below the field characteristic. That total-count check is more conservative than checking each relation separately.

The transcript order is the domain tag, fixed config, canonical serialized statement, preprocessing commitment, component claims, original-trace commitment, verified/mixed 24-bit interaction nonce, common lookup draw, independently checked public boundary plus component sums, mixed component sums, interaction commitment, and the unchanged core STARK protocol. Twelve components are instantiated in the same order for witness, claims, interaction traces and verification. The full verifier executes after the boundary check; early structural checks do not replace it.

No constraint, cryptographic arithmetic, FRI setting or dependency source was changed by this adapter. No new unsafe block was introduced. This targeted source review found no unresolved binding or lookup-closure issue in the implementation examined. It is not an independent audit of the reused generated Poseidon AIR or of S-two. Negative and integration evidence is recorded separately below.

## Required implementation evidence

Source review must establish exact boundary signs, tuple limb order, unique-request multiplicities, padding reads, transcript order, fixed preprocessing authority, degree bounds and the complete dependency list. Security parameters must remain the selected pinned settings, explicitly recorded rather than supplied by a proof or inherited from test defaults.

Tests must compare every requested permutation and path root against the existing Python fixture and an independent Rust felt252/Poseidon reference. The real native verifier must reject an unchanged proof when the public root, leaf, index, sibling, intermediate input/output, sponge padding, request occurrence or memory binding is altered. Separate boundary tests must exercise duplicate aggregation and zero-multiplicity padding. Proof/config/commitment corruption must fail. A successful prover-side fixture check is not a substitute for these verifier tests.

Measurements must include preprocessing, witness construction, proving and verification in a fresh process. Report complete-process peak RSS and cgroup peak, CPU/thread limits, swap, phase and total time, proof bytes and public-transcript bytes separately, component heights and source/build identities. Native one-thread success does not establish WASM compatibility. The fixed range tables impose a material cost even for 128 permutations; any logical-cell estimate is not an RSS lower bound for every possible storage schedule.

## Baseline evidence and approved storage follow-up

The archived `results/baseline-8g-1t` process exited successfully and its summary records a complete native proof verification, independent Rust/Python reference parity, the expected 126 distinct requests, 128 aggregator rows and 768 public memory terms. Peak RSS was 4.281917572 GiB; sampled cgroup peak was 4.284519196 GiB under an 8 GiB cap, with zero swap and no OOM kill. External process elapsed time was 8.580180097 seconds; the client's narrower internal timer was 8.369771952 seconds. These timings must not be conflated. The STARK binary was 258,621 bytes; its envelope including the public statement was 334,307 bytes. The public statement alone was 76,996 bytes in JSON. These are different encodings and do not add arithmetically.

`results/baseline-2g-1t` records an OOM kill under the 2 GiB cap and no completed proof. The last completed artifact was the component shape, before a successful base commitment. Baseline success at 8 GiB is therefore not evidence of a 2 GiB client.

All three fresh baseline processes passed. Their RSS peaks were 4.281650543–4.281917572 GiB and external elapsed times were 8.580180097–8.815943766 seconds. Independent hashing confirmed all three complete binary envelopes have SHA256 `7883c50e7125e608365e7887b50df589ac57bcc91438fe2f1f660caf56a9631e`. The archived release unit log records three passing statement/parity/duplicate-padding tests. The separate saved-proof verification run passed all 13 mutation rejections, including a structurally valid public output change, changed OOD sample and untrusted preprocessing root. Three additional controls checked that omitting padding reads, discarding duplicate multiplicities or substituting the public memory dictionary makes the exact boundary-plus-original-sums equation nonzero. These controls test that verifier equation directly; they are distinct from the 13 full verification attempts.

The baseline compiled source identities supplied for review were `client/src/main.rs` SHA256 `4e80eb48b697e6f3b85004f8709a11c16050159b051353e3b4d0e004a9409e6c`, `client/src/statement.rs` SHA256 `59e93a6864e5064d393fb36480b9a46c4db9f368993b3a16327efe3d7650209b`, and executable SHA256 `0ca540ea98f0034face61e4c4628f0aa198fd9f3d2fd399a5249f541b0fd1128`. Mechanical compiler fixes and the saved-proof verification entry point do not change the reviewed relation. The saved-proof verifier regenerates its preprocessing root from pinned definitions before checking the deserialized public envelope.

The approved follow-up is only an opt-in call to existing `pcs.set_bounded_memory_mode(16)` immediately after PCS construction and before the first commitment. The baseline remains the default. The choice is recorded in measurement metadata, never mixed into the transcript or serialized proof. All twelve components are `FrameworkComponent`s and therefore use the already reviewed coefficient-backed evaluation adapter; all trees are created as owned trees by `tree_builder`, so their coefficients are available before evaluations are evicted. No special component bypasses that adapter.

The implemented flag was re-reviewed: it accepts only the fixed `--bounded-columns=16` option, calls the existing setter before the first `tree_builder`, and changes only summary fields otherwise. Statement, configuration, transcript and verification logic are unchanged. Source review and the exact-byte integration check below support this isolated storage change.

Frozen final adapter identities, independently read after the flag integration:

| File | SHA256 |
| --- | --- |
| `client/src/main.rs` | `b15fda90e181163a5e7ba1a9b6aac29b594ad376fb86c5e5ee00b921cfaf9fc8` |
| `client/src/statement.rs` | `59e93a6864e5064d393fb36480b9a46c4db9f368993b3a16327efe3d7650209b` |
| `client/Cargo.toml` | `69326a165c8026e84c1b265ae0d935f188b47058d2a04ffa5f91f9c3afaf8247` |
| `client/Cargo.lock` | `3467d6bd73a0eaedd9d4e16b781d1154319a055897f5209ca6ebae433725d730` |

The inspected PCS, quotient, polynomial and framework adapter source files are byte-identical to the earlier reviewed `target/bounded-memory/stwo` copies:

| Source beneath `stwo/` | SHA256 |
| --- | --- |
| `crates/stwo/src/prover/pcs/mod.rs` | `28196748fe6d477e0636816dc00922d6ca3914bc3e477663794106e9502b5851` |
| `crates/stwo/src/prover/pcs/quotient_ops.rs` | `f5d38747be4bcd21e9cb509ee87fc221f71bb04fd73edb3eec39cce0ec63bcf1` |
| `crates/stwo/src/prover/poly/circle/mod.rs` | `591d9e9b3e6b982d561573b849e1f670de74c94f78eed0a5e361606b7cb3dc4b` |
| `crates/constraint-framework/src/prover/component_prover.rs` | `492d234a2157d7efbcb09efbfdf2fc7dc3539d6153252255c19aa54fcde76e8e` |

Their preservation obligations remain exact committed domains and bit-reversed prefixes, the same OOD values, stable FRI coefficient/order assignment, and the same reconstructed Merkle roots and openings. The existing mode changes retention and evaluation scheduling; it introduces no new proof mathematics here. Full envelope byte equality against the saved baseline and unchanged native verification are required for this integration.

This mode still materializes one complete tree during each commitment and opening; composition regeneration is component-scoped, and only FRI regeneration is bounded to 16 columns. It is not a global 16-column memory bound and does not guarantee the 2 GiB target. No new algorithm, dependency change, parameter reduction or privacy construction is approved in this follow-up.

## Final integration result and decision

Independent byte comparison of all eight archived successful binary envelopes confirmed exact equality, including their public statement, claims, configuration, roots, interaction nonce and full STARK proof. Every successful run recorded native verification. Their common SHA256 is `7883c50e7125e608365e7887b50df589ac57bcc91438fe2f1f660caf56a9631e`. The final executable is SHA256 `9c44542bd838100722358edc8c92f91e08012c4e59ebbf2b6ea35813c95c8974`. The three release unit tests also passed after the flag integration; the baseline and final logs therefore contain six executions of three distinct tests.

| Same final executable, one native thread | Cap | Successful runs | Peak RSS | External process elapsed |
| --- | --- | --- | --- | --- |
| Baseline storage | 8 GiB | 1 | 4.282493591 GiB | 8.669931740 s |
| Coefficient-backed storage | 3 GiB | 3 | 1.969985962–1.970123291 GiB | 14.077670533–14.136051890 s |

These four matched runs used the same fixture, configuration and proof relation, with zero swap and no OOM kill. The three bounded runs' recorded cgroup peaks were 1.967674255–1.967761993 GiB. Against the same-executable baseline, peak RSS decreased approximately 54%; mean elapsed time increased approximately 63%. These are fresh native processes on the recorded host with CPU affinity and Rayon thread count fixed to one, not desktop-wide or browser memory measurements.

At the **2 GiB cap**, the bounded configuration passed once at 1.969989777 GiB RSS, then its identical executable and input were OOM-killed on the next fresh run after interaction witness generation during commitment/STARK proving. The first success therefore does not support a reliable 2 GiB claim. Together with the baseline 2 GiB OOM, the archive contains two failed cap probes, eight completed proofs and one separate saved-proof mutation-check process. The run-to-run memory variation was observed; its exact allocator/runtime cause was not isolated in this experiment.

The narrow storage change preserves the measured proof exactly and improves native memory substantially. It does **not** satisfy the agreed criterion of substantial headroom below 2 GiB, even for this public arithmetic subset. A complete private payment, its client privacy wrapper and WASM/browser runtime remain unmeasured. This result supports preserving the experiment and its allocation lessons; it does not justify advancing to a full private-payment client on a claim that the resource or privacy gates have passed.

Final evidence is in `results/aggregate.json`, the per-run resource/command/proof files, `results/baseline-verification-checks/checks/negative-tests.json`, and the release unit logs. Dependency manifests identify 203 S-two source files (manifest SHA256 `013fb80b335e502ec7a9a7d4a2597ed4d1294455b965b4df3847a9cc72151642`) and 322 stwo-cairo source files (manifest SHA256 `1fd51b147d9b74757563ce255e63d7b3b3b44dbad2a08b537518862f96369985`). No further source change or new privacy analysis was part of the final integration review.

## What remains for private membership and payments

This benchmark exposes every path value and intermediate state by design. A private implementation cannot use this public boundary to disclose or validate its hidden witness. It still needs constrained hidden path bits/index reconstruction, child selection, sponge padding with felt-field carry/reduction, path chaining, and binding of only the intended public leaf/root or commitment outputs. Those constraints must connect to the same Poseidon relation without exporting the paths.

The complete Templar transaction additionally requires its actual note commitments and ownership authorization, nullifiers, amount/token conservation, output-note construction and transaction/public-intent binding. The current sparse public fixture establishes none of those. Therefore this benchmark measures a substantial arithmetic component, not the total footprint of a private two-input/two-output client proof.

## Client privacy routes visible in the pinned sources

This is a design-level assessment only; no further disclosure diagnostics or new masking construction are included.

1. **Existing fixed Cairo privacy recursion.** The pinned `proving-utils/crates/privacy_prove/src/lib.rs::privacy_recursive_prove` builds a Cairo execution proof, prepares it as the witness of the fixed Cairo-verifier circuit, invokes the pinned circuit blinding/finalization, and exports the recursive artifact plus its defined public output preimage. That is the concrete integrated route present in the sources. Keeping both inner execution and privacy wrapping on the client preserves the intended client/server boundary. Its measured native costs remain the current working reference; this review does not independently establish its zero-knowledge theorem.
2. **Direct AIR with a client-local privacy wrapper.** A compact Poseidon AIR could become the private input to a fixed, reviewed verifier circuit running on the client. Only the completed privacy-qualified wrapper artifact and public statement would be sent to a server. The pin provides generic circuit/STARK building blocks, but a custom AIR verifier circuit, its fixed topology/root, complete statement binding, privacy parameter justification and compatible serialization would still require review and measurement. The generic circuit blinding API is not, by its existence alone, a documented guarantee for every new topology.
3. **Direct application circuit or native AIR masking.** The pinned circuit code supports arithmetic and Blake gate families. It does not supply a ready-made, reviewed felt252/Poseidon payment circuit with a general privacy guarantee. The reused Cairo Poseidon AIR also does not provide a turnkey privacy mode. A new application circuit or new native masking design would therefore be separate cryptographic work, outside this experiment.

The source-level name `privacy` and a proof that verifies are not sufficient evidence for a new construction's witness privacy. Likewise a server-side wrapper cannot make data already handed to that server private from it. The practical decision is to keep the existing integrated route as the reference while this experiment isolates arithmetic cost; adoption of a compact client architecture requires a separately supported privacy route and its full client resource measurement.
