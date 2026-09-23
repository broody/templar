# TMPZK002 client verifier port

2026-09-23. Goal: a server circuit ("circuit A") that verifies one frozen
`TMPZK002` Blake private-membership proof against its public statement.
The existing Cairo bridge verifies circuit A's proof inside the virtual OS,
and `privacy_recursive_prove_large` wraps that execution as PROOF2. The
client format is ported unchanged; circuit-friendly format changes come later
and need their own review.

## Why two layers

A direct Cairo verifier does not fit one transaction. A virtual block allows
1.1B L2 gas at 100 gas per step, so about 11M steps. The ~89k Blake
compressions alone cost about 297M gas. QM31 arithmetic is unavailable as an
opcode in the privacy component set, and batching over 120 queries × 1,191
columns needs about 430k QM31 multiply-adds. Circuit A absorbs this work. The
bridge's cost grows only with circuit A's log size. It measured 4.7M account
steps at log20.

## Oracle

`oracle/` compiles the unchanged `bench/m31-private-blake/client/src` against
the server's stwo pin. All 8 client tests pass. It accepts the 6 retained
native/browser proofs. Every circuit gadget is tested differentially against
it.

## Statement

Public input is `x = MAGIC || circuit_digest || serde_json(Public{chain,pool,root})`,
exactly as in `proof::public_bytes`. Circuit A takes `x` as guessed bytes, uses
them in every transcript hash, and outputs `Blake2s(len(x) || x)` together
with the nine root words and the chain/pool felts. The bridge rebuilds canonical `x` from
its felt inputs (milestone M5). No host acceptance flag crosses a boundary.

## Verifier mapping (`proof::verify`)

| Native step | Circuit treatment |
| --- | --- |
| `Reader` framing, canonical fields, exact length | Not an input. Openings are guessed values. Canonicality comes from `m31_to_u32`/byte range checks. Acceptance is existential over valid encodings, which equals native acceptance of the unique canonical encoding. |
| `ro(tag, parts)` | Byte stream: 37-byte domain, u64 lengths, parts. Payloads sit at byte offset 1 mod 4, so each value/digest is byte-split and repacked (M1). |
| Transcript `commit` / `coins` | Fixed 16 phases, `ro("state")` and indexed `ro("coins")` blocks (M1). |
| `field()` rejection sampling (≤12 tries) | Circuit requires the first candidate to be valid. Native rejects a candidate with probability ~2^-29. A rare valid proof would be unwrappable (completeness only), and this is documented. |
| `ood()` rational map + `valid_ood` | Same rule: first candidate must pass. Checks are enforced as nonzero/inequality constraints. |
| `queries()` sort + dedup | All 120 draws processed in draw order. Duplicates repeat identical checks. Low 13 bits come from coin words (M3). |
| `open()` Merkle paths | Leaf `ro("leaf")`, 13 `ro("node")` levels, direction from index bits. No node sharing because topology must not depend on data (M2). |
| `check_ood` | 1,273 AIR constraints in QM31 at z and z−step. Selector polys are fixed coefficients evaluated at z (M4). |
| `batch_at` per query | Linear DEEP combination: two denominators per query, one inversion each (M4). |
| FRI folds and final constant | Ten single folds. Twiddle `x` comes from index bits via circle-point products. Final value equals opened `last` (M4). |

## Estimated size (before optimization)

About 89k Blake compressions → ~7.1M BlakeG rows (log23). About 2M byte range
checks via TripleXor (log21). QM31 ops are about 1M (log20). Server circuit
proving at log23 is unmeasured. StarkWare's own leaf-verifier registry uses
`blake_g_gate` log23.

## Milestones

- **M1** Byte-framed `ro`, transcript and coins in circuit; differential tests
  plus `blake-vectors.json`.
- **M2** Merkle opening gadget; all openings of a real proof authenticate.
- **M3** Query derivation, index bits, domain points, previous-row index.
- **M4** OOD AIR check, DEEP batch, FRI; full verify of retained proofs;
  mutation rejections matching the client's negative suite.
- **M5** Statement binding, circuit-A proof, Cairo bridge regeneration, virtual-OS
  capture, PROOF2 large; Sepolia submission through the operator's node.
- **Review** Independent math review of the mapping (rejection-sampling
  deviations, existential encoding argument, byte-split soundness) before M5.

## Status (2026-09-23)

| Milestone | Result | Tests |
| --- | --- | --- |
| M1 `ro`/transcript/coins | All 6 RO domains, 16 phases × 120 coin words and 30 field draws match the client's independent Python vectors | `tests/m1_transcript.rs` (5) |
| M2 Merkle | Real openings of every tree authenticate; value, salt, sibling and index tampering rejected | `tests/m2_merkle.rs` (3) |
| M3 queries/domain | In-circuit transcripts of 3 proofs reproduce the final state and all 120 draws; points, previous rows and 10 twiddle layers match stwo | `tests/m3_queries.rs` (3) |
| M4 complete verifier | All 6 retained proofs (3 native, 3 browser) accepted with one topology; 7 content/statement mutations rejected | `tests/m4_ood.rs` (4), `tests/m4_full.rs` (2) |

Constraints are not re-typed. `sym.rs` runs the client's own
`air::constraints` over a symbolic field and compiles the graph. A test checks
the compiled constraints against native evaluation on random points. The root
enters as a variable: it is traced as zero, and `s3·root_j` is subtracted from
exactly the nine root constraints (checked against the real code).

Size of the full circuit: 6,351,520 BlakeG rows (log23), 3,188,958 TripleXor
(log22), 306,000 M31→u32 (log19). Building it takes ~7 s and 3 GiB per proof.

### First circuit-A proof (`results/log25-baseline/proof-1/`)

The retained native proof-1 was proven as circuit A: 144 s proving (4 pinned
workers), 92.2 GiB peak RSS under a 100 GiB cap, zero swap. The proof verifies
natively in 2.8 ms, and the output/trace/topology/config controls are rejected.
The largest component is `qm31_ops` at log25. It is dominated by byte splitting,
repacking and range-check glue, not by Blake (log23) or DEEP arithmetic. Encoded
for the Cairo bridge, the proof is 60,644 felts. The upstream unused-variable
lint is clean. Every unused variable is a leftover coin word or a discarded
point coordinate, marked where it is produced.

### log23 circuit A (`results/circuit-a/`)

`src/aligned.rs` builds every leaf and node message at word level. For a canonical
word `(lo, hi)`, `m31_to_u32(256 lo) = (256 b0, b1)` and `m31_to_u32(256 hi) =
(256 b2, b3)` exactly. Each offset-1 message word is `T_prev.hi + S + i T.lo`. No
value or digest byte is guessed. Salts and siblings are guessed directly as aligned
words: full words are canonical by TripleXor, partial words by byte checks. Order
selection happens on the 9 aligned words. Result: 6.31M qm31_ops (log23), 69.6 s,
39.7 GiB. Bridge rebuilt from the new manifest, 7/7 standalone checks, exact OS
message, PROOF2 141 s / 62.6 GiB.

### Items for the math review

1. **Existential encoding.** Openings are guessed values. Their encodings come from
   `m31_to_u32`, and the aligned words from the `S`/`T` limb identity. Guessed salt and
   sibling words are canonical by TripleXor, and partial words by byte checks tied to
   the low limb. Every guessed scalar is projected to `(v,0,0,0)`.
2. **First-candidate sampling.** `field()` and `ood()` must succeed on the first
   draw. Native retries have probability ~2^-29 and 2^-60 respectively. This
   loses completeness only.
3. **Queries.** All 120 draws are processed in draw order without dedup.
4. **FRI pairs.** One shared path per sibling pair; `[leaf(2m)] ++ siblings[1..]`
   is a valid odd path, so this is equivalent to opening both.
5. **Previous-row openings.** They are authenticated (kept for exact equivalence)
   but unused by any native check. Dropping them saves ~14k compressions.
6. **Gate semantics relied on.** TripleXor enforces canonical inputs/outputs;
   `m31_to_u32` enforces canonicality and rejects the representation p. The Gate
   relation pads single-coordinate consumers with zeros.
7. **Statement.** Outputs are `Blake2s(x)` and the root. The bridge must rebuild
   `x` byte-exactly (MAGIC, client circuit digest, serde_json of Public).

## Later optimizations (require format review)

Word-aligned framing, Poseidon2-M31 Merkle commitments (reusing the client's
permutation), narrower base leaves, node sharing via sorted-query topology.
