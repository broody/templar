# Upstream check: H2 in stock `proving@5a7c5ed`, plus a new H4

2026-09-23. `src/main.rs` links only against unmodified upstream (`target/proving-main` at
`5a7c5ed`). It uses the full component profile, upstream's `add_zk_blinding` with
`n_queries + NON_QUERY_INFO_LEAK` = 80 rows, and the production circuit FRI config
(blowup 2¹, 70 queries, PoW 26). Those are the settings `privacy_circuit_verify` (the
recursive privacy proof behind PROOF1 and PROOF2) and `leaf_prover` use. The circuit is
synthetic, with private data in every witness component:
- 400 mul/add gates over 16 private QM31 values;
- private Blake G (40), triple XOR (30) and M31→u32 (20) instances.

Nothing here touches our fork.

## Results

Two-seed rank audit, fixed lookup challenges. Each unblinded combination is classified:
- **constraint identity:** zero on every row, witness rows included; harmless;
- **witness-dependent:** nonzero on some witness row; a leak.

| Tree, log size (components) | Rank | Unblinded | Witness-dependent |
| --- | ---: | ---: | ---: |
| base 12 (`qm31_ops`) | 8/12 | 4 | **4: H2**, `dst_k − op0_k − op1_k` |
| base 7 (`eq`, `triple_xor`, `m31_to_u32`, `blake_g_gate`) | 77/80 | 3 | 0: limb and copy identities |
| **interaction 7** (same) | 88/92 | 4 | **4: H4**, nonzero on exactly the 40 Blake G instances |
| every other group (the tables) | full | 0 | 0 |

**H2, end to end on a real upstream proof.** We prove with seed A
(`prove_circuit_assignment`). For each H2 combination we evaluate it on every query's
opened values and look the result up in seed B's committed extension (8,192 points).
- **70/70** queries match, for all four combinations.
- Control: a single column's opened values match seed B **0/70**.

## H4 (new): an unblinded LogUp batch in `blake_g_gate`

- **What we saw.** The difference of interaction columns 92–95 and 88–91 (one QM31, a single
  fraction batch of `blake_g_gate`) does not change with the seed. It is zero on every
  blinding row and nonzero on the 40 private G instances.
- **Likely cause.** `blake_g_gate_zk_blinding` never uses the gate's outputs, so on blinding
  rows the output-yield lookups have multiplicity 0 and contribute nothing. On real rows the
  outputs are used, so that batch carries `mult / (γ − ℓ(addr, out))` for the private G
  outputs.
- **Consequence.** The verifier opens interaction columns at every query and at OODS, so it
  learns evaluations of a witness-only polynomial built from Blake G outputs.
- **What we did not run.** An end-to-end lookup against a proof would need the proof's own
  lookup challenges, which come from its transcript. The rank result already shows the
  polynomial is seed-independent on every row.
- **Fix direction.** Give blinding rows nonzero output multiplicity, for example by
  consuming each blinded output once (as the qm31 blinding's `x + 0 = x` self-use does), or
  pair output yields with blinded lookups in the same batch.

## Relevance

- Upstream's recursive privacy circuit (`privacy_circuit_verify`) and the large-path leaf
  prover use exactly this blinding, and their circuits are dominated by Blake and qm31
  arithmetic. So H2, and likely H4, apply to the ZK of StarkWare's privacy proofs. **This is
  not yet tested on those circuits themselves.**
- The mod-p bias (H3, `qm31_from_u32s` on raw `u32`s) is in the same upstream code.
- **Handling:** private disclosure to StarkWare. The draft is in broody/templar#2 (internal
  notes). Do not post publicly.
