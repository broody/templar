# PROOF2's leaf circuit: H2 and H4 apply, plus a suspected H5

2026-09-26. **Private: undisclosed upstream findings.** Keep them out of public issues, public
forks and `docs/`.

`src/main.rs` audits the PROOF2 that the prover server actually sends. That proof is the
large-path leaf-verifier circuit at `broody/proving@b54ed94f` (`target/proving-server`), which
wraps a bucket-25 Cairo proof. Its blinding code is upstream's, unchanged; it matches
`5a7c5ed`'s up to a type refactor.

## Method

Input: a P5 job (`os.pie.zip`, `proof.bin`).

1. **The real proof.** The harness runs the Cairo stage as `prove_leaf_bounded` does. It builds
   the leaf-verifier circuit and blinds it as the leaf prover does:
   - 45 rows per component (35 queries + `NON_QUERY_INFO_LEAK` 10);
   - seeded with the Cairo proof's trace root.

   It then pads the circuit to the registry targets and proves it (bounded, 16 columns). The
   uncompressed proof must equal the job's `proof.bin` payload. **It does, byte for byte**, so the
   audit is of the proof that was produced.
2. **Rank audit.** Two more seeds, traced with proof A's own lookup challenges (replayed from its
   transcript; the replayed roots equal proof A's commitments). Per tree and log size, the audit
   finds the column combinations that no seed changes, then classifies each one:
   - a constraint identity (zero on every row);
   - witness-dependent (a leak).
3. **End to end.** The harness evaluates those combinations on proof A's opened values at each
   query and looks the tuple up in seed B's committed extension (2²⁵ points). A control looks up
   as many single columns.

Jobs: `ordinary-transfer` and `braavos-transfer`, same results. Reports:
[`results/`](results/). Each run takes about 200 s and peaks at about 72 GB RSS.

## Results

Circuit: trace log size 23. FRI: blowup 2², 35 queries, PoW 26.

| Tree, log size (components) | Rank | Unblinded | Witness-dependent |
| --- | ---: | ---: | ---: |
| base 23 (`qm31_ops`, `blake_g_gate`) | 58/64 | 6 | **4: H2**, `dst_k − op0_k − op1_k` |
| base 21 (`m31_to_u32`) | 3/4 | 1 | 0: limb identity |
| **interaction 23** (same as base 23) | 56/60 | 4 | **4: H4**, `blake_g_gate` interaction columns 44–47 minus 40–43 |
| every other group | full | 0 | 0 |

- **H2.** The four limb combinations are nonzero on 1.4–4.0M rows.
  - The base 23 group's other two unblinded combinations are copy identities between
    `blake_g_gate` columns.
- **H4.** Nonzero on exactly 6,013,440 rows. That is every real Blake G instance and none of the
  45 blinding rows.
- **End to end**, both jobs:
  - base: 35/35 queries found in seed B's extension; control 0/35;
  - interaction: 35/35; control 0/35.
- **Two seeds are not enough.** The two-seed kernel also held five dense `blake_g_gate` base
  combinations: 45 blinding rows cannot span its roughly 50 independent columns for one fixed
  pair of seeds. The third seed removes them. The base end-to-end tuple included them, and they
  match seed B by construction. The four H2 combinations survive three seeds, so their match is
  the evidence.

Mode does not matter: the bound spend gives the same kernel as the ordinary one, only the row
counts differ.

## Also found

- **The blinding seed is the Cairo proof's trace root**
  (`build_and_fill_cairo_verifier_circuit`), the same upstream.
  - PROOF2 is a deterministic function of the job. A retry returns the same proof, so retries do
    not accumulate H2 evaluations.
  - The blinding is pseudorandom only to someone who cannot compute the Cairo trace.
- **H5 (suspected, not demonstrated): range-limited columns get too little randomness.**
  - `NON_QUERY_INFO_LEAK` counts leaked information in M31s. The blinding count, queries + 10,
    therefore assumes each blinding row adds one uniform M31 to every column. Many columns hold
    small limbs. Bits per value, from the run:

    | Component | Columns by width |
    | --- | --- |
    | `blake_g_gate` | 16 bits ×24, 12 ×2, 9 ×4, 8 ×14, 7 ×2, 4 ×6 |
    | `triple_xor` | 16 bits ×8, 8 ×12 |
    | `m31_to_u32` | 16 bits and 15 bits |

    The lookup tables' multiplicity columns move by small counts.
  - A 4-bit column receives 45 × 4 = 180 bits of blinding. The proof opens it at 35 queries plus
    two QM31 OODS points: 43 M31s, about 1,330 bits.
  - For a fixed witness, the openings therefore lie in a set of density about 2⁻¹¹⁵⁰, and the
    openings are not statistically hidden. Even 16-bit columns fall short: 720 bits.
  - Given a candidate witness, membership is a small lattice problem: 45 unknowns in [0, 16),
    35 equations mod p, and a short-vector gap of about 2¹⁹. LLL should settle it. So a
    distinguisher holding two candidate witnesses could likely tell them apart.
  - To demonstrate: flip one cell of a real witness row and show that LLL finds the true
    blinding vector for the real witness but none for the flipped one. That needs `fpylll` or
    similar, which is not installed.

## What it means

- **PROOF2 is not zero-knowledge as built.**
  - H2 reveals four witness-only polynomials in the clear, and H4 one QM31, each at 35 points
    plus OODS.
  - Mode hiding (spec §12) and everything else in the Cairo trace depend on this.
- **No practical attack is known.** The leaked polynomials depend on the entire leaf-verifier
  witness:
  - the Cairo proof's openings, FRI and Merkle hashing;
  - the Fiat–Shamir challenges derived from the Cairo trace.

  An attacker would have to predict them for each candidate. That needs the whole Cairo trace,
  including the client proof and the signatures. The leaked values are a few hundred M31s out of
  an 8M-row witness.
- **Only StarkWare can fix it.**
  - Both findings are topology: add-only qm31 rows, and zero output multiplicities in Blake
    blinding. Changing values in the prover does not remove them.
  - A fixed circuit has a new preprocessed root. `verify_recursive_circuit` accepts only the
    recursion root and the roots in the large-proofs registry, so Starknet would refuse it until
    StarkWare ships a new registry.
  - Our H2 fix (`broody/proving-private#1`) applies to our own client circuits only.
- **Disclosure.** This extends the pending private report:
  - H2 and H4 now confirmed on the production PROOF2 circuit;
  - H5 as a suspected issue, after a Math Reviewer pass.

## Run

```bash
cd bench/m31-private-wrapper/proof2-hiding
RUSTFLAGS="-C target-cpu=native" cargo build --release
./target/release/templar-proof2-hiding ~/.local/share/templar/runs/account-bound-p5/jobs/ordinary-transfer OUT_DIR
```

The toolchain is the fork's nightly (`rust-toolchain.toml`), and `Cargo.lock` is seeded from
the fork's. Run nothing else heavy alongside: about 72 GB peak.
