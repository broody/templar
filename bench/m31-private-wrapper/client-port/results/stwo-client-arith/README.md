# stwo-circuits client route, end to end (arithmetic-only profile)

2026-09-23. **The membership relation is proved on the client as a blinded stwo-circuits
proof that uses only `eq` and `qm31_ops`. It is verified by the Cairo bridge inside the
virtual OS and wrapped as a verified PROOF2.** There are no Blake, XOR or M31-to-u32
components, no lookup tables and no statement hash. The client peak is 0.56 GiB, or
0.28 GiB in bounded-memory mode, down from 2.75 GiB on the stock component set.

| Stage | Where | Time | Peak memory | Evidence |
| --- | --- | ---: | ---: | --- |
| Client proof (membership + statement, 45-row blinding) | client, 1 thread | 2.5–5.5 s typical, 17.5 s outlier | 0.56 GiB | `client/` |
| Same, bounded-memory mode (16-column FRI batches) | client, 1 thread | 4.1–10.2 s | **0.28 GiB** | `bounded-memory/` |
| Bridge, standalone Cairo | server | — | — | 3.38M steps, 10/10 checks (`bridge-validation/`) |
| Virtual OS execution of the account | server | 8.8 s | 0.84 GiB | 4.93M steps, exact message (`os-capture/`) |
| PROOF2 large path | server | 116 s | 52.2 GiB | verified, 3/3 rejections (`proof2/`) |

Stock route for comparison (`../stwo-client-stock/`): client 2.75 GiB, bridge 5.06M
steps, OS 7.22M steps, PROOF2 140 s / 63.1 GiB.

## What changed

- **Profile** (fork `broody/proving`, branch `templar/arithmetic-profile`: Rust `4656ab6c0`,
  Cairo `852bc4d87`, on upstream `5a7c5ed`). `Profile::Arithmetic` keeps `eq` and `qm31_ops`.
  Every other component is absent, with log size 0. A present component is at least log 4,
  so 0 is unambiguous, and the circuit hash commits it because it hashes every component's
  log size.
  - The prover skips absent traces, columns, padding and blinding.
  - Both verifiers (Rust native and Cairo `circuit_air`) skip absent components' columns
    and constraints. They reject a nonzero claimed sum for an absent component. That sum
    has no trace behind it, so it would otherwise be a free term that could balance a
    cheating LogUp sum.
  - The in-circuit Rust verifier (for recursion) still accepts only the full profile.
  - Upstream suites pass on the fork: circuit-common, circuit-verifier, circuit-prover
    (plus 5 new profile tests) and Cairo `circuit_air`.
- **Statement without a hash.** The eight outputs carry 32 M31 limbs, packed four per QM31
  with upstream `from_partial_evals`:

  | Limbs | Content |
  | --- | --- |
  | 0–1 | tag `TMPZ` `SA01` |
  | 2–10 | chain id, 28-bit LE |
  | 11–19 | pool address, 28-bit LE |
  | 20–28 | root |
  | 29–31 | zero |

  Guessed limbs are upstream `guess_m31`, which a `pointwise_mul` pins to the base field,
  so each output decodes to exactly one limb tuple. The bridge checks the tag, the zero
  padding and that each chain/pool limb is below 2^28, and recombines each as a canonical
  felt252. The account asserts the proof's chain equals the transaction's chain. It
  emits `(class, 'TMPZSA01_MEMBERSHIP_V1', chain, pool, root[9])`. The pool checks `pool`
  is itself and `root` is one of its roots. The account is 49,851 Sierra felts (stock:
  79,481).
- **Bridge** (`cairo-arith/`, `build_bridge_arith.py`): the fork's five Cairo crates are
  vendored unchanged except the two GENERATED sections, which are regenerated for this
  shape by `examples/gen_cairo_consts.rs`. Absent columns render as `INVALID_COLUMN_IDX`.
  `circuit_air`'s own `compute_circuit_hash_matches_reference` test pins upstream's
  production constants, so it is not run on a regenerated shape. The layout test and the
  pinned circuit hash cover that instead.

## Bounded-memory mode

The fork also carries our bounded-memory PCS mode (`8acdbe55d`), a three-way merge of
`bench/bounded-memory/stwo.patch` from stwo `489a0f3` onto this stwo. It includes the runtime
files only; the unused streamed-Merkle API is left out.
- Owned trees keep polynomial coefficients instead of expanded evaluations.
- Each tree is regenerated alone to open it, and its root is checked.
- FRI quotients are accumulated `max_fri_columns` columns at a time.

It changes storage only. A new circuit-prover test checks that bounded proofs equal
unbounded ones field for field, for both profiles, and verify. The ported PCS and framework
tests pass (13 PCS/quotient, 18 framework), as do the full stwo (299) and circuit-prover
(29) suites.

Same binary, same circuit, 1 thread, three fresh witnesses each (`bounded-memory/runs.json`):

| Mode | Peak RSS | Proving |
| --- | ---: | ---: |
| Unbounded | 587 MB (0.56 GiB) | 2.8–5.9 s |
| Bounded, 16-column batches | **295 MB (0.28 GiB)** | 4.1–10.2 s |
| Bounded, 1-column batches | 304 MB | 4.4–12.5 s |

A bounded-mode proof is accepted by the same pinned Cairo bridge (3.37M steps). The circuit
hash is unchanged, since the mode does not touch the circuit.

## Tamper controls

- **Native** (Rust, `examples/support`): output, trace root, preprocessed root, circuit hash,
  config, and moving one unit of `eq`'s claimed sum onto the absent `triple_xor`.
- **Cairo bridge:** tag, root output, absent claimed sum ("absent component claims a
  nonzero sum"), proof body, wrong pool, wrong chain, wrong root, trailing data and
  truncated data.
- **PROOF2:** changed output, flipped proof byte and truncated proof.

## Caveats

- **Timing.** Proving time on one thread is dominated by the 26-bit PoW grind, so it varies
  run to run: 17.5 s recorded, 2.5 / 3.2 / 5.5 s on repeats. Memory is stable at 0.56 GiB.
- **Hiding** rests on upstream row padding (45 rows of `eq` and `qm31_ops`), which is
  unproven. With no lookup tables, no table multiplicity depends on the witness. The
  remaining question is the one in broody/templar#2.
- **Review.** The profile is our fork; it needs review before production (see the
  checklist in the zk-guide page "Two ways to build the client proof").
- **Scope.** Membership only; the chain state is a synthetic local fixture (block 100);
  nothing was submitted. The PROOF2 input PIE is `bfec231e…` (`proof2/inputs.sha256`).
